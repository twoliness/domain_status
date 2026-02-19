//! URL scanning orchestration module.
//!
//! This module contains the main `run_scan` function and supporting types
//! for executing URL scans. The implementation is decomposed into:
//!
//! - `resources` - Data structures for scan state and resources
//! - `init` - Resource initialization logic
//! - `task` - Per-URL task processing
//! - `finalize` - Scan finalization and cleanup

mod finalize;
mod init;
mod resources;
mod task;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;
use log::warn;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::app::{log_progress, validate_and_normalize_url};
use crate::config::{LOGGING_INTERVAL, STATUS_SERVER_LOGGING_INTERVAL_SECS};

pub use resources::{ScanLoopResult, ScanResources, UrlTaskParams};

// Re-export for public API
pub use init::init_scan_resources;

/// Results of a URL scanning run.
///
/// Contains summary statistics and metadata about the completed scan.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// Total number of URLs processed
    pub total_urls: usize,
    /// Number of URLs successfully processed
    pub successful: usize,
    /// Number of URLs that failed to process
    pub failed: usize,
    /// Path to the SQLite database containing results
    pub db_path: PathBuf,
    /// Run identifier (format: `run_<timestamp_millis>`)
    pub run_id: String,
    /// Elapsed time in seconds
    pub elapsed_seconds: f64,
}

/// Helper function to invoke the progress callback if provided.
///
/// This reduces code duplication by centralizing the callback invocation logic.
#[allow(clippy::type_complexity)]
fn invoke_progress_callback(
    callback: &Option<Arc<dyn Fn(usize, usize, usize) + Send + Sync>>,
    completed: &Arc<std::sync::atomic::AtomicUsize>,
    failed: &Arc<std::sync::atomic::AtomicUsize>,
    total: usize,
) {
    if let Some(ref cb) = callback {
        cb(
            completed.load(Ordering::SeqCst),
            failed.load(Ordering::SeqCst),
            total,
        );
    }
}

/// Runs a URL scan with the provided configuration.
///
/// This is the main entry point for the library. It reads URLs from the input file,
/// processes them concurrently, and stores results in a SQLite database.
///
/// # Arguments
///
/// * `config` - Configuration for the scan (file path, concurrency, timeouts, etc.)
///
/// # Returns
///
/// Returns a `ScanReport` containing summary statistics, or an error if the scan
/// failed to complete.
///
/// # Errors
///
/// This function will return an error if:
/// - The input file cannot be opened
/// - Database initialization fails
/// - Network resources cannot be initialized
///
/// # Example
///
/// ```no_run
/// use domain_status::{Config, run_scan};
/// use std::path::PathBuf;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config {
///     file: PathBuf::from("urls.txt"),
///     ..Default::default()
/// };
/// let report = run_scan(config).await?;
/// println!("Processed {} URLs", report.total_urls);
/// # Ok(())
/// # }
/// ```
#[allow(clippy::too_many_lines)]
pub async fn run_scan(config: crate::config::Config) -> Result<ScanReport> {
    // Phase 1: Initialize all resources
    let (resources, mut url_source, total_lines, progress_callback) =
        init_scan_resources(config).await?;

    // Phase 2: Start status server if configured
    if let Some(port) = resources.config.status_port {
        let status_state = crate::status_server::StatusState {
            total_urls: Arc::clone(&resources.total_urls_in_file),
            total_urls_attempted: Arc::clone(&resources.total_urls_attempted),
            completed_urls: Arc::clone(&resources.completed_urls),
            failed_urls: Arc::clone(&resources.failed_urls),
            start_time: Arc::new(resources.start_time),
            error_stats: resources.error_stats.clone(),
            timing_stats: Some(Arc::clone(&resources.timing_stats)),
        };
        tokio::spawn(async move {
            if let Err(e) = crate::status_server::start_status_server(port, status_state).await {
                log::warn!("Failed to run status server: {}", e);
            }
        });
    }

    // Phase 3: Run the main scan loop
    // Use JoinSet instead of FuturesUnordered for better memory efficiency.
    // JoinSet allows interleaved spawning and reaping, preventing memory accumulation
    // when processing large URL lists (1M+ URLs).
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: usize = 10;

    loop {
        // Interleaved reaping: Try to reap any completed tasks before spawning new ones.
        // This prevents JoinHandle accumulation when tasks complete faster than new ones are read.
        // Using timeout(Duration::ZERO) for non-blocking check - if a task is ready, we get it;
        // otherwise we immediately continue to spawn new tasks.
        while let Ok(Some(task_result)) =
            tokio::time::timeout(std::time::Duration::ZERO, tasks.join_next()).await
        {
            if let Err(join_error) = task_result {
                resources.failed_urls.fetch_add(1, Ordering::SeqCst);
                log::warn!("Failed to join task (panicked): {:?}", join_error);
            }
        }

        let line_result = url_source.next_line().await;
        let line = match line_result {
            Ok(Some(line)) => {
                consecutive_errors = 0;
                line
            }
            Ok(None) => break,
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors > MAX_CONSECUTIVE_ERRORS {
                    return Err(anyhow::anyhow!(
                        "Too many consecutive read errors ({}): {}",
                        consecutive_errors,
                        e
                    ));
                }
                warn!("Failed to read line from input: {e}");
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some(url) = validate_and_normalize_url(trimmed) else {
            continue;
        };

        let permit = match Arc::clone(&resources.semaphore).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                warn!("Semaphore closed, skipping URL: {url}");
                continue;
            }
        };

        resources
            .total_urls_attempted
            .fetch_add(1, Ordering::SeqCst);

        let task_params = UrlTaskParams {
            url: Arc::from(url.as_str()),
            ctx: Arc::clone(&resources.shared_ctx),
            permit,
            request_limiter: resources.request_limiter.as_ref().map(Arc::clone),
            adaptive_limiter: resources.adaptive_limiter.as_ref().map(Arc::clone),
            completed_urls: Arc::clone(&resources.completed_urls),
            failed_urls: Arc::clone(&resources.failed_urls),
            total_urls_for_callback: total_lines,
            progress_callback: progress_callback.clone(),
        };

        // JoinSet::spawn() is like FuturesUnordered::push(tokio::spawn(...))
        // but manages the JoinHandle internally without accumulating them all in memory
        tasks.spawn(task::process_url_task(task_params));
    }

    // Phase 4: Set up logging and drain tasks
    let cancel = CancellationToken::new();
    let cancel_logging = cancel.child_token();

    let completed_urls_for_logging = Arc::clone(&resources.completed_urls);
    let failed_urls_for_logging = Arc::clone(&resources.failed_urls);
    let total_urls_for_logging = Arc::clone(&resources.total_urls_attempted);
    let start_time = resources.start_time;

    let logging_task = if resources.config.status_port.is_none() {
        Some(tokio::task::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(LOGGING_INTERVAL as u64));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        log_progress(start_time, &completed_urls_for_logging, &failed_urls_for_logging, Some(&total_urls_for_logging));
                    }
                    _ = cancel_logging.cancelled() => {
                        break;
                    }
                }
            }
        }))
    } else {
        Some(tokio::task::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                STATUS_SERVER_LOGGING_INTERVAL_SECS,
            ));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        log_progress(start_time, &completed_urls_for_logging, &failed_urls_for_logging, Some(&total_urls_for_logging));
                    }
                    _ = cancel_logging.cancelled() => {
                        break;
                    }
                }
            }
        }))
    };

    // Drain all remaining tasks (blocking wait until all complete)
    while let Some(task_result) = tasks.join_next().await {
        if let Err(join_error) = task_result {
            resources.failed_urls.fetch_add(1, Ordering::SeqCst);
            log::warn!("Failed to join task (panicked): {:?}", join_error);
        }
    }

    // Phase 5: Finalize
    let loop_result = ScanLoopResult {
        cancel,
        logging_task,
    };

    finalize::finalize_scan(resources, loop_result).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FailOn, LogFormat, LogLevel};
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_joinset_interleaved_reaping() {
        // Test that JoinSet correctly handles interleaved spawning and reaping
        // This validates our migration from FuturesUnordered to JoinSet
        let mut tasks: JoinSet<i32> = JoinSet::new();

        // Spawn a few tasks
        for i in 0..5 {
            tasks.spawn(async move { i });
        }

        // Reap completed tasks using the same pattern as run_scan
        let mut results = Vec::new();
        while let Ok(Some(result)) =
            tokio::time::timeout(std::time::Duration::from_millis(100), tasks.join_next()).await
        {
            if let Ok(value) = result {
                results.push(value);
            }
        }

        // All tasks should have completed
        assert_eq!(results.len(), 5, "Should have reaped all 5 tasks");

        // Verify JoinSet is empty
        assert!(
            tasks.is_empty(),
            "JoinSet should be empty after draining all tasks"
        );
    }

    #[tokio::test]
    async fn test_joinset_handles_panicked_tasks() {
        // Test that JoinSet correctly surfaces panicked tasks (important for error handling)
        let mut tasks: JoinSet<()> = JoinSet::new();

        // Spawn a task that will panic
        tasks.spawn(async {
            panic!("intentional panic for testing");
        });

        // Spawn a normal task
        tasks.spawn(async {});

        // Drain and verify we get the panic error
        let mut panics = 0;
        let mut successes = 0;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(()) => successes += 1,
                Err(_join_error) => panics += 1,
            }
        }

        assert_eq!(panics, 1, "Should have captured 1 panicked task");
        assert_eq!(successes, 1, "Should have captured 1 successful task");
    }

    #[tokio::test]
    async fn test_joinset_zero_timeout_non_blocking() {
        // Test that Duration::ZERO timeout is truly non-blocking
        // This is critical for the interleaved reaping pattern in run_scan
        let mut tasks: JoinSet<()> = JoinSet::new();

        // Spawn a task that takes a long time
        tasks.spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });

        // Zero timeout should return immediately (no waiting for the long task)
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(std::time::Duration::ZERO, tasks.join_next()).await;
        let elapsed = start.elapsed();

        // Should have timed out (Err) or returned None very quickly
        assert!(
            result.is_err() || matches!(result, Ok(None)),
            "Zero timeout should not block waiting for long task"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(10),
            "Zero timeout should return almost immediately, took {:?}",
            elapsed
        );

        // Cleanup: abort the long-running task
        tasks.abort_all();
    }

    #[tokio::test]
    async fn test_run_scan_validation_failure() {
        let config = Config {
            max_concurrency: 0, // Invalid - should fail validation
            ..Default::default()
        };

        let result = run_scan(config).await;
        assert!(result.is_err(), "Should fail with invalid configuration");
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Configuration validation failed")
                || error_msg.contains("max_concurrency")
                || error_msg.contains("greater than 0"),
            "Expected validation error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_run_scan_file_not_found() {
        let config = Config {
            file: std::path::PathBuf::from("/nonexistent/file/that/does/not/exist.txt"),
            ..Default::default()
        };

        let result = run_scan(config).await;
        assert!(result.is_err(), "Should fail when file doesn't exist");
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to open input file")
                || error_msg.contains("No such file")
                || error_msg.contains("not found"),
            "Expected file not found error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_run_scan_database_initialization_failure() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path().to_path_buf();
        drop(temp_file);

        let config = Config {
            file: std::path::PathBuf::from("/dev/null"),
            db_path,
            ..Default::default()
        };

        let result = run_scan(config).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_run_scan_empty_file() {
        let temp_input = NamedTempFile::new().expect("Failed to create temp file");
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");

        let config = Config {
            file: temp_input.path().to_path_buf(),
            db_path: temp_db.path().to_path_buf(),
            max_concurrency: 30,
            timeout_seconds: 10,
            rate_limit_rps: 15,
            adaptive_error_threshold: 0.2,
            fail_on: FailOn::Never,
            fail_on_pct_threshold: 10,
            enable_whois: false,
            log_level: LogLevel::Info,
            log_format: LogFormat::Plain,
            user_agent: crate::config::DEFAULT_USER_AGENT.to_string(),
            fingerprints: None,
            geoip: None,
            status_port: None,
            log_file: None,
            progress_callback: None,
        };

        let result = run_scan(config).await;
        match result {
            Ok(report) => {
                assert_eq!(report.total_urls, 0);
                assert_eq!(report.successful, 0);
                assert_eq!(report.failed, 0);
            }
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("database")
                        || error_msg.contains("Database")
                        || error_msg.contains("migration")
                        || error_msg.contains("Failed to initialize"),
                    "Expected database/setup error for empty file test, got: {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_run_scan_file_with_comments() {
        let temp_input = NamedTempFile::new().expect("Failed to create temp file");
        std::fs::write(
            temp_input.path(),
            "# This is a comment\nhttps://example.com\n# Another comment\n",
        )
        .expect("Failed to write test file");

        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");

        let config = Config {
            file: temp_input.path().to_path_buf(),
            db_path: temp_db.path().to_path_buf(),
            max_concurrency: 1,
            timeout_seconds: 10,
            rate_limit_rps: 15,
            adaptive_error_threshold: 0.2,
            fail_on: FailOn::Never,
            fail_on_pct_threshold: 10,
            enable_whois: false,
            log_level: LogLevel::Info,
            log_format: LogFormat::Plain,
            user_agent: crate::config::DEFAULT_USER_AGENT.to_string(),
            fingerprints: None,
            geoip: None,
            status_port: None,
            log_file: None,
            progress_callback: None,
        };

        let result = run_scan(config).await;
        let _ = result;
    }
}
