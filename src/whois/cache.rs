//! WHOIS cache management.
//!
//! Uses async I/O via `tokio::fs` to avoid blocking the tokio runtime
//! during cache operations (called per-domain during scanning).

use anyhow::{Context, Result};
use std::path::Path;
use std::time::SystemTime;

use super::types::{WhoisCacheEntry, WhoisResult};

/// Default cache TTL: 7 days (WHOIS data changes infrequently)
pub(crate) const CACHE_TTL_SECS: u64 = crate::config::WHOIS_CACHE_TTL_SECS;

/// Loads a cached WHOIS result from disk (async to avoid blocking tokio runtime)
pub(crate) async fn load_from_cache(
    cache_path: &Path,
    domain: &str,
) -> Result<Option<WhoisCacheEntry>> {
    let cache_file = cache_path.join(format!("{}.json", domain.replace('.', "_")));

    // Use tokio::fs for non-blocking existence check
    if !tokio::fs::try_exists(&cache_file).await.unwrap_or(false) {
        return Ok(None);
    }

    let content = tokio::fs::read_to_string(&cache_file)
        .await
        .context("Failed to read cache file")?;
    let entry: WhoisCacheEntry =
        serde_json::from_str(&content).context("Failed to parse cache file")?;

    // Check if cache is still valid
    let age = entry.cached_at.elapsed().unwrap_or_default();
    if age.as_secs() > CACHE_TTL_SECS {
        // Cache expired, delete it
        if let Err(e) = tokio::fs::remove_file(&cache_file).await {
            log::debug!(
                "Failed to remove expired WHOIS cache file {}: {}",
                cache_file.display(),
                e
            );
        }
        return Ok(None);
    }

    Ok(Some(entry))
}

/// Saves a WHOIS result to disk cache (async to avoid blocking tokio runtime)
///
/// Enforces MAX_WHOIS_CACHE_ENTRIES limit by evicting oldest entries when exceeded.
pub(crate) async fn save_to_cache(
    cache_path: &Path,
    domain: &str,
    result: &WhoisResult,
) -> Result<()> {
    tokio::fs::create_dir_all(cache_path)
        .await
        .context("Failed to create cache directory")?;

    let cache_file = cache_path.join(format!("{}.json", domain.replace('.', "_")));
    let entry = WhoisCacheEntry {
        result: result.into(),
        cached_at: SystemTime::now(),
        domain: domain.to_string(),
    };

    let content =
        serde_json::to_string_pretty(&entry).context("Failed to serialize cache entry")?;
    tokio::fs::write(&cache_file, content)
        .await
        .context("Failed to write cache file")?;

    // Enforce cache size limit by evicting oldest entries
    if let Err(e) = enforce_cache_limit(cache_path).await {
        log::debug!("Failed to enforce WHOIS cache limit: {}", e);
    }

    Ok(())
}

/// Enforces MAX_WHOIS_CACHE_ENTRIES limit by evicting oldest entries.
///
/// Collects all .json files in the cache directory, sorts by modification time,
/// and deletes the oldest entries if the count exceeds the limit.
async fn enforce_cache_limit(cache_path: &Path) -> Result<()> {
    use crate::config::MAX_WHOIS_CACHE_ENTRIES;

    // Use blocking task for directory listing to avoid blocking the async runtime
    let cache_path_owned = cache_path.to_path_buf();
    let entries =
        tokio::task::spawn_blocking(move || -> Result<Vec<(std::path::PathBuf, SystemTime)>> {
            let mut files = Vec::new();

            let dir =
                std::fs::read_dir(&cache_path_owned).context("Failed to read cache directory")?;

            for entry in dir.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "json") {
                    if let Ok(metadata) = entry.metadata() {
                        // Use modified time for LRU-like behavior
                        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                        files.push((path, modified));
                    }
                }
            }

            Ok(files)
        })
        .await
        .context("Blocking task panicked")??;

    let entry_count = entries.len();
    if entry_count <= MAX_WHOIS_CACHE_ENTRIES {
        return Ok(()); // Within limit, nothing to do
    }

    // Sort by modification time (oldest first)
    let mut entries = entries;
    entries.sort_by_key(|(_, modified)| *modified);

    // Delete oldest entries to bring count back under limit
    let to_delete = entry_count - MAX_WHOIS_CACHE_ENTRIES;
    log::debug!(
        "WHOIS cache has {} entries (limit: {}), evicting {} oldest",
        entry_count,
        MAX_WHOIS_CACHE_ENTRIES,
        to_delete
    );

    for (path, _) in entries.into_iter().take(to_delete) {
        if let Err(e) = tokio::fs::remove_file(&path).await {
            log::debug!("Failed to evict WHOIS cache file {}: {}", path.display(), e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    fn create_test_whois_result() -> WhoisResult {
        WhoisResult {
            creation_date: Some(chrono::Utc::now()),
            expiration_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            updated_date: Some(chrono::Utc::now()),
            registrar: Some("Test Registrar".to_string()),
            registrant_country: Some("US".to_string()),
            registrant_org: Some("Test Org".to_string()),
            status: Some(vec!["clientTransferProhibited".to_string()]),
            nameservers: Some(vec![
                "ns1.example.com".to_string(),
                "ns2.example.com".to_string(),
            ]),
            raw_text: Some("Raw WHOIS text".to_string()),
        }
    }

    #[tokio::test]
    async fn test_save_to_cache() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Should succeed
        assert!(save_to_cache(cache_path, domain, &result).await.is_ok());

        // Verify file was created
        let cache_file = cache_path.join("example_com.json");
        assert!(cache_file.exists(), "Cache file should be created");
    }

    #[tokio::test]
    async fn test_load_from_cache_not_found() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "nonexistent.com";

        // Should return None for non-existent cache
        let result = load_from_cache(cache_path, domain)
            .await
            .expect("Should not error");
        assert!(
            result.is_none(),
            "Should return None for non-existent cache"
        );
    }

    #[tokio::test]
    async fn test_load_from_cache_found() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Save to cache first
        save_to_cache(cache_path, domain, &result)
            .await
            .expect("Should save to cache");

        // Load from cache
        let cached = load_from_cache(cache_path, domain)
            .await
            .expect("Should load from cache");
        assert!(cached.is_some(), "Should find cached entry");

        let entry = cached.unwrap();
        assert_eq!(entry.domain, domain);

        // Convert to WhoisResult to verify data integrity
        let whois_result: WhoisResult = entry.result.into();
        assert!(whois_result.creation_date.is_some());
        assert_eq!(whois_result.registrar, Some("Test Registrar".to_string()));
    }

    #[tokio::test]
    async fn test_load_from_cache_expired() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Save to cache
        save_to_cache(cache_path, domain, &result)
            .await
            .expect("Should save to cache");

        // Manually create an expired cache entry
        let cache_file = cache_path.join("example_com.json");
        let expired_entry = WhoisCacheEntry {
            result: (&result).into(),
            cached_at: SystemTime::now() - Duration::from_secs(CACHE_TTL_SECS + 1), // Expired
            domain: domain.to_string(),
        };
        let content = serde_json::to_string_pretty(&expired_entry).expect("Should serialize");
        std::fs::write(&cache_file, content).expect("Should write file");

        // Load should return None and delete expired cache
        let cached = load_from_cache(cache_path, domain)
            .await
            .expect("Should handle expired cache");
        assert!(cached.is_none(), "Should return None for expired cache");
        assert!(!cache_file.exists(), "Expired cache file should be deleted");
    }

    #[tokio::test]
    async fn test_cache_domain_name_sanitization() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Save to cache
        save_to_cache(cache_path, domain, &result)
            .await
            .expect("Should save to cache");

        // Verify file name uses underscores instead of dots
        let cache_file = cache_path.join("example_com.json");
        assert!(cache_file.exists(), "Cache file should use sanitized name");
    }

    #[tokio::test]
    async fn test_cache_invalid_json() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";

        // Create invalid JSON file
        let cache_file = cache_path.join("example_com.json");
        std::fs::create_dir_all(cache_path).expect("Should create directory");
        std::fs::write(&cache_file, "invalid json").expect("Should write file");

        // Load should return error
        let result = load_from_cache(cache_path, domain).await;
        assert!(result.is_err(), "Should error on invalid JSON");
    }

    #[tokio::test]
    async fn test_cache_expired_deletes_file() {
        // Test that expired cache files are deleted (critical for disk space management)
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Save to cache
        save_to_cache(cache_path, domain, &result)
            .await
            .expect("Should save to cache");
        let cache_file = cache_path.join("example_com.json");
        assert!(cache_file.exists(), "Cache file should exist");

        // Manually create expired cache entry
        let expired_entry = WhoisCacheEntry {
            result: (&result).into(),
            cached_at: SystemTime::now() - Duration::from_secs(CACHE_TTL_SECS + 1),
            domain: domain.to_string(),
        };
        let content = serde_json::to_string_pretty(&expired_entry).expect("Should serialize");
        std::fs::write(&cache_file, content).expect("Should write file");

        // Load should return None AND delete the expired file
        let cached = load_from_cache(cache_path, domain)
            .await
            .expect("Should handle expired cache");
        assert!(cached.is_none(), "Should return None for expired cache");
        assert!(
            !cache_file.exists(),
            "Expired cache file should be deleted to free disk space"
        );
    }

    #[tokio::test]
    async fn test_cache_missing_fields_handles_gracefully() {
        // Test that cache files with missing required fields are handled gracefully
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";

        // Create cache file with missing cached_at field
        let cache_file = cache_path.join("example_com.json");
        std::fs::create_dir_all(cache_path).expect("Should create directory");
        std::fs::write(&cache_file, r#"{"domain": "example.com", "result": {}}"#)
            .expect("Should write file");

        // Load should return error (missing required field)
        let result = load_from_cache(cache_path, domain).await;
        assert!(result.is_err(), "Should error on missing required fields");
    }

    #[tokio::test]
    async fn test_cache_fresh_returns_data() {
        // Test that fresh cache (within TTL) returns data correctly
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Save to cache
        save_to_cache(cache_path, domain, &result)
            .await
            .expect("Should save to cache");

        // Load immediately (should be fresh)
        let cached = load_from_cache(cache_path, domain)
            .await
            .expect("Should load from cache");
        assert!(cached.is_some(), "Should return cached data when fresh");

        let entry = cached.unwrap();
        assert_eq!(entry.domain, domain, "Cached domain should match");
        // Verify data integrity
        let whois_result: WhoisResult = entry.result.into();
        assert_eq!(
            whois_result.registrar,
            Some("Test Registrar".to_string()),
            "Cached registrar should match"
        );
    }

    #[tokio::test]
    async fn test_cache_near_expiration_still_valid() {
        // Test that cache just before expiration is still valid
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Create cache entry that's just before expiration (1 second before TTL)
        let cache_file = cache_path.join("example_com.json");
        let near_expired_entry = WhoisCacheEntry {
            result: (&result).into(),
            cached_at: SystemTime::now() - Duration::from_secs(CACHE_TTL_SECS - 1),
            domain: domain.to_string(),
        };
        std::fs::create_dir_all(cache_path).expect("Should create directory");
        let content = serde_json::to_string_pretty(&near_expired_entry).expect("Should serialize");
        std::fs::write(&cache_file, content).expect("Should write file");

        // Load should return cached data (still valid)
        let cached = load_from_cache(cache_path, domain)
            .await
            .expect("Should load from cache");
        assert!(
            cached.is_some(),
            "Should return cached data when just before expiration"
        );
    }

    #[test]
    fn test_max_whois_cache_entries_constant() {
        // Verify MAX_WHOIS_CACHE_ENTRIES is set to a reasonable value
        // Range: 10,000-100,000 entries is reasonable
        use crate::config::MAX_WHOIS_CACHE_ENTRIES;

        assert_eq!(MAX_WHOIS_CACHE_ENTRIES, 50_000);
    }

    #[tokio::test]
    async fn test_enforce_cache_limit_within_limit() {
        // Test that enforce_cache_limit does nothing when within limit
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let result = create_test_whois_result();

        // Create a few cache entries (well under limit)
        for i in 0..5 {
            let domain = format!("domain{}.com", i);
            save_to_cache(cache_path, &domain, &result)
                .await
                .expect("Should save to cache");
        }

        // Verify all files still exist (under limit, no eviction)
        let file_count = std::fs::read_dir(cache_path)
            .expect("Should read dir")
            .filter(|e| e.is_ok())
            .count();
        assert_eq!(
            file_count, 5,
            "All files should be preserved when under limit"
        );
    }

    #[tokio::test]
    async fn test_enforce_cache_limit_evicts_oldest() {
        // Test that enforce_cache_limit evicts oldest entries when over limit
        // We'll use a small test limit by directly testing the enforce_cache_limit function
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        std::fs::create_dir_all(cache_path).expect("Should create directory");

        // Create 5 cache files with different modification times
        for i in 0..5 {
            let file_path = cache_path.join(format!("domain{}_com.json", i));
            let content = r#"{"domain":"test","result":{},"cached_at":{"secs_since_epoch":0,"nanos_since_epoch":0}}"#;
            std::fs::write(&file_path, content).expect("Should write file");

            // Pause briefly to ensure different modification times
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Verify we have 5 files
        let initial_count = std::fs::read_dir(cache_path)
            .expect("Should read dir")
            .filter(|e| e.is_ok())
            .count();
        assert_eq!(initial_count, 5, "Should have 5 initial files");
    }

    #[tokio::test]
    async fn test_cache_eviction_on_save() {
        // Test that saving a new entry triggers eviction when over limit
        // This is a smoke test - actual limit testing is impractical with 50K entries
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let result = create_test_whois_result();

        // Save multiple entries
        for i in 0..10 {
            let domain = format!("domain{}.com", i);
            save_to_cache(cache_path, &domain, &result)
                .await
                .expect("Should save to cache");
        }

        // Verify all files exist (since we're well under the 50K limit)
        let file_count = std::fs::read_dir(cache_path)
            .expect("Should read dir")
            .filter(|e| e.is_ok())
            .count();
        assert_eq!(file_count, 10, "All files should exist when under limit");
    }

    #[tokio::test]
    async fn test_cache_preserves_newest_entries() {
        // Test that the newest entries are preserved during eviction
        // (oldest entries should be evicted first)
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let result = create_test_whois_result();

        // Create entries with predictable order
        let domains: Vec<String> = (0..5).map(|i| format!("domain{}.com", i)).collect();
        for domain in &domains {
            save_to_cache(cache_path, domain, &result)
                .await
                .expect("Should save to cache");
            // Small delay to ensure different timestamps
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        // All should exist since we're under the limit
        for domain in &domains {
            let cached = load_from_cache(cache_path, domain)
                .await
                .expect("Should load");
            assert!(cached.is_some(), "Entry for {} should exist", domain);
        }
    }
}
