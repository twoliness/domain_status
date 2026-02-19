//! HTTP client initialization.
//!
//! This module provides functions to initialize HTTP clients with proper
//! configuration for requests and redirect handling.

use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use reqwest::ClientBuilder;

/// Initializes the HTTP client with default settings.
///
/// Creates a `reqwest::Client` configured with:
/// - User-Agent header from options
/// - Timeout from options
/// - Redirect following DISABLED (SSRF protection)
/// - HTTP/2 support enabled
/// - Rustls TLS backend (no native TLS)
///
/// # Security Note
///
/// Redirects are disabled to prevent SSRF bypass via TOCTOU race conditions.
/// Redirect chains are manually resolved by `resolve_redirect_chain()` with SSRF
/// validation at each hop. If this client followed redirects automatically,
/// a malicious server could redirect to internal IPs after validation.
///
/// # Arguments
///
/// * `config` - Configuration containing user-agent and timeout settings
///
/// # Returns
///
/// A configured HTTP client ready for making requests.
///
/// # Errors
///
/// Returns a `reqwest::Error` if client creation fails.
pub async fn init_client(config: &Config) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    use crate::config::TCP_CONNECT_TIMEOUT_SECS;

    // Always allow invalid certificates to maximize data capture
    // Certificate issues will be recorded as security warnings
    // SECURITY: Disable redirects to prevent SSRF bypass via TOCTOU race conditions.
    // After resolve_redirect_chain() validates the redirect chain, if this client
    // followed redirects, a malicious server could redirect to an internal IP.
    let client = ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none()) // SECURITY: Prevent SSRF bypass
        .timeout(Duration::from_secs(config.timeout_seconds))
        .connect_timeout(Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS)) // FIX: Enforce TCP connect timeout
        .user_agent(config.user_agent.clone())
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;
    Ok(Arc::new(client))
}

/// Initializes a shared HTTP client for redirect resolution.
///
/// Creates a `reqwest::Client` with redirects disabled so we can manually track
/// the redirect chain. This allows us to capture the full redirect path including
/// intermediate URLs.
///
/// # Arguments
///
/// * `config` - Configuration containing user-agent and timeout settings
///
/// # Returns
///
/// A configured HTTP client with redirects disabled.
///
/// # Errors
///
/// Returns a `reqwest::Error` if client creation fails.
pub async fn init_redirect_client(config: &Config) -> Result<Arc<reqwest::Client>, reqwest::Error> {
    use crate::config::TCP_CONNECT_TIMEOUT_SECS;

    // Always allow invalid certificates to maximize data capture
    // Certificate issues will be recorded as security warnings
    let client = ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(config.timeout_seconds))
        .connect_timeout(Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS)) // FIX: Enforce TCP connect timeout
        .user_agent(config.user_agent.clone())
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;
    Ok(Arc::new(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    use crate::config::FailOn;

    fn create_test_config() -> Config {
        // Create Config manually with required fields
        Config {
            file: PathBuf::from("test.txt"),
            user_agent: "test-agent/1.0".to_string(),
            timeout_seconds: 10,
            db_path: PathBuf::from("./test.db"),
            max_concurrency: 30,
            fail_on: FailOn::Never,
            fail_on_pct_threshold: 10,
            rate_limit_rps: 15,
            log_level: crate::config::LogLevel::Info,
            log_format: crate::config::LogFormat::Plain,
            status_port: None,
            fingerprints: None,
            geoip: None,
            enable_whois: false,
            adaptive_error_threshold: 0.2,
            log_file: None,
            progress_callback: None,
        }
    }

    #[tokio::test]
    async fn test_init_client_success() {
        let config = create_test_config();
        let result = init_client(&config).await;
        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(Arc::strong_count(&client), 1);
    }

    #[tokio::test]
    async fn test_init_client_with_custom_timeout() {
        let mut config = create_test_config();
        config.timeout_seconds = 30;
        let result = init_client(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_client_with_custom_user_agent() {
        let mut config = create_test_config();
        config.user_agent = "Custom-Agent/2.0".to_string();
        let result = init_client(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_redirect_client_success() {
        let config = create_test_config();
        let result = init_redirect_client(&config).await;
        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(Arc::strong_count(&client), 1);
    }

    #[tokio::test]
    async fn test_init_client_and_redirect_client_different_instances() {
        let config = create_test_config();
        let client1 = init_client(&config).await.unwrap();
        let client2 = init_redirect_client(&config).await.unwrap();
        // They should be different Arc instances
        assert!(!Arc::ptr_eq(&client1, &client2));
    }

    #[tokio::test]
    async fn test_init_client_empty_user_agent() {
        // Test that empty user agent string is handled gracefully
        let mut config = create_test_config();
        config.user_agent = String::new();
        let result = init_client(&config).await;
        // Should succeed even with empty user agent (reqwest allows it)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_client_zero_timeout() {
        // Test that zero timeout is handled (edge case - should still create client)
        let mut config = create_test_config();
        config.timeout_seconds = 0;
        let result = init_client(&config).await;
        // Should succeed (zero timeout means no timeout, not immediate failure)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_client_very_large_timeout() {
        // Test that very large timeout values don't cause overflow
        let mut config = create_test_config();
        config.timeout_seconds = u64::MAX / 1000; // Large but reasonable timeout
        let result = init_client(&config).await;
        // Should succeed (Duration handles large values gracefully)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_redirect_client_empty_user_agent() {
        // Test that empty user agent works for redirect client too
        let mut config = create_test_config();
        config.user_agent = String::new();
        let result = init_redirect_client(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_redirect_client_zero_timeout() {
        // Test that zero timeout works for redirect client
        let mut config = create_test_config();
        config.timeout_seconds = 0;
        let result = init_redirect_client(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_client_does_not_follow_redirects() {
        // CRITICAL SECURITY TEST: Verify the main client does NOT follow redirects.
        // This prevents SSRF bypass via TOCTOU race conditions.
        // After resolve_redirect_chain() validates the redirect chain, if the main client
        // followed redirects, a malicious server could redirect to an internal IP.
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        let redirect_url = format!("http://{}/redirect", server.addr());
        let target_url = format!("http://{}/target", server.addr());

        // Set up server to return 302 redirect
        server.expect(
            Expectation::matching(request::method_path("GET", "/redirect"))
                .respond_with(status_code(302).insert_header("Location", target_url.clone())),
        );

        // The target should NOT be hit if redirects are disabled
        // (we don't add an expectation for /target)

        let config = create_test_config();
        let client = init_client(&config).await.expect("Should create client");

        // Make request to the redirect URL
        let response = client
            .get(&redirect_url)
            .send()
            .await
            .expect("Should send request");

        // Verify we got the 302 status (not followed to target)
        assert_eq!(
            response.status().as_u16(),
            302,
            "Main client should NOT follow redirects - got status {} instead of 302",
            response.status().as_u16()
        );

        // Verify the URL is still the redirect URL (not the target)
        assert_eq!(
            response.url().path(),
            "/redirect",
            "Main client should NOT follow redirects"
        );
    }

    #[tokio::test]
    async fn test_both_clients_have_redirects_disabled() {
        // Verify that both init_client and init_redirect_client have redirects disabled
        // This is critical for SSRF protection
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        let redirect_url = format!("http://{}/redirect", server.addr());
        let target_url = format!("http://{}/target", server.addr());

        // Set up two expectations - one for each client
        server.expect(
            Expectation::matching(request::method_path("GET", "/redirect"))
                .times(2..) // Both clients will hit this
                .respond_with(status_code(302).insert_header("Location", target_url.clone())),
        );

        let config = create_test_config();
        let main_client = init_client(&config)
            .await
            .expect("Should create main client");
        let redirect_client = init_redirect_client(&config)
            .await
            .expect("Should create redirect client");

        // Test main client
        let main_response = main_client
            .get(&redirect_url)
            .send()
            .await
            .expect("Main client should send request");
        assert_eq!(
            main_response.status().as_u16(),
            302,
            "Main client should not follow redirects"
        );

        // Test redirect client
        let redirect_response = redirect_client
            .get(&redirect_url)
            .send()
            .await
            .expect("Redirect client should send request");
        assert_eq!(
            redirect_response.status().as_u16(),
            302,
            "Redirect client should not follow redirects"
        );
    }
}
