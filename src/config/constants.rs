//! Configuration constants.
//!
//! This module defines all configuration constants used throughout the application,
//! including timeouts, size limits, and other operational parameters.

use std::time::Duration;

// constants (used as defaults)
#[allow(dead_code)]
/// Maximum concurrent requests (semaphore limit)
/// Increased from 20 to 30 for better throughput while maintaining low bot detection risk
pub const SEMAPHORE_LIMIT: usize = 30;
/// Interval in seconds for logging progress updates during URL processing
pub const LOGGING_INTERVAL: usize = 5;
/// Per-URL processing timeout in seconds
/// Set to 35s to allow for slow sites while still being reasonable
/// Formula: HTTP timeout (10s) + DNS timeout (3s) + TCP/TLS timeouts (10s) + enrichment (5s) + buffer (7s) = ~35s
/// Note: DNS timeout reduced to 3s helps fail fast on DNS issues, but overall timeout kept at 35s
/// to account for enrichment operations (GeoIP, WHOIS, technology detection, etc.)
pub const URL_PROCESSING_TIMEOUT: Duration = Duration::from_secs(35);
/// Default database file path
pub const DB_PATH: &str = "./domain_status.db";

// Network operation timeouts
/// DNS query timeout in seconds
/// Reduced to 3s - most DNS queries complete in <1s, 3s provides good buffer while failing fast
/// This significantly reduces time wasted on slow/unresponsive DNS servers
pub const DNS_TIMEOUT_SECS: u64 = 3;

// DNS record size limits
/// Maximum total size of concatenated DNS TXT records in bytes (1KB)
/// Prevents memory exhaustion from DNS tunneling attacks (e.g., 500KB of data in TXT records)
/// Most legitimate TXT records (SPF, DMARC, DKIM) are <512 bytes
/// Large enterprise SPF records occasionally reach 1KB; this provides reasonable headroom
/// TXT records exceeding this limit are truncated with a warning logged
pub const MAX_TXT_RECORD_SIZE: usize = 1024;

/// Maximum number of TXT records to process per domain
/// Prevents memory/storage exhaustion from malicious DNS servers returning thousands of TXT records
/// Most legitimate domains have 1-5 TXT records (SPF, DMARC, DKIM, domain verification)
/// 20 provides generous headroom while capping the worst-case scenario
pub const MAX_TXT_RECORD_COUNT: usize = 20;

/// TCP connection timeout in seconds
pub const TCP_CONNECT_TIMEOUT_SECS: u64 = 5;
/// TLS handshake timeout in seconds
pub const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 5;
/// WHOIS lookup timeout in seconds
/// Most WHOIS queries complete in <2s. Set to 5s to provide buffer while preventing worker blocking.
/// Without this, whois-service defaults to 30s which could consume most of URL_PROCESSING_TIMEOUT.
pub const WHOIS_TIMEOUT_SECS: u64 = 5;

/// Default User-Agent string for HTTP requests.
///
/// **Note:** This is a fallback value. The actual User-Agent is automatically
/// fetched at startup from Chrome's release API and cached locally for 30 days.
/// This ensures the User-Agent stays current over time without manual updates.
///
/// Users can override this via the `--user-agent` CLI flag.
///
/// The auto-update mechanism:
/// - Fetches latest Chrome version from Chrome's release API at startup
/// - Caches the version locally for 30 days (in `.user_agent_cache/`)
/// - Falls back to this hardcoded value if fetch fails
/// - Only updates if user didn't provide `--user-agent` flag
///
/// For better bot evasion, consider:
/// - Letting the auto-update mechanism keep it current (default behavior)
/// - Rotating between different User-Agent strings
/// - Customizing per target site via `--user-agent` flag
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

// Response and body size limits
/// Maximum response body size in bytes (2MB)
/// Responses larger than this are skipped to prevent memory exhaustion
pub const MAX_RESPONSE_BODY_SIZE: usize = 2 * 1024 * 1024;

// Script content size limits
/// Maximum script content size in bytes (100KB per script)
/// Limits the amount of inline JavaScript we extract per script tag
/// This prevents DoS attacks via large inline scripts
/// Enforced in src/fetch/response/html.rs when extracting inline script content
pub const MAX_SCRIPT_CONTENT_SIZE: usize = 100 * 1024; // 100KB per script

// HTML text extraction limits
/// Maximum HTML text content to extract in characters (50KB)
/// Limits the amount of text we extract from HTML for performance
/// This prevents excessive memory usage on very large pages
pub const MAX_HTML_TEXT_EXTRACTION_CHARS: usize = 50_000;
/// Maximum HTML preview length in characters for debugging (500 chars)
/// Used when logging HTML previews for debugging purposes
pub const MAX_HTML_PREVIEW_CHARS: usize = 500;

// Error message and header size limits
/// Maximum error message length in characters (2000 chars)
/// Prevents database bloat from unbounded error messages
/// Error messages longer than this are truncated with a note about the original length
pub const MAX_ERROR_MESSAGE_LENGTH: usize = 2000;
/// Maximum HTTP header value length in characters (1000 chars)
/// Prevents database bloat from very long header values (e.g., accept-ch headers)
/// Header values longer than this are truncated
pub const MAX_HEADER_VALUE_LENGTH: usize = 1000;
/// Maximum number of HTTP response headers to process
/// Prevents memory exhaustion from header bomb attacks (e.g., malicious sites sending 10K+ headers)
/// Most legitimate sites have <50 headers; 100 provides ample headroom
/// Headers beyond this limit are ignored with a warning logged
pub const MAX_HEADER_COUNT: usize = 100;
// Note: JavaScript execution constants removed - we don't execute JavaScript
// We match JS patterns as text (like WappalyzerGo) instead of executing JavaScript

// Redirect handling
/// Maximum number of redirect hops to follow
/// Prevents infinite redirect loops and excessive request chains
pub const MAX_REDIRECT_HOPS: usize = 10;

// Retry strategy
/// Initial delay in milliseconds before first retry
/// Reduced from 1000ms to 500ms for faster recovery while still providing backoff benefit
/// This reduces total retry overhead from ~3s to ~1.5s per failed request
pub const RETRY_INITIAL_DELAY_MS: u64 = 500;
/// Factor by which retry delay is multiplied on each attempt
pub const RETRY_FACTOR: u64 = 2;
/// Maximum delay between retries in seconds
/// Reduced from 20s to 15s for faster recovery from transient issues
pub const RETRY_MAX_DELAY_SECS: u64 = 15;
/// Maximum number of retry attempts (including initial attempt)
/// Set to 3 = initial attempt + 2 retries (total 3 attempts)
/// This prevents infinite retries and ensures we don't exceed URL_PROCESSING_TIMEOUT
pub const RETRY_MAX_ATTEMPTS: usize = 3;

// Status server timing
/// Status server logging interval in seconds (when status server is enabled)
pub const STATUS_SERVER_LOGGING_INTERVAL_SECS: u64 = 30;

// HTTP status codes (for clarity and consistency)
/// HTTP status code for "Too Many Requests" (rate limiting)
pub const HTTP_STATUS_TOO_MANY_REQUESTS: u16 = 429;

// Network download limits (for remote rulesets and GeoIP)
/// Maximum size for fingerprint ruleset downloads in bytes (10MB)
/// Prevents DoS attacks via extremely large ruleset files
pub const MAX_RULESET_DOWNLOAD_SIZE: usize = 10 * 1024 * 1024;
/// Maximum size for GeoIP database downloads in bytes (100MB)
/// GeoIP databases are large but should not exceed this limit
pub const MAX_GEOIP_DOWNLOAD_SIZE: usize = 100 * 1024 * 1024;
/// Maximum number of retries for network downloads (rulesets, GeoIP)
pub const MAX_NETWORK_DOWNLOAD_RETRIES: usize = 3;

// Cache TTL constants (in seconds)
/// Fingerprint ruleset cache TTL: 7 days
/// Based on commit history, HTTP Archive updates technologies roughly weekly
pub const FINGERPRINT_CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// WHOIS cache TTL: 7 days (WHOIS data changes infrequently)
pub const WHOIS_CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Maximum number of WHOIS cache entries (files) to maintain
/// Prevents unbounded disk usage and filesystem performance degradation
/// when scanning 100K+ domains. Oldest entries are evicted when limit is reached.
pub const MAX_WHOIS_CACHE_ENTRIES: usize = 50_000;
/// User-Agent cache TTL: 30 days
/// Chrome releases roughly every 4 weeks, so 30 days ensures we stay current
pub const USER_AGENT_CACHE_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// GeoIP cache TTL: 7 days
pub const GEOIP_CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
