//! DNS record queries (NS, TXT, MX).
//!
//! This module provides functions to query various DNS record types:
//! - Nameserver records (NS)
//! - Text records (TXT)
//! - Mail exchanger records (MX)

use anyhow::{Error, Result};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

/// Queries NS (nameserver) records for a domain.
///
/// # Arguments
///
/// * `domain` - The domain to query
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A vector of nameserver hostnames, or an empty vector if the query fails.
pub async fn lookup_ns_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<String>, Error> {
    // For TXT/NS/MX lookups, use domain as-is (no trailing dot needed)
    match resolver.lookup(domain, RecordType::NS).await {
        Ok(lookup) => {
            let nameservers: Vec<String> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::NS(ns) = rdata {
                        Some(ns.to_utf8())
                    } else {
                        None
                    }
                })
                .collect();
            Ok(nameservers)
        }
        Err(e) => {
            let error_msg = e.to_string();
            // "no records found" is expected for some domains - return empty vector
            if error_msg.contains("no records found") || error_msg.contains("NXDomain") {
                Ok(Vec::new())
            } else {
                // Actual failures (timeouts, network errors, etc.) should be propagated as errors
                // so they can be recorded as partial failures
                if error_msg.contains("timeout") || error_msg.contains("timed out") {
                    log::warn!("NS record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup NS records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

/// Queries TXT (text) records for a domain.
///
/// # Arguments
///
/// * `domain` - The domain to query
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A vector of TXT record strings, or an empty vector if the query fails.
pub async fn lookup_txt_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<String>, Error> {
    match resolver.lookup(domain, RecordType::TXT).await {
        Ok(lookup) => {
            // Count total TXT records for logging
            let total_count = lookup.iter().filter(|r| matches!(r, RData::TXT(_))).count();
            if total_count > crate::config::MAX_TXT_RECORD_COUNT {
                log::warn!(
                    "Domain {} has {} TXT records (limit: {}), capping (potential DNS abuse)",
                    domain,
                    total_count,
                    crate::config::MAX_TXT_RECORD_COUNT
                );
            }

            let txt_records: Vec<String> = lookup
                .iter()
                // Cap the number of TXT records to prevent memory/storage exhaustion
                .take(crate::config::MAX_TXT_RECORD_COUNT)
                .filter_map(|rdata| {
                    if let RData::TXT(txt) = rdata {
                        // TXT records can contain multiple strings - join them
                        let concatenated: String = txt
                            .iter()
                            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                            .collect::<Vec<String>>()
                            .join("");

                        // Truncate to MAX_TXT_RECORD_SIZE to prevent memory exhaustion from DNS tunneling
                        let original_len = concatenated.len();
                        let truncated = if original_len > crate::config::MAX_TXT_RECORD_SIZE {
                            log::warn!(
                                "TXT record for {} is {} bytes (limit: {}), truncating (potential DNS tunneling attack)",
                                domain,
                                original_len,
                                crate::config::MAX_TXT_RECORD_SIZE
                            );
                            concatenated[..crate::config::MAX_TXT_RECORD_SIZE].to_string()
                        } else {
                            concatenated
                        };

                        Some(truncated)
                    } else {
                        None
                    }
                })
                .collect();
            Ok(txt_records)
        }
        Err(e) => {
            let error_msg = e.to_string();
            // "no records found" is expected for domains without TXT records - return empty vector
            if error_msg.contains("no records found") || error_msg.contains("NXDomain") {
                Ok(Vec::new())
            } else {
                // Actual failures (timeouts, network errors, etc.) should be propagated as errors
                // so they can be recorded as partial failures
                if error_msg.contains("timeout") || error_msg.contains("timed out") {
                    log::warn!("TXT record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup TXT records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

/// Queries MX (mail exchanger) records for a domain.
///
/// # Arguments
///
/// * `domain` - The domain to query
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A vector of (priority, hostname) tuples, sorted by priority (lower = higher priority).
/// Returns an empty vector if the query fails or no MX records exist.
pub async fn lookup_mx_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<(u16, String)>, Error> {
    match resolver.lookup(domain, RecordType::MX).await {
        Ok(lookup) => {
            let mut mx_records: Vec<(u16, String)> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::MX(mx) = rdata {
                        Some((mx.preference(), mx.exchange().to_utf8()))
                    } else {
                        None
                    }
                })
                .collect();
            // Sort by priority (lower preference = higher priority)
            mx_records.sort_by_key(|(priority, _)| *priority);
            Ok(mx_records)
        }
        Err(e) => {
            let error_msg = e.to_string();
            // "no records found" is expected for domains without mail servers - return empty vector
            if error_msg.contains("no records found") || error_msg.contains("NXDomain") {
                Ok(Vec::new())
            } else {
                // Actual failures (timeouts, network errors, etc.) should be propagated as errors
                // so they can be recorded as partial failures
                if error_msg.contains("timeout") || error_msg.contains("timed out") {
                    log::warn!("MX record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup MX records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{MAX_TXT_RECORD_COUNT, MAX_TXT_RECORD_SIZE};

    #[test]
    fn test_max_txt_record_count_constant_value() {
        // Verify MAX_TXT_RECORD_COUNT is set to a reasonable value (20)
        // This caps the number of TXT records to prevent memory/storage exhaustion
        // Range: 1-100 records is reasonable
        assert_eq!(MAX_TXT_RECORD_COUNT, 20);
    }

    #[test]
    fn test_max_txt_record_size_constant_value() {
        // Verify MAX_TXT_RECORD_SIZE is set to a reasonable value (1KB)
        // This truncates individual TXT records to prevent memory exhaustion
        // Range: 512-4096 bytes is reasonable
        assert_eq!(MAX_TXT_RECORD_SIZE, 1024);
    }

    #[test]
    fn test_txt_record_limits_prevent_memory_exhaustion() {
        // Verify that the combination of count and size limits prevents memory exhaustion
        // Worst case: MAX_TXT_RECORD_COUNT * MAX_TXT_RECORD_SIZE = 20 * 1024 = 20KB
        // This is a reasonable upper bound for TXT records per domain
        let worst_case_bytes = MAX_TXT_RECORD_COUNT * MAX_TXT_RECORD_SIZE;
        assert_eq!(worst_case_bytes, 20 * 1024);
        assert!(
            worst_case_bytes <= 100 * 1024,
            "Worst case should be under 100KB"
        );
    }

    #[test]
    fn test_take_iterator_behavior() {
        // Verify that .take() correctly limits the number of items
        // This tests the underlying behavior we rely on in lookup_txt_records
        let items: Vec<i32> = (0..100).collect();
        let limited: Vec<i32> = items.iter().take(MAX_TXT_RECORD_COUNT).cloned().collect();
        assert_eq!(limited.len(), MAX_TXT_RECORD_COUNT);
        assert_eq!(limited.len(), 20);
    }

    #[test]
    fn test_take_iterator_with_fewer_items() {
        // Verify that .take() works correctly when there are fewer items than the limit
        let items: Vec<i32> = (0..5).collect();
        let limited: Vec<i32> = items.iter().take(MAX_TXT_RECORD_COUNT).cloned().collect();
        assert_eq!(limited.len(), 5);
    }
}
