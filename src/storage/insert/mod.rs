//! Database insert operations.
//!
//! This module provides functions to insert various types of records into the database:
//! - URL status records and related satellite tables
//! - Run metadata and statistics
//! - GeoIP data
//! - Enrichment data (structured data, social media, WHOIS, analytics)
//! - Failure records
//!
//! All inserts use parameterized queries to prevent SQL injection.

pub mod enrichment;
pub mod failure;
mod record;
pub mod retry;
mod run;
pub mod url;
mod utils;

// Re-export public API
pub use enrichment::{
    insert_analytics_ids, insert_geoip_data, insert_security_warnings, insert_social_media_links,
    insert_structured_data, insert_whois_data,
};
pub use failure::{insert_url_failure, insert_url_partial_failure};
pub use record::insert_batch_record;
pub use run::{
    insert_run_metadata, query_run_history, update_run_stats, RunMetadata, RunStats, RunSummary,
};
pub use url::{insert_url_record, UrlRecordInsertParams};
