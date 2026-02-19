//! Main URL record insertion.
//!
//! This module handles inserting URL status records and all related satellite tables
//! (technologies, nameservers, TXT records, MX records, headers, OIDs, redirect chain, SANs).

mod satellite;

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

use super::super::models::UrlRecord;
use super::retry::with_sqlite_retry;
use super::utils::naive_datetime_to_millis;

use satellite::{
    insert_certificate_sans, insert_http_headers, insert_mx_records, insert_nameservers,
    insert_oids, insert_redirect_chain, insert_security_headers, insert_technologies,
    insert_txt_records,
};

/// Parameters for inserting a URL record.
///
/// This struct groups all parameters needed to insert a URL record, reducing
/// function argument count and improving maintainability.
pub struct UrlRecordInsertParams<'a> {
    /// Database connection pool
    pub pool: &'a SqlitePool,
    /// The URL record to insert
    pub record: &'a UrlRecord,
    /// Security headers HashMap (will be inserted into url_security_headers table)
    pub security_headers: &'a std::collections::HashMap<String, String>,
    /// HTTP headers HashMap (will be inserted into url_http_headers table)
    pub http_headers: &'a std::collections::HashMap<String, String>,
    /// Vector of OID strings (will be inserted into url_oids table)
    pub oids: &'a std::collections::HashSet<String>,
    /// Vector of redirect URLs (will be inserted into url_redirect_chain table)
    pub redirect_chain: &'a [String],
    /// Vector of detected technologies (will be inserted into url_technologies table)
    pub technologies: &'a [crate::fingerprint::DetectedTechnology],
    /// Vector of DNS names from certificate SAN extension (will be inserted into url_certificate_sans table)
    pub subject_alternative_names: &'a [String],
}

/// Inserts a `UrlRecord` into the database with retry logic for transient errors.
///
/// This function inserts data into:
/// 1. The main `url_status` table (fact table with atomic fields)
/// 2. Normalized child tables (url_technologies, url_nameservers, url_txt_records, url_mx_records, url_security_headers, url_http_headers, url_oids, url_redirect_chain)
///
/// All inserts are wrapped in a transaction for atomicity. SQLITE_BUSY and SQLITE_LOCKED
/// errors are automatically retried with exponential backoff.
///
/// Note: Multi-valued fields (technologies, nameservers, txt_records, mx_records, security_headers, http_headers,
/// oids, redirect_chain) are stored only in normalized child tables, not as JSON in the main table.
/// This eliminates data duplication and establishes a single source of truth.
///
/// # Arguments
///
/// * `params` - Parameters for URL record insertion
///
/// # Returns
///
/// Returns the `id` of the inserted (or updated) `url_status` record, or an error if insertion fails.
// Large function handling comprehensive URL record insertion with transaction management and multiple satellite table inserts.
// Consider refactoring into smaller focused functions in Phase 4.
#[allow(clippy::too_many_lines)]
pub async fn insert_url_record(params: UrlRecordInsertParams<'_>) -> Result<i64, DatabaseError> {
    with_sqlite_retry(|| insert_url_record_impl(&params)).await
}

/// Internal implementation of insert_url_record (without retry logic).
#[allow(clippy::too_many_lines)]
async fn insert_url_record_impl(params: &UrlRecordInsertParams<'_>) -> Result<i64, DatabaseError> {
    let valid_from_millis = naive_datetime_to_millis(params.record.ssl_cert_valid_from.as_ref());
    let valid_to_millis = naive_datetime_to_millis(params.record.ssl_cert_valid_to.as_ref());

    log::debug!(
        "Inserting UrlRecord: initial_domain={}",
        params.record.initial_domain
    );

    // Start transaction for atomic dual-write
    let mut tx = params.pool.begin().await.map_err(DatabaseError::SqlError)?;

    // 1. Insert into main url_status table
    // Use RETURNING clause to get the ID in a single query (SQLite 3.35.0+)
    // This eliminates the need for a separate SELECT query and improves performance
    let url_status_id_result = sqlx::query_scalar::<_, i64>(
        "INSERT INTO url_status (
            initial_domain, final_domain, ip_address, reverse_dns_name, http_status, http_status_text,
            response_time_seconds, title, keywords, description, tls_version, ssl_cert_subject,
            ssl_cert_issuer, ssl_cert_valid_from_ms, ssl_cert_valid_to_ms, is_mobile_friendly, observed_at_ms,
            spf_record, dmarc_record, cipher_suite, key_algorithm, run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(final_domain, observed_at_ms) DO UPDATE SET
            initial_domain=excluded.initial_domain,
            ip_address=excluded.ip_address,
            reverse_dns_name=excluded.reverse_dns_name,
            http_status=excluded.http_status,
            http_status_text=excluded.http_status_text,
            response_time_seconds=excluded.response_time_seconds,
            title=excluded.title,
            keywords=excluded.keywords,
            description=excluded.description,
            tls_version=excluded.tls_version,
            ssl_cert_subject=excluded.ssl_cert_subject,
            ssl_cert_issuer=excluded.ssl_cert_issuer,
            ssl_cert_valid_from_ms=excluded.ssl_cert_valid_from_ms,
            ssl_cert_valid_to_ms=excluded.ssl_cert_valid_to_ms,
            is_mobile_friendly=excluded.is_mobile_friendly,
            spf_record=excluded.spf_record,
            dmarc_record=excluded.dmarc_record,
            cipher_suite=excluded.cipher_suite,
            key_algorithm=excluded.key_algorithm,
            run_id=excluded.run_id
        RETURNING id",
    )
    .bind(&params.record.initial_domain)
    .bind(&params.record.final_domain)
    .bind(&params.record.ip_address)
    .bind(&params.record.reverse_dns_name)
    .bind(params.record.status)
    .bind(&params.record.status_desc)
    .bind(params.record.response_time)
    .bind(&params.record.title)
    .bind(&params.record.keywords)
    .bind(&params.record.description)
    .bind(params.record.tls_version.as_ref().map(|v| v.as_str()))
    .bind(&params.record.ssl_cert_subject)
    .bind(&params.record.ssl_cert_issuer)
    .bind(valid_from_millis)
    .bind(valid_to_millis)
    .bind(params.record.is_mobile_friendly)
    .bind(params.record.timestamp)
    .bind(&params.record.spf_record)
    .bind(&params.record.dmarc_record)
    .bind(&params.record.cipher_suite)
    .bind(params.record.key_algorithm.as_ref().map(|k| k.as_str()))
    .bind(&params.record.run_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        log::error!(
            "Failed to insert UrlRecord for domain {} (final_domain: {}, status: {}, timestamp: {}): {} (SQL: INSERT INTO url_status ... ON CONFLICT)",
            params.record.initial_domain,
            params.record.final_domain,
            params.record.status,
            params.record.timestamp,
            e
        );
        DatabaseError::SqlError(e)
    });

    let url_status_id = match url_status_id_result {
        Ok(id) => id,
        Err(e) => {
            // Main insert failed - explicitly rollback transaction
            // Note: We ignore rollback errors since the transaction will be rolled back
            // by Drop anyway, but being explicit makes the intent clear
            if let Err(rollback_err) = tx.rollback().await {
                log::warn!(
                    "Failed to rollback transaction after main insert error (this is non-fatal): {}",
                    rollback_err
                );
            }
            return Err(e);
        }
    };

    // 2-10. Insert into satellite tables
    //
    // DESIGN DECISION: Satellite insert functions return () and handle errors internally.
    // This design prioritizes partial success over atomicity:
    // - If a satellite insert fails (e.g., technologies), the main URL record is still saved
    // - Partial data is better than no data at all
    // - Failures are logged for monitoring but don't block the main record insertion
    //
    // This differs from failure record satellite inserts (insert_url_failure_impl) which
    // propagate errors because failure records require atomicity - either all related data
    // is saved together, or none of it is (transaction rollback).
    //
    // If any satellite insert panics, the transaction will be rolled back by Drop.
    insert_technologies(&mut tx, url_status_id, params.technologies).await;
    insert_nameservers(&mut tx, url_status_id, &params.record.nameservers).await;
    insert_txt_records(&mut tx, url_status_id, &params.record.txt_records).await;
    insert_mx_records(&mut tx, url_status_id, &params.record.mx_records).await;
    insert_security_headers(&mut tx, url_status_id, params.security_headers).await;
    insert_http_headers(&mut tx, url_status_id, params.http_headers).await;
    insert_oids(&mut tx, url_status_id, params.oids).await;
    insert_redirect_chain(&mut tx, url_status_id, params.redirect_chain).await;
    insert_certificate_sans(&mut tx, url_status_id, params.subject_alternative_names).await;

    // Commit transaction - all inserts succeeded
    // If any satellite insert had failed internally, it would have been logged but not propagated.
    // The transaction will be rolled back by Drop if commit fails.
    tx.commit().await.map_err(|e| {
        log::error!(
            "Failed to commit transaction for url_status_id {} (domain: {}): {}",
            url_status_id,
            params.record.initial_domain,
            e
        );
        DatabaseError::SqlError(e)
    })?;

    Ok(url_status_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use sqlx::Row;
    use std::collections::{HashMap, HashSet};

    use crate::storage::migrations::run_migrations;

    /// Creates an in-memory SQLite database pool for testing
    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    /// Creates a test run record for FK constraint
    async fn create_test_run(pool: &SqlitePool, run_id: &str) {
        sqlx::query(
            "INSERT INTO runs (run_id, start_time_ms) VALUES (?, ?)
             ON CONFLICT(run_id) DO NOTHING",
        )
        .bind(run_id)
        .bind(1704067200000i64)
        .execute(pool)
        .await
        .expect("Failed to insert test run");
    }

    /// Creates a minimal UrlRecord for testing
    fn create_test_url_record() -> UrlRecord {
        UrlRecord {
            initial_domain: "example.com".to_string(),
            final_domain: "example.com".to_string(),
            ip_address: "93.184.216.34".to_string(),
            reverse_dns_name: Some("example.com".to_string()),
            status: 200,
            status_desc: "OK".to_string(),
            response_time: 0.123,
            title: "Example Domain".to_string(),
            keywords: Some("example, test".to_string()),
            description: Some("Example description".to_string()),
            tls_version: Some(crate::models::TlsVersion::Tls13),
            ssl_cert_subject: Some("CN=example.com".to_string()),
            ssl_cert_issuer: Some("CN=Let's Encrypt".to_string()),
            ssl_cert_valid_from: NaiveDate::from_ymd_opt(2024, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0),
            ssl_cert_valid_to: NaiveDate::from_ymd_opt(2025, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0),
            is_mobile_friendly: true,
            timestamp: 1704067200000, // 2024-01-01 00:00:00 UTC in milliseconds
            nameservers: Some(r#"["ns1.example.com", "ns2.example.com"]"#.to_string()),
            txt_records: Some(r#"["v=spf1 include:_spf.example.com ~all"]"#.to_string()),
            mx_records: Some(r#"[{"priority": 10, "hostname": "mail.example.com"}]"#.to_string()),
            spf_record: Some("v=spf1 include:_spf.example.com ~all".to_string()),
            dmarc_record: Some("v=DMARC1; p=none".to_string()),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
            key_algorithm: Some(crate::models::KeyAlgorithm::ECDSA),
            run_id: Some("test-run-1".to_string()),
        }
    }

    #[tokio::test]
    async fn test_insert_url_record_basic() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let result = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
        })
        .await;

        assert!(result.is_ok());
        let url_status_id = result.unwrap();
        assert!(url_status_id > 0);

        // Verify the record was inserted
        let row = sqlx::query(
            "SELECT initial_domain, final_domain, http_status, title FROM url_status WHERE id = ?",
        )
        .bind(url_status_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch inserted record");

        assert_eq!(row.get::<String, _>("initial_domain"), "example.com");
        assert_eq!(row.get::<String, _>("final_domain"), "example.com");
        assert_eq!(row.get::<i64, _>("http_status"), 200);
        assert_eq!(row.get::<String, _>("title"), "Example Domain");
    }

    #[tokio::test]
    async fn test_insert_url_record_with_technologies() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = vec![
            crate::fingerprint::DetectedTechnology {
                name: "WordPress".to_string(),
                version: None,
            },
            crate::fingerprint::DetectedTechnology {
                name: "PHP".to_string(),
                version: None,
            },
        ];
        let sans = Vec::new();

        let url_status_id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
        })
        .await
        .expect("Failed to insert record");

        // Verify technologies were inserted
        let tech_rows =
            sqlx::query("SELECT technology_name FROM url_technologies WHERE url_status_id = ?")
                .bind(url_status_id)
                .fetch_all(&pool)
                .await
                .expect("Failed to fetch technologies");

        assert_eq!(tech_rows.len(), 2);
        let tech_names: Vec<String> = tech_rows
            .iter()
            .map(|row| row.get::<String, _>("technology_name"))
            .collect();
        assert!(tech_names.contains(&"WordPress".to_string()));
        assert!(tech_names.contains(&"PHP".to_string()));
    }

    #[tokio::test]
    async fn test_insert_url_record_with_redirect_chain() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = vec![
            "http://example.com".to_string(),
            "https://example.com".to_string(),
        ];
        let technologies = Vec::new();
        let sans = Vec::new();

        let url_status_id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
        })
        .await
        .expect("Failed to insert record");

        // Verify redirect chain was inserted
        let redirect_rows = sqlx::query(
            "SELECT redirect_url FROM url_redirect_chain WHERE url_status_id = ? ORDER BY sequence_order",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch redirect chain");

        assert_eq!(redirect_rows.len(), 2);
        assert_eq!(
            redirect_rows[0].get::<String, _>("redirect_url"),
            "http://example.com"
        );
        assert_eq!(
            redirect_rows[1].get::<String, _>("redirect_url"),
            "https://example.com"
        );
    }

    #[tokio::test]
    async fn test_insert_url_record_with_security_headers() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let record = create_test_url_record();
        let mut security_headers = HashMap::new();
        security_headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        security_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let url_status_id = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
        })
        .await
        .expect("Failed to insert record");

        // Verify security headers were inserted
        let header_rows = sqlx::query(
            "SELECT header_name, header_value FROM url_security_headers WHERE url_status_id = ?",
        )
        .bind(url_status_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch security headers");

        assert_eq!(header_rows.len(), 2);
        let mut header_map = HashMap::new();
        for row in header_rows {
            let name: String = row.get("header_name");
            let value: String = row.get("header_value");
            header_map.insert(name, value);
        }
        assert_eq!(
            header_map.get("Strict-Transport-Security"),
            Some(&"max-age=31536000".to_string())
        );
        assert_eq!(
            header_map.get("X-Content-Type-Options"),
            Some(&"nosniff".to_string())
        );
    }

    #[tokio::test]
    async fn test_insert_url_record_upsert() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        // Insert first time
        let id1 = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
        })
        .await
        .expect("Failed to insert record");

        // Update record and insert again (same final_domain and timestamp)
        record.title = "Updated Title".to_string();
        record.status = 301;
        let id2 = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
        })
        .await
        .expect("Failed to upsert record");

        // Should return same ID (UPSERT)
        assert_eq!(id1, id2);

        // Verify the record was updated
        let row = sqlx::query("SELECT title, http_status FROM url_status WHERE id = ?")
            .bind(id1)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch updated record");

        assert_eq!(row.get::<String, _>("title"), "Updated Title");
        assert_eq!(row.get::<i64, _>("http_status"), 301);
    }

    #[tokio::test]
    async fn test_insert_url_record_nullable_fields() {
        let pool = create_test_pool().await;
        create_test_run(&pool, "test-run-1").await;
        let mut record = create_test_url_record();
        // Set nullable fields to None
        record.keywords = None;
        record.description = None;
        record.reverse_dns_name = None;
        record.tls_version = None;
        record.ssl_cert_subject = None;
        record.ssl_cert_issuer = None;
        record.ssl_cert_valid_from = None;
        record.ssl_cert_valid_to = None;
        record.spf_record = None;
        record.dmarc_record = None;
        record.cipher_suite = None;
        record.key_algorithm = None;
        record.run_id = None;

        let security_headers = HashMap::new();
        let http_headers = HashMap::new();
        let oids = HashSet::new();
        let redirect_chain = Vec::new();
        let technologies = Vec::new();
        let sans = Vec::new();

        let result = insert_url_record(UrlRecordInsertParams {
            pool: &pool,
            record: &record,
            security_headers: &security_headers,
            http_headers: &http_headers,
            oids: &oids,
            redirect_chain: &redirect_chain,
            technologies: &technologies,
            subject_alternative_names: &sans,
        })
        .await;

        assert!(result.is_ok());
        // Verify NULL fields are handled correctly
        let row =
            sqlx::query("SELECT keywords, description, tls_version FROM url_status WHERE id = ?")
                .bind(result.unwrap())
                .fetch_one(&pool)
                .await
                .expect("Failed to fetch record");

        assert!(row.get::<Option<String>, _>("keywords").is_none());
        assert!(row.get::<Option<String>, _>("description").is_none());
        assert!(row.get::<Option<String>, _>("tls_version").is_none());
    }
}
