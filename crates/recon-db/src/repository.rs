//! PostgreSQL-backed persistence for scan runs and their results.
//!
//! # Why runtime-checked queries, not `query!`/`query_as!`
//!
//! sqlx's compile-time-checked macros (`query!`, `query_as!`) connect to a live
//! database — or read a checked-in `.sqlx` offline cache generated from one — while
//! *compiling* this crate. Neither is available in every environment this crate is
//! built in (in particular, no PostgreSQL instance was reachable while writing this
//! module), and requiring one would make `cargo build` fail for anyone without a
//! database configured, which is not acceptable for a workspace member other crates
//! depend on.
//!
//! Every query below instead goes through [`sqlx::query`] / [`sqlx::query_as`] with
//! bound parameters (`$1`, `$2`, ...). These are still prepared statements sent over
//! the PostgreSQL protocol — never string concatenation — just checked against the
//! schema at run time instead of at compile time. The one exception is
//! [`ScanRepository::save_results`]'s batch insert, which uses [`sqlx::QueryBuilder`]
//! as the task explicitly allows, since neither `query!` nor a single bound `query!`
//! call can express a variable-length `VALUES` list.

use sqlx::{PgPool, QueryBuilder};
use uuid::Uuid;

use crate::{DbError, ScanResultRecord};

/// Repository for the `scans` and `scan_results` tables.
///
/// Built from an already-configured [`sqlx::PgPool`] (see [`crate::DbConfig`] for how
/// to obtain a connection string) so that pooling and connection lifecycle stay the
/// caller's responsibility.
pub struct ScanRepository {
    pool: PgPool,
}

impl ScanRepository {
    /// Wraps an existing connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Creates a new `scans` row for `target_domain` and returns its id.
    ///
    /// `started_at` is set to the current time; `finished_at` and `candidates_tested`
    /// are left unset until [`ScanRepository::finish_scan`] is called.
    ///
    /// # Errors
    /// Returns [`DbError::Query`] if the insert fails.
    pub async fn create_scan(&self, target_domain: &str) -> Result<Uuid, DbError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO scans (id, target_domain, started_at, finished_at, candidates_tested)
             VALUES ($1, $2, now(), NULL, NULL)",
        )
        .bind(id)
        .bind(target_domain)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Marks `scan_id` as finished: sets `finished_at` to now and records how many
    /// candidates were tested.
    ///
    /// # Errors
    /// Returns [`DbError::Query`] if the update fails.
    pub async fn finish_scan(&self, scan_id: Uuid, candidates_tested: i32) -> Result<(), DbError> {
        sqlx::query("UPDATE scans SET finished_at = now(), candidates_tested = $2 WHERE id = $1")
            .bind(scan_id)
            .bind(candidates_tested)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Bulk-inserts `results` as rows of `scan_results` belonging to `scan_id`, in a
    /// single `INSERT ... VALUES (...), (...), ...` statement rather than one round-trip
    /// per row.
    ///
    /// `scan_id` is taken as an explicit parameter (rather than trusted from each
    /// record's own `scan_id` field) so a caller cannot accidentally scatter one batch
    /// across scans by mixing up records built for different runs.
    ///
    /// Does nothing (and issues no query) when `results` is empty.
    ///
    /// # Errors
    /// Returns [`DbError::Query`] if the insert fails.
    pub async fn save_results(&self, scan_id: Uuid, results: &[ScanResultRecord]) -> Result<(), DbError> {
        if results.is_empty() {
            return Ok(());
        }

        let mut builder = QueryBuilder::new(
            "INSERT INTO scan_results (id, scan_id, subdomain, ip, cname, http_status, title, priority, created_at) ",
        );
        builder.push_values(results, |mut row, record| {
            row.push_bind(record.id)
                .push_bind(scan_id)
                .push_bind(&record.subdomain)
                .push_bind(&record.ip)
                .push_bind(&record.cname)
                .push_bind(record.http_status)
                .push_bind(&record.title)
                .push_bind(&record.priority)
                .push_bind(record.created_at);
        });

        builder.build().execute(&self.pool).await?;
        Ok(())
    }

    /// Returns the id of the most recently *finished* scan of `target_domain`, if any.
    ///
    /// Scans that are still in progress (`finished_at IS NULL`) are never returned,
    /// since their result set is incomplete and unsuitable as a diff baseline.
    ///
    /// # Errors
    /// Returns [`DbError::Query`] if the query fails.
    pub async fn get_last_completed_scan(&self, target_domain: &str) -> Result<Option<Uuid>, DbError> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM scans
             WHERE target_domain = $1 AND finished_at IS NOT NULL
             ORDER BY finished_at DESC
             LIMIT 1",
        )
        .bind(target_domain)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(id,)| id))
    }

    /// Loads every `scan_results` row belonging to `scan_id`.
    ///
    /// # Errors
    /// Returns [`DbError::Query`] if the query fails.
    pub async fn get_scan_results(&self, scan_id: Uuid) -> Result<Vec<ScanResultRecord>, DbError> {
        let records = sqlx::query_as::<_, ScanResultRecord>(
            "SELECT id, scan_id, subdomain, ip, cname, http_status, title, priority, created_at
             FROM scan_results
             WHERE scan_id = $1",
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }
}

/// Integration tests that exercise a real PostgreSQL database.
///
/// These are `#[ignore]`d by default so `cargo test` succeeds without any database
/// configured (see the module-level rustdoc for why `recon-db` avoids compile-time
/// database dependence entirely). To run them:
///
/// 1. Start a local PostgreSQL instance and create an empty database for it, e.g.
///    `createdb recon_rs_test`.
/// 2. Set `DATABASE_URL` to point at it, e.g.
///    `export DATABASE_URL=postgres://user:password@localhost:5432/recon_rs_test`.
/// 3. Apply migrations: `cargo install sqlx-cli --no-default-features --features
///    rustls,postgres` once, then `sqlx migrate run --source crates/recon-db/migrations`
///    (or `cd crates/recon-db && sqlx migrate run`).
/// 4. Run `cargo test -p recon-db -- --ignored`.
///
/// Each test below creates its own scan(s) and never truncates the tables, so re-running
/// them against a persistent database accumulates rows; point `DATABASE_URL` at a
/// disposable test database.
#[cfg(test)]
mod tests {
    use super::*;
    use recon_core::ScanResult;
    use std::collections::HashMap;

    async fn connect_from_env() -> PgPool {
        let config = crate::DbConfig::from_env().expect("DATABASE_URL must be set to run ignored DB tests");
        PgPool::connect(&config.database_url)
            .await
            .expect("failed to connect to DATABASE_URL")
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL database; see module rustdoc"]
    async fn create_scan_then_finish_scan_round_trips() {
        let pool = connect_from_env().await;
        let repo = ScanRepository::new(pool);

        let scan_id = repo.create_scan("example.com").await.expect("create_scan should succeed");
        repo.finish_scan(scan_id, 42).await.expect("finish_scan should succeed");

        let last = repo
            .get_last_completed_scan("example.com")
            .await
            .expect("get_last_completed_scan should succeed");
        assert_eq!(last, Some(scan_id));
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL database; see module rustdoc"]
    async fn save_results_then_get_scan_results_round_trips() {
        let pool = connect_from_env().await;
        let repo = ScanRepository::new(pool);

        let scan_id = repo.create_scan("example.com").await.expect("create_scan should succeed");
        let scan_result = ScanResult {
            subdomain: "api-dev.example.com".to_string(),
            cname: None,
            http_title: Some("Internal Panel".to_string()),
            headers: HashMap::new(),
        };
        let record = ScanResultRecord::new(scan_id, scan_result, None, Some(200), None);

        repo.save_results(scan_id, std::slice::from_ref(&record))
            .await
            .expect("save_results should succeed");

        let saved = repo
            .get_scan_results(scan_id)
            .await
            .expect("get_scan_results should succeed");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].subdomain, "api-dev.example.com");
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL database; see module rustdoc"]
    async fn save_results_is_a_no_op_on_an_empty_slice() {
        let pool = connect_from_env().await;
        let repo = ScanRepository::new(pool);

        let scan_id = repo.create_scan("example.com").await.expect("create_scan should succeed");
        repo.save_results(scan_id, &[]).await.expect("save_results should succeed");

        let saved = repo
            .get_scan_results(scan_id)
            .await
            .expect("get_scan_results should succeed");
        assert!(saved.is_empty());
    }
}
