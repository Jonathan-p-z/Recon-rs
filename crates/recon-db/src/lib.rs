#![deny(clippy::all)]

//! `recon-db`: PostgreSQL persistence and scan-to-scan change detection for
//! [`recon_core`], for **authorized** bug bounty engagements.
//!
//! This crate stores the output of successive scans of the same target and diffs them
//! — new subdomains, disappeared subdomains, HTTP status changes — so an operator can
//! see what changed between two runs instead of re-triaging everything each time. It
//! performs no network scanning itself; that stays [`recon_core`]'s job.
//!
//! See [`repository`] for why this crate's queries are runtime-checked
//! (`sqlx::query`/`sqlx::query_as`) rather than the compile-time-checked
//! `query!`/`query_as!` macros.

mod config;
mod diff;
mod record;
mod repository;

pub use config::DbConfig;
pub use diff::{compute_diff, ScanDiff};
pub use record::ScanResultRecord;
pub use repository::ScanRepository;

/// Embedded schema migrations for the `scans`/`scan_results` tables, compiled directly
/// into the binary via `sqlx::migrate!` so no separate `sqlx migrate run` step is
/// required on a fresh machine — [`DbConfig::connect`] runs it automatically.
///
/// The path is resolved relative to *this crate's* `CARGO_MANIFEST_DIR` at compile
/// time (`crates/recon-db/migrations`), independent of the caller's working directory.
/// `Migrator::run` is idempotent: it tracks applied versions in a `_sqlx_migrations`
/// table and skips migrations already applied.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Errors that can occur while configuring or using [`ScanRepository`].
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// A database query or connection attempt failed.
    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),
    /// The database configuration could not be loaded (e.g. `DATABASE_URL` is unset).
    #[error("database configuration error: {0}")]
    Config(String),
    /// A schema migration failed to apply.
    #[error("database migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}
