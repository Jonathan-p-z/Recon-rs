//! Errors surfaced by `recon-cli`'s orchestration layer.

/// Errors that can occur while loading configuration, running a scan, or writing its
/// report.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// A `recon-core` operation failed (config loading, DNS resolution, HTTP probing).
    #[error(transparent)]
    Recon(#[from] recon_core::ReconError),
    /// A `recon-db` operation failed (connection, migration, query).
    #[error(transparent)]
    Db(#[from] recon_db::DbError),
    /// Reading the seed file, or writing a report, failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// `--target` is not covered by the loaded program's `[scope]` — the scan is
    /// refused outright rather than merely warned about.
    #[error("target '{target}' is not in the authorized scope for this program — refusing to scan (scope: {scope_domains})")]
    OutOfScope {
        /// The rejected `--target` value.
        target: String,
        /// The program's configured scope domains, joined for display.
        scope_domains: String,
    },
}
