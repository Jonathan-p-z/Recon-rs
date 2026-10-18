#![deny(clippy::all)]

//! `recon-cli`: CLI entry point orchestrating `recon-core` (passive recon) and
//! `recon-db` (persistence) for **authorized** bug bounty engagements.
//!
//! ⚠️ Only ever run this against a `--target` domain you are explicitly authorized to
//! test under a bug bounty or pentest engagement's scope. When `--program` is given,
//! `--target` is validated against that program's `[scope]` before anything else
//! happens, and the scan is refused if it doesn't match — see [`recon_core::matches_scope`].
//! Without `--program`, no technical scope-list enforcement happens at all; that
//! responsibility is entirely the operator's.
//!
//! Each run writes a Markdown report locally under `--output`; there is no external
//! notification of any kind (no webhook, no email), by design.
//!
//! Run from the workspace root so the default `--config`/`--output` paths resolve
//! correctly, e.g. `cargo run -p recon-cli -- --target example.com`.

mod configs;
mod error;
mod pipeline;
mod report;
mod seed;

use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use configs::Configs;
use error::PipelineError;

/// Command-line arguments for `recon-cli`.
///
/// Deliberately has **no** fields for `requests_per_second`, `max_concurrent`,
/// `timeout_ms`, or any other resolver/prober throttling knob: those come exclusively
/// from `resolver.toml`/`prober.toml` inside `--config`, so a scan's rate limit can
/// never be silently bypassed or bumped from the command line under time pressure. This
/// omission is intentional, not an oversight.
#[derive(Debug, Parser)]
#[command(name = "recon-cli", version, about = "Passive subdomain recon for authorized bug bounty engagements.")]
struct Cli {
    /// Target domain to scan. Must be explicitly in scope for an authorized engagement.
    /// Enforced against `--program`'s `[scope]` when that flag is given; otherwise this
    /// tool performs no technical scope-list enforcement of its own.
    #[arg(long)]
    target: String,

    /// Directory containing `patterns.toml`, `resolver.toml`, and `prober.toml`.
    #[arg(long, default_value = "config/")]
    config: PathBuf,

    /// Directory to write Markdown reports into.
    #[arg(long, default_value = "./reports/")]
    output: PathBuf,

    /// Path to a program config file (e.g. `config/programs/vfc-vdp.toml`) bundling an
    /// authorized `[scope]` and a program-specific `[prober]` override (rate limit,
    /// identifying headers, user agent). When given: `--target` is validated against
    /// `[scope].domains` before anything else happens, and the scan is refused outright
    /// (not just warned about) if it is not covered; the program's `[prober]` table
    /// entirely replaces `--config`'s `prober.toml` for this run (`patterns.toml` and
    /// `resolver.toml` are unaffected — see [`recon_core::ProgramConfig`]). Omit for a
    /// generic scan with no program-specific scope enforcement.
    #[arg(long)]
    program: Option<PathBuf>,

    /// Optional file of already-known subdomains used to seed naming-pattern
    /// detection: one FQDN per line, blank lines and `#`-prefixed comments ignored.
    /// Omit for an empty seed list.
    #[arg(long)]
    seed_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // Deliberate choice: no unwrap()/expect()/panic! here. A failed scan (bad config,
    // unreachable database, network failure) is an expected outcome that should exit
    // cleanly with a logged cause, not surface an unreadable panic backtrace to the
    // operator.
    if let Err(err) = run().await {
        tracing::error!(error = %err, "scan failed");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), PipelineError> {
    let cli = Cli::parse();

    let mut configs = Configs::load(&cli.config)?;

    // Scope validation happens before any other work (config loading aside) — no DB
    // connection, no DNS query, no HTTP request is ever issued for an out-of-scope
    // target, and a mismatch is a hard error, never merely logged as a warning.
    if let Some(program_path) = &cli.program {
        let program = recon_core::ProgramConfig::load(program_path)?;
        if !recon_core::matches_scope(&cli.target, &program.scope.domains) {
            return Err(PipelineError::OutOfScope {
                target: cli.target.clone(),
                scope_domains: program.scope.domains.join(", "),
            });
        }
        tracing::info!(program = %program_path.display(), "target is in scope; program prober config applied");
        configs.prober = program.prober;
    }

    let seed = seed::load_seed_file(cli.seed_file.as_deref())?;

    let db_config = recon_db::DbConfig::from_env()?;
    let pool = db_config.connect().await?;
    let repo = recon_db::ScanRepository::new(pool);

    let summary = pipeline::run_scan(&cli.target, &configs, seed, &repo).await?;

    let markdown = report::generate_markdown_report(&summary, &cli.target);
    let report_path = report::write_report(&cli.output, &cli.target, &markdown, summary.finished_at)?;
    tracing::info!(path = %report_path.display(), "report written");

    Ok(())
}
