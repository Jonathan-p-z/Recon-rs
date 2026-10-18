#![deny(clippy::all)]

//! `recon-core`: passive reconnaissance building blocks for **authorized** bug bounty
//! engagements.
//!
//! This crate is strictly informational. It derives naming conventions from
//! already-discovered subdomains, generates candidate names worth probing, and scores
//! already-collected scan results against known vulnerability signatures. It contains
//! no scanning, no exploitation, and no credential-bruteforcing logic — use it only
//! against targets you are explicitly authorized to test.

pub mod permutation_engine;
pub mod prober;
pub mod program;
mod rate_limit;
pub mod resolver;

pub use permutation_engine::{
    NamingPattern, PatternDictionary, Priority, ScanResult, ScoredCandidate, Separator,
    TokenKind, VulnSignature,
};
pub use prober::{HttpProber, ProberConfig, ProbeResult};
pub use program::{matches_scope, ProgramConfig, ScopeSection};
pub use resolver::{DnsBackend, DnsResolver, HickoryBackend, ResolveOutcome, ResolverConfig};

use std::path::PathBuf;

/// Errors that can occur while loading configuration or processing recon data.
#[derive(Debug, thiserror::Error)]
pub enum ReconError {
    /// The configuration file could not be read from disk.
    #[error("failed to read config file {path}: {source}")]
    Io {
        /// Path that failed to load.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The configuration file content could not be parsed as valid TOML.
    #[error("failed to parse TOML config: {0}")]
    Parse(#[from] toml::de::Error),
    /// A configured DNS server address is not a valid IP address.
    #[error("invalid DNS server address `{0}`: expected an IP address")]
    InvalidDnsServer(String),
    /// The HTTP client could not be built from the given [`crate::prober::ProberConfig`].
    #[error("failed to build HTTP client: {0}")]
    HttpClientBuild(String),
}
