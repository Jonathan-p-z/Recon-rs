//! Loading the three TOML configuration files a scan needs.

use std::path::Path;

use recon_core::{PatternDictionary, ProberConfig, ResolverConfig};

use crate::error::PipelineError;

/// `patterns.toml`, `resolver.toml`, and `prober.toml`, loaded once up front and
/// threaded through the rest of the pipeline. Loading eagerly — before any DB row is
/// created or network request issued — means a malformed config file fails fast.
pub struct Configs {
    /// Naming dictionary and passive vulnerability signatures.
    pub patterns: PatternDictionary,
    /// DNS resolver rate limiting and server configuration.
    pub resolver: ResolverConfig,
    /// HTTP prober rate limiting and client configuration.
    pub prober: ProberConfig,
}

impl Configs {
    /// Loads `patterns.toml`, `resolver.toml`, and `prober.toml` from `dir`.
    ///
    /// # Errors
    /// Returns [`PipelineError::Recon`] if any of the three files is missing or fails
    /// to parse.
    pub fn load(dir: &Path) -> Result<Self, PipelineError> {
        Ok(Self {
            patterns: PatternDictionary::load(&dir.join("patterns.toml"))?,
            resolver: ResolverConfig::load(&dir.join("resolver.toml"))?,
            prober: ProberConfig::load(&dir.join("prober.toml"))?,
        })
    }
}
