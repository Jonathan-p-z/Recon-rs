//! Per-program configuration: an authorized scope plus a program-specific
//! [`ProberConfig`] override, loaded from a single TOML file such as
//! `config/programs/vfc-vdp.toml`.
//!
//! This lets one generic `config/` directory (patterns/resolver/prober defaults) coexist
//! with several bug bounty programs' specific requirements — rate limits, identifying
//! headers, and authorized domains — without duplicating the generic config per program.

use std::path::Path;

use serde::Deserialize;

use crate::prober::ProberConfig;
use crate::ReconError;

/// The `[scope]` table of a program config file.
#[derive(Debug, Clone, Deserialize)]
pub struct ScopeSection {
    /// Authorized domain patterns for this program. Each entry is either an exact
    /// domain (`"vfc.com"`) or a subdomain wildcard (`"*.vfc.com"`) — see
    /// [`matches_scope`] for exactly what each form authorizes.
    pub domains: Vec<String>,
}

/// A bug bounty program's configuration: its authorized scope, and a [`ProberConfig`]
/// override carrying that program's specific rate limits and identifying headers.
///
/// Deliberately does not also carry `patterns`/`resolver` config: naming-pattern
/// dictionaries and DNS resolver settings are not something bug bounty programs
/// typically impose rules about, so those keep coming from the generic `config/`
/// directory even when a program file is in use — only `[prober]` (rate limits, headers,
/// user agent) tends to be dictated by a program's published rules.
#[derive(Debug, Clone, Deserialize)]
pub struct ProgramConfig {
    /// This program's authorized scope.
    pub scope: ScopeSection,
    /// This program's required prober behavior (rate limit, headers, user agent).
    pub prober: ProberConfig,
}

impl ProgramConfig {
    /// Loads and parses a [`ProgramConfig`] from a TOML file on disk.
    ///
    /// # Errors
    /// Returns [`ReconError::Io`] if the file cannot be read, or [`ReconError::Parse`]
    /// if its content is not valid TOML matching the expected schema.
    pub fn load(path: &Path) -> Result<Self, ReconError> {
        let content = std::fs::read_to_string(path).map_err(|source| ReconError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let config: ProgramConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

/// Returns whether `domain` is authorized under `scope_patterns`.
///
/// Each pattern is either:
/// - An **exact domain** (e.g. `"vfc.com"`), matched case-insensitively against
///   `domain` as a whole — nothing else matches it, not even a subdomain.
/// - A **subdomain wildcard** (e.g. `"*.vfc.com"`), which authorizes both the base
///   domain itself (`vfc.com`) — since that is the natural value to pass as a scan's
///   `--target` when the intent is "enumerate subdomains under vfc.com", which is
///   exactly what a `*.vfc.com` scope entry grants permission to do — and any true
///   subdomain of it (`sub.vfc.com`, `deep.sub.vfc.com`, ...).
///
/// Matching is always done against a dot-delimited label suffix, never a raw substring:
/// `*.vfc.com` does **not** match `vfc.com.evil.com` (which ends in `.evil.com`, not
/// `.vfc.com`) or `notvfc.com` (which has no label boundary before `vfc.com` at all) —
/// a naive `domain.contains("vfc.com")`-style check would incorrectly let both through.
#[must_use]
pub fn matches_scope(domain: &str, scope_patterns: &[String]) -> bool {
    let domain = domain.to_ascii_lowercase();
    scope_patterns.iter().any(|pattern| {
        let pattern = pattern.to_ascii_lowercase();
        match pattern.strip_prefix("*.") {
            Some(base) => domain == base || domain.ends_with(&format!(".{base}")),
            None => domain == pattern,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vfc_scope() -> Vec<String> {
        vec![
            "*.vfc.com".to_string(),
            "*.vfc-int.com".to_string(),
            "*.thenorthface.com".to_string(),
            "*.timberland.com".to_string(),
            "*.vans.com".to_string(),
        ]
    }

    #[test]
    fn wildcard_matches_a_direct_subdomain() {
        assert!(matches_scope("sub.vfc.com", &vfc_scope()));
        assert!(matches_scope("api-dev.vfc.com", &vfc_scope()));
    }

    #[test]
    fn wildcard_matches_a_multi_label_subdomain() {
        assert!(matches_scope("deep.sub.vfc.com", &vfc_scope()));
    }

    #[test]
    fn wildcard_matches_its_own_base_domain() {
        // `--target vfc.com` is the natural way to say "enumerate subdomains under
        // vfc.com", which `*.vfc.com` scope grants permission to do.
        assert!(matches_scope("vfc.com", &vfc_scope()));
    }

    #[test]
    fn wildcard_does_not_match_a_domain_that_merely_ends_with_the_base_as_a_substring() {
        // The classic bypass attempt: "vfc.com.evil.com" contains "vfc.com" as a raw
        // substring, but is not a subdomain of it — it is a subdomain of evil.com.
        assert!(!matches_scope("vfc.com.evil.com", &vfc_scope()));
    }

    #[test]
    fn wildcard_does_not_match_a_domain_with_no_label_boundary() {
        // "notvfc.com" is not "something.vfc.com" — there is no dot before "vfc.com".
        assert!(!matches_scope("notvfc.com", &vfc_scope()));
        assert!(!matches_scope("evilvfc.com", &vfc_scope()));
    }

    #[test]
    fn wildcard_does_not_match_an_unrelated_domain() {
        assert!(!matches_scope("example.com", &vfc_scope()));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(matches_scope("SUB.VFC.COM", &vfc_scope()));
        assert!(matches_scope("sub.VfC.cOm", &vfc_scope()));
    }

    #[test]
    fn exact_pattern_matches_only_itself_not_subdomains() {
        let scope = vec!["exact.example.com".to_string()];
        assert!(matches_scope("exact.example.com", &scope));
        assert!(!matches_scope("sub.exact.example.com", &scope));
        assert!(!matches_scope("exact.example.com.evil.com", &scope));
    }

    #[test]
    fn every_configured_vfc_scope_domain_covers_its_own_base() {
        for base in ["vfc.com", "vfc-int.com", "thenorthface.com", "timberland.com", "vans.com"] {
            assert!(matches_scope(base, &vfc_scope()), "{base} should be in scope");
        }
    }

    #[test]
    fn loads_the_real_vfc_vdp_program_file() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest_dir).join("../../config/programs/vfc-vdp.toml");

        let program = ProgramConfig::load(&path).expect("config/programs/vfc-vdp.toml should parse");

        assert_eq!(
            program.scope.domains,
            vec![
                "*.vfc.com".to_string(),
                "*.vfc-int.com".to_string(),
                "*.thenorthface.com".to_string(),
                "*.timberland.com".to_string(),
                "*.vans.com".to_string(),
            ]
        );
        assert_eq!(program.prober.requests_per_second, 5);
        assert_eq!(program.prober.max_concurrent, 20);
        assert!(program.prober.user_agent.contains("VFC-VDP"));
        // The username itself is operator-specific (this file is expected to be edited
        // in place with a real HackerOne handle), so only check internal consistency:
        // the header value must actually reference the configured hacker_username.
        assert!(!program.prober.hacker_username.is_empty());
        let expected_header_value = format!("HackerOne-{}", program.prober.hacker_username);
        assert_eq!(
            program.prober.custom_headers.get("X-VFC-VDP").map(String::as_str),
            Some(expected_header_value.as_str())
        );
        assert!(matches_scope("scan-target.vfc.com", &program.scope.domains));
    }
}
