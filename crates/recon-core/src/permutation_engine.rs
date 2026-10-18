//! Naming-convention detection, directed candidate generation, and passive
//! vulnerability-signature scoring.
//!
//! Everything here is informational: it never issues network requests, never attempts
//! authentication, and never mutates external state. It only reasons over subdomain
//! strings and scan results that the caller already collected.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::ReconError;

/// A named list of tokens belonging to one category of the naming dictionary
/// (environments, regions, technical functions, versions, separators, business terms).
#[derive(Debug, Clone, Deserialize)]
pub struct TokenCategory {
    /// Raw tokens configured for this category.
    pub tokens: Vec<String>,
}

/// The `[vuln_signatures]` table of the configuration file: a flat list of rules.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct VulnSignatureSection {
    /// The individual `[[vuln_signatures.rule]]` entries.
    #[serde(default, rename = "rule")]
    pub rule: Vec<VulnSignature>,
}

/// A single passive vulnerability-detection rule loaded from configuration.
///
/// `condition` is carried through as metadata for future use: the minimal [`ScanResult`]
/// type defined in this crate does not yet model richer signals (DNS resolution state,
/// authentication detection) that some conditions (e.g. `unresolved_bucket`,
/// `no_auth_detected`) describe. Only `match_type` is currently evaluated by
/// [`score_result`].
#[derive(Debug, Clone, Deserialize)]
pub struct VulnSignature {
    /// Human-readable identifier for the rule.
    pub name: String,
    /// What kind of field the `pattern` is matched against (`cname_pattern`,
    /// `title_contains`, `header_pattern`, ...).
    pub match_type: String,
    /// The substring to look for, interpreted according to `match_type`.
    pub pattern: String,
    /// Additional condition metadata (not fully evaluated by this minimal model yet).
    pub condition: String,
    /// Severity to assign when the rule matches (`critical`, `high`, `medium`, `low`).
    pub priority: String,
}

/// The full naming dictionary loaded from `config/patterns.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct PatternDictionary {
    /// Environment tokens (`dev`, `staging`, `prod`, ...).
    pub environnements: TokenCategory,
    /// Region tokens (`eu`, `us-east-1`, ...).
    pub regions: TokenCategory,
    /// Technical function tokens (`api`, `admin`, `vpn`, ...).
    pub fonctions_techniques: TokenCategory,
    /// Version tokens (`v1`, `legacy`, `beta`, ...).
    pub versions: TokenCategory,
    /// Separator characters observed in the wild (`-`, `_`, none).
    pub separateurs: TokenCategory,
    /// Business/domain-specific tokens, populated per engagement.
    pub metier: TokenCategory,
    /// Passive vulnerability-signature rules.
    pub vuln_signatures: VulnSignatureSection,
}

impl PatternDictionary {
    /// Loads and parses a [`PatternDictionary`] from a TOML file on disk.
    ///
    /// # Errors
    /// Returns [`ReconError::Io`] if the file cannot be read, or [`ReconError::Parse`]
    /// if its content is not valid TOML matching the expected schema.
    pub fn load(path: &Path) -> Result<Self, ReconError> {
        let content = fs::read_to_string(path).map_err(|source| ReconError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let dictionary: PatternDictionary = toml::from_str(&content)?;
        Ok(dictionary)
    }
}

/// The separator a target actually uses between naming tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Separator {
    /// Tokens joined with `-` (e.g. `api-dev`).
    Hyphen,
    /// Tokens joined with `_` (e.g. `api_dev`).
    Underscore,
    /// No separator observed (single-token labels, or concatenated tokens).
    #[default]
    None,
}

impl Separator {
    /// Returns the literal string form of this separator.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Separator::Hyphen => "-",
            Separator::Underscore => "_",
            Separator::None => "",
        }
    }
}

/// The semantic category a naming token appears to belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// Deployment environment (dev, staging, prod, ...).
    Environment,
    /// Geographic or infrastructure region.
    Region,
    /// Technical function (api, admin, vpn, ...).
    Function,
    /// Version marker (v1, legacy, beta, ...).
    Version,
    /// Business/domain-specific term.
    Business,
    /// Token that did not match any known category hint.
    Unknown,
}

const ENV_HINTS: &[&str] = &[
    "dev", "staging", "stage", "test", "uat", "qa", "preprod", "prod", "sandbox", "demo",
    "recette",
];
const REGION_HINTS: &[&str] = &[
    "eu", "us", "apac", "fr", "de", "uk", "internal", "eu-west", "eu-west-1", "us-east",
    "us-east-1",
];
const FUNCTION_HINTS: &[&str] = &[
    "api", "admin", "portal", "panel", "dashboard", "cms", "auth", "sso", "login", "vpn",
    "mail", "git", "gitlab", "github", "ci", "cd", "jenkins", "jira", "confluence", "wiki",
    "docs", "status", "monitoring", "grafana", "kibana", "backup", "db", "database", "cache",
    "redis", "queue", "worker", "webhook", "static", "cdn", "assets", "media", "upload",
    "download", "files", "storage", "s3", "app", "mobile", "intranet", "extranet", "support",
    "help", "helpdesk",
];
const VERSION_HINTS: &[&str] = &["v1", "v2", "v3", "old", "new", "legacy", "beta", "alpha", "next"];

/// Classifies a single lowercase-normalized token using built-in category hints.
///
/// This classification is independent of the user-supplied [`PatternDictionary`]: it is
/// only used to infer the *structure* (separator and token order) of a target's naming
/// convention from a handful of already-known subdomains.
fn classify_token(token: &str) -> TokenKind {
    let lower = token.to_lowercase();
    if ENV_HINTS.contains(&lower.as_str()) {
        TokenKind::Environment
    } else if REGION_HINTS.contains(&lower.as_str()) {
        TokenKind::Region
    } else if FUNCTION_HINTS.contains(&lower.as_str()) {
        TokenKind::Function
    } else if VERSION_HINTS.contains(&lower.as_str()) {
        TokenKind::Version
    } else {
        TokenKind::Unknown
    }
}

/// The naming convention inferred from a set of already-known subdomains.
#[derive(Debug, Clone, Default)]
pub struct NamingPattern {
    /// Dominant separator character used between tokens.
    pub separator: Separator,
    /// Most frequently observed order of token categories (e.g. `[Function, Environment]`
    /// for a convention like `api-dev`).
    pub token_order: Vec<TokenKind>,
    /// Observed frequency of each raw (lowercased) token across the known subdomains.
    pub token_frequency: HashMap<String, usize>,
}

/// Extracts the naming convention used by a target from a list of already-discovered
/// subdomains.
///
/// Only the leftmost DNS label of each subdomain is considered (e.g. `api-dev` in
/// `api-dev.example.com`). The function detects the dominant separator character and the
/// most common order of semantic token categories, and records how often each raw token
/// appears so that [`generate_candidates`] can prioritize realistic combinations.
#[must_use]
pub fn extract_pattern(known_subdomains: &[String]) -> NamingPattern {
    let mut hyphen_count = 0usize;
    let mut underscore_count = 0usize;

    for subdomain in known_subdomains {
        let label = subdomain.split('.').next().unwrap_or(subdomain.as_str());
        if label.contains('-') {
            hyphen_count += 1;
        }
        if label.contains('_') {
            underscore_count += 1;
        }
    }

    let separator = if hyphen_count == 0 && underscore_count == 0 {
        Separator::None
    } else if hyphen_count >= underscore_count {
        Separator::Hyphen
    } else {
        Separator::Underscore
    };

    let split_char = match separator {
        Separator::Hyphen => Some('-'),
        Separator::Underscore => Some('_'),
        Separator::None => None,
    };

    let mut token_frequency: HashMap<String, usize> = HashMap::new();
    let mut order_votes: HashMap<Vec<TokenKind>, usize> = HashMap::new();

    for subdomain in known_subdomains {
        let label = subdomain.split('.').next().unwrap_or(subdomain.as_str());
        let tokens: Vec<&str> = match split_char {
            Some(c) => label.split(c).filter(|t| !t.is_empty()).collect(),
            None => vec![label],
        };

        for token in &tokens {
            *token_frequency.entry(token.to_lowercase()).or_insert(0) += 1;
        }

        let kinds: Vec<TokenKind> = tokens
            .iter()
            .map(|t| classify_token(t))
            .filter(|kind| *kind != TokenKind::Unknown)
            .collect();

        if kinds.len() >= 2 {
            *order_votes.entry(kinds).or_insert(0) += 1;
        }
    }

    let token_order = order_votes
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(order, _)| order)
        .unwrap_or_default();

    NamingPattern {
        separator,
        token_order,
        token_frequency,
    }
}

/// A generated candidate subdomain along with its plausibility score.
///
/// Higher scores indicate combinations built from tokens that were observed more often
/// (directly or via their category) in the target's real naming convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoredCandidate {
    /// The generated candidate label (without the base domain).
    pub candidate: String,
    /// Plausibility score; higher is more likely to be a real, in-scope asset.
    pub score: u64,
}

impl Ord for ScoredCandidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score
            .cmp(&other.score)
            .then_with(|| self.candidate.cmp(&other.candidate))
    }
}

impl PartialOrd for ScoredCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn tokens_for_kind(dict: &PatternDictionary, kind: TokenKind) -> &[String] {
    match kind {
        TokenKind::Environment => &dict.environnements.tokens,
        TokenKind::Region => &dict.regions.tokens,
        TokenKind::Function => &dict.fonctions_techniques.tokens,
        TokenKind::Version => &dict.versions.tokens,
        TokenKind::Business => &dict.metier.tokens,
        TokenKind::Unknown => &[],
    }
}

/// Generates candidate subdomain labels by directed combination of dictionary tokens
/// according to the detected [`NamingPattern`], scoring each candidate by how frequently
/// its component tokens were actually observed on the target.
///
/// This performs a *directed* combination over only the token categories present in
/// `pattern.token_order` (falling back to `[Function, Environment]` when no order could
/// be inferred), not a raw cartesian product over every dictionary category. Candidates
/// already present in `seed` are skipped. The result is a max-heap so the caller can pop
/// the most promising candidates first.
#[must_use]
pub fn generate_candidates(
    seed: &[String],
    pattern: &NamingPattern,
    dict: &PatternDictionary,
) -> BinaryHeap<ScoredCandidate> {
    let order: Vec<TokenKind> = if pattern.token_order.is_empty() {
        vec![TokenKind::Function, TokenKind::Environment]
    } else {
        pattern.token_order.clone()
    };

    let seed_set: HashSet<String> = seed.iter().map(|s| s.to_lowercase()).collect();
    let separator = pattern.separator.as_str();

    let mut partials: Vec<(String, u64)> = vec![(String::new(), 0)];

    for kind in order {
        let tokens = tokens_for_kind(dict, kind);
        if tokens.is_empty() {
            continue;
        }

        let mut next_partials = Vec::with_capacity(partials.len() * tokens.len());
        for (prefix, score) in &partials {
            for token in tokens {
                let candidate = if prefix.is_empty() {
                    token.clone()
                } else {
                    format!("{prefix}{separator}{token}")
                };
                let token_score = *pattern
                    .token_frequency
                    .get(&token.to_lowercase())
                    .unwrap_or(&0) as u64;
                next_partials.push((candidate, *score + token_score + 1));
            }
        }
        partials = next_partials;
    }

    partials
        .into_iter()
        .filter(|(candidate, _)| !candidate.is_empty() && !seed_set.contains(&candidate.to_lowercase()))
        .map(|(candidate, score)| ScoredCandidate { candidate, score })
        .collect()
}

/// A single already-collected scan result, kept minimal so this module compiles and can
/// be tested in isolation. The workspace's shared scan-result type will replace this.
#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    /// The subdomain this result was collected for.
    pub subdomain: String,
    /// DNS CNAME target, if any.
    pub cname: Option<String>,
    /// HTTP response page title, if any.
    pub http_title: Option<String>,
    /// HTTP response headers.
    pub headers: HashMap<String, String>,
}

/// Severity assigned to a scan result after matching it against vulnerability
/// signatures. Ordered from least to most urgent so [`score_result`] can track the
/// maximum severity across all matching rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Nothing notable matched.
    Low,
    /// Worth a look, low urgency.
    Medium,
    /// Should be investigated soon.
    High,
    /// Likely exploitable, investigate immediately (within program scope/rules).
    Critical,
}

impl Priority {
    /// Parses a priority string from configuration, defaulting to [`Priority::Low`] for
    /// unrecognized values rather than failing.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "critical" => Priority::Critical,
            "high" => Priority::High,
            "medium" => Priority::Medium,
            _ => Priority::Low,
        }
    }
}

/// Scores an already-collected [`ScanResult`] against a list of [`VulnSignature`] rules,
/// returning the highest [`Priority`] among all matching rules (or [`Priority::Low`] if
/// none match).
///
/// This is purely a post-processing classification step: it does not perform any
/// network I/O, exploitation, or automated action. It exists to help a human operator
/// triage results that were already gathered elsewhere in the pipeline.
#[must_use]
pub fn score_result(result: &ScanResult, signatures: &[VulnSignature]) -> Priority {
    let mut best = Priority::Low;

    for signature in signatures {
        let matched = match signature.match_type.as_str() {
            "cname_pattern" => result
                .cname
                .as_deref()
                .map(|cname| cname.to_lowercase().contains(&signature.pattern.to_lowercase()))
                .unwrap_or(false),
            "title_contains" => result
                .http_title
                .as_deref()
                .map(|title| title.to_lowercase().contains(&signature.pattern.to_lowercase()))
                .unwrap_or(false),
            "header_pattern" => result
                .headers
                .values()
                .any(|value| value.to_lowercase().contains(&signature.pattern.to_lowercase())),
            _ => false,
        };

        if matched {
            let priority = Priority::parse(&signature.priority);
            if priority > best {
                best = priority;
            }
        }
    }

    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dict() -> PatternDictionary {
        PatternDictionary {
            environnements: TokenCategory {
                tokens: vec!["dev".to_string(), "prod".to_string(), "staging".to_string()],
            },
            regions: TokenCategory { tokens: vec![] },
            fonctions_techniques: TokenCategory {
                tokens: vec!["api".to_string(), "portal".to_string()],
            },
            versions: TokenCategory { tokens: vec![] },
            separateurs: TokenCategory {
                tokens: vec!["-".to_string()],
            },
            metier: TokenCategory { tokens: vec![] },
            vuln_signatures: VulnSignatureSection { rule: vec![] },
        }
    }

    #[test]
    fn extract_pattern_detects_hyphen_and_function_environment_order() {
        let known = vec![
            "api-dev.example.com".to_string(),
            "admin-prod.example.com".to_string(),
            "portal-staging.example.com".to_string(),
        ];

        let pattern = extract_pattern(&known);

        assert_eq!(pattern.separator, Separator::Hyphen);
        assert_eq!(pattern.token_order, vec![TokenKind::Function, TokenKind::Environment]);
        assert_eq!(pattern.token_frequency.get("api"), Some(&1));
        assert_eq!(pattern.token_frequency.get("dev"), Some(&1));
    }

    #[test]
    fn extract_pattern_defaults_to_no_separator_when_labels_are_atomic() {
        let known = vec!["mail.example.com".to_string(), "vpn.example.com".to_string()];

        let pattern = extract_pattern(&known);

        assert_eq!(pattern.separator, Separator::None);
        assert!(pattern.token_order.is_empty());
    }

    #[test]
    fn generate_candidates_scores_frequently_observed_tokens_higher() {
        let known = vec![
            "api-dev.example.com".to_string(),
            "api-prod.example.com".to_string(),
            "api-staging.example.com".to_string(),
            "portal-dev.example.com".to_string(),
        ];
        let pattern = extract_pattern(&known);
        let dict = sample_dict();

        let heap = generate_candidates(&known, &pattern, &dict);

        assert!(!heap.is_empty());
        // Every generated candidate must respect the detected separator and must not
        // duplicate an already-known subdomain label.
        for scored in &heap {
            assert!(scored.candidate.contains('-'));
        }

        let top = heap.into_sorted_vec();
        let best = top.last().expect("heap should not be empty");
        // "api" appears 3x in the known set vs "portal" 1x, so an "api-*" candidate
        // should outrank any "portal-*" candidate.
        assert!(best.candidate.starts_with("api-"));
    }

    #[test]
    fn generate_candidates_skips_already_known_subdomains() {
        let pattern = NamingPattern {
            separator: Separator::Hyphen,
            token_order: vec![TokenKind::Function, TokenKind::Environment],
            token_frequency: HashMap::new(),
        };
        let dict = PatternDictionary {
            environnements: TokenCategory {
                tokens: vec!["dev".to_string()],
            },
            regions: TokenCategory { tokens: vec![] },
            fonctions_techniques: TokenCategory {
                tokens: vec!["api".to_string()],
            },
            versions: TokenCategory { tokens: vec![] },
            separateurs: TokenCategory { tokens: vec![] },
            metier: TokenCategory { tokens: vec![] },
            vuln_signatures: VulnSignatureSection { rule: vec![] },
        };

        // "api-dev" would be the only combination and it's already known -> nothing new.
        let heap = generate_candidates(&["api-dev".to_string()], &pattern, &dict);
        assert!(heap.is_empty());
    }

    #[test]
    fn score_result_flags_s3_takeover_as_critical() {
        let signatures = vec![VulnSignature {
            name: "subdomain_takeover_s3".to_string(),
            match_type: "cname_pattern".to_string(),
            pattern: "s3.amazonaws.com".to_string(),
            condition: "unresolved_bucket".to_string(),
            priority: "critical".to_string(),
        }];
        let result = ScanResult {
            subdomain: "assets.example.com".to_string(),
            cname: Some("assets-bucket.s3.amazonaws.com".to_string()),
            http_title: None,
            headers: HashMap::new(),
        };

        assert_eq!(score_result(&result, &signatures), Priority::Critical);
    }

    #[test]
    fn score_result_flags_exposed_jenkins_as_high() {
        let signatures = vec![VulnSignature {
            name: "exposed_jenkins".to_string(),
            match_type: "title_contains".to_string(),
            pattern: "Jenkins".to_string(),
            condition: "no_auth_detected".to_string(),
            priority: "high".to_string(),
        }];
        let result = ScanResult {
            subdomain: "ci.example.com".to_string(),
            cname: None,
            http_title: Some("Dashboard [Jenkins]".to_string()),
            headers: HashMap::new(),
        };

        assert_eq!(score_result(&result, &signatures), Priority::High);
    }

    #[test]
    fn score_result_returns_low_when_nothing_matches() {
        let signatures = vec![VulnSignature {
            name: "exposed_kibana".to_string(),
            match_type: "title_contains".to_string(),
            pattern: "Kibana".to_string(),
            condition: "no_auth_detected".to_string(),
            priority: "high".to_string(),
        }];
        let result = ScanResult {
            subdomain: "www.example.com".to_string(),
            cname: None,
            http_title: Some("Welcome".to_string()),
            headers: HashMap::new(),
        };

        assert_eq!(score_result(&result, &signatures), Priority::Low);
    }

    #[test]
    fn score_result_picks_highest_priority_among_multiple_matches() {
        let signatures = vec![
            VulnSignature {
                name: "outdated_apache".to_string(),
                match_type: "header_pattern".to_string(),
                pattern: "Apache/2.2".to_string(),
                condition: "always".to_string(),
                priority: "medium".to_string(),
            },
            VulnSignature {
                name: "exposed_kibana".to_string(),
                match_type: "title_contains".to_string(),
                pattern: "Kibana".to_string(),
                condition: "no_auth_detected".to_string(),
                priority: "high".to_string(),
            },
        ];
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "Apache/2.2 (Unix)".to_string());
        let result = ScanResult {
            subdomain: "logs.example.com".to_string(),
            cname: None,
            http_title: Some("Kibana".to_string()),
            headers,
        };

        assert_eq!(score_result(&result, &signatures), Priority::High);
    }

    #[test]
    fn pattern_dictionary_loads_real_config_file() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest_dir).join("../../config/patterns.toml");

        let dict = PatternDictionary::load(&path).expect("config/patterns.toml should parse");

        assert!(dict.environnements.tokens.contains(&"dev".to_string()));
        assert!(dict.fonctions_techniques.tokens.contains(&"api".to_string()));
        assert_eq!(dict.vuln_signatures.rule.len(), 5);
    }
}
