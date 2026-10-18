//! Asynchronous DNS resolution for recon candidates, with **mandatory** rate limiting.
//!
//! # ⚠️ Politique de rate limit
//!
//! Les valeurs par défaut de ce module ([`ResolverConfig::default`], `config/resolver.toml`)
//! sont volontairement prudentes. Elles DOIVENT être ajustées selon la politique de rate
//! limit explicite du programme de bug bounty ciblé, **jamais augmentées sans avoir
//! vérifié cette politique**.
//!
//! Le rate limiting n'est pas une option désactivable : chaque requête DNS individuelle
//! attend son tour via [`governor::RateLimiter`] avant de partir, sans exception. Ce
//! module ne fait que de la résolution DNS passive ; il ne contient aucune logique
//! d'exploitation ni de bruteforce de credentials.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig as HickoryConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use serde::Deserialize;

use crate::rate_limit::RateLimitedGate;
use crate::ReconError;

/// Configuration for [`DnsResolver`], deserializable from a TOML file such as
/// `config/resolver.toml`.
///
/// All fields have deliberately conservative defaults (see the module-level notice).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ResolverConfig {
    /// Maximum number of DNS requests issued per second, across the whole resolver.
    pub requests_per_second: u32,
    /// Maximum number of DNS requests in flight at the same time.
    pub max_concurrent: usize,
    /// Per-request timeout, in milliseconds, after which a lookup is treated as
    /// [`ResolveOutcome::NotFound`].
    pub timeout_ms: u64,
    /// DNS servers to query, in rotation, instead of the system resolver.
    pub dns_servers: Vec<String>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10,
            max_concurrent: 50,
            timeout_ms: 3000,
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        }
    }
}

impl ResolverConfig {
    /// Loads and parses a [`ResolverConfig`] from a TOML file on disk.
    ///
    /// # Errors
    /// Returns [`ReconError::Io`] if the file cannot be read, or [`ReconError::Parse`]
    /// if its content is not valid TOML matching the expected schema.
    pub fn load(path: &Path) -> Result<Self, ReconError> {
        let content = std::fs::read_to_string(path).map_err(|source| ReconError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let config: ResolverConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

/// The outcome of resolving a single candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// The candidate resolved directly to an IP address.
    Resolved {
        /// The resolved IP address.
        ip: IpAddr,
    },
    /// The candidate resolved to a CNAME rather than a direct IP address.
    Cname {
        /// The CNAME target.
        target: String,
    },
    /// The candidate did not resolve, or the lookup exceeded its timeout.
    NotFound,
    /// The lookup failed for a reason other than "not found" (e.g. a malformed name or
    /// a transport error talking to the configured DNS servers).
    Error(String),
}

/// Abstraction over the underlying DNS lookup mechanism.
///
/// This exists so that [`DnsResolver`] can be exercised in tests without ever
/// performing a real network resolution: production code uses [`HickoryBackend`], while
/// tests plug in a mock implementation.
pub trait DnsBackend: Send + Sync + 'static {
    /// Performs a single, un-rate-limited, un-timed-out lookup for `name`. Rate
    /// limiting, concurrency limiting, and timeouts are all applied by [`DnsResolver`],
    /// not by the backend.
    fn lookup(&self, name: &str) -> impl std::future::Future<Output = ResolveOutcome> + Send;
}

/// Production [`DnsBackend`] backed by `hickory-resolver`, querying the configured
/// `dns_servers` directly rather than the system resolver.
pub struct HickoryBackend {
    resolver: TokioAsyncResolver,
}

impl HickoryBackend {
    /// Builds a backend that queries the DNS servers listed in `config.dns_servers`.
    ///
    /// # Errors
    /// Returns [`ReconError::InvalidDnsServer`] if any configured server is not a valid
    /// IP address.
    pub fn new(config: &ResolverConfig) -> Result<Self, ReconError> {
        let mut server_ips = Vec::with_capacity(config.dns_servers.len());
        for server in &config.dns_servers {
            let ip: IpAddr = server
                .parse()
                .map_err(|_| ReconError::InvalidDnsServer(server.clone()))?;
            server_ips.push(ip);
        }

        let name_servers = NameServerConfigGroup::from_ips_clear(&server_ips, 53, true);
        let hickory_config = HickoryConfig::from_parts(None, vec![], name_servers);
        let resolver = TokioAsyncResolver::tokio(hickory_config, ResolverOpts::default());

        Ok(Self { resolver })
    }
}

impl DnsBackend for HickoryBackend {
    async fn lookup(&self, name: &str) -> ResolveOutcome {
        match self.resolver.lookup_ip(name).await {
            Ok(response) => match response.iter().next() {
                Some(ip) => ResolveOutcome::Resolved { ip },
                None => ResolveOutcome::NotFound,
            },
            Err(_) => match self.resolver.lookup(name, RecordType::CNAME).await {
                Ok(response) => match response.iter().next() {
                    Some(record) => ResolveOutcome::Cname {
                        target: record.to_string(),
                    },
                    None => ResolveOutcome::NotFound,
                },
                Err(err) => ResolveOutcome::Error(err.to_string()),
            },
        }
    }
}

/// Rate-limited, concurrency-bounded asynchronous DNS resolver for recon candidates.
///
/// Every individual lookup — whether issued through [`DnsResolver::resolve_one`] or as
/// part of [`DnsResolver::resolve_batch`] — first waits its turn on a shared
/// [`governor::RateLimiter`] configured from [`ResolverConfig::requests_per_second`].
/// This is not optional and cannot be bypassed from within this type.
pub struct DnsResolver<B: DnsBackend = HickoryBackend> {
    backend: B,
    gate: RateLimitedGate,
    timeout: Duration,
}

impl DnsResolver<HickoryBackend> {
    /// Builds a resolver backed by real DNS queries against `config.dns_servers`.
    ///
    /// # Errors
    /// Returns [`ReconError::InvalidDnsServer`] if any configured DNS server is not a
    /// valid IP address.
    pub fn new(config: &ResolverConfig) -> Result<Self, ReconError> {
        let backend = HickoryBackend::new(config)?;
        Ok(Self::with_backend(config, backend))
    }
}

impl<B: DnsBackend> DnsResolver<B> {
    /// Builds a resolver around an arbitrary [`DnsBackend`] — primarily useful for
    /// injecting a mock backend in tests, since it still applies rate limiting,
    /// concurrency limiting, and timeouts exactly like production code.
    #[must_use]
    pub fn with_backend(config: &ResolverConfig, backend: B) -> Self {
        Self {
            backend,
            gate: RateLimitedGate::new(config.requests_per_second, config.max_concurrent),
            timeout: Duration::from_millis(config.timeout_ms),
        }
    }

    /// Resolves a single candidate.
    ///
    /// Waits for the shared rate limiter, then for a free concurrency slot, then
    /// performs the lookup with a hard per-request timeout: a lookup that does not
    /// complete within `timeout_ms` is reported as [`ResolveOutcome::NotFound`] rather
    /// than blocking indefinitely.
    pub async fn resolve_one(&self, candidate: &str) -> ResolveOutcome {
        let _permit = match self.gate.acquire().await {
            Ok(permit) => permit,
            Err(_) => return ResolveOutcome::Error("resolver semaphore is closed".to_string()),
        };

        match tokio::time::timeout(self.timeout, self.backend.lookup(candidate)).await {
            Ok(outcome) => outcome,
            Err(_) => ResolveOutcome::NotFound,
        }
    }

    /// Resolves a batch of candidates, respecting the configured rate limit and maximum
    /// concurrency.
    ///
    /// Internally uses [`futures::stream::iter`] combined with `buffer_unordered` so
    /// that at most `max_concurrent` lookups are ever in flight; the shared rate limiter
    /// further throttles the overall request rate regardless of how many lookups are
    /// started concurrently.
    pub async fn resolve_batch(&self, candidates: Vec<String>) -> Vec<ResolveOutcome> {
        stream::iter(candidates)
            .map(|candidate| async move { self.resolve_one(&candidate).await })
            .buffer_unordered(self.gate.max_concurrent())
            .collect()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Instant;

    /// A [`DnsBackend`] that never touches the network: it answers from a fixed map (or
    /// a default outcome) after an optional artificial delay, so tests can exercise
    /// timeout and rate-limiting behavior deterministically and offline.
    struct MockBackend {
        responses: HashMap<String, ResolveOutcome>,
        default_outcome: ResolveOutcome,
        delay: Duration,
    }

    impl MockBackend {
        fn instant() -> Self {
            Self {
                responses: HashMap::new(),
                default_outcome: ResolveOutcome::NotFound,
                delay: Duration::ZERO,
            }
        }

        fn with_delay(delay: Duration, outcome: ResolveOutcome) -> Self {
            Self {
                responses: HashMap::new(),
                default_outcome: outcome,
                delay,
            }
        }

        fn with_responses(responses: HashMap<String, ResolveOutcome>) -> Self {
            Self {
                responses,
                default_outcome: ResolveOutcome::NotFound,
                delay: Duration::ZERO,
            }
        }
    }

    impl DnsBackend for MockBackend {
        async fn lookup(&self, name: &str) -> ResolveOutcome {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            self.responses
                .get(name)
                .cloned()
                .unwrap_or_else(|| self.default_outcome.clone())
        }
    }

    fn config(requests_per_second: u32, max_concurrent: usize, timeout_ms: u64) -> ResolverConfig {
        ResolverConfig {
            requests_per_second,
            max_concurrent,
            timeout_ms,
            dns_servers: vec!["1.1.1.1".to_string()],
        }
    }

    #[test]
    fn resolver_config_has_conservative_defaults() {
        let config = ResolverConfig::default();
        assert_eq!(config.requests_per_second, 10);
        assert_eq!(config.max_concurrent, 50);
        assert_eq!(config.timeout_ms, 3000);
        assert_eq!(config.dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn resolver_config_parses_from_toml() {
        let toml_str = r#"
            requests_per_second = 5
            max_concurrent = 20
            timeout_ms = 1500
            dns_servers = ["9.9.9.9"]
        "#;

        let parsed: ResolverConfig = toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(parsed.requests_per_second, 5);
        assert_eq!(parsed.max_concurrent, 20);
        assert_eq!(parsed.timeout_ms, 1500);
        assert_eq!(parsed.dns_servers, vec!["9.9.9.9"]);
    }

    #[test]
    fn resolver_config_loads_real_config_file() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest_dir).join("../../config/resolver.toml");

        let config = ResolverConfig::load(&path).expect("config/resolver.toml should parse");

        assert_eq!(config.requests_per_second, 10);
        assert_eq!(config.max_concurrent, 50);
        assert_eq!(config.timeout_ms, 3000);
        assert_eq!(config.dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[tokio::test]
    async fn resolve_one_returns_the_backend_mapped_outcome() {
        let mut responses = HashMap::new();
        responses.insert(
            "api-dev.example.com".to_string(),
            ResolveOutcome::Resolved {
                ip: "203.0.113.10".parse().expect("valid IP"),
            },
        );
        responses.insert(
            "legacy.example.com".to_string(),
            ResolveOutcome::Cname {
                target: "assets.cdn.example.net".to_string(),
            },
        );

        let resolver = DnsResolver::with_backend(
            &config(100, 10, 1000),
            MockBackend::with_responses(responses),
        );

        assert_eq!(
            resolver.resolve_one("api-dev.example.com").await,
            ResolveOutcome::Resolved {
                ip: "203.0.113.10".parse().expect("valid IP")
            }
        );
        assert_eq!(
            resolver.resolve_one("legacy.example.com").await,
            ResolveOutcome::Cname {
                target: "assets.cdn.example.net".to_string()
            }
        );
        assert_eq!(
            resolver.resolve_one("unknown.example.com").await,
            ResolveOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn slow_backend_times_out_as_not_found() {
        let resolver = DnsResolver::with_backend(
            &config(100, 10, 50),
            MockBackend::with_delay(
                Duration::from_millis(500),
                ResolveOutcome::Resolved {
                    ip: "203.0.113.20".parse().expect("valid IP"),
                },
            ),
        );

        let outcome = resolver.resolve_one("slow.example.com").await;
        assert_eq!(outcome, ResolveOutcome::NotFound);
    }

    #[tokio::test]
    async fn resolve_batch_processes_every_candidate() {
        let resolver = DnsResolver::with_backend(&config(100, 10, 1000), MockBackend::instant());

        let candidates = vec![
            "a.example.com".to_string(),
            "b.example.com".to_string(),
            "c.example.com".to_string(),
        ];
        let outcomes = resolver.resolve_batch(candidates).await;

        assert_eq!(outcomes.len(), 3);
        assert!(outcomes.iter().all(|o| *o == ResolveOutcome::NotFound));
    }

    #[tokio::test]
    async fn rate_limiter_spaces_out_requests_beyond_burst_capacity() {
        // requests_per_second = 2 allows an initial burst of 2 lookups, then forces the
        // remaining 2 to each wait ~500ms for the quota to refill — regardless of
        // max_concurrent, since the rate limiter is shared across every in-flight call.
        let resolver = DnsResolver::with_backend(&config(2, 10, 5000), MockBackend::instant());

        let candidates = vec![
            "a.example.com".to_string(),
            "b.example.com".to_string(),
            "c.example.com".to_string(),
            "d.example.com".to_string(),
        ];

        let start = Instant::now();
        let outcomes = resolver.resolve_batch(candidates).await;
        let elapsed = start.elapsed();

        assert_eq!(outcomes.len(), 4);
        assert!(
            elapsed >= Duration::from_millis(450),
            "rate limiter did not space out requests, elapsed = {elapsed:?}"
        );
    }

    /// Integration test hitting real DNS servers over the network — not run by default
    /// `cargo test` (would be flaky/slow/network-dependent like `recon-db`'s `#[ignore]`d
    /// DB tests). Run explicitly with:
    ///
    /// ```text
    /// cargo test -p recon-core --lib resolver::tests::real_hickory_backend_resolves_vfc_dot_com -- --ignored --nocapture
    /// ```
    ///
    /// Written to debug a real scan reporting `resolved_count=0` on 616 candidates
    /// against `vfc.com`, despite `nslookup vfc.com` / `nslookup vfc.com 1.1.1.1`
    /// succeeding manually on the same machine (resolving to `54.208.101.55`). Exercises
    /// three layers separately so a failure pinpoints exactly where things diverge from
    /// the working manual lookup:
    /// 1. [`HickoryBackend::new`] — resolver construction from the exact `dns_servers`
    ///    configured in `config/resolver.toml`.
    /// 2. [`HickoryBackend`]'s raw [`DnsBackend::lookup`] — the actual query/response,
    ///    bypassing [`DnsResolver`]'s rate limiter and timeout wrapper entirely.
    /// 3. The full [`DnsResolver::resolve_one`] — same call path production code
    ///    (`recon-cli`'s pipeline) actually uses, to rule the wrapper itself in or out.
    #[tokio::test]
    #[ignore = "hits real DNS servers over the network; run with `cargo test -p recon-core --ignored`"]
    async fn real_hickory_backend_resolves_vfc_dot_com() {
        let config = ResolverConfig {
            requests_per_second: 10,
            max_concurrent: 5,
            timeout_ms: 5000,
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        };

        eprintln!("[debug] step 1: building HickoryBackend from dns_servers = {:?}", config.dns_servers);
        let backend = match HickoryBackend::new(&config) {
            Ok(backend) => {
                eprintln!("[debug] step 1 OK: HickoryBackend constructed");
                backend
            }
            Err(err) => panic!("step 1 FAILED (resolver construction): {err}"),
        };

        eprintln!("[debug] step 2: raw HickoryBackend::lookup(\"vfc.com\")");
        let start = Instant::now();
        let outcome = backend.lookup("vfc.com").await;
        let elapsed = start.elapsed();
        eprintln!("[debug] step 2 result after {elapsed:?}: {outcome:?}");

        match &outcome {
            ResolveOutcome::Resolved { ip } => {
                eprintln!("[debug] step 2 OK: vfc.com -> {ip}");
                assert_eq!(*ip, "54.208.101.55".parse::<IpAddr>().expect("valid IP"));
            }
            ResolveOutcome::Cname { target } => {
                eprintln!("[debug] step 2: vfc.com is a CNAME to {target} (not the expected direct A record, but not a failure either)");
            }
            ResolveOutcome::NotFound => {
                panic!(
                    "step 2 FAILED (query/response): raw backend reported NotFound for vfc.com, \
                     but manual `nslookup vfc.com 1.1.1.1` resolves it to 54.208.101.55 on this \
                     machine — see the [debug] lines above from HickoryBackend::lookup's internal \
                     eprintln!s for the real underlying error"
                );
            }
            ResolveOutcome::Error(err) => {
                panic!("step 2 FAILED (query/response): raw backend reported an error for vfc.com: {err}");
            }
        }

        eprintln!("[debug] step 3: full DnsResolver::resolve_one(\"vfc.com\") (rate limit + timeout wrapper)");
        let resolver = DnsResolver::new(&config).expect("DnsResolver::new should build from the same config");
        let wrapped_outcome = resolver.resolve_one("vfc.com").await;
        eprintln!("[debug] step 3 result: {wrapped_outcome:?}");
        assert!(
            matches!(wrapped_outcome, ResolveOutcome::Resolved { .. } | ResolveOutcome::Cname { .. }),
            "step 3 FAILED (DnsResolver wrapper): raw backend succeeded in step 2 but the full \
             wrapper (rate limiter + {:?} timeout) reported {wrapped_outcome:?} — the timeout is \
             the likely culprit if step 2 took close to or longer than that",
            config.timeout_ms
        );
    }
}
