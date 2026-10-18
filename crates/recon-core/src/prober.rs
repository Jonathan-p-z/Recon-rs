//! Passive HTTP/HTTPS probing of hosts that already resolved in DNS, with the same
//! **mandatory** rate limiting philosophy as [`crate::resolver`] — both modules share
//! [`crate::rate_limit`]'s primitives rather than rolling their own throttling, so the
//! policy cannot silently diverge between them. This module specifically uses
//! [`crate::rate_limit::PerHostRateLimitedGate`] rather than the resolver's
//! [`crate::rate_limit::RateLimitedGate`] — see [`ProberConfig::requests_per_second`]
//! for why.
//!
//! # Passive-only guarantee
//!
//! This module performs a single plain `GET` request per host and nothing else:
//! - No authentication of any kind (no credentials, no login flow).
//! - No request body / payload is ever sent.
//! - No protection-bypass behavior: the `user_agent` MUST identify this tool honestly
//!   (see [`ProberConfig::user_agent`]) and must never be rotated or disguised as a
//!   browser to evade detection or `robots.txt`-based blocking.
//!
//! It only reads what a target exposes by default to any ordinary HTTP client.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::Deserialize;

use crate::permutation_engine::ScanResult;
use crate::rate_limit::PerHostRateLimitedGate;
use crate::ReconError;

/// Configuration for [`HttpProber`], deserializable from a TOML file such as
/// `config/prober.toml`, or from the `[prober]` table of a
/// [`crate::program::ProgramConfig`] file for a specific bug bounty program.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProberConfig {
    /// Maximum number of HTTP requests issued per second **to any single host** — this
    /// is a per-host limit, not an aggregate cap on the whole scan.
    ///
    /// # Why per-host, not aggregate
    ///
    /// Some bug bounty programs' published rules state their rate limit per host
    /// (e.g. "max 5 requests/second per host"), which is a materially different, and
    /// *looser*, constraint than "5 requests/second in total across every host being
    /// scanned": a scan touching 50 hosts under a per-host rule may legitimately issue
    /// up to 250 requests/second in aggregate, all fully compliant. Enforcing this
    /// value as a single shared/aggregate limit (as [`crate::resolver::DnsResolver`]
    /// does, appropriately, for DNS queries against a shared resolver) would therefore
    /// not be "extra cautious" here — it would silently under-utilize what the program
    /// actually authorizes without ever being asked to, and more importantly would not
    /// actually be *equivalent* to what a per-host rule specifies, since it caps the
    /// wrong quantity. [`HttpProber`] therefore enforces this value per host via
    /// [`crate::rate_limit::PerHostRateLimitedGate`], keyed by the host string passed
    /// to [`HttpProber::probe_one`]/[`HttpProber::probe_batch`].
    pub requests_per_second: u32,
    /// Maximum number of HTTP requests in flight at the same time, across every host —
    /// unlike `requests_per_second`, this stays a global cap (see
    /// [`crate::rate_limit::PerHostRateLimitedGate`]'s rustdoc for why).
    pub max_concurrent: usize,
    /// Per-request timeout, in milliseconds.
    pub timeout_ms: u64,
    /// `User-Agent` header sent with every request. Must honestly identify this tool —
    /// never a browser user agent used to evade detection. Overridable per program via
    /// a program config file's `[prober]` table (e.g. `config/programs/vfc-vdp.toml`).
    pub user_agent: String,
    /// Whether to follow HTTP redirects (capped at 3 hops when enabled).
    pub follow_redirects: bool,
    /// A HackerOne (or similar platform) username, for programs that require it to be
    /// identifiable in traffic. Kept as a plain, informational config value: this crate
    /// deliberately does **not** derive any specific HTTP header from it, since the
    /// header name/format a program wants (`X-VFC-VDP: HackerOne-<username>` for VF
    /// Corporation's VDP, something else entirely for another program) is itself
    /// program-specific and does not belong hard-coded into this generic prober. Set
    /// the actual required header via [`ProberConfig::custom_headers`] instead — see
    /// `config/programs/vfc-vdp.toml` for a worked example that sets both, since the
    /// operator is the one responsible for keeping the two consistent.
    pub hacker_username: String,
    /// Extra headers sent with every request, beyond `User-Agent` — the general
    /// mechanism for programs that require specific identifying headers (VF
    /// Corporation's `X-VFC-VDP`, or any other program's equivalent requirement). Every
    /// key/value pair here must be a valid HTTP header name/value; see
    /// [`HttpProber::new`].
    pub custom_headers: HashMap<String, String>,
}

impl Default for ProberConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10,
            max_concurrent: 30,
            timeout_ms: 5000,
            user_agent: "recon-rs/0.1 (security research)".to_string(),
            follow_redirects: true,
            hacker_username: String::new(),
            custom_headers: HashMap::new(),
        }
    }
}

impl ProberConfig {
    /// Loads and parses a [`ProberConfig`] from a TOML file on disk.
    ///
    /// # Errors
    /// Returns [`ReconError::Io`] if the file cannot be read, or [`ReconError::Parse`]
    /// if its content is not valid TOML matching the expected schema.
    pub fn load(path: &Path) -> Result<Self, ReconError> {
        let content = std::fs::read_to_string(path).map_err(|source| ReconError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let config: ProberConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

/// Maximum number of redirects followed when [`ProberConfig::follow_redirects`] is
/// `true`.
const MAX_REDIRECTS: usize = 3;

/// The result of probing a single host over HTTP/HTTPS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// The host that was probed.
    pub host: String,
    /// HTTP status code of the response, if a response was received at all.
    pub status_code: Option<u16>,
    /// Text content of the page's `<title>` element, if present and non-empty.
    pub title: Option<String>,
    /// Response headers (header name, case as returned by the server, to value).
    pub headers: HashMap<String, String>,
    /// Wall-clock time spent on the request that produced this result.
    pub response_time_ms: u64,
    /// Which scheme actually produced this result: `"http"` or `"https"`.
    pub scheme_used: String,
    /// DNS CNAME for `host`, if the caller already learned one upstream (typically from
    /// [`crate::resolver::DnsResolver`]). This module never performs DNS lookups
    /// itself; it only carries this value through so it survives conversion to
    /// [`ScanResult`].
    pub cname: Option<String>,
    /// Description of why the probe failed, if it did.
    pub error: Option<String>,
}

impl ProbeResult {
    fn success(
        host: &str,
        scheme: &str,
        status: u16,
        headers: HashMap<String, String>,
        title: Option<String>,
        elapsed: Duration,
        cname: Option<String>,
    ) -> Self {
        Self {
            host: host.to_string(),
            status_code: Some(status),
            title,
            headers,
            response_time_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            scheme_used: scheme.to_string(),
            cname,
            error: None,
        }
    }

    fn failure(host: &str, scheme: &str, elapsed: Duration, cname: Option<String>, error: String) -> Self {
        Self {
            host: host.to_string(),
            status_code: None,
            title: None,
            headers: HashMap::new(),
            response_time_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            scheme_used: scheme.to_string(),
            cname,
            error: Some(error),
        }
    }
}

/// Converts a [`ProbeResult`] into the [`ScanResult`] consumed by
/// [`crate::permutation_engine::score_result`].
///
/// This conversion is intentionally lossy: [`ScanResult`] predates HTTP probing and only
/// models the fields today's vulnerability signatures actually inspect (subdomain,
/// CNAME, page title, headers). `status_code`, `response_time_ms`, `scheme_used`, and
/// `error` are recon-quality metadata that no current signature consults, so they are
/// dropped here rather than growing `ScanResult` speculatively; if a future signature
/// needs them, extend `ScanResult` then.
impl From<ProbeResult> for ScanResult {
    fn from(probe: ProbeResult) -> Self {
        ScanResult {
            subdomain: probe.host,
            cname: probe.cname,
            http_title: probe.title,
            headers: probe.headers,
        }
    }
}

/// Extracts the text content of the first `<title>` element found in `body`, using a
/// minimal string scan rather than a full HTML parser — sufficient for recon purposes
/// and avoids pulling in an HTML parsing dependency for a single tag.
fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let open_start = lower.find("<title")?;
    let open_end = lower[open_start..].find('>')? + open_start + 1;
    let close_start_rel = lower[open_end..].find("</title")?;
    let raw = body.get(open_end..open_end + close_start_rel)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Builds a [`reqwest::header::HeaderMap`] of default headers from `custom_headers`,
/// validating each key/value along the way rather than letting `reqwest` panic or
/// silently drop a malformed entry.
fn build_default_headers(custom_headers: &HashMap<String, String>) -> Result<reqwest::header::HeaderMap, ReconError> {
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in custom_headers {
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|source| ReconError::HttpClientBuild(format!("invalid header name `{name}`: {source}")))?;
        let header_value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|source| ReconError::HttpClientBuild(format!("invalid header value for `{name}`: {source}")))?;
        headers.insert(header_name, header_value);
    }
    Ok(headers)
}

/// Rate-limited, concurrency-bounded HTTP/HTTPS prober for already-resolved hosts.
///
/// Reuses a single [`reqwest::Client`] across every request (connection pooling is left
/// to `reqwest`) and gates every request through
/// [`crate::rate_limit::PerHostRateLimitedGate`] — see
/// [`ProberConfig::requests_per_second`] for why this module uses a per-host gate
/// rather than the resolver's shared/aggregate one.
pub struct HttpProber {
    client: Client,
    gate: PerHostRateLimitedGate,
}

impl HttpProber {
    /// Builds a prober from the given configuration.
    ///
    /// # Errors
    /// Returns [`ReconError::HttpClientBuild`] if the underlying `reqwest::Client`
    /// cannot be constructed (e.g. an invalid TLS configuration), or if any entry in
    /// [`ProberConfig::custom_headers`] is not a valid HTTP header name/value.
    pub fn new(config: &ProberConfig) -> Result<Self, ReconError> {
        let redirect_policy = if config.follow_redirects {
            reqwest::redirect::Policy::limited(MAX_REDIRECTS)
        } else {
            reqwest::redirect::Policy::none()
        };

        let client = Client::builder()
            .user_agent(config.user_agent.clone())
            .default_headers(build_default_headers(&config.custom_headers)?)
            .redirect(redirect_policy)
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|source| ReconError::HttpClientBuild(source.to_string()))?;

        Ok(Self {
            client,
            gate: PerHostRateLimitedGate::new(config.requests_per_second, config.max_concurrent),
        })
    }

    async fn fetch(&self, url: &str) -> Result<(u16, HashMap<String, String>, String), reqwest::Error> {
        let response = self.client.get(url).send().await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let body = response.text().await.unwrap_or_default();
        Ok((status, headers, body))
    }

    /// Probes a single host: plain `GET https://{host}/`, falling back to plain
    /// `GET http://{host}/` only when the HTTPS attempt fails to connect at all (TLS
    /// handshake failure, connection refused, timeout, ...) — never merely because the
    /// server answered with an error status code, since that is itself a valid,
    /// informative result.
    ///
    /// `cname` is threaded through from the caller (typically the CNAME already learned
    /// from [`crate::resolver::DnsResolver`] for this host) purely so it survives the
    /// [`From<ProbeResult> for ScanResult`] conversion; this module never resolves DNS
    /// itself.
    pub async fn probe_one(&self, host: &str, cname: Option<String>) -> ProbeResult {
        let _permit = match self.gate.acquire(host).await {
            Ok(permit) => permit,
            Err(_) => {
                return ProbeResult::failure(
                    host,
                    "https",
                    Duration::ZERO,
                    cname,
                    "prober semaphore is closed".to_string(),
                )
            }
        };

        let https_url = format!("https://{host}/");
        let start = Instant::now();
        if let Ok((status, headers, body)) = self.fetch(&https_url).await {
            return ProbeResult::success(
                host,
                "https",
                status,
                headers,
                extract_title(&body),
                start.elapsed(),
                cname,
            );
        }

        let http_url = format!("http://{host}/");
        let start = Instant::now();
        match self.fetch(&http_url).await {
            Ok((status, headers, body)) => ProbeResult::success(
                host,
                "http",
                status,
                headers,
                extract_title(&body),
                start.elapsed(),
                cname,
            ),
            Err(err) => ProbeResult::failure(host, "http", start.elapsed(), cname, err.to_string()),
        }
    }

    /// Probes a batch of hosts, respecting the configured rate limit and maximum
    /// concurrency, via [`futures::stream::iter`] + `buffer_unordered` exactly like
    /// [`crate::resolver::DnsResolver::resolve_batch`].
    ///
    /// No per-host CNAME is threaded through this entry point; call
    /// [`HttpProber::probe_one`] directly when CNAME data from the resolver needs to be
    /// carried into the resulting [`ScanResult`].
    pub async fn probe_batch(&self, hosts: Vec<String>) -> Vec<ProbeResult> {
        stream::iter(hosts)
            .map(|host| async move { self.probe_one(&host, None).await })
            .buffer_unordered(self.gate.max_concurrent())
            .collect()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant as StdInstant;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(requests_per_second: u32, max_concurrent: usize, timeout_ms: u64) -> ProberConfig {
        ProberConfig {
            requests_per_second,
            max_concurrent,
            timeout_ms,
            user_agent: "recon-rs-test/0.1 (security research)".to_string(),
            follow_redirects: true,
            hacker_username: String::new(),
            custom_headers: HashMap::new(),
        }
    }

    fn host_from_uri(uri: &str) -> String {
        uri.trim_start_matches("http://").to_string()
    }

    #[test]
    fn prober_config_has_conservative_defaults() {
        let config = ProberConfig::default();
        assert_eq!(config.requests_per_second, 10);
        assert_eq!(config.max_concurrent, 30);
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.user_agent, "recon-rs/0.1 (security research)");
        assert!(config.follow_redirects);
        assert_eq!(config.hacker_username, "");
        assert!(config.custom_headers.is_empty());
    }

    #[test]
    fn prober_config_parses_from_toml() {
        let toml_str = r#"
            requests_per_second = 3
            max_concurrent = 5
            timeout_ms = 2000
            user_agent = "custom-agent/1.0"
            follow_redirects = false
            hacker_username = "h1_handle"

            [custom_headers]
            "X-VFC-VDP" = "HackerOne-h1_handle"
        "#;

        let parsed: ProberConfig = toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(parsed.requests_per_second, 3);
        assert_eq!(parsed.max_concurrent, 5);
        assert_eq!(parsed.timeout_ms, 2000);
        assert_eq!(parsed.user_agent, "custom-agent/1.0");
        assert!(!parsed.follow_redirects);
        assert_eq!(parsed.hacker_username, "h1_handle");
        assert_eq!(
            parsed.custom_headers.get("X-VFC-VDP").map(String::as_str),
            Some("HackerOne-h1_handle")
        );
    }

    #[test]
    fn prober_config_loads_real_config_file() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest_dir).join("../../config/prober.toml");

        let config = ProberConfig::load(&path).expect("config/prober.toml should parse");

        assert_eq!(config.requests_per_second, 10);
        assert_eq!(config.max_concurrent, 30);
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.user_agent, "recon-rs/0.1 (security research)");
        assert!(config.follow_redirects);
        assert_eq!(config.hacker_username, "");
        assert!(config.custom_headers.is_empty());
    }

    #[test]
    fn extract_title_finds_basic_title() {
        let body = "<html><head><title>  Welcome to Jenkins  </title></head><body></body></html>";
        assert_eq!(extract_title(body), Some("Welcome to Jenkins".to_string()));
    }

    #[test]
    fn extract_title_returns_none_when_absent_or_empty() {
        assert_eq!(extract_title("<html><body>no title here</body></html>"), None);
        assert_eq!(extract_title("<title></title>"), None);
    }

    #[tokio::test]
    async fn probe_one_captures_status_title_and_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Server", "nginx")
                    .insert_header("Content-Type", "text/html")
                    .set_body_string("<html><head><title>Internal Panel</title></head></html>"),
            )
            .mount(&server)
            .await;

        let prober = HttpProber::new(&config(100, 10, 2000)).expect("client should build");
        let host = host_from_uri(&server.uri());

        let result = prober.probe_one(&host, Some("target.cdn.example.net".to_string())).await;

        assert_eq!(result.scheme_used, "http");
        assert_eq!(result.status_code, Some(200));
        assert_eq!(result.title, Some("Internal Panel".to_string()));
        assert_eq!(result.headers.get("server").map(String::as_str), Some("nginx"));
        assert_eq!(result.cname, Some("target.cdn.example.net".to_string()));
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn probe_one_does_not_fall_back_on_error_status_codes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let prober = HttpProber::new(&config(100, 10, 2000)).expect("client should build");
        let host = host_from_uri(&server.uri());

        let result = prober.probe_one(&host, None).await;

        // The mock server only speaks HTTP, so if the prober had incorrectly fallen
        // back to a second (HTTP) attempt after a mere 500, this would still pass;
        // what actually matters is that a bad status is reported as a normal result,
        // not as an `error`.
        assert_eq!(result.status_code, Some(500));
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn probe_one_reports_error_when_nothing_is_listening() {
        let prober = HttpProber::new(&config(100, 10, 500)).expect("client should build");

        // Port 1 is reserved/unassigned and nothing should ever be listening there.
        let result = prober.probe_one("127.0.0.1:1", None).await;

        assert_eq!(result.status_code, None);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn probe_batch_processes_every_host() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<title>ok</title>"))
            .mount(&server)
            .await;

        let prober = HttpProber::new(&config(100, 10, 2000)).expect("client should build");
        let host = host_from_uri(&server.uri());

        let hosts = vec![host.clone(), host.clone(), host];
        let results = prober.probe_batch(hosts).await;

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.status_code == Some(200)));
    }

    #[tokio::test]
    async fn rate_limiter_spaces_out_requests_beyond_burst_capacity() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        // requests_per_second = 2 allows an initial burst of 2 probes, then forces the
        // remaining 2 to each wait ~500ms for the quota to refill.
        let prober = HttpProber::new(&config(2, 10, 5000)).expect("client should build");
        let host = host_from_uri(&server.uri());
        let hosts = vec![host.clone(), host.clone(), host.clone(), host];

        let start = StdInstant::now();
        let results = prober.probe_batch(hosts).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 4);
        assert!(
            elapsed >= Duration::from_millis(450),
            "rate limiter did not space out requests, elapsed = {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn rate_limit_is_independent_per_host_not_shared_across_hosts() {
        let server_a = MockServer::start().await;
        let server_b = MockServer::start().await;
        for server in [&server_a, &server_b] {
            Mock::given(method("GET"))
                .and(path("/"))
                .respond_with(ResponseTemplate::new(200))
                .mount(server)
                .await;
        }

        // requests_per_second = 2 allows a burst of 2 per host. Two requests to host A
        // and two to host B (4 total, exceeding the "2/sec" figure in aggregate) should
        // all land within each host's own burst capacity, proving the two hosts don't
        // share one quota — unlike `rate_limiter_spaces_out_requests_beyond_burst_capacity`
        // above, which exercises the same host four times and does observe throttling.
        let prober = HttpProber::new(&config(2, 10, 5000)).expect("client should build");
        let host_a = host_from_uri(&server_a.uri());
        let host_b = host_from_uri(&server_b.uri());

        let start = StdInstant::now();
        let results = tokio::join!(
            prober.probe_one(&host_a, None),
            prober.probe_one(&host_a, None),
            prober.probe_one(&host_b, None),
            prober.probe_one(&host_b, None),
        );
        let elapsed = start.elapsed();

        assert_eq!(results.0.status_code, Some(200));
        assert_eq!(results.1.status_code, Some(200));
        assert_eq!(results.2.status_code, Some(200));
        assert_eq!(results.3.status_code, Some(200));
        assert!(
            elapsed < Duration::from_millis(450),
            "requests to independent hosts should not throttle each other, elapsed = {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn custom_headers_and_user_agent_are_sent_on_every_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .and(wiremock::matchers::header("X-VFC-VDP", "HackerOne-h1_handle"))
            .and(wiremock::matchers::header("User-Agent", "recon-rs-test-vfc/0.1"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let mut custom_headers = HashMap::new();
        custom_headers.insert("X-VFC-VDP".to_string(), "HackerOne-h1_handle".to_string());
        let mut cfg = config(100, 10, 2000);
        cfg.user_agent = "recon-rs-test-vfc/0.1".to_string();
        cfg.hacker_username = "h1_handle".to_string();
        cfg.custom_headers = custom_headers;

        let prober = HttpProber::new(&cfg).expect("client should build");
        let host = host_from_uri(&server.uri());

        let result = prober.probe_one(&host, None).await;

        // wiremock's `header` matcher means the mock would not have matched (and the
        // server would answer 404 instead of the stubbed 200) if either header were
        // missing or wrong — this is the actual assertion.
        assert_eq!(result.status_code, Some(200));
    }

    #[test]
    fn new_rejects_an_invalid_custom_header_name() {
        let mut cfg = config(10, 10, 1000);
        cfg.custom_headers.insert("not a valid header name".to_string(), "value".to_string());

        let result = HttpProber::new(&cfg);

        assert!(matches!(result, Err(ReconError::HttpClientBuild(_))));
    }
}
