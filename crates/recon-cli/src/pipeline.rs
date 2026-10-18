//! Orchestrates one full scan run: candidate generation, DNS resolution, HTTP probing,
//! persistence, and diffing against the previous completed scan of the same target.
//!
//! `run_scan` itself has no dedicated integration test: it is thin orchestration glue
//! over primitives already covered elsewhere — `recon_core::DnsResolver`/`HttpProber`
//! against a mock DNS backend / `wiremock` server, and `recon_db::ScanRepository`
//! against a real PostgreSQL instance in its `#[ignore]`d tests (see that crate's
//! `repository.rs` for how to run them). What *is* unit-tested here, with hand-built
//! inputs and no DB or network, are the pure pieces: [`candidate_fqdns`],
//! [`cname_from_outcome`], and [`build_record`] (which also exercises
//! `recon_core::score_result` end-to-end for a couple of signatures).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use recon_core::permutation_engine::{extract_pattern, generate_candidates, score_result};
use recon_core::{DnsResolver, HttpProber, ProbeResult, ResolveOutcome, ScanResult, ScoredCandidate, VulnSignature};
use recon_db::{compute_diff, ScanDiff, ScanRepository, ScanResultRecord};
use uuid::Uuid;

use crate::configs::Configs;
use crate::error::PipelineError;

/// Outcome of one full [`run_scan`] call, ready for
/// [`crate::report::generate_markdown_report`].
#[derive(Debug, Clone)]
pub struct ScanSummary {
    /// The target domain that was scanned.
    pub target: String,
    /// The `scans` row id for this run.
    pub scan_id: Uuid,
    /// When this run started.
    pub started_at: DateTime<Utc>,
    /// When this run finished.
    pub finished_at: DateTime<Utc>,
    /// Number of FQDNs attempted for DNS resolution this run — every permutation
    /// [`recon_core::permutation_engine::generate_candidates`] produced, plus every
    /// `seed` subdomain not already among them (see [`merge_seed_into_targets`]).
    pub candidates_tested: usize,
    /// Number of candidates that actually resolved (directly or via CNAME).
    pub resolved_count: usize,
    /// Every result persisted for this run.
    pub results: Vec<ScanResultRecord>,
    /// `None` when there is no previous completed scan of this target to diff against
    /// (first-ever scan of this target); `Some` — possibly with every field empty —
    /// otherwise.
    pub diff: Option<ScanDiff>,
}

/// Runs one full scan of `target`: generates candidates from `seed`'s naming pattern,
/// resolves and probes them — together with `seed`'s own subdomains, so a scan also
/// reconfirms that already-known subdomains are still alive rather than only ever using
/// them to infer a naming convention — persists the results, and diffs against the
/// previous completed scan of the same target (if any).
///
/// # Errors
/// Returns [`PipelineError::Recon`] if building the DNS resolver or HTTP prober fails,
/// or [`PipelineError::Db`] if any database operation fails.
pub async fn run_scan(
    target: &str,
    configs: &Configs,
    seed: Vec<String>,
    db: &ScanRepository,
) -> Result<ScanSummary, PipelineError> {
    let started_at = Utc::now();

    let scan_id = db.create_scan(target).await?;
    tracing::info!(scan_target = %target, %scan_id, "created scan");

    // Captured *before* this run is marked finished below: otherwise, once
    // `finish_scan` runs, `get_last_completed_scan` would return this very run's own
    // id and the diff against "the previous scan" would always come out empty.
    let previous_scan_id = db.get_last_completed_scan(target).await?;

    let pattern = extract_pattern(&seed);
    let candidates: Vec<ScoredCandidate> = generate_candidates(&seed, &pattern, &configs.patterns).into_vec();
    tracing::info!(generated_candidates = candidates.len(), "generated candidates");

    let fqdns = merge_seed_into_targets(candidate_fqdns(&candidates, target), &seed);
    let candidates_tested = fqdns.len();
    tracing::info!(candidates_tested, seed_count = seed.len(), "final target list built (generated candidates + seed)");

    let resolver = Arc::new(DnsResolver::new(&configs.resolver)?);
    let resolved = resolve_all(Arc::clone(&resolver), fqdns).await;
    let resolved_count = resolved.len();
    tracing::info!(resolved_count, "resolved candidates");

    let prober = Arc::new(HttpProber::new(&configs.prober)?);
    let hosts_with_cname: Vec<(String, Option<String>)> = resolved
        .iter()
        .map(|(host, outcome)| (host.clone(), cname_from_outcome(outcome)))
        .collect();
    let mut probe_results = probe_all(Arc::clone(&prober), hosts_with_cname).await;
    tracing::info!(probed = probe_results.len(), "probed resolved candidates");

    let signatures = &configs.patterns.vuln_signatures.rule;
    let mut results = Vec::with_capacity(resolved.len());
    for (host, outcome) in &resolved {
        let probe = probe_results.remove(host);
        results.push(build_record(scan_id, host.clone(), outcome, probe, signatures));
    }

    db.save_results(scan_id, &results).await?;
    tracing::info!(saved = results.len(), "saved results");

    let finished_at = Utc::now();
    db.finish_scan(scan_id, i32::try_from(candidates_tested).unwrap_or(i32::MAX)).await?;

    let diff = match previous_scan_id {
        Some(previous_id) => {
            let previous_results = db.get_scan_results(previous_id).await?;
            Some(compute_diff(&previous_results, &results))
        }
        None => None,
    };

    Ok(ScanSummary {
        target: target.to_string(),
        scan_id,
        started_at,
        finished_at,
        candidates_tested,
        resolved_count,
        results,
        diff,
    })
}

/// Builds the fully-qualified hostnames to resolve, appending `.{target}` to each
/// generated candidate label (`ScoredCandidate::candidate` is a label only, without the
/// base domain).
#[must_use]
fn candidate_fqdns(candidates: &[ScoredCandidate], target: &str) -> Vec<String> {
    candidates.iter().map(|c| format!("{}.{target}", c.candidate)).collect()
}

/// Appends `seed`'s subdomains to `candidate_fqdns`, case-insensitively deduplicated.
///
/// `generate_candidates` only ever produces *new* permutations — it deliberately skips
/// anything already in `seed` (that's the whole point of a seed: don't waste requests
/// re-guessing what's already known) — so without this, a scan's `seed` subdomains
/// would only ever be used to infer a naming convention via `extract_pattern` and would
/// never themselves be resolved, probed, or show up in `resolved_count`/`scan_results`.
/// Re-testing them here is what lets a scan confirm a previously-known subdomain is
/// still alive from one run to the next.
///
/// Generated candidates come first (unchanged), so `candidates_tested`/logging still
/// reflects `generate_candidates`'s output before the seed addition, for anyone reading
/// the first N entries.
#[must_use]
fn merge_seed_into_targets(candidate_fqdns: Vec<String>, seed: &[String]) -> Vec<String> {
    let mut seen: HashSet<String> = candidate_fqdns.iter().map(|fqdn| fqdn.to_ascii_lowercase()).collect();
    let mut targets = candidate_fqdns;
    for subdomain in seed {
        if seen.insert(subdomain.to_ascii_lowercase()) {
            targets.push(subdomain.clone());
        }
    }
    targets
}

/// Extracts the CNAME target learned during resolution, if any.
fn cname_from_outcome(outcome: &ResolveOutcome) -> Option<String> {
    match outcome {
        ResolveOutcome::Cname { target } => Some(target.clone()),
        _ => None,
    }
}

/// Resolves every FQDN concurrently, reusing `resolver`'s own internal rate limiting
/// and concurrency cap (each call to
/// [`recon_core::DnsResolver::resolve_one`] waits on the same shared gate regardless of
/// how many callers are in flight) — this function adds no throttling of its own.
///
/// `resolve_batch` is deliberately not used here: its `buffer_unordered`-based
/// implementation does not return results in input order, and `ResolveOutcome` does not
/// carry the source candidate back, so there would be no reliable way to know which
/// FQDN a given outcome belongs to. Spawning one task per candidate and returning
/// `(fqdn, outcome)` pairs from each task carries that correlation through explicitly.
///
/// Only candidates that actually resolved (`Resolved`/`Cname`) are kept in the result.
async fn resolve_all(resolver: Arc<DnsResolver>, fqdns: Vec<String>) -> Vec<(String, ResolveOutcome)> {
    let mut set = tokio::task::JoinSet::new();
    for fqdn in fqdns {
        let resolver = Arc::clone(&resolver);
        set.spawn(async move {
            let outcome = resolver.resolve_one(&fqdn).await;
            (fqdn, outcome)
        });
    }

    let mut resolved = Vec::new();
    while let Some(joined) = set.join_next().await {
        // A `JoinError` here means the spawned task itself panicked; `resolve_one`
        // does not panic in normal operation, so such a task is simply skipped rather
        // than aborting the whole scan.
        if let Ok((fqdn, outcome)) = joined {
            if matches!(outcome, ResolveOutcome::Resolved { .. } | ResolveOutcome::Cname { .. }) {
                resolved.push((fqdn, outcome));
            }
        }
    }
    resolved
}

/// Probes every `(host, cname)` pair concurrently, reusing `prober`'s own internal rate
/// limiting (same reasoning as [`resolve_all`]). Returns a map keyed by host so results
/// correlate back to their resolve outcome without depending on task completion order.
///
/// `probe_batch` is deliberately not used: it always passes `cname: None` internally
/// (see its rustdoc), which would discard the CNAME already learned during resolution —
/// information [`recon_core::score_result`]'s `cname_pattern` signatures (e.g.
/// subdomain-takeover detection) depend on. Calling `probe_one` directly with the
/// resolver-learned CNAME preserves it.
async fn probe_all(prober: Arc<HttpProber>, hosts: Vec<(String, Option<String>)>) -> HashMap<String, ProbeResult> {
    let mut set = tokio::task::JoinSet::new();
    for (host, cname) in hosts {
        let prober = Arc::clone(&prober);
        set.spawn(async move {
            let result = prober.probe_one(&host, cname).await;
            (host, result)
        });
    }

    let mut results = HashMap::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((host, result)) = joined {
            results.insert(host, result);
        }
    }
    results
}

/// Merges one resolved candidate's DNS outcome with its (optional) HTTP probe result
/// into a persisted [`ScanResultRecord`], scoring it against `signatures` via
/// [`score_result`].
///
/// `ip`/`cname` are sourced from `outcome` (the resolver's own findings), never from
/// `probe.cname` — [`probe_all`] always threads the resolver-learned CNAME into
/// `probe_one`, but sourcing it from `outcome` here directly is simpler and avoids ever
/// depending on `ProbeResult.cname` agreeing with it.
fn build_record(
    scan_id: Uuid,
    subdomain: String,
    outcome: &ResolveOutcome,
    probe: Option<ProbeResult>,
    signatures: &[VulnSignature],
) -> ScanResultRecord {
    let ip = match outcome {
        ResolveOutcome::Resolved { ip } => Some(ip.to_string()),
        _ => None,
    };
    let cname = cname_from_outcome(outcome);
    let http_status = probe.as_ref().and_then(|p| p.status_code).map(i32::from);
    let title = probe.as_ref().and_then(|p| p.title.clone());
    let headers = probe.map(|p| p.headers).unwrap_or_default();

    let scan_result = ScanResult { subdomain, cname, http_title: title, headers };
    let priority = score_result(&scan_result, signatures);

    // Always `Some`: this pipeline always scores every resolved result. A `None`
    // priority on `ScanResultRecord` only means "scoring was never run" (see
    // `recon_db::ScanResultRecord::new`'s rustdoc) — never applicable here.
    ScanResultRecord::new(scan_id, scan_result, ip, http_status, Some(priority))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn candidate_fqdns_appends_target_domain() {
        let candidates = vec![
            ScoredCandidate { candidate: "api-dev".to_string(), score: 5 },
            ScoredCandidate { candidate: "admin".to_string(), score: 1 },
        ];

        let fqdns = candidate_fqdns(&candidates, "example.com");

        assert_eq!(fqdns, vec!["api-dev.example.com".to_string(), "admin.example.com".to_string()]);
    }

    #[test]
    fn merge_seed_into_targets_appends_seed_after_generated_candidates() {
        let candidates = vec!["apidev.vfc.com".to_string(), "apiuat.vfc.com".to_string()];
        let seed = vec!["api.vfc.com".to_string(), "www.vfc.com".to_string()];

        let merged = merge_seed_into_targets(candidates, &seed);

        assert_eq!(
            merged,
            vec![
                "apidev.vfc.com".to_string(),
                "apiuat.vfc.com".to_string(),
                "api.vfc.com".to_string(),
                "www.vfc.com".to_string(),
            ]
        );
    }

    #[test]
    fn merge_seed_into_targets_deduplicates_case_insensitively() {
        let candidates = vec!["Api.vfc.com".to_string()];
        let seed = vec!["api.VFC.com".to_string(), "www.vfc.com".to_string()];

        let merged = merge_seed_into_targets(candidates, &seed);

        assert_eq!(merged, vec!["Api.vfc.com".to_string(), "www.vfc.com".to_string()]);
    }

    #[test]
    fn merge_seed_into_targets_handles_an_empty_seed() {
        let candidates = vec!["apidev.vfc.com".to_string()];

        let merged = merge_seed_into_targets(candidates.clone(), &[]);

        assert_eq!(merged, candidates);
    }

    #[test]
    fn cname_from_outcome_extracts_cname_only_for_cname_variant() {
        let cname = ResolveOutcome::Cname { target: "target.cdn.example.net".to_string() };
        let resolved = ResolveOutcome::Resolved { ip: "203.0.113.10".parse::<IpAddr>().expect("valid IP") };

        assert_eq!(cname_from_outcome(&cname), Some("target.cdn.example.net".to_string()));
        assert_eq!(cname_from_outcome(&resolved), None);
        assert_eq!(cname_from_outcome(&ResolveOutcome::NotFound), None);
    }

    fn jenkins_signature() -> VulnSignature {
        VulnSignature {
            name: "exposed_jenkins".to_string(),
            match_type: "title_contains".to_string(),
            pattern: "Jenkins".to_string(),
            condition: "no_auth_detected".to_string(),
            priority: "high".to_string(),
        }
    }

    fn s3_takeover_signature() -> VulnSignature {
        VulnSignature {
            name: "subdomain_takeover_s3".to_string(),
            match_type: "cname_pattern".to_string(),
            pattern: "s3.amazonaws.com".to_string(),
            condition: "unresolved_bucket".to_string(),
            priority: "critical".to_string(),
        }
    }

    #[test]
    fn build_record_scores_and_merges_ip_from_resolved_outcome() {
        let scan_id = Uuid::new_v4();
        let outcome = ResolveOutcome::Resolved { ip: "203.0.113.10".parse::<IpAddr>().expect("valid IP") };
        let probe = ProbeResult {
            host: "ci.example.com".to_string(),
            status_code: Some(200),
            title: Some("Dashboard [Jenkins]".to_string()),
            headers: HashMap::new(),
            response_time_ms: 42,
            scheme_used: "https".to_string(),
            cname: None,
            error: None,
        };

        let record = build_record(scan_id, "ci.example.com".to_string(), &outcome, Some(probe), &[jenkins_signature()]);

        assert_eq!(record.scan_id, scan_id);
        assert_eq!(record.ip, Some("203.0.113.10".to_string()));
        assert_eq!(record.cname, None);
        assert_eq!(record.http_status, Some(200));
        assert_eq!(record.priority, Some("high".to_string()));
    }

    #[test]
    fn build_record_scores_cname_takeover_signature_even_without_a_probe() {
        let scan_id = Uuid::new_v4();
        let outcome = ResolveOutcome::Cname { target: "assets-bucket.s3.amazonaws.com".to_string() };

        let record = build_record(
            scan_id,
            "assets.example.com".to_string(),
            &outcome,
            None,
            &[s3_takeover_signature()],
        );

        assert_eq!(record.ip, None);
        assert_eq!(record.cname, Some("assets-bucket.s3.amazonaws.com".to_string()));
        assert_eq!(record.http_status, None);
        assert_eq!(record.priority, Some("critical".to_string()));
    }

    #[test]
    fn build_record_defaults_to_low_priority_when_nothing_matches() {
        let scan_id = Uuid::new_v4();
        let outcome = ResolveOutcome::Resolved { ip: "203.0.113.20".parse::<IpAddr>().expect("valid IP") };

        let record = build_record(scan_id, "www.example.com".to_string(), &outcome, None, &[jenkins_signature()]);

        assert_eq!(record.priority, Some("low".to_string()));
    }
}
