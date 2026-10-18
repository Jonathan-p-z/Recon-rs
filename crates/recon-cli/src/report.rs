//! Rendering a [`crate::pipeline::ScanSummary`] as Markdown, and writing it to disk.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use recon_db::ScanResultRecord;

use crate::error::PipelineError;
use crate::pipeline::ScanSummary;

/// Filesystem-safe, sortable, unambiguous timestamp for report filenames, e.g.
/// `20260828T143000Z`. No colons (invalid in Windows filenames); always UTC (hence the
/// trailing `Z`).
const TIMESTAMP_FORMAT: &str = "%Y%m%dT%H%M%SZ";

/// Sort rank for a stored priority string, highest severity first. Absent or
/// unrecognized priorities sort last, even after `"low"` — a result this pipeline
/// somehow never scored is less immediately actionable than a confirmed `"low"`.
///
/// This is a small hand-rolled mapping rather than a round-trip through
/// `recon_core::Priority::parse`, because `parse` deliberately treats "unrecognized" and
/// "low" the same way (defaulting both to [`recon_core::Priority::Low`]) — which would
/// erase the distinction this report wants to keep between "never scored" and
/// "confirmed low priority".
fn priority_rank(priority: Option<&str>) -> u8 {
    match priority {
        Some("critical") => 0,
        Some("high") => 1,
        Some("medium") => 2,
        Some("low") => 3,
        _ => 4,
    }
}

/// Human-readable label for a stored priority string.
fn priority_label(priority: Option<&str>) -> &str {
    priority.unwrap_or("(non évalué)")
}

/// Table-cell rendering for an optional HTTP status code.
fn status_cell(status: Option<i32>) -> String {
    status.map_or_else(|| "-".to_string(), |code| code.to_string())
}

/// Renders `summary` as a Markdown report for `target`.
///
/// `target` is taken as an explicit parameter (rather than reading `summary.target`
/// alone) so the report header always reflects what the caller believes it just
/// scanned; in debug builds this is cross-checked against `summary.target` (which
/// should always agree, since both ultimately come from the same scan run) to catch a
/// caller/summary mismatch early.
#[must_use]
pub fn generate_markdown_report(summary: &ScanSummary, target: &str) -> String {
    debug_assert_eq!(summary.target, target, "ScanSummary.target must match the report target");

    let mut out = String::new();

    write_header(&mut out, summary, target);
    write_headline(&mut out, summary);

    if let Some(diff) = &summary.diff {
        write_new_subdomains(&mut out, &diff.new_subdomains);
        write_status_changes(&mut out, &diff.status_changed);
        write_disappeared(&mut out, &diff.disappeared_subdomains);
    }

    write_full_summary_table(&mut out, &summary.results);
    write_footer(&mut out, summary);

    out
}

fn write_header(out: &mut String, summary: &ScanSummary, target: &str) {
    let duration_secs = (summary.finished_at - summary.started_at).num_seconds();

    out.push_str(&format!("# Rapport de recon — {target}\n\n"));
    out.push_str(&format!("- Date du scan : {}\n", summary.finished_at.format("%Y-%m-%d %H:%M:%S UTC")));
    out.push_str(&format!("- Durée du scan : {duration_secs}s\n"));
    out.push_str(&format!("- Candidats testés : {}\n", summary.candidates_tested));
    out.push_str(&format!("- Sous-domaines résolus : {}\n\n", summary.resolved_count));
}

/// Trailing metadata line, kept out of the header proper since it's for
/// traceability/debugging (correlating a report back to its `scans` row) rather than
/// something an operator reads at a glance.
fn write_footer(out: &mut String, summary: &ScanSummary) {
    out.push_str(&format!("\n---\n_Scan ID : {}_\n", summary.scan_id));
}

/// Distinct copy for "first scan ever" vs. "scanned before, genuinely nothing changed",
/// so an operator can tell the two apart at a glance without reading the full report.
fn write_headline(out: &mut String, summary: &ScanSummary) {
    match &summary.diff {
        None => out.push_str(
            "> ℹ️ **Premier scan de ce domaine** — aucun scan précédent à comparer, \
             rien à signaler comme nouveau ou changé pour cette exécution.\n\n",
        ),
        Some(diff) if diff.new_subdomains.is_empty() && diff.status_changed.is_empty() => {
            out.push_str("> ✅ **Rien de nouveau depuis le dernier scan.**\n\n");
        }
        Some(_) => {}
    }
}

fn write_new_subdomains(out: &mut String, new_subdomains: &[ScanResultRecord]) {
    if new_subdomains.is_empty() {
        return;
    }
    out.push_str("## 🆕 Nouveaux sous-domaines\n\n");
    out.push_str("| Sous-domaine | Statut HTTP | Priorité |\n|---|---|---|\n");

    let mut sorted: Vec<&ScanResultRecord> = new_subdomains.iter().collect();
    sorted.sort_by_key(|record| priority_rank(record.priority.as_deref()));

    for record in sorted {
        out.push_str(&format!(
            "| {} | {} | {} |\n",
            record.subdomain,
            status_cell(record.http_status),
            priority_label(record.priority.as_deref())
        ));
    }
    out.push('\n');
}

fn write_status_changes(out: &mut String, status_changed: &[(ScanResultRecord, ScanResultRecord)]) {
    if status_changed.is_empty() {
        return;
    }
    out.push_str("## ⚠️ Changements de statut\n\n");
    out.push_str("| Sous-domaine | Statut précédent | Statut actuel | Priorité actuelle |\n|---|---|---|---|\n");

    let mut sorted: Vec<&(ScanResultRecord, ScanResultRecord)> = status_changed.iter().collect();
    sorted.sort_by_key(|(_, current)| priority_rank(current.priority.as_deref()));

    for (previous, current) in sorted {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            current.subdomain,
            status_cell(previous.http_status),
            status_cell(current.http_status),
            priority_label(current.priority.as_deref()),
        ));
    }
    out.push('\n');
}

fn write_disappeared(out: &mut String, disappeared: &[String]) {
    if disappeared.is_empty() {
        return;
    }
    out.push_str("## 📉 Sous-domaines disparus\n\n");
    out.push_str(
        "_Informationnel — ces hôtes répondaient lors du scan précédent mais plus \
         maintenant ; peut simplement indiquer une infra désactivée, pas nécessairement \
         un problème._\n\n",
    );
    for subdomain in disappeared {
        out.push_str(&format!("- {subdomain}\n"));
    }
    out.push('\n');
}

fn write_full_summary_table(out: &mut String, results: &[ScanResultRecord]) {
    out.push_str("## Résumé complet\n\n");
    if results.is_empty() {
        out.push_str("_Aucun sous-domaine résolu lors de ce scan._\n\n");
        return;
    }
    out.push_str("| Sous-domaine | Statut HTTP | Priorité |\n|---|---|---|\n");

    let mut sorted: Vec<&ScanResultRecord> = results.iter().collect();
    sorted.sort_by_key(|record| priority_rank(record.priority.as_deref()));

    for record in sorted {
        out.push_str(&format!(
            "| {} | {} | {} |\n",
            record.subdomain,
            status_cell(record.http_status),
            priority_label(record.priority.as_deref())
        ));
    }
}

/// Writes `report` to `{output_dir}/{target}_{timestamp}.md`, then writes the same
/// content to `{output_dir}/{target}_latest.md` as a plain file copy (not a symbolic
/// link) so the newest report can always be found under a stable name, without
/// platform-specific symlink handling or stale-symlink edge cases.
///
/// `timestamp` is taken from the caller (pass `summary.finished_at`) rather than
/// calling `Utc::now()` here, so the filename deterministically reflects when the scan
/// itself finished and this function stays trivially testable.
///
/// Returns the path of the timestamped report.
///
/// # Errors
/// Returns [`PipelineError::Io`] if `output_dir` cannot be created, or if either file
/// cannot be written.
pub fn write_report(output_dir: &Path, target: &str, report: &str, timestamp: DateTime<Utc>) -> Result<PathBuf, PipelineError> {
    std::fs::create_dir_all(output_dir)?;

    let dated_path = output_dir.join(format!("{target}_{}.md", timestamp.format(TIMESTAMP_FORMAT)));
    std::fs::write(&dated_path, report)?;

    let latest_path = output_dir.join(format!("{target}_latest.md"));
    std::fs::write(latest_path, report)?;

    Ok(dated_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use recon_db::ScanDiff;
    use uuid::Uuid;

    fn record(subdomain: &str, http_status: Option<i32>, priority: Option<&str>) -> ScanResultRecord {
        ScanResultRecord {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            subdomain: subdomain.to_string(),
            ip: None,
            cname: None,
            http_status,
            title: None,
            priority: priority.map(str::to_string),
            created_at: Utc::now(),
        }
    }

    fn base_summary(diff: Option<ScanDiff>, results: Vec<ScanResultRecord>) -> ScanSummary {
        ScanSummary {
            target: "example.com".to_string(),
            scan_id: Uuid::new_v4(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            candidates_tested: 42,
            resolved_count: results.len(),
            results,
            diff,
        }
    }

    #[test]
    fn first_scan_reports_no_history() {
        let results = vec![record("www.example.com", Some(200), Some("low"))];
        let summary = base_summary(None, results);

        let report = generate_markdown_report(&summary, "example.com");

        assert!(report.contains("Premier scan de ce domaine"));
        assert!(!report.contains("Rien de nouveau depuis le dernier scan"));
        assert!(!report.contains("🆕 Nouveaux sous-domaines"));
        assert!(report.contains("## Résumé complet"));
        assert!(report.contains("www.example.com"));
    }

    #[test]
    fn scan_with_new_subdomains_and_status_changes_lists_both_sections_sorted_by_priority() {
        let critical = record("assets.example.com", None, Some("critical"));
        let low = record("static.example.com", Some(200), Some("low"));
        let previous_status = record("api.example.com", Some(200), Some("medium"));
        let current_status = record("api.example.com", Some(403), Some("medium"));

        let diff = ScanDiff {
            new_subdomains: vec![low.clone(), critical.clone()],
            disappeared_subdomains: vec![],
            status_changed: vec![(previous_status, current_status)],
        };
        let summary = base_summary(Some(diff), vec![critical, low]);

        let report = generate_markdown_report(&summary, "example.com");

        assert!(!report.contains("Premier scan de ce domaine"));
        assert!(!report.contains("Rien de nouveau depuis le dernier scan"));
        assert!(report.contains("## 🆕 Nouveaux sous-domaines"));
        assert!(report.contains("## ⚠️ Changements de statut"));
        assert!(!report.contains("## 📉 Sous-domaines disparus"));

        // "critical" must be listed before "low" in the new-subdomains section.
        let new_section_start = report.find("## 🆕").expect("section must be present");
        let status_section_start = report.find("## ⚠️").expect("section must be present");
        let new_section = &report[new_section_start..status_section_start];
        let critical_pos = new_section.find("assets.example.com").expect("critical row present");
        let low_pos = new_section.find("static.example.com").expect("low row present");
        assert!(critical_pos < low_pos, "critical priority row should be listed before low priority row");
    }

    #[test]
    fn scan_with_no_changes_reports_up_to_date() {
        let results = vec![record("www.example.com", Some(200), Some("low"))];
        let diff = ScanDiff::default();
        let summary = base_summary(Some(diff), results);

        let report = generate_markdown_report(&summary, "example.com");

        assert!(report.contains("Rien de nouveau depuis le dernier scan"));
        assert!(!report.contains("Premier scan de ce domaine"));
        assert!(!report.contains("## 🆕 Nouveaux sous-domaines"));
        assert!(!report.contains("## ⚠️ Changements de statut"));
    }

    #[test]
    fn disappeared_subdomains_render_even_when_headline_says_nothing_new() {
        let diff = ScanDiff {
            new_subdomains: vec![],
            disappeared_subdomains: vec!["old.example.com".to_string()],
            status_changed: vec![],
        };
        let summary = base_summary(Some(diff), vec![]);

        let report = generate_markdown_report(&summary, "example.com");

        assert!(report.contains("Rien de nouveau depuis le dernier scan"));
        assert!(report.contains("## 📉 Sous-domaines disparus"));
        assert!(report.contains("old.example.com"));
    }

    #[test]
    fn priority_rank_orders_critical_first_and_unscored_last() {
        assert!(priority_rank(Some("critical")) < priority_rank(Some("high")));
        assert!(priority_rank(Some("high")) < priority_rank(Some("medium")));
        assert!(priority_rank(Some("medium")) < priority_rank(Some("low")));
        assert!(priority_rank(Some("low")) < priority_rank(None));
    }
}
