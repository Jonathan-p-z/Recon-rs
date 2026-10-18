//! The persisted representation of a single scanned subdomain.

use chrono::{DateTime, Utc};
use recon_core::{Priority, ScanResult};
use uuid::Uuid;

/// One row of the `scan_results` table.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct ScanResultRecord {
    /// Primary key of this result row.
    pub id: Uuid,
    /// The scan run this result belongs to.
    pub scan_id: Uuid,
    /// The subdomain that was tested.
    pub subdomain: String,
    /// Resolved IP address, if any.
    pub ip: Option<String>,
    /// DNS CNAME target, if any.
    pub cname: Option<String>,
    /// HTTP status code observed while probing, if any.
    pub http_status: Option<i32>,
    /// HTTP response page title, if any.
    pub title: Option<String>,
    /// Severity assigned by [`recon_core::score_result`]
    /// (`critical`/`high`/`medium`/`low`), or `None` if scoring was never run for this
    /// result.
    pub priority: Option<String>,
    /// When this row was written.
    pub created_at: DateTime<Utc>,
}

/// Renders a [`Priority`] the way it is stored in the `priority` column.
///
/// `recon_core::Priority` has no fifth "unscored" variant — [`Priority::Low`] already
/// doubles as "nothing notable matched" (see its rustdoc) — so only the four listed
/// values are ever produced here. The column itself is nullable so a caller that never
/// ran signature scoring at all can store `NULL` instead of guessing a priority.
#[must_use]
fn priority_as_str(priority: Priority) -> &'static str {
    match priority {
        Priority::Critical => "critical",
        Priority::High => "high",
        Priority::Medium => "medium",
        Priority::Low => "low",
    }
}

impl ScanResultRecord {
    /// Builds a new record ready to be persisted via [`crate::ScanRepository::save_results`],
    /// from a scan's already-computed [`recon_core::ScanResult`] plus the fields that do
    /// not exist on it.
    ///
    /// A plain `From<ScanResult>` cannot express this conversion: unlike
    /// [`recon_core::prober::ProbeResult`] → [`ScanResult`] (which drops fields),
    /// `ScanResult` → `ScanResultRecord` needs to *add* context `ScanResult` simply does
    /// not carry — `scan_id` (which scan run this belongs to), `ip` and `http_status`
    /// (`ScanResult`'s HTTP-derived fields are limited to `http_title`), and `priority`
    /// (computed separately via [`recon_core::score_result`], never stored on
    /// `ScanResult` itself), plus this record's own generated `id`/`created_at`. Rather
    /// than hide that missing context behind a partially-populated `From` impl, this
    /// constructor takes it all explicitly.
    #[must_use]
    pub fn new(
        scan_id: Uuid,
        result: ScanResult,
        ip: Option<String>,
        http_status: Option<i32>,
        priority: Option<Priority>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            scan_id,
            subdomain: result.subdomain,
            ip,
            cname: result.cname,
            http_status,
            title: result.http_title,
            priority: priority.map(|p| priority_as_str(p).to_string()),
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn new_carries_scan_result_fields_through_and_fills_in_the_rest() {
        let scan_id = Uuid::new_v4();
        let scan_result = ScanResult {
            subdomain: "api-dev.example.com".to_string(),
            cname: Some("target.cdn.example.net".to_string()),
            http_title: Some("Internal Panel".to_string()),
            headers: HashMap::new(),
        };

        let record = ScanResultRecord::new(
            scan_id,
            scan_result,
            Some("203.0.113.10".to_string()),
            Some(200),
            Some(Priority::High),
        );

        assert_eq!(record.scan_id, scan_id);
        assert_eq!(record.subdomain, "api-dev.example.com");
        assert_eq!(record.ip, Some("203.0.113.10".to_string()));
        assert_eq!(record.cname, Some("target.cdn.example.net".to_string()));
        assert_eq!(record.http_status, Some(200));
        assert_eq!(record.title, Some("Internal Panel".to_string()));
        assert_eq!(record.priority, Some("high".to_string()));
    }

    #[test]
    fn new_stores_no_priority_when_scoring_was_not_run() {
        let scan_result = ScanResult {
            subdomain: "mail.example.com".to_string(),
            cname: None,
            http_title: None,
            headers: HashMap::new(),
        };

        let record = ScanResultRecord::new(Uuid::new_v4(), scan_result, None, None, None);

        assert_eq!(record.priority, None);
    }

    #[test]
    fn priority_as_str_covers_every_variant() {
        assert_eq!(priority_as_str(Priority::Critical), "critical");
        assert_eq!(priority_as_str(Priority::High), "high");
        assert_eq!(priority_as_str(Priority::Medium), "medium");
        assert_eq!(priority_as_str(Priority::Low), "low");
    }
}
