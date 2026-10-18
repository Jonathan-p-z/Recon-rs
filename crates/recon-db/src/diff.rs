//! Pure comparison of two scans of the same target, with no database access.

use std::collections::HashMap;

use crate::ScanResultRecord;

/// The differences between a previous and a current scan of the same target domain,
/// keyed by `subdomain`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanDiff {
    /// Subdomains present in the current scan but absent from the previous one.
    pub new_subdomains: Vec<ScanResultRecord>,
    /// Subdomains present in the previous scan but absent from the current one.
    pub disappeared_subdomains: Vec<String>,
    /// Subdomains present in both scans whose `http_status` differs, as (previous, current) pairs.
    pub status_changed: Vec<(ScanResultRecord, ScanResultRecord)>,
}

/// Compares two sets of [`ScanResultRecord`]s from successive scans of the same target,
/// matching entries by `subdomain`.
///
/// This is a pure function — it takes already-loaded records (e.g. from
/// [`crate::ScanRepository::get_scan_results`]) and does no I/O itself, which keeps it
/// trivial to unit-test with in-memory fixtures.
///
/// "Status changed" is judged on `http_status`, the only field both scans record that
/// can meaningfully flip between two runs of the same host (e.g. `200` → `403`, or a
/// host that stops responding at all: `Some(_)` → `None`).
#[must_use]
pub fn compute_diff(previous: &[ScanResultRecord], current: &[ScanResultRecord]) -> ScanDiff {
    let previous_by_subdomain: HashMap<&str, &ScanResultRecord> = previous
        .iter()
        .map(|record| (record.subdomain.as_str(), record))
        .collect();
    let current_by_subdomain: HashMap<&str, &ScanResultRecord> = current
        .iter()
        .map(|record| (record.subdomain.as_str(), record))
        .collect();

    let mut new_subdomains = Vec::new();
    let mut status_changed = Vec::new();

    for record in current {
        match previous_by_subdomain.get(record.subdomain.as_str()) {
            None => new_subdomains.push(record.clone()),
            Some(previous_record) => {
                if previous_record.http_status != record.http_status {
                    status_changed.push(((*previous_record).clone(), record.clone()));
                }
            }
        }
    }

    let mut disappeared_subdomains: Vec<String> = previous
        .iter()
        .filter(|record| !current_by_subdomain.contains_key(record.subdomain.as_str()))
        .map(|record| record.subdomain.clone())
        .collect();
    disappeared_subdomains.sort();

    ScanDiff {
        new_subdomains,
        disappeared_subdomains,
        status_changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn record(subdomain: &str, http_status: Option<i32>) -> ScanResultRecord {
        ScanResultRecord {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            subdomain: subdomain.to_string(),
            ip: None,
            cname: None,
            http_status,
            title: None,
            priority: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn detects_new_subdomains() {
        let previous = vec![record("api.example.com", Some(200))];
        let current = vec![record("api.example.com", Some(200)), record("admin.example.com", Some(200))];

        let diff = compute_diff(&previous, &current);

        assert_eq!(diff.new_subdomains.len(), 1);
        assert_eq!(diff.new_subdomains[0].subdomain, "admin.example.com");
        assert!(diff.disappeared_subdomains.is_empty());
        assert!(diff.status_changed.is_empty());
    }

    #[test]
    fn detects_disappeared_subdomains() {
        let previous = vec![record("api.example.com", Some(200)), record("old.example.com", Some(200))];
        let current = vec![record("api.example.com", Some(200))];

        let diff = compute_diff(&previous, &current);

        assert_eq!(diff.disappeared_subdomains, vec!["old.example.com".to_string()]);
        assert!(diff.new_subdomains.is_empty());
        assert!(diff.status_changed.is_empty());
    }

    #[test]
    fn detects_status_changes() {
        let previous = vec![record("api.example.com", Some(200))];
        let current = vec![record("api.example.com", Some(403))];

        let diff = compute_diff(&previous, &current);

        assert_eq!(diff.status_changed.len(), 1);
        let (before, after) = &diff.status_changed[0];
        assert_eq!(before.http_status, Some(200));
        assert_eq!(after.http_status, Some(403));
        assert!(diff.new_subdomains.is_empty());
        assert!(diff.disappeared_subdomains.is_empty());
    }

    #[test]
    fn treats_a_host_going_unreachable_as_a_status_change() {
        let previous = vec![record("api.example.com", Some(200))];
        let current = vec![record("api.example.com", None)];

        let diff = compute_diff(&previous, &current);

        assert_eq!(diff.status_changed.len(), 1);
    }

    #[test]
    fn no_differences_when_scans_are_identical() {
        let previous = vec![record("api.example.com", Some(200)), record("admin.example.com", Some(200))];
        let current = previous.clone();

        let diff = compute_diff(&previous, &current);

        assert!(diff.new_subdomains.is_empty());
        assert!(diff.disappeared_subdomains.is_empty());
        assert!(diff.status_changed.is_empty());
    }

    #[test]
    fn handles_an_empty_previous_scan() {
        let current = vec![record("api.example.com", Some(200))];

        let diff = compute_diff(&[], &current);

        assert_eq!(diff.new_subdomains.len(), 1);
        assert!(diff.disappeared_subdomains.is_empty());
    }
}
