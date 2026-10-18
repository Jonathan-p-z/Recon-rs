//! Loading the optional `--seed-file` of already-known subdomains.

use std::path::Path;

/// Parses seed-file content into a list of already-known FQDNs: one per non-blank,
/// non-comment line. Lines are trimmed; lines empty after trimming, or starting with
/// `#`, are ignored. Pure — no I/O — so it is unit-tested directly.
#[must_use]
pub fn parse_seed(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Reads and parses a seed file, or returns an empty list when `path` is `None` (no
/// `--seed-file` given).
///
/// # Errors
/// Returns [`std::io::Error`] if `path` is `Some` and the file cannot be read.
pub fn load_seed_file(path: Option<&Path>) -> std::io::Result<Vec<String>> {
    match path {
        None => Ok(Vec::new()),
        Some(path) => Ok(parse_seed(&std::fs::read_to_string(path)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_blank_and_comment_lines() {
        let content = "api-dev.example.com\n\n# a comment\n  admin.example.com  \n";

        assert_eq!(
            parse_seed(content),
            vec!["api-dev.example.com".to_string(), "admin.example.com".to_string()]
        );
    }

    #[test]
    fn empty_content_yields_empty_seed() {
        assert!(parse_seed("").is_empty());
        assert!(parse_seed("\n\n# only comments\n").is_empty());
    }

    #[test]
    fn load_seed_file_returns_empty_list_when_no_path_given() {
        let result = load_seed_file(None).expect("None path must never error");
        assert!(result.is_empty());
    }
}
