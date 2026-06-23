//! Pure GitHub source-string parsing and release-asset selection.
//!
//! No network I/O — the actual fetch lives in the uplinks (CLI, gateway),
//! never the kernel install path. This module only turns a capsule source
//! string into `(org, repo)`, and selects a `.capsule` release asset out of
//! the GitHub release JSON the uplink fetched. Keeping it I/O-free lets the
//! CLI and the gateway share one resolver while the kernel-side install
//! handler stays provably fetch-free.

use anyhow::bail;

/// Strip common version prefixes (`v`, `V`) from a Git tag before semver parsing.
#[must_use]
pub fn strip_version_prefix(tag: &str) -> &str {
    tag.strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .unwrap_or(tag)
}

/// Strip a `?query` / `#fragment` tail from a single URL path segment.
fn strip_query_fragment(seg: &str) -> &str {
    seg.split(['?', '#']).next().unwrap_or(seg)
}

/// Reduce a repo path segment to the bare repo name: the first path
/// component, minus any `?query` / `#fragment` and an optional `.git`
/// suffix. Returns `None` if nothing is left.
///
/// These segments are untrusted (a source string from a caller, or a
/// path scraped out of a URL), so normalising here keeps a malformed
/// shape (`repo/extra`, `repo?tab=readme`, `repo.git`) from leaking into
/// the `api.github.com/repos/{org}/{repo}` URL the uplink builds.
fn normalize_repo_segment(rest: &str) -> Option<&str> {
    let repo = rest.split('/').next()?;
    let repo = strip_query_fragment(repo);
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    (!repo.is_empty()).then_some(repo)
}

/// Extract `(org, repo)` from a GitHub URL. Anchors on the
/// `github.com/` marker so extra path segments (`/tree/main`, `.git`,
/// `?tab=readme`) are safely ignored. Both segments are normalised so a
/// query/fragment on either (`org?x=y`, `repo#frag`) can't leak into the
/// API URL.
#[must_use]
pub fn extract_github_org_repo(url: &str) -> Option<(&str, &str)> {
    let idx = url.find("github.com/")?;
    let after_host = &url[idx.saturating_add("github.com/".len())..];
    let trimmed = after_host.trim_end_matches('/');
    let (org, rest) = trimmed.split_once('/')?;
    let org = strip_query_fragment(org);
    let repo = normalize_repo_segment(rest)?;
    if org.is_empty() {
        return None;
    }
    Some((org, repo))
}

/// Parse a capsule source string into `(org, repo)` for GitHub-backed sources.
///
/// Handles `@org/repo`, `github.com/org/repo`, and
/// `https://github.com/org/repo`. The URL forms are matched on a known
/// **prefix**, not a substring — a local path that merely contains
/// `github.com/` (e.g. a vendored checkout under
/// `/tmp/github.com/org/repo`) must NOT be misread as a remote source and
/// fetched. This mirrors the CLI's own dispatch shapes.
#[must_use]
pub fn parse_github_source(source: &str) -> Option<(String, String)> {
    if let Some(repo_path) = source.strip_prefix('@') {
        let (org, rest) = repo_path.split_once('/')?;
        let org = strip_query_fragment(org);
        let repo = normalize_repo_segment(rest)?;
        if org.is_empty() {
            return None;
        }
        return Some((org.to_string(), repo.to_string()));
    }

    if source.starts_with("github.com/")
        || source.starts_with("https://github.com/")
        || source.starts_with("http://github.com/")
    {
        let (org, repo) = extract_github_org_repo(source)?;
        return Some((org.to_string(), repo.to_string()));
    }

    None
}

/// Collect every `.capsule` release asset as `(name, download_url)` pairs,
/// skipping any asset that is not a `.capsule` or lacks a download URL.
///
/// Pure over the GitHub release `assets` JSON array so the selection logic is
/// unit-testable without a live release.
#[must_use]
pub fn capsule_assets(assets: &[serde_json::Value]) -> Vec<(String, String)> {
    assets
        .iter()
        .filter_map(|asset| {
            let name = asset.get("name").and_then(serde_json::Value::as_str)?;
            if !name.ends_with(".capsule") {
                return None;
            }
            let download_url = asset
                .get("browser_download_url")
                .and_then(serde_json::Value::as_str)?;
            Some((name.to_string(), download_url.to_string()))
        })
        .collect()
}

/// Choose which `.capsule` to install when a source yields several. A monorepo
/// builds/releases one archive per capsule crate, named `<capsule>.capsule`, so
/// picking "the first" would install the wrong one. Returns the index into
/// `names` of the chosen archive.
///
/// * none        -> `Ok(None)` (caller falls back, e.g. release -> clone+build).
/// * exactly one -> `Ok(Some(0))` — unambiguous; `name_hint` is irrelevant.
/// * several     -> the one named `<name_hint>.capsule`. Without a hint, or with
///   no matching name, refuse rather than silently install the wrong capsule.
pub fn pick_capsule(names: &[&str], name_hint: Option<&str>) -> anyhow::Result<Option<usize>> {
    match names {
        [] => Ok(None),
        [_] => Ok(Some(0)),
        many => {
            let Some(hint) = name_hint else {
                bail!(
                    "source produced {} .capsule archives but no capsule name to pick one; \
                     expected an archive named '<capsule>.capsule'",
                    many.len()
                );
            };
            // Match the hint against each candidate's stem via `strip_suffix`
            // (no per-call allocation) rather than `format!`-ing the target.
            match many
                .iter()
                .position(|n| n.strip_suffix(".capsule") == Some(hint))
            {
                Some(idx) => Ok(Some(idx)),
                None => bail!(
                    "no '.capsule' archive named '{hint}.capsule' among [{}]",
                    many.join(", ")
                ),
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_version_prefix() {
        assert_eq!(strip_version_prefix("v1.2.3"), "1.2.3");
        assert_eq!(strip_version_prefix("V1.0.0"), "1.0.0");
        assert_eq!(strip_version_prefix("1.0.0"), "1.0.0");
        assert_eq!(strip_version_prefix("v0.0.1-alpha"), "0.0.1-alpha");
        assert_eq!(strip_version_prefix("release-1.0.0"), "release-1.0.0");
    }

    #[test]
    fn test_extract_github_org_repo() {
        let (org, repo) = extract_github_org_repo("https://github.com/org/repo").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");

        let (org, repo) = extract_github_org_repo("github.com/myorg/myrepo").unwrap();
        assert_eq!(org, "myorg");
        assert_eq!(repo, "myrepo");

        let (org, repo) = extract_github_org_repo("https://github.com/org/repo/").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");

        assert!(extract_github_org_repo("singlepart").is_none());
    }

    #[test]
    fn test_extract_github_org_repo_extra_path() {
        let (org, repo) = extract_github_org_repo("https://github.com/org/repo/tree/main").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_extract_github_org_repo_git_suffix() {
        let (org, repo) = extract_github_org_repo("https://github.com/org/repo.git").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_github_source_at_prefix() {
        let (org, repo) = parse_github_source("@org/repo").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_github_source_https() {
        let (org, repo) = parse_github_source("https://github.com/org/repo").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_github_source_bare() {
        let (org, repo) = parse_github_source("github.com/org/repo").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_github_source_non_github() {
        assert!(parse_github_source("./local/path").is_none());
        assert!(parse_github_source("/absolute/path").is_none());
    }

    #[test]
    fn extract_github_org_repo_strips_query_and_fragment() {
        let (org, repo) =
            extract_github_org_repo("https://github.com/org/repo?tab=readme").unwrap();
        assert_eq!((org, repo), ("org", "repo"));
        let (org, repo) = extract_github_org_repo("https://github.com/org/repo#frag").unwrap();
        assert_eq!((org, repo), ("org", "repo"));
        let (org, repo) = extract_github_org_repo("github.com/org/repo.git?x=y").unwrap();
        assert_eq!((org, repo), ("org", "repo"));
        // A query/fragment clinging to the ORG segment is stripped too.
        let (org, repo) = extract_github_org_repo("https://github.com/org?x=y/repo").unwrap();
        assert_eq!((org, repo), ("org", "repo"));
    }

    #[test]
    fn parse_github_source_at_form_takes_first_segment_only() {
        // Extra path segments / query strings on `@org/repo` are trimmed to
        // the bare repo name rather than leaking into the API URL.
        assert_eq!(
            parse_github_source("@org/repo/extra"),
            Some(("org".to_string(), "repo".to_string()))
        );
        assert_eq!(
            parse_github_source("@org/repo?x=y"),
            Some(("org".to_string(), "repo".to_string()))
        );
        assert_eq!(
            parse_github_source("@org/repo.git"),
            Some(("org".to_string(), "repo".to_string()))
        );
        // A query/fragment on the ORG segment is stripped, not leaked.
        assert_eq!(
            parse_github_source("@org?x=y/repo"),
            Some(("org".to_string(), "repo".to_string()))
        );
        // No repo segment at all is not GitHub-shaped.
        assert!(parse_github_source("@org").is_none());
    }

    #[test]
    fn parse_github_source_requires_github_prefix_not_substring() {
        // A local path that merely CONTAINS `github.com/` must not be
        // classified as remote (which would trigger an unwanted fetch).
        assert!(parse_github_source("/tmp/github.com/org/repo").is_none());
        assert!(parse_github_source("./vendor/github.com/org/repo").is_none());
        // The genuine prefix forms still resolve.
        assert_eq!(
            parse_github_source("github.com/org/repo"),
            Some(("org".to_string(), "repo".to_string()))
        );
        assert_eq!(
            parse_github_source("https://github.com/org/repo"),
            Some(("org".to_string(), "repo".to_string()))
        );
    }

    #[test]
    fn pick_capsule_none_when_empty() {
        assert!(matches!(pick_capsule(&[], Some("sage")), Ok(None)));
    }

    #[test]
    fn pick_capsule_single_is_unambiguous() {
        // A lone archive is used regardless of name — a single-capsule repo's
        // asset need not match the requested capsule name.
        assert_eq!(
            pick_capsule(&["whatever.capsule"], Some("sage")).unwrap(),
            Some(0)
        );
        assert_eq!(pick_capsule(&["whatever.capsule"], None).unwrap(), Some(0));
    }

    #[test]
    fn pick_capsule_several_matches_by_exact_name() {
        let names = ["sage.capsule", "sage-mcp.capsule", "sage-install.capsule"];
        assert_eq!(pick_capsule(&names, Some("sage-mcp")).unwrap(), Some(1));
        // exact match — "sage" must NOT collide with "sage-mcp.capsule"
        assert_eq!(pick_capsule(&names, Some("sage")).unwrap(), Some(0));
        assert_eq!(pick_capsule(&names, Some("sage-install")).unwrap(), Some(2));
    }

    #[test]
    fn pick_capsule_several_without_hint_errors() {
        assert!(pick_capsule(&["a.capsule", "b.capsule"], None).is_err());
    }

    #[test]
    fn pick_capsule_several_no_match_errors() {
        assert!(pick_capsule(&["a.capsule", "b.capsule"], Some("c")).is_err());
    }

    #[test]
    fn capsule_assets_collects_all_capsule_entries() {
        let assets = vec![
            serde_json::json!({
                "name": "sage.capsule",
                "browser_download_url": "https://example.com/sage.capsule"
            }),
            serde_json::json!({
                "name": "sage-mcp.capsule",
                "browser_download_url": "https://example.com/sage-mcp.capsule"
            }),
        ];
        let got = capsule_assets(&assets);
        assert_eq!(
            got,
            vec![
                (
                    "sage.capsule".to_string(),
                    "https://example.com/sage.capsule".to_string()
                ),
                (
                    "sage-mcp.capsule".to_string(),
                    "https://example.com/sage-mcp.capsule".to_string()
                ),
            ]
        );
    }

    #[test]
    fn capsule_assets_skips_non_capsule_and_urlless() {
        let assets = vec![
            serde_json::json!({
                "name": "release-notes.txt",
                "browser_download_url": "https://example.com/release-notes.txt"
            }),
            serde_json::json!({
                "name": "cli.capsule",
                "browser_download_url": "https://example.com/cli.capsule"
            }),
            serde_json::json!({ "name": "checksums.sha256" }),
            // `.capsule` asset with no download URL is skipped, not panicked on.
            serde_json::json!({ "name": "broken.capsule" }),
        ];
        let got = capsule_assets(&assets);
        assert_eq!(
            got,
            vec![(
                "cli.capsule".to_string(),
                "https://example.com/cli.capsule".to_string()
            )]
        );
    }

    #[test]
    fn capsule_assets_empty_when_no_capsule_assets() {
        let assets = vec![serde_json::json!({
            "name": "binary.tar.gz",
            "browser_download_url": "https://example.com/binary.tar.gz"
        })];
        assert!(capsule_assets(&assets).is_empty());
    }
}
