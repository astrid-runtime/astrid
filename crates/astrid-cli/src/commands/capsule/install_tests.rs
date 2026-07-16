//! Tests for [`super`] — the `astrid capsule install` source-resolution path.
//! Kept in a sibling file (referenced via `#[path]`) so `install.rs` stays
//! under the per-file CI line cap.

use super::*;

#[test]
fn manual_install_vars_parse_once_per_key() {
    let items = vec!["mode=headless".to_string(), "token=a=b".to_string()];
    let options = ManualInstallOptions::from_cli(true, &items).expect("valid variables");
    assert!(options.yes);
    assert_eq!(
        options.vars.get("mode").map(String::as_str),
        Some("headless")
    );
    assert_eq!(options.vars.get("token").map(String::as_str), Some("a=b"));
}

#[test]
fn manual_install_vars_reject_malformed_or_duplicate_keys() {
    assert!(ManualInstallOptions::from_cli(true, &["missing".to_string()]).is_err());
    assert!(ManualInstallOptions::from_cli(true, &["=value".to_string()]).is_err());
    assert!(
        ManualInstallOptions::from_cli(
            true,
            &["mode=headless".to_string(), "mode=repl".to_string()],
        )
        .is_err()
    );
}

// Source-string parsing (`strip_version_prefix`, `extract_github_org_repo`,
// `parse_github_source`) now lives in `astrid_capsule_install::github_source`
// and is tested there. Only the CLI-local `@version` suffix splitter stays
// here.
#[test]
fn test_split_version_suffix_versioned() {
    let (base, version) = split_version_suffix("@org/repo@1.2.0");
    assert_eq!(base, "@org/repo");
    assert_eq!(version, Some("1.2.0"));
}

#[test]
fn test_split_version_suffix_no_version() {
    let (base, version) = split_version_suffix("@org/repo");
    assert_eq!(base, "@org/repo");
    assert_eq!(version, None);
}

#[test]
fn test_split_version_suffix_non_alias_untouched() {
    // Plain URLs and local paths never carry an `@version` suffix.
    let (base, version) = split_version_suffix("github.com/org/repo");
    assert_eq!(base, "github.com/org/repo");
    assert_eq!(version, None);

    let (base, version) = split_version_suffix("./local/path");
    assert_eq!(base, "./local/path");
    assert_eq!(version, None);
}

#[test]
fn test_split_version_suffix_trailing_at_is_no_pin() {
    // A dangling `@` with no version is not a pin.
    let (base, version) = split_version_suffix("@org/repo@");
    assert_eq!(base, "@org/repo@");
    assert_eq!(version, None);
}

fn find_wasm_asset(assets: &[serde_json::Value]) -> Option<String> {
    assets.iter().find_map(|asset| {
        let name = asset.get("name")?.as_str()?;
        if !Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("wasm"))
        {
            return None;
        }
        Some(name.to_string())
    })
}

#[test]
fn try_install_wasm_asset_prefers_first_wasm() {
    let assets = vec![
        serde_json::json!({
            "name": "first.wasm",
            "browser_download_url": "https://example.com/first.wasm"
        }),
        serde_json::json!({
            "name": "second.wasm",
            "browser_download_url": "https://example.com/second.wasm"
        }),
    ];
    assert_eq!(find_wasm_asset(&assets).as_deref(), Some("first.wasm"));
}

#[test]
fn try_install_wasm_asset_skips_non_wasm() {
    let assets = vec![serde_json::json!({
        "name": "capsule.capsule",
        "browser_download_url": "https://example.com/capsule.capsule"
    })];
    assert!(
        find_wasm_asset(&assets).is_none(),
        ".capsule should not match .wasm check"
    );
}

#[test]
fn try_install_wasm_asset_case_insensitive() {
    let assets = vec![serde_json::json!({
        "name": "capsule.WASM",
        "browser_download_url": "https://example.com/capsule.WASM"
    })];
    assert_eq!(
        find_wasm_asset(&assets).as_deref(),
        Some("capsule.WASM"),
        "should match .WASM case-insensitively"
    );
}

#[test]
fn release_tag_url_percent_encodes_slash_in_tag() {
    // A tag containing `/` must be encoded as a SINGLE path segment so it
    // can't restructure the URL path. `release/1.0` → `release%2F1.0`.
    let url = release_tag_url("org", "repo", "release/1.0").unwrap();
    assert_eq!(
        url,
        "https://api.github.com/repos/org/repo/releases/tags/release%2F1.0"
    );
    assert!(
        url.contains("%2F"),
        "slash in tag must be percent-encoded: {url}"
    );
    assert!(
        !url.contains("tags/release/1.0"),
        "tag slash must not split into extra path segments: {url}"
    );
}

#[test]
fn release_tag_url_plain_tag_unchanged() {
    let url = release_tag_url("unicity-astrid", "capsule-cli", "v0.1.0").unwrap();
    assert_eq!(
        url,
        "https://api.github.com/repos/unicity-astrid/capsule-cli/releases/tags/v0.1.0"
    );
}

#[test]
fn capsule_toml_raw_url_format() {
    let org = "unicity-astrid";
    let repo = "capsule-cli";
    let tag = "v0.1.0";
    let url = format!("https://raw.githubusercontent.com/{org}/{repo}/{tag}/Capsule.toml");
    assert_eq!(
        url,
        "https://raw.githubusercontent.com/unicity-astrid/capsule-cli/v0.1.0/Capsule.toml"
    );
}
