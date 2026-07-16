//! Tests for [`super`] — the `astrid capsule install` source-resolution path.
//! Kept in a sibling file (referenced via `#[path]`) so `install.rs` stays
//! under the per-file CI line cap.

use super::*;

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

#[test]
fn direct_install_reads_only_manifest_declared_preseed_values() {
    let defs: std::collections::HashMap<String, astrid_capsule::manifest::EnvDef> = toml::from_str(
        r#"
api_key = { type = "secret", request = "API key" }
auth_mode = { type = "string", default = "api_key" }
"#,
    )
    .unwrap();
    let values = process_env_values(&defs, |name| match name {
        "ASTRID_VAR_API_KEY" => Some("secret-value".to_string()),
        "ASTRID_VAR_AUTH_MODE" => Some("subscription".to_string()),
        "ASTRID_VAR_UNDECLARED" => Some("ignored".to_string()),
        _ => None,
    })
    .unwrap();

    assert_eq!(values.len(), 2);
    assert_eq!(values["api_key"], "secret-value");
    assert_eq!(values["auth_mode"], "subscription");
    assert!(!values.contains_key("undeclared"));
}

#[test]
fn direct_install_rejects_case_colliding_manifest_env_fields() {
    let defs: std::collections::HashMap<String, astrid_capsule::manifest::EnvDef> = toml::from_str(
        r#"
api_key = { type = "secret", request = "API key" }
API_KEY = { type = "string" }
"#,
    )
    .unwrap();

    let error = process_env_values(&defs, |_| Some("credential".to_string()))
        .expect_err("case-colliding fields must fail before any value is provisioned");
    assert!(error.to_string().contains("both normalize"));
    assert!(error.to_string().contains("ASTRID_VAR_API_KEY"));
}

#[test]
fn untrusted_source_children_never_inherit_capsule_preseeds() {
    let sanitized = sanitized_source_environment([
        ("PATH", "/usr/bin:/bin"),
        ("HOME", "/tmp/operator"),
        ("ASTRID_VAR_API_KEY", "runtime-secret"),
        ("astrid_var_token", "case-folded-runtime-secret"),
    ]);
    let sanitized = sanitized
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();

    assert_eq!(
        sanitized.get(std::ffi::OsStr::new("PATH")),
        Some(&std::ffi::OsString::from("/usr/bin:/bin"))
    );
    assert_eq!(
        sanitized.get(std::ffi::OsStr::new("HOME")),
        Some(&std::ffi::OsString::from("/tmp/operator"))
    );
    assert_eq!(sanitized.len(), 2);
}

#[test]
fn direct_install_persists_preseed_after_success_using_manifest_types() {
    let source = tempfile::tempdir().unwrap();
    std::fs::write(
        source.path().join("Capsule.toml"),
        r#"
[package]
name = "configured-capsule"
version = "1.0.0"

[env]
api_key = { type = "secret", request = "API key" }
auth_mode = { type = "string", default = "api_key" }
"#,
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    let principal = astrid_core::PrincipalId::default();
    let provided = serde_json::Map::from_iter([
        (
            "api_key".to_string(),
            serde_json::Value::String("secret-value".to_string()),
        ),
        (
            "auth_mode".to_string(),
            serde_json::Value::String("subscription".to_string()),
        ),
    ]);

    install_from_local_path_for_principal(
        source.path(),
        false,
        &home,
        Some("test-fixture"),
        &principal,
        None,
        Some(&provided),
    )
    .unwrap();

    let env_path = home
        .principal_home(&principal)
        .env_dir()
        .join("configured-capsule.env.json");
    let env: serde_json::Value = serde_json::from_slice(&std::fs::read(env_path).unwrap()).unwrap();
    assert_eq!(env, serde_json::json!({"auth_mode": "subscription"}));
    assert_eq!(
        std::fs::read_to_string(
            home.secrets_dir()
                .join("default/configured-capsule/api_key")
        )
        .unwrap(),
        "secret-value"
    );
}
