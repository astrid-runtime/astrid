//! Tests for [`super`] — the `astrid init` distro-provisioning path. Kept
//! in a sibling file (referenced via `#[path]`) so `init.rs` stays under
//! the per-file CI line cap.

use super::*;

#[test]
fn provider_selection_parses_multi_select() {
    assert_eq!(parse_provider_selection("1,2", 3), vec![1, 2]);
    assert_eq!(parse_provider_selection(" 2 , 3 ", 3), vec![2, 3]);
    assert_eq!(parse_provider_selection("1", 3), vec![1]);
}

#[test]
fn provider_selection_drops_out_of_range_and_garbage() {
    assert_eq!(parse_provider_selection("0,4,2,abc", 3), vec![2]);
    assert!(parse_provider_selection("", 3).is_empty());
    assert!(parse_provider_selection("9,10", 3).is_empty());
}

#[test]
fn provider_selection_dedupes_preserving_order() {
    assert_eq!(parse_provider_selection("2,1,2,1", 3), vec![2, 1]);
}

#[test]
fn provider_selection_preserves_entry_order() {
    // User order is honoured (3 then 1), not numeric-sorted.
    assert_eq!(parse_provider_selection("3,1", 3), vec![3, 1]);
}

#[test]
fn extract_var_refs_finds_all() {
    assert_eq!(extract_var_refs("{{ foo }}"), vec!["foo"]);
    assert_eq!(extract_var_refs("{{ a }}-{{ b }}"), vec!["a", "b"],);
    assert!(extract_var_refs("no vars").is_empty());
}

#[test]
fn resolve_template_replaces_vars() {
    let mut vars = HashMap::new();
    vars.insert("key".to_string(), "secret123".to_string());
    vars.insert("url".to_string(), "https://api.example.com".to_string());

    assert_eq!(resolve_template("{{ key }}", &vars), "secret123",);
    assert_eq!(
        resolve_template("prefix-{{ url }}-suffix", &vars),
        "prefix-https://api.example.com-suffix",
    );
}

#[test]
fn resolve_template_handles_missing_var() {
    let vars = HashMap::new();
    // Unresolved template stays as-is.
    assert_eq!(resolve_template("{{ missing }}", &vars), "{{ missing }}",);
}

#[test]
fn distro_source_resolution_rejects_bare_names_without_a_network_default() {
    let error = resolve_distro_url("example-distro").expect_err("bare name has no provenance");
    assert!(error.to_string().contains("@owner/repo"));
    assert!(error.to_string().contains("local Distro.toml path"));
}

#[test]
fn distro_source_resolution_rejects_non_repository_at_paths() {
    for source in ["@", "@owner", "@/repo", "@owner/", "@owner/repo/extra"] {
        assert!(resolve_distro_url(source).is_err(), "must reject {source}");
    }
}

#[test]
fn distro_source_resolution_at_prefix() {
    assert_eq!(
        resolve_distro_url("@myorg/mydistro").unwrap(),
        "https://raw.githubusercontent.com/myorg/mydistro/main/Distro.toml",
    );
}

#[test]
fn distro_source_resolution_full_url() {
    let url = "https://example.com/Distro.toml";
    assert_eq!(resolve_distro_url(url).unwrap(), url);
}

// ---- Part A: headless selection / variable resolution ----

use super::super::distro::manifest::{DistroCapsule, VariableDef};

fn cap(name: &str, group: Option<&str>, default: bool) -> DistroCapsule {
    DistroCapsule {
        name: name.to_string(),
        source: format!("@org/{name}"),
        version: "0.1.0".to_string(),
        tag: None,
        branch: None,
        rev: None,
        default,
        group: group.map(String::from),
        role: None,
        env: HashMap::new(),
    }
}

#[test]
fn parse_cli_vars_splits_first_equals() {
    let raw = vec!["A=1".to_string(), "URL=https://x?y=z".to_string()];
    let map = parse_cli_vars(&raw).unwrap();
    assert_eq!(map["A"], "1");
    assert_eq!(map["URL"], "https://x?y=z");
}

#[test]
fn parse_cli_vars_rejects_no_equals() {
    assert!(parse_cli_vars(&["NOEQ".to_string()]).is_err());
    assert!(parse_cli_vars(&["=value".to_string()]).is_err());
}

#[test]
fn headless_select_takes_defaults_and_ungrouped() {
    let caps = vec![
        cap("cli", None, false),
        cap("openai", Some("llm"), true),
        cap("anthropic", Some("llm"), false),
    ];
    let selected = select_capsules(caps, true).unwrap();
    let names: std::collections::HashSet<&str> = selected.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains("cli"), "ungrouped always selected");
    assert!(names.contains("openai"), "group default selected");
    assert!(!names.contains("anthropic"), "non-default not selected");
}

#[test]
fn headless_select_falls_back_to_first_when_no_default() {
    let caps = vec![
        cap("cli", None, false),
        cap("alpha", Some("llm"), false),
        cap("beta", Some("llm"), false),
    ];
    let selected = select_capsules(caps, true).unwrap();
    let names: std::collections::HashSet<&str> = selected.iter().map(|c| c.name.as_str()).collect();
    // First in manifest order within the group is "alpha".
    assert!(names.contains("alpha"));
    assert!(!names.contains("beta"));
}

fn var(secret: bool, default: Option<&str>) -> VariableDef {
    VariableDef {
        secret,
        description: None,
        default: default.map(String::from),
    }
}

fn cap_with_env(name: &str, key: &str, template: &str) -> DistroCapsule {
    let mut c = cap(name, None, false);
    c.env.insert(key.to_string(), template.to_string());
    c
}

#[test]
fn headless_collect_uses_cli_var_override() {
    let mut variables = HashMap::new();
    variables.insert("api_key".to_string(), var(true, Some("from-default")));
    let selected = vec![cap_with_env("llm", "API_KEY", "{{ api_key }}")];
    let mut cli = HashMap::new();
    cli.insert("api_key".to_string(), "from-cli".to_string());

    let vars = collect_variables(&variables, &selected, true, &cli).unwrap();
    assert_eq!(vars["api_key"], "from-cli");
}

#[test]
fn headless_collect_uses_env_then_default() {
    let mut variables = HashMap::new();
    variables.insert("base_url".to_string(), var(false, Some("https://default")));
    let mut needed = std::collections::HashSet::new();
    needed.insert("base_url".to_string());

    // No CLI var, no env → default.
    let vars = collect_variables_headless(&variables, &needed, &HashMap::new(), |_| None).unwrap();
    assert_eq!(vars["base_url"], "https://default");

    // Env (ASTRID_VAR_BASE_URL) beats default — injected lookup, no
    // process-global state.
    let vars = collect_variables_headless(&variables, &needed, &HashMap::new(), |k| {
        (k == "ASTRID_VAR_BASE_URL").then(|| "https://from-env".to_string())
    })
    .unwrap();
    assert_eq!(vars["base_url"], "https://from-env");
}

#[tokio::test]
async fn offline_refuses_remote_capsule_source() {
    // A local Distro.toml with a remote @org/repo capsule must not
    // silently fetch under --offline.
    let selected = vec![cap("llm", None, false)]; // source "@org/llm"
    let err = install_capsules(&selected, true, &astrid_core::PrincipalId::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("--offline"), "got: {err}");
    assert!(err.to_string().contains("network/GitHub"), "got: {err}");
}

#[test]
fn offline_guard_blocks_only_github_sources() {
    // GitHub-backed shapes are network sources (rejected under --offline).
    assert!(is_network_capsule_source("@org/repo"));
    assert!(is_network_capsule_source("@org/repo@1.2.0"));
    assert!(is_network_capsule_source("github.com/org/repo"));
    assert!(is_network_capsule_source("https://github.com/org/repo"));

    // Local paths are NOT network sources — including a bare relative
    // path like `capsules/cli.capsule`, which the old guard wrongly
    // rejected because it didn't start with `.` or `/`.
    assert!(!is_network_capsule_source("capsules/cli.capsule"));
    assert!(!is_network_capsule_source("./capsules/cli.capsule"));
    assert!(!is_network_capsule_source("/abs/path/cli.capsule"));
    assert!(!is_network_capsule_source("cli.capsule"));
}

#[test]
fn headless_collect_errors_on_missing_required_var() {
    let mut variables = HashMap::new();
    variables.insert("api_key".to_string(), var(true, None)); // no default
    let mut needed = std::collections::HashSet::new();
    needed.insert("api_key".to_string());

    let err =
        collect_variables_headless(&variables, &needed, &HashMap::new(), |_| None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("api_key"), "got: {msg}");
    assert!(msg.contains("ASTRID_VAR_API_KEY"), "got: {msg}");
}

// ---- Issue #1095: per-principal provisioning ----

/// Regression: `write_env_files` must write under the principal it is
/// given, NOT a hardcoded `default`. Before the fix, env files always
/// landed in `home/default/.config/env/`, so a scoped principal (e.g.
/// `claude-code`) got an empty env view. This test fails without the
/// principal-aware fix (the file appears under `default`, not the scope).
#[test]
fn write_env_files_targets_the_given_principal() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());
    let scope = astrid_core::PrincipalId::new("claude-code").unwrap();
    let default = astrid_core::PrincipalId::default();
    assert_ne!(scope.as_str(), default.as_str(), "scope must differ");

    let selected = vec![cap_with_env("cli", "TOKEN", "{{ tok }}")];
    let mut vars = HashMap::new();
    vars.insert("tok".to_string(), "abc123".to_string());

    write_env_files(&home, &scope, &selected, &vars).unwrap();

    // Lands under the scoped principal's home...
    let scoped_path = home.principal_home(&scope).env_dir().join("cli.env.json");
    assert!(
        scoped_path.exists(),
        "env file must be under the scoped principal's home"
    );

    // ...and NOT under `default` (the pre-fix hardcoded target).
    let default_path = home.principal_home(&default).env_dir().join("cli.env.json");
    assert!(
        !default_path.exists(),
        "env file must NOT be written under `default` for a scoped principal"
    );
}

/// A `Distro.lock` is written ONLY on a full success (or an empty
/// selection). A partial or wholly-failed run writes no lock so a re-run
/// re-attempts the missing capsules instead of short-circuiting at the
/// freshness gate (`is_lock_fresh` can't diff the capsule set).
#[test]
fn should_write_lock_gates_on_success() {
    // Full success → write.
    assert!(should_write_lock(5, 5));
    // Empty selection is not a failure → write (marks the run done).
    assert!(should_write_lock(0, 0));
    // Partial success → do NOT write: a version-matched lock would make the
    // next `init` short-circuit and never retry the failures.
    assert!(!should_write_lock(5, 3));
    // Every install failed → do NOT write.
    assert!(!should_write_lock(5, 0));
    assert!(!should_write_lock(1, 0));
}

/// Regression: a PARTIAL run must leave no `Distro.lock` on disk, so a
/// later `run_init` reloads nothing at the freshness gate and re-provisions
/// the missing capsules. Before the fix (which wrote a lock whenever
/// `succeeded > 0`), a partial run persisted a version-matched lock and the
/// retry was silently wedged. Exercised through `persist_lock_if_earned`,
/// the exact seam `run_init` uses to decide.
#[test]
fn partial_run_leaves_no_lock_for_retry() {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join("distro.lock");
    let lock = create_lock_from_parts(1, "example-distro", "1.0.0", Vec::new());

    // Partial (3 of 5): no lock written, returns false.
    let wrote = persist_lock_if_earned(&lock_path, 5, 3, &lock).unwrap();
    assert!(!wrote, "partial run must not write a lock");
    assert!(
        load_lock(&lock_path).unwrap().is_none(),
        "partial run must leave no Distro.lock on disk, else the retry is wedged"
    );

    // Full (5 of 5): lock written, returns true — a re-run then correctly
    // short-circuits at the freshness gate.
    let wrote = persist_lock_if_earned(&lock_path, 5, 5, &lock).unwrap();
    assert!(wrote, "full success must write the lock");
    assert!(
        load_lock(&lock_path).unwrap().is_some(),
        "full success must persist the lock"
    );
}
