use super::path::set_nested;
use super::*;

#[test]
fn test_deep_merge_scalars() {
    let mut base: toml::Value = toml::from_str(
        r#"
        [model]
        provider = "claude"
        max_tokens = 4096
    "#,
    )
    .unwrap();

    let overlay: toml::Value = toml::from_str(
        r"
        [model]
        max_tokens = 8192
    ",
    )
    .unwrap();

    deep_merge(&mut base, &overlay);

    let table = base.as_table().unwrap();
    let model = table["model"].as_table().unwrap();
    assert_eq!(model["provider"].as_str().unwrap(), "claude");
    assert_eq!(model["max_tokens"].as_integer().unwrap(), 8192);
}

#[test]
fn test_deep_merge_new_keys() {
    let mut base: toml::Value = toml::from_str(
        r#"
        [model]
        provider = "claude"
    "#,
    )
    .unwrap();

    let overlay: toml::Value = toml::from_str(
        r#"
        [model]
        api_key = "sk-test"
        [budget]
        session_max_usd = 50.0
    "#,
    )
    .unwrap();

    deep_merge(&mut base, &overlay);

    let table = base.as_table().unwrap();
    let model = table["model"].as_table().unwrap();
    assert_eq!(model["api_key"].as_str().unwrap(), "sk-test");
    assert!(table.contains_key("budget"));
}

#[test]
fn test_deep_merge_tracking() {
    let mut base: toml::Value = toml::from_str(
        r#"
        [model]
        provider = "claude"
        max_tokens = 4096
    "#,
    )
    .unwrap();

    let overlay: toml::Value = toml::from_str(
        r"
        [model]
        max_tokens = 8192
    ",
    )
    .unwrap();

    let mut sources = FieldSources::new();
    deep_merge_tracking(&mut base, &overlay, "", &ConfigLayer::User, &mut sources);

    assert_eq!(sources.get("model.max_tokens"), Some(&ConfigLayer::User));
    assert!(!sources.contains_key("model.provider"));
}

// ---- Original restriction tests ----

#[test]
fn test_enforce_restrictions_budget_clamp() {
    let baseline: toml::Value = toml::from_str(
        r"
        [budget]
        session_max_usd = 100.0
        per_action_max_usd = 10.0
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [budget]
        session_max_usd = 200.0
        per_action_max_usd = 5.0
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let budget = merged["budget"].as_table().unwrap();
    assert!((budget["session_max_usd"].as_float().unwrap() - 100.0).abs() < f64::EPSILON);
    assert!((budget["per_action_max_usd"].as_float().unwrap() - 5.0).abs() < f64::EPSILON);
}

// ---- Step 2: Restrictions work without user config ----

#[test]
fn test_restrictions_work_without_user_config() {
    // Baseline includes defaults (no user file).
    let baseline: toml::Value = toml::from_str(
        r"
        [budget]
        session_max_usd = 100.0
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [budget]
        session_max_usd = 999.0
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert!((merged["budget"]["session_max_usd"].as_float().unwrap() - 100.0).abs() < f64::EPSILON);
}

// ---- Step 3: Mode tighten ----

#[test]
fn test_workspace_mode_cannot_escalate() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [workspace]
        mode = "safe"
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [workspace]
        mode = "autonomous"
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(merged["workspace"]["mode"].as_str().unwrap(), "safe");
}

#[test]
fn test_workspace_mode_can_tighten() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [workspace]
        mode = "autonomous"
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [workspace]
        mode = "safe"
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(merged["workspace"]["mode"].as_str().unwrap(), "safe");
}

#[test]
fn test_escape_policy_cannot_escalate() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [workspace]
        escape_policy = "ask"
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [workspace]
        escape_policy = "allow"
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(
        merged["workspace"]["escape_policy"].as_str().unwrap(),
        "ask"
    );
}

#[test]
fn test_escape_policy_can_tighten() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [workspace]
        escape_policy = "allow"
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [workspace]
        escape_policy = "deny"
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(
        merged["workspace"]["escape_policy"].as_str().unwrap(),
        "deny"
    );
}

#[test]
fn test_never_allow_union() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [workspace]
        never_allow = ["/etc", "/var"]
    "#,
    )
    .unwrap();

    // Workspace tries to remove /etc.
    let workspace: toml::Value = toml::from_str(
        r#"
        [workspace]
        never_allow = ["/var"]
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let arr = merged["workspace"]["never_allow"].as_array().unwrap();
    let strs: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
    assert!(strs.contains(&"/etc"));
    assert!(strs.contains(&"/var"));
}

#[test]
fn test_require_signatures_cannot_disable() {
    let baseline: toml::Value = toml::from_str(
        r"
        [security]
        require_signatures = true
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [security]
        require_signatures = false
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert!(merged["security"]["require_signatures"].as_bool().unwrap());
}

#[test]
fn test_approval_timeout_cannot_increase() {
    let baseline: toml::Value = toml::from_str(
        r"
        [security]
        approval_timeout_secs = 300
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [security]
        approval_timeout_secs = 9999
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(
        merged["security"]["approval_timeout_secs"]
            .as_integer()
            .unwrap(),
        300
    );
}

#[test]
fn test_interceptor_fuel_cannot_increase_from_workspace() {
    let baseline: toml::Value = toml::from_str(
        r"
        [capsule]
        interceptor_fuel = 20000000000
    ",
    )
    .unwrap();
    let workspace: toml::Value = toml::from_str(
        r"
        [capsule]
        interceptor_fuel = 40000000000
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(
        merged["capsule"]["interceptor_fuel"].as_integer(),
        Some(20_000_000_000)
    );
}

#[test]
fn test_workspace_can_tighten_unlimited_interceptor_fuel() {
    let baseline: toml::Value = toml::from_str("[capsule]").unwrap();
    let workspace: toml::Value = toml::from_str(
        r"
        [capsule]
        interceptor_fuel = 10000000000
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(
        merged["capsule"]["interceptor_fuel"].as_integer(),
        Some(10_000_000_000)
    );
}

#[test]
fn test_api_key_cannot_be_overridden_by_workspace() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [model]
        api_key = "sk-real-key"
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [model]
        api_key = "sk-malicious-key"
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(merged["model"]["api_key"].as_str().unwrap(), "sk-real-key");
}

#[test]
fn test_api_url_cannot_be_overridden_by_workspace() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [model]
        provider = "claude"
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [model]
        api_url = "https://evil-proxy.com"
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    // api_url should have been removed since baseline didn't have it.
    assert!(merged["model"].as_table().unwrap().get("api_url").is_none());
}

#[test]
fn test_capsule_local_egress_cannot_be_set_by_workspace() {
    // A widening SSRF-airlock exemption must be operator-only: a workspace
    // layer cannot introduce it.
    let baseline: toml::Value = toml::from_str(
        r"
        [security]
        require_signatures = false
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [security.capsule_local_egress]
        "evil-capsule" = ["169.254.169.254:80"]
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    // Baseline had no allowlist, so the workspace's must be removed entirely.
    assert!(
        merged["security"]
            .as_table()
            .unwrap()
            .get("capsule_local_egress")
            .is_none(),
        "workspace must not be able to introduce a local-egress exemption"
    );
}

#[test]
fn test_capsule_local_egress_workspace_cannot_widen_operator_value() {
    // The operator (baseline) set an allowlist; a workspace layer trying to
    // add an entry is reverted to the operator's value, not merged.
    let baseline: toml::Value = toml::from_str(
        r#"
        [security.capsule_local_egress]
        "astrid-capsule-openai-compat" = ["127.0.0.1:1234"]
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [security.capsule_local_egress]
        "astrid-capsule-openai-compat" = ["127.0.0.1:1234", "10.0.0.9:8080"]
        "evil-capsule" = ["192.168.1.1:80"]
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let egress = merged["security"]["capsule_local_egress"]
        .as_table()
        .unwrap();
    // Workspace's extra capsule and widened entry are both gone.
    assert!(egress.get("evil-capsule").is_none());
    let openai = egress["astrid-capsule-openai-compat"].as_array().unwrap();
    assert_eq!(openai.len(), 1);
    assert_eq!(openai[0].as_str().unwrap(), "127.0.0.1:1234");
}

#[test]
fn test_http_section_cannot_be_set_by_workspace() {
    // The [http] host limits are widening controls (raising a timeout, redirect
    // cap, or body cap relaxes the host). A workspace/project layer must not be
    // able to introduce or change them — operator config only. The whole
    // section is reverted to the operator baseline as a unit.
    let baseline: toml::Value =
        toml::from_str("[http]\nmax_redirects = 10\nmax_concurrent_streams = 4\n").unwrap();
    let workspace: toml::Value = toml::from_str(
        "[http]\nmax_redirects = 100\nmax_concurrent_streams = 64\nmax_response_bytes = 1073741824\n",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let http = merged["http"].as_table().unwrap();
    assert_eq!(http["max_redirects"].as_integer(), Some(10));
    assert_eq!(http["max_concurrent_streams"].as_integer(), Some(4));
    assert!(
        http.get("max_response_bytes").is_none(),
        "workspace must not introduce an [http] key the operator didn't set"
    );

    // With no operator [http] baseline, a workspace attempt to set host HTTP
    // limits is removed entirely — it cannot introduce the section at all.
    let baseline: toml::Value = toml::from_str("[security]\nrequire_signatures = false\n").unwrap();
    let workspace: toml::Value = toml::from_str("[http]\ndefault_timeout_secs = 600\n").unwrap();
    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);
    assert!(
        merged.as_table().unwrap().get("http").is_none(),
        "workspace must not introduce an [http] section"
    );
}

#[test]
fn test_allow_wasm_hooks_cannot_enable() {
    let baseline: toml::Value = toml::from_str(
        r"
        [hooks]
        allow_wasm_hooks = false
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [hooks]
        allow_wasm_hooks = true
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert!(!merged["hooks"]["allow_wasm_hooks"].as_bool().unwrap());
}

#[test]
fn test_allow_agent_hooks_cannot_enable() {
    let baseline: toml::Value = toml::from_str(
        r"
        [hooks]
        allow_agent_hooks = false
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [hooks]
        allow_agent_hooks = true
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert!(!merged["hooks"]["allow_agent_hooks"].as_bool().unwrap());
}

#[test]
fn test_rate_limits_cannot_increase() {
    let baseline: toml::Value = toml::from_str(
        r"
        [rate_limits]
        elicitation_per_server_per_min = 10
        max_pending_requests = 50
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [rate_limits]
        elicitation_per_server_per_min = 100
        max_pending_requests = 500
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(
        merged["rate_limits"]["elicitation_per_server_per_min"]
            .as_integer()
            .unwrap(),
        10
    );
    assert_eq!(
        merged["rate_limits"]["max_pending_requests"]
            .as_integer()
            .unwrap(),
        50
    );
}

#[test]
fn test_warn_at_percent_cannot_increase() {
    let baseline: toml::Value = toml::from_str(
        r"
        [budget]
        warn_at_percent = 80
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [budget]
        warn_at_percent = 99
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(
        merged["budget"]["warn_at_percent"].as_integer().unwrap(),
        80
    );
}

// ---- Step 4: Workspace server injection ----

#[test]
fn test_workspace_server_forced_untrusted() {
    let baseline: toml::Value = toml::from_str("[servers]").unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [servers.evil]
        command = "evil-server"
        trusted = true
        auto_start = true
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let evil = &merged["servers"]["evil"];
    assert!(!evil["trusted"].as_bool().unwrap());
}

#[test]
fn test_workspace_server_forced_no_autostart() {
    let baseline: toml::Value = toml::from_str("[servers]").unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [servers.evil]
        command = "evil-server"
        trusted = false
        auto_start = true
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let evil = &merged["servers"]["evil"];
    assert!(!evil["auto_start"].as_bool().unwrap());
}

#[test]
fn test_existing_server_keeps_trusted() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [servers.mydb]
        command = "db-server"
        trusted = true
        auto_start = true
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [servers.mydb]
        args = ["--verbose"]
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let mydb = &merged["servers"]["mydb"];
    assert!(mydb["trusted"].as_bool().unwrap());
    assert!(mydb["auto_start"].as_bool().unwrap());
}

// ---- A1: Workspace cannot change security-critical fields on baseline servers ----

#[test]
fn test_workspace_cannot_change_baseline_server_command() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [servers.mydb]
        command = "safe-server"
        trusted = true
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [servers.mydb]
        command = "evil-server"
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let mydb = &merged["servers"]["mydb"];
    assert_eq!(mydb["command"].as_str().unwrap(), "safe-server");
    assert!(mydb["trusted"].as_bool().unwrap());
}

#[test]
fn test_workspace_cannot_change_baseline_server_args() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [servers.mydb]
        command = "safe-server"
        args = ["--safe"]
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [servers.mydb]
        args = ["--evil-flag"]
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let mydb = &merged["servers"]["mydb"];
    let args = mydb["args"].as_array().unwrap();
    assert_eq!(args[0].as_str().unwrap(), "--safe");
}

#[test]
fn test_workspace_cannot_change_baseline_server_trusted() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [servers.mydb]
        command = "safe-server"
        trusted = false
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [servers.mydb]
        trusted = true
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let mydb = &merged["servers"]["mydb"];
    assert!(!mydb["trusted"].as_bool().unwrap());
}

#[test]
fn test_workspace_can_add_non_protected_fields_to_baseline_server() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [servers.mydb]
        command = "safe-server"
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [servers.mydb]
        auto_start = true
        transport = "stdio"
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let mydb = &merged["servers"]["mydb"];
    // Non-protected fields should be allowed
    assert_eq!(mydb["transport"].as_str().unwrap(), "stdio");
    // auto_start is not in the protected list for baseline servers
    assert!(mydb["auto_start"].as_bool().unwrap());
}

// ---- A2: auto_allow_read/write cannot expand beyond baseline ----

#[test]
fn test_auto_allow_write_cannot_expand() {
    let baseline: toml::Value = toml::from_str(
        r"
        [workspace]
        auto_allow_write = []
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [workspace]
        auto_allow_write = ["/**"]
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let arr = merged["workspace"]["auto_allow_write"].as_array().unwrap();
    assert!(arr.is_empty());
}

#[test]
fn test_auto_allow_read_cannot_expand() {
    let baseline: toml::Value = toml::from_str(
        r#"
        [workspace]
        auto_allow_read = ["/usr/share"]
    "#,
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r#"
        [workspace]
        auto_allow_read = ["/usr/share", "/etc/secrets"]
    "#,
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    let arr = merged["workspace"]["auto_allow_read"].as_array().unwrap();
    let strs: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
    assert!(strs.contains(&"/usr/share"));
    assert!(!strs.contains(&"/etc/secrets"));
}

// ---- idle_secs, allow_http_hooks, allow_command_hooks restrictions ----

#[test]
fn test_idle_secs_cannot_increase() {
    let baseline: toml::Value = toml::from_str(
        r"
        [timeouts]
        idle_secs = 3600
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [timeouts]
        idle_secs = 86400
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(merged["timeouts"]["idle_secs"].as_integer().unwrap(), 3600);
}

#[test]
fn test_idle_secs_can_decrease() {
    let baseline: toml::Value = toml::from_str(
        r"
        [timeouts]
        idle_secs = 3600
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [timeouts]
        idle_secs = 600
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert_eq!(merged["timeouts"]["idle_secs"].as_integer().unwrap(), 600);
}

#[test]
fn test_allow_http_hooks_cannot_enable() {
    let baseline: toml::Value = toml::from_str(
        r"
        [hooks]
        allow_http_hooks = false
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [hooks]
        allow_http_hooks = true
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert!(!merged["hooks"]["allow_http_hooks"].as_bool().unwrap());
}

#[test]
fn test_allow_command_hooks_cannot_enable() {
    let baseline: toml::Value = toml::from_str(
        r"
        [hooks]
        allow_command_hooks = false
    ",
    )
    .unwrap();

    let workspace: toml::Value = toml::from_str(
        r"
        [hooks]
        allow_command_hooks = true
    ",
    )
    .unwrap();

    let mut merged = baseline.clone();
    deep_merge(&mut merged, &workspace);
    enforce_restrictions(&mut merged, &baseline, &workspace);

    assert!(!merged["hooks"]["allow_command_hooks"].as_bool().unwrap());
}

// ---- Step 7: Robustness ----

#[test]
fn test_set_nested_no_panic_on_missing_table() {
    let mut val: toml::Value = toml::from_str("[model]\nprovider = \"unknown\"").unwrap();
    // This should not panic — the intermediate "nonexistent" table is missing.
    set_nested(
        &mut val,
        &["nonexistent", "field"],
        toml::Value::Boolean(true),
    );
    // Value should be unchanged.
    assert_eq!(val["model"]["provider"].as_str().unwrap(), "unknown");
}
