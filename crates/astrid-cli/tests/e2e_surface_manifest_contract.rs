use toml::Value;

const SURFACE_STATUSES: &[&str] = &["covered", "mapped", "waived", "future"];
const CAPABILITY_STATUSES: &[&str] = &["covered", "mapped", "waived"];
const CLI_MODES: &[&str] = &[
    "bounded_failure",
    "capsule_dynamic",
    "deferred",
    "filesystem",
    "host_mutating",
    "interactive",
    "interactive_editor",
    "long_running",
    "mutating",
    "network",
    "network_or_local",
    "process",
    "prompt",
    "read",
];
const CLI_PRINCIPALS: &[&str] = &[
    "admin",
    "admin_and_agent",
    "admin_and_ops",
    "agent",
    "agent_and_admin",
    "local_cli",
    "new_principal",
];
const HTTP_AUTH_MODES: &[&str] = &["bearer", "public", "public_token"];

#[test]
fn cli_manifest_rows_have_valid_contract_fields() {
    let entries = manifest_table(
        include_str!("../../../e2e/cli-scenarios.toml"),
        "commands",
        "cli-scenarios.toml",
    );

    for (name, entry) in &entries {
        let table = entry_table(name, entry, "cli-scenarios.toml");
        assert_non_empty_string(name, table, "scenario");
        let status = assert_known_value(name, table, "status", SURFACE_STATUSES);
        assert_known_value(name, table, "mode", CLI_MODES);
        assert_known_value(name, table, "principal", CLI_PRINCIPALS);
        assert_reason_for_deferred_status(name, table, status);
    }
}

#[test]
fn http_manifest_rows_have_valid_contract_fields() {
    let entries = manifest_table(
        include_str!("../../../e2e/http-scenarios.toml"),
        "routes",
        "http-scenarios.toml",
    );

    for (name, entry) in &entries {
        let table = entry_table(name, entry, "http-scenarios.toml");
        assert_non_empty_string(name, table, "scenario");
        let status = assert_known_value(name, table, "status", SURFACE_STATUSES);
        assert_known_value(name, table, "auth", HTTP_AUTH_MODES);
        assert_reason_for_deferred_status(name, table, status);
    }
}

#[test]
fn first_party_capsule_manifest_rows_have_valid_contract_fields() {
    let entries = manifest_table(
        include_str!("../../../e2e/first-party-capsule-scenarios.toml"),
        "capsule_commands",
        "first-party-capsule-scenarios.toml",
    );

    for (name, entry) in &entries {
        let table = entry_table(name, entry, "first-party-capsule-scenarios.toml");
        assert_non_empty_string(name, table, "scenario");
        let status = assert_known_value(name, table, "status", SURFACE_STATUSES);
        let provider = assert_non_empty_string(name, table, "provider");
        assert_non_empty_string(name, table, "reason");
        if provider == "unassigned" {
            assert!(
                matches!(status, "waived" | "future"),
                "capsule command {name:?} may use provider \"unassigned\" only for waived or future work"
            );
        }
    }
}

#[test]
fn capability_manifest_rows_have_valid_contract_fields() {
    let entries = manifest_table(
        include_str!("../../../e2e/capability-scenarios.toml"),
        "capabilities",
        "capability-scenarios.toml",
    );

    for (name, entry) in &entries {
        let table = entry_table(name, entry, "capability-scenarios.toml");
        assert_non_empty_string(name, table, "scenario");
        let status = assert_known_value(name, table, "status", CAPABILITY_STATUSES);
        match status {
            "covered" | "mapped" => {
                assert_non_empty_string_array(name, table, "allow");
                assert_non_empty_string_array(name, table, "deny");
                assert_absent_or_empty(name, table, "waiver");
            },
            "waived" => {
                assert_non_empty_string(name, table, "waiver");
                assert_absent_or_empty(name, table, "allow");
                assert_absent_or_empty(name, table, "deny");
            },
            _ => unreachable!(),
        }
    }
}

fn manifest_table(src: &'static str, table: &str, manifest: &str) -> toml::value::Table {
    let parsed: Value = toml::from_str(src).unwrap_or_else(|error| {
        panic!("{manifest} parses: {error}");
    });
    parsed
        .get(table)
        .and_then(Value::as_table)
        .unwrap_or_else(|| panic!("{manifest} must contain [{table}]"))
        .clone()
}

fn entry_table<'a>(name: &str, entry: &'a Value, manifest: &str) -> &'a toml::value::Table {
    entry
        .as_table()
        .unwrap_or_else(|| panic!("{manifest} entry {name:?} must be a table"))
}

fn assert_known_value<'a>(
    name: &str,
    table: &'a toml::value::Table,
    field: &str,
    valid: &[&str],
) -> &'a str {
    let value = assert_non_empty_string(name, table, field);
    assert!(
        valid.contains(&value),
        "manifest entry {name:?} has invalid {field:?} value {value:?}"
    );
    value
}

fn assert_non_empty_string<'a>(name: &str, table: &'a toml::value::Table, field: &str) -> &'a str {
    let value = table
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("manifest entry {name:?} needs string field {field:?}"));
    assert!(
        !value.trim().is_empty(),
        "manifest entry {name:?} needs non-empty {field:?}"
    );
    value
}

fn assert_non_empty_string_array(name: &str, table: &toml::value::Table, field: &str) {
    let values = table
        .get(field)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("manifest entry {name:?} needs array field {field:?}"));
    assert!(
        !values.is_empty(),
        "manifest entry {name:?} needs non-empty {field:?}"
    );
    for value in values {
        let Some(item) = value.as_str() else {
            panic!("manifest entry {name:?} has non-string {field:?} item");
        };
        assert!(
            !item.trim().is_empty(),
            "manifest entry {name:?} has empty {field:?} item"
        );
    }
}

fn assert_reason_for_deferred_status(name: &str, table: &toml::value::Table, status: &str) {
    if matches!(status, "waived" | "future") {
        assert_non_empty_string(name, table, "reason");
    }
}

fn assert_absent_or_empty(name: &str, table: &toml::value::Table, field: &str) {
    match table.get(field) {
        None => {},
        Some(Value::Array(values)) if values.is_empty() => {},
        Some(Value::String(value)) if value.trim().is_empty() => {},
        Some(_) => panic!("manifest entry {name:?} must not carry non-empty {field:?}"),
    }
}
