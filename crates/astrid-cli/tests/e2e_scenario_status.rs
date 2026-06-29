use std::collections::{BTreeMap, BTreeSet};

const REQUIRED_SCENARIO_FIELDS: &[&str] = &[
    "status", "surfaces", "auth", "success", "denial", "state", "evidence",
];

const VALID_SCENARIO_STATUSES: &[&str] = &["covered", "mapped", "waived"];
const VALID_SURFACES: &[&str] = &["capability", "capsule", "cli", "http"];

#[test]
fn mapped_runtime_scenarios_have_mapped_surface_work() {
    let scenario_src = include_str!("../../../e2e/runtime-scenario-specs.toml");
    let mut references = BTreeMap::<String, Vec<ScenarioReference>>::new();

    collect_references(
        &mut references,
        include_str!("../../../e2e/cli-scenarios.toml"),
        "commands",
        "cli-scenarios.toml",
    );
    collect_references(
        &mut references,
        include_str!("../../../e2e/http-scenarios.toml"),
        "routes",
        "http-scenarios.toml",
    );
    collect_references(
        &mut references,
        include_str!("../../../e2e/first-party-capsule-scenarios.toml"),
        "capsule_commands",
        "first-party-capsule-scenarios.toml",
    );
    collect_references(
        &mut references,
        include_str!("../../../e2e/capability-scenarios.toml"),
        "capabilities",
        "capability-scenarios.toml",
    );

    let parsed: toml::Value =
        toml::from_str(scenario_src).expect("runtime-scenario-specs.toml parses");
    let scenarios = parsed
        .get("scenarios")
        .and_then(toml::Value::as_table)
        .expect("runtime-scenario-specs.toml must contain [scenarios]");

    let stale: Vec<_> = scenarios
        .iter()
        .filter_map(|(scenario, entry)| {
            let table = entry
                .as_table()
                .unwrap_or_else(|| panic!("runtime scenario {scenario:?} must be a table"));
            let status = table
                .get("status")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            if status != "mapped" {
                return None;
            }

            let refs = references.get(scenario)?;
            if refs.iter().any(|reference| reference.status == "mapped")
                || non_empty_field(table, "remaining")
            {
                return None;
            }

            Some(format!("{scenario}: {}", format_references(refs)))
        })
        .collect();

    assert!(
        stale.is_empty(),
        "runtime scenarios marked mapped but with no mapped surface work or remaining-work note:\n{}",
        stale.join("\n")
    );
}

#[test]
fn covered_runtime_scenarios_have_only_covered_surface_rows() {
    let scenario_src = include_str!("../../../e2e/runtime-scenario-specs.toml");
    let mut references = BTreeMap::<String, Vec<ScenarioReference>>::new();
    collect_all_references(&mut references);

    let parsed: toml::Value =
        toml::from_str(scenario_src).expect("runtime-scenario-specs.toml parses");
    let scenarios = runtime_scenarios(&parsed);

    let overstated: Vec<_> = scenarios
        .iter()
        .filter_map(|(scenario, entry)| {
            let table = entry
                .as_table()
                .unwrap_or_else(|| panic!("runtime scenario {scenario:?} must be a table"));
            let status = table
                .get("status")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            if status != "covered" {
                return None;
            }
            let refs = references.get(scenario)?;
            let unfinished: Vec<_> = refs
                .iter()
                .filter(|reference| matches!(reference.status.as_str(), "mapped" | "future"))
                .collect();
            if unfinished.is_empty() {
                return None;
            }
            Some(format!(
                "{scenario}: {}",
                format_references_refs(&unfinished)
            ))
        })
        .collect();

    assert!(
        overstated.is_empty(),
        "runtime scenarios marked covered but referenced by mapped/future surface rows:\n{}",
        overstated.join("\n")
    );
}

#[test]
fn runtime_scenarios_are_executable_contracts() {
    let scenario_src = include_str!("../../../e2e/runtime-scenario-specs.toml");
    let parsed: toml::Value =
        toml::from_str(scenario_src).expect("runtime-scenario-specs.toml parses");
    let scenarios = runtime_scenarios(&parsed);

    let duplicate_keys = duplicate_scenario_keys(scenario_src);
    assert!(
        duplicate_keys.is_empty(),
        "runtime scenario specs contain duplicate keys:\n{}",
        duplicate_keys.join("\n")
    );

    for (scenario, entry) in scenarios {
        let table = entry
            .as_table()
            .unwrap_or_else(|| panic!("runtime scenario {scenario:?} must be a table"));
        for field in REQUIRED_SCENARIO_FIELDS {
            assert!(
                non_empty_field(table, field),
                "runtime scenario {scenario:?} needs non-empty {field:?}"
            );
        }

        let status = string_field(table, "status", scenario);
        assert!(
            VALID_SCENARIO_STATUSES.contains(&status),
            "runtime scenario {scenario:?} has invalid status {status:?}"
        );

        let surfaces = string_array_field(table, "surfaces", scenario);
        for surface in surfaces {
            assert!(
                VALID_SURFACES.contains(&surface),
                "runtime scenario {scenario:?} has invalid surface {surface:?}"
            );
        }

        match status {
            "covered" => {
                assert!(
                    !non_empty_field(table, "remaining"),
                    "covered runtime scenario {scenario:?} must not carry remaining work"
                );
            },
            "mapped" => {
                assert!(
                    non_empty_field(table, "remaining"),
                    "mapped runtime scenario {scenario:?} needs explicit remaining work"
                );
            },
            "waived" => {
                assert!(
                    non_empty_field(table, "waiver"),
                    "waived runtime scenario {scenario:?} needs an explicit waiver"
                );
            },
            _ => unreachable!(),
        }
    }
}

#[test]
fn surface_manifests_reference_declared_runtime_scenarios() {
    let scenario_src = include_str!("../../../e2e/runtime-scenario-specs.toml");
    let parsed: toml::Value =
        toml::from_str(scenario_src).expect("runtime-scenario-specs.toml parses");
    let declared: BTreeSet<_> = runtime_scenarios(&parsed).keys().cloned().collect();
    let mut references = BTreeMap::<String, Vec<ScenarioReference>>::new();

    collect_all_references(&mut references);

    let missing: Vec<_> = references
        .iter()
        .filter(|(scenario, _)| !declared.contains(*scenario))
        .map(|(scenario, refs)| format!("{scenario}: {}", format_references(refs)))
        .collect();

    assert!(
        missing.is_empty(),
        "surface manifests reference undeclared runtime scenarios:\n{}",
        missing.join("\n")
    );
}

#[test]
fn bearer_only_approval_responses_do_not_claim_static_capability_coverage() {
    let http_src = include_str!("../../../e2e/http-scenarios.toml");
    let http: toml::Value = toml::from_str(http_src).expect("http-scenarios.toml parses");
    let routes = http
        .get("routes")
        .and_then(toml::Value::as_table)
        .expect("http-scenarios.toml must contain [routes]");

    for route in [
        "POST /api/agent/approval-response",
        "POST /api/agent/elicit-response",
    ] {
        let auth = routes
            .get(route)
            .and_then(toml::Value::as_table)
            .and_then(|table| table.get("auth"))
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("HTTP route {route:?} needs auth"));
        assert_eq!(
            auth, "bearer",
            "HTTP route {route:?} changed auth; revisit self:approval:respond coverage"
        );
    }

    let capabilities_src = include_str!("../../../e2e/capability-scenarios.toml");
    let capabilities: toml::Value =
        toml::from_str(capabilities_src).expect("capability-scenarios.toml parses");
    let status = capabilities
        .get("capabilities")
        .and_then(toml::Value::as_table)
        .and_then(|capabilities| capabilities.get("self:approval:respond"))
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("status"))
        .and_then(toml::Value::as_str)
        .expect("self:approval:respond capability row needs status");

    assert_eq!(
        status, "waived",
        "bearer-only approval response routes must not be counted as static self:approval:respond coverage"
    );
}

#[derive(Debug)]
struct ScenarioReference {
    manifest: &'static str,
    name: String,
    status: String,
}

fn collect_references(
    references: &mut BTreeMap<String, Vec<ScenarioReference>>,
    src: &'static str,
    table_name: &str,
    manifest: &'static str,
) {
    let parsed: toml::Value = toml::from_str(src).unwrap_or_else(|error| {
        panic!("{manifest} parses: {error}");
    });
    let entries = parsed
        .get(table_name)
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("{manifest} must contain [{table_name}]"));

    for (name, entry) in entries {
        let table = entry
            .as_table()
            .unwrap_or_else(|| panic!("{manifest} entry {name:?} must be a table"));
        let scenario = table
            .get("scenario")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("{manifest} entry {name:?} needs a scenario"));
        let status = table
            .get("status")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("{manifest} entry {name:?} needs a status"));
        references
            .entry(scenario.to_string())
            .or_default()
            .push(ScenarioReference {
                manifest,
                name: name.clone(),
                status: status.to_string(),
            });
    }
}

fn collect_all_references(references: &mut BTreeMap<String, Vec<ScenarioReference>>) {
    collect_references(
        references,
        include_str!("../../../e2e/cli-scenarios.toml"),
        "commands",
        "cli-scenarios.toml",
    );
    collect_references(
        references,
        include_str!("../../../e2e/http-scenarios.toml"),
        "routes",
        "http-scenarios.toml",
    );
    collect_references(
        references,
        include_str!("../../../e2e/first-party-capsule-scenarios.toml"),
        "capsule_commands",
        "first-party-capsule-scenarios.toml",
    );
    collect_references(
        references,
        include_str!("../../../e2e/capability-scenarios.toml"),
        "capabilities",
        "capability-scenarios.toml",
    );
}

fn format_references(refs: &[ScenarioReference]) -> String {
    format_references_refs(&refs.iter().collect::<Vec<_>>())
}

fn format_references_refs(refs: &[&ScenarioReference]) -> String {
    refs.iter()
        .map(|reference| {
            format!(
                "{}:{}={}",
                reference.manifest, reference.name, reference.status
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn runtime_scenarios(parsed: &toml::Value) -> &toml::value::Table {
    parsed
        .get("scenarios")
        .and_then(toml::Value::as_table)
        .expect("runtime-scenario-specs.toml must contain [scenarios]")
}

fn string_field<'a>(table: &'a toml::value::Table, field: &str, scenario: &str) -> &'a str {
    table
        .get(field)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("runtime scenario {scenario:?} needs string {field:?}"))
}

fn string_array_field<'a>(
    table: &'a toml::value::Table,
    field: &str,
    scenario: &str,
) -> Vec<&'a str> {
    table
        .get(field)
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("runtime scenario {scenario:?} needs array {field:?}"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("runtime scenario {scenario:?} has non-string {field:?}"))
        })
        .collect()
}

fn non_empty_field(table: &toml::value::Table, field: &str) -> bool {
    match table.get(field) {
        Some(toml::Value::String(value)) => !value.trim().is_empty(),
        Some(toml::Value::Array(items)) => items.iter().any(|item| match item {
            toml::Value::String(value) => !value.trim().is_empty(),
            _ => true,
        }),
        _ => false,
    }
}

fn duplicate_scenario_keys(src: &str) -> Vec<String> {
    let mut table = String::new();
    let mut seen = BTreeMap::<String, BTreeSet<String>>::new();
    let mut duplicates = Vec::new();

    for (index, raw_line) in src.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(name) = line
            .strip_prefix("[scenarios.")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            table = name.to_string();
            continue;
        }

        if table.is_empty() || line.starts_with('[') {
            continue;
        }

        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_string();
        let inserted = seen.entry(table.clone()).or_default().insert(key.clone());
        if !inserted {
            let line_number = index.checked_add(1).expect("line number does not overflow");
            duplicates.push(format!("line {line_number}: scenarios.{table}.{key}"));
        }
    }

    duplicates
}
