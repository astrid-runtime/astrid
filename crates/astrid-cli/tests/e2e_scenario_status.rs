use std::collections::BTreeMap;

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

fn format_references(refs: &[ScenarioReference]) -> String {
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

fn non_empty_field(table: &toml::value::Table, field: &str) -> bool {
    match table.get(field) {
        Some(toml::Value::String(value)) => !value.trim().is_empty(),
        Some(toml::Value::Array(items)) => !items.is_empty(),
        _ => false,
    }
}
