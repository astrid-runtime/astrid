//! Drift checks for enforcement capability mappings and registry definitions.

use astrid_core::capability_grammar::known_capabilities;
use astrid_core::capability_registry::capability_registry_revision_1;
use std::collections::BTreeSet;

use crate::kernel_router::admin::required_capability_for_admin_request;
use crate::kernel_router::test_util::{all_admin_request_variants, all_kernel_request_variants};
use crate::kernel_router::{AuthorityScope, required_capability};

#[test]
fn registry_revision_1_covers_every_kernel_request_cap() {
    let registry = capability_registry_revision_1().unwrap();
    let registered = registry
        .entries()
        .iter()
        .map(|entry| entry.id().as_str())
        .collect::<BTreeSet<_>>();
    let scopes = [AuthorityScope::Self_, AuthorityScope::Global];
    for req in all_kernel_request_variants() {
        for scope in scopes {
            let cap = required_capability(&req, scope);
            assert!(
                registered.contains(cap),
                "kernel returns capability {cap:?} without a registry revision 1 entry"
            );
        }
    }
}

#[test]
fn registry_revision_1_covers_every_admin_request_cap() {
    let registry = capability_registry_revision_1().unwrap();
    let registered = registry
        .entries()
        .iter()
        .map(|entry| entry.id().as_str())
        .collect::<BTreeSet<_>>();
    let scopes = [AuthorityScope::Self_, AuthorityScope::Global];
    for req in &all_admin_request_variants() {
        for scope in scopes {
            let cap = required_capability_for_admin_request(req, scope);
            assert!(
                registered.contains(cap),
                "admin op returns capability {cap:?} without a registry revision 1 entry"
            );
        }
    }
}

#[test]
fn registry_revision_1_freezes_the_complete_role_partition() {
    let primary = BTreeSet::from([
        "system:shutdown",
        "system:status",
        "capsule:install",
        "self:capsule:install",
        "capsule:reload",
        "self:capsule:reload",
        "self:capsule:remove",
        "self:workspace:promote",
        "self:workspace:rollback",
        "self:capsule:list",
        "agent:create",
        "agent:create:inherit",
        "agent:create:clone",
        "agent:delete",
        "agent:enable",
        "agent:disable",
        "agent:modify",
        "self:agent:list",
        "quota:set",
        "self:quota:set",
        "quota:get",
        "self:quota:get",
        "group:create",
        "group:delete",
        "group:modify",
        "self:group:list",
        "caps:grant",
        "caps:revoke",
        "caps:token:mint",
        "caps:token:revoke",
        "caps:token:list",
        "invite:issue",
        "invite:list",
        "invite:revoke",
        "self:approval:respond",
        "self:auth:pair",
        "auth:pair",
    ]);
    let secondary = BTreeSet::from([
        "capsule:list",
        "agent:list",
        "group:list",
        "audit:read_all",
        "self:auth:pair:admin",
        "system:resources:unbounded",
        "net_bind",
        "uplink",
        "capsule:access:any",
    ]);
    let token_authenticated = BTreeSet::from(["invite:redeem", "auth:pair:redeem"]);
    let dormant = BTreeSet::from(["authority:profile:manage", "authority:repair"]);
    let mapping_only = BTreeSet::from(["capsule:remove"]);

    let classes = [
        &primary,
        &secondary,
        &token_authenticated,
        &dormant,
        &mapping_only,
    ];
    for (index, class) in classes.iter().enumerate() {
        for other in classes.iter().skip(index + 1) {
            assert!(
                class.is_disjoint(other),
                "baseline enforcement classes overlap: {:?}",
                class.intersection(other).collect::<Vec<_>>()
            );
        }
    }

    let classified = classes
        .into_iter()
        .flat_map(|class| class.iter().copied())
        .collect::<BTreeSet<_>>();
    let revision = capability_registry_revision_1().unwrap();
    let revision_ids = revision
        .entries()
        .iter()
        .map(|entry| entry.id().as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(classified, revision_ids);
}

#[test]
fn e2e_capability_manifest_covers_catalog() {
    let manifest: toml::Value =
        toml::from_str(include_str!("../../../../e2e/capability-scenarios.toml"))
            .expect("capability e2e manifest parses");
    let specs =
        parse_runtime_scenario_specs(include_str!("../../../../e2e/runtime-scenario-specs.toml"));
    let capabilities = manifest
        .get("capabilities")
        .and_then(toml::Value::as_table)
        .expect("manifest has [capabilities]");

    let catalog: BTreeSet<&'static str> = known_capabilities().collect();
    let manifest_ids: BTreeSet<&str> = capabilities.keys().map(String::as_str).collect();

    let missing: Vec<&str> = catalog.difference(&manifest_ids).copied().collect();
    assert!(
        missing.is_empty(),
        "new capability id has no e2e scenario mapping: {}",
        missing.join(", ")
    );

    let stale: Vec<&str> = manifest_ids.difference(&catalog).copied().collect();
    assert!(
        stale.is_empty(),
        "capability e2e manifest references unknown ids: {}",
        stale.join(", ")
    );

    for (id, entry) in capabilities {
        let table = entry
            .as_table()
            .unwrap_or_else(|| panic!("capability {id} must be a table"));
        let scenario = table
            .get("scenario")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        assert!(!scenario.is_empty(), "capability {id} needs a scenario");
        assert_scenario_declared(id, scenario, &specs);

        let status = table
            .get("status")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        match status {
            "covered" | "mapped" => {
                assert_scenario_contract(id, scenario, &specs, "capability");
                let allow = table.get("allow").and_then(toml::Value::as_array);
                let deny = table.get("deny").and_then(toml::Value::as_array);
                assert!(
                    allow.is_some_and(|items| !items.is_empty()),
                    "capability {id} needs an allow expectation"
                );
                assert!(
                    deny.is_some_and(|items| !items.is_empty()),
                    "capability {id} needs a deny expectation"
                );
            },
            "waived" => {
                let waiver = table
                    .get("waiver")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("");
                assert!(!waiver.is_empty(), "waived capability {id} needs a reason");
            },
            other => panic!(
                "capability {id} has invalid status {other:?}; use covered, mapped, or waived"
            ),
        }
    }
}

fn parse_runtime_scenario_specs(src: &str) -> toml::Value {
    let parsed: toml::Value = toml::from_str(src).expect("runtime-scenario-specs.toml parses");
    let scenarios = parsed
        .get("scenarios")
        .and_then(toml::Value::as_table)
        .expect("runtime-scenario-specs.toml must contain a [scenarios] table");

    for (name, entry) in scenarios {
        let table = entry
            .as_table()
            .unwrap_or_else(|| panic!("runtime scenario {name:?} must be a table"));
        for field in [
            "status", "surfaces", "auth", "success", "denial", "state", "evidence",
        ] {
            assert!(
                non_empty_field(table, field),
                "runtime scenario {name:?} is missing non-empty field {field:?}"
            );
        }
        let status = table
            .get("status")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("runtime scenario {name:?} has non-string status"));
        assert!(
            matches!(status, "mapped" | "covered" | "waived" | "future"),
            "runtime scenario {name:?} has invalid status {status:?}"
        );
        if status == "waived" {
            assert!(
                non_empty_field(table, "waiver"),
                "waived runtime scenario {name:?} needs a waiver"
            );
        }
    }

    parsed
}

fn scenario_contract<'a>(
    id: &str,
    scenario: &str,
    specs: &'a toml::Value,
) -> &'a toml::value::Table {
    let scenarios = specs
        .get("scenarios")
        .and_then(toml::Value::as_table)
        .expect("runtime specs already validated");
    scenarios
        .get(scenario)
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("capability {id} references unknown scenario {scenario:?}"))
}

fn assert_scenario_declared(id: &str, scenario: &str, specs: &toml::Value) {
    scenario_contract(id, scenario, specs);
}

fn assert_scenario_contract(id: &str, scenario: &str, specs: &toml::Value, surface: &str) {
    let spec = scenario_contract(id, scenario, specs);
    let surfaces = spec
        .get("surfaces")
        .and_then(toml::Value::as_array)
        .expect("runtime specs already validated");
    assert!(
        surfaces.iter().any(|v| v.as_str() == Some(surface)),
        "capability {id} references scenario {scenario:?}, which does not declare surface {surface:?}"
    );
}

fn non_empty_field(table: &toml::value::Table, field: &str) -> bool {
    match table.get(field) {
        Some(toml::Value::String(s)) => !s.trim().is_empty(),
        Some(toml::Value::Array(items)) => !items.is_empty(),
        _ => false,
    }
}
