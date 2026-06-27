//! Drift checks for `astrid_core::capability_grammar::CAPABILITY_CATALOG`.
//!
//! The structured catalog is what the HTTP gateway returns from
//! `/api/sys/capabilities`. If a new capability lands in
//! `required_capability` or `required_capability_for_admin_request`
//! without being added to the catalog, the gateway silently omits
//! it from discovery — breaking dashboards that build cap-grant UI
//! from the list. These tests enumerate every string returned by
//! both match tables (across both [`AuthorityScope`] variants) and
//! assert each appears in the catalog.

use astrid_core::PrincipalId;
use astrid_core::capability_grammar::known_capabilities;
use astrid_core::kernel_api::{AdminRequestKind, KernelRequest};
use astrid_core::profile::Quotas;
use std::collections::BTreeSet;

use crate::kernel_router::admin::required_capability_for_admin_request;
use crate::kernel_router::{AuthorityScope, required_capability};

/// Mirror of `tests::all_request_variants` from the parent module —
/// duplicated here because the parent's helper lives inside a
/// `#[cfg(test)] mod tests` block and isn't visible to sibling test
/// modules. Adding a `KernelRequest` variant requires updating both
/// lists; the size is small enough that the duplication beats
/// plumbing visibility through.
fn all_kernel_request_variants() -> Vec<KernelRequest> {
    vec![
        KernelRequest::Shutdown { reason: None },
        KernelRequest::GetStatus,
        KernelRequest::ReloadCapsules,
        KernelRequest::ReloadCapsule {
            id: "x".to_string(),
        },
        KernelRequest::UnloadCapsule {
            id: "x".to_string(),
        },
        KernelRequest::InstallCapsule {
            source: "x".to_string(),
            workspace: false,
        },
        KernelRequest::ListCapsules,
        KernelRequest::GetCommands,
        KernelRequest::GetCapsuleMetadata,
        KernelRequest::ApproveCapability {
            request_id: "r".to_string(),
            signature: "s".to_string(),
        },
    ]
}

#[test]
fn known_capabilities_covers_every_kernel_request_cap() {
    let scopes = [AuthorityScope::Self_, AuthorityScope::Global];
    for req in all_kernel_request_variants() {
        for scope in scopes {
            let cap = required_capability(&req, scope);
            assert!(
                known_capabilities().any(|c| c == cap),
                "kernel returns capability {cap:?} not in \
                 astrid_core::capability_grammar::CAPABILITY_CATALOG — \
                 update the catalog when adding a capability"
            );
        }
    }
}

fn all_admin_request_variants() -> Vec<AdminRequestKind> {
    let p = PrincipalId::default();
    vec![
        AdminRequestKind::AgentCreate {
            name: "alice".into(),
            groups: vec![],
            grants: vec![],
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
        AdminRequestKind::AgentDelete {
            principal: p.clone(),
        },
        AdminRequestKind::AgentEnable {
            principal: p.clone(),
        },
        AdminRequestKind::AgentDisable {
            principal: p.clone(),
        },
        AdminRequestKind::AgentModify {
            principal: p.clone(),
            add_groups: vec![],
            remove_groups: vec![],
            add_capsules: vec![],
            remove_capsules: vec![],
        },
        AdminRequestKind::AgentList,
        AdminRequestKind::QuotaSet {
            principal: p.clone(),
            quotas: Quotas::default(),
        },
        AdminRequestKind::QuotaGet {
            principal: p.clone(),
        },
        AdminRequestKind::GroupCreate {
            name: "g".into(),
            capabilities: vec![],
            description: None,
            unsafe_admin: false,
        },
        AdminRequestKind::GroupDelete { name: "g".into() },
        AdminRequestKind::GroupModify {
            name: "g".into(),
            capabilities: None,
            description: None,
            unsafe_admin: None,
        },
        AdminRequestKind::GroupList,
        AdminRequestKind::CapsGrant {
            principal: p.clone(),
            capabilities: vec![],
            unsafe_admin: false,
        },
        AdminRequestKind::CapsRevoke {
            principal: p.clone(),
            capabilities: vec![],
        },
        AdminRequestKind::CapsTokenMint {
            principal: p.clone(),
            resource: "mcp://server:tool".into(),
            permission: None,
            ttl_secs: None,
        },
        AdminRequestKind::CapsTokenRevoke {
            token_id: "00000000-0000-0000-0000-000000000000".into(),
        },
        AdminRequestKind::CapsTokenList {
            principal: p.clone(),
        },
        AdminRequestKind::InviteIssue {
            group: "agent".into(),
            expires_secs: None,
            max_uses: 1,
            metadata: None,
        },
        AdminRequestKind::InviteRedeem {
            token: "x".into(),
            public_key: String::new(),
            display_name: None,
        },
        AdminRequestKind::InviteList,
        AdminRequestKind::InviteRevoke { token: "x".into() },
        AdminRequestKind::PairDeviceIssue {
            expires_secs: None,
            label: None,
            scope: astrid_core::kernel_api::PairScopeArg::Full,
        },
        AdminRequestKind::PairDeviceRedeem {
            token: "x".into(),
            public_key: String::new(),
        },
        AdminRequestKind::PairDeviceList {
            principal: p.clone(),
        },
        AdminRequestKind::PairDeviceRevoke {
            principal: p,
            key_id: "k".into(),
        },
    ]
}

#[test]
fn known_capabilities_covers_every_admin_request_cap() {
    let scopes = [AuthorityScope::Self_, AuthorityScope::Global];
    for req in &all_admin_request_variants() {
        for scope in scopes {
            let cap = required_capability_for_admin_request(req, scope);
            assert!(
                known_capabilities().any(|c| c == cap),
                "admin op returns capability {cap:?} not in \
                 astrid_core::capability_grammar::CAPABILITY_CATALOG — \
                 update the catalog when adding a capability"
            );
        }
    }
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
        assert_scenario_contract(id, scenario, &specs, "capability");

        let status = table
            .get("status")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        match status {
            "covered" | "mapped" => {
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

fn assert_scenario_contract(id: &str, scenario: &str, specs: &toml::Value, surface: &str) {
    let scenarios = specs
        .get("scenarios")
        .and_then(toml::Value::as_table)
        .expect("runtime specs already validated");
    let spec = scenarios
        .get(scenario)
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("capability {id} references unknown scenario {scenario:?}"));
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
