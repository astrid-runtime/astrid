//! Layer 6 admin-topic integration tests (issue #672).
//!
//! Exercises the authorization decision surface for every
//! [`AdminKernelRequest`] variant by composing the same building blocks
//! the kernel assembles at runtime:
//!
//! - [`GroupConfig`](astrid_core::GroupConfig) / [`PrincipalProfile`]
//!   / [`CapabilityCheck`](astrid_capabilities::CapabilityCheck)
//! - [`PrincipalProfileCache`](astrid_capsule::profile_cache::PrincipalProfileCache)
//!   with an explicit [`AstridHome`](astrid_core::dirs::AstridHome)
//!   rooted in a tempdir
//! - The pure mapping functions from
//!   [`astrid_kernel::kernel_router::admin`]
//!
//! Stateful handler behaviour (write-lock serialization, `ArcSwap`
//! hot-reload, atomic `groups.toml` / `profile.toml` writes) is covered
//! by the in-crate tests under
//! `crates/astrid-kernel/src/kernel_router/admin/state_tests.rs`, which
//! can construct a test kernel directly. The tests here focus on the
//! wire-format / decision-matrix contract visible from outside the
//! kernel crate.

#![allow(clippy::arithmetic_side_effects, clippy::field_reassign_with_default)]

use astrid_capabilities::{CapabilityCheck, PermissionError};
use astrid_core::kernel_api::{
    AdminKernelRequest, AdminKernelResponse, AdminRequestKind, AdminResponseBody, AgentSummary,
    GroupSummary,
};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::Quotas;
use astrid_core::{GroupConfig, PrincipalProfile};
use astrid_kernel::kernel_router::AuthorityScope;
use astrid_kernel::kernel_router::admin::{
    admin_request_method, admin_target_principal, required_capability_for_admin_request,
    resolve_admin_scope,
};

// ── Fixtures ──────────────────────────────────────────────────────────

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

fn admin_profile() -> PrincipalProfile {
    let mut p = PrincipalProfile::default();
    p.groups = vec!["admin".to_string()];
    p
}

fn agent_profile() -> PrincipalProfile {
    let mut p = PrincipalProfile::default();
    p.groups = vec!["agent".to_string()];
    p
}

fn restricted_profile() -> PrincipalProfile {
    let mut p = PrincipalProfile::default();
    p.groups = vec!["restricted".to_string()];
    p
}

fn all_admin_variants() -> Vec<AdminRequestKind> {
    vec![
        AdminRequestKind::AgentCreate {
            name: "new_agent".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
        AdminRequestKind::AgentDelete {
            principal: pid("target"),
        },
        AdminRequestKind::AgentEnable {
            principal: pid("target"),
        },
        AdminRequestKind::AgentDisable {
            principal: pid("target"),
        },
        AdminRequestKind::AgentList,
        AdminRequestKind::QuotaSet {
            principal: pid("target"),
            quotas: Quotas::default(),
        },
        AdminRequestKind::QuotaGet {
            principal: pid("target"),
        },
        AdminRequestKind::GroupCreate {
            name: "ops".into(),
            capabilities: vec!["capsule:install".into()],
            description: None,
            unsafe_admin: false,
        },
        AdminRequestKind::GroupDelete { name: "ops".into() },
        AdminRequestKind::GroupModify {
            name: "ops".into(),
            capabilities: None,
            description: None,
            unsafe_admin: None,
        },
        AdminRequestKind::GroupList,
        AdminRequestKind::CapsGrant {
            principal: pid("target"),
            capabilities: vec!["self:capsule:install".into()],
            unsafe_admin: false,
        },
        AdminRequestKind::CapsRevoke {
            principal: pid("target"),
            capabilities: vec!["self:*".into()],
        },
    ]
}

fn authorize(
    profile: &PrincipalProfile,
    groups: &GroupConfig,
    caller: &PrincipalId,
    cap: &str,
) -> Result<(), PermissionError> {
    CapabilityCheck::new(profile, groups, caller.clone()).require(cap)
}

// ── Full cross-tenant matrix ─────────────────────────────────────────

#[test]
fn admin_group_passes_every_admin_topic() {
    let groups = GroupConfig::builtin_only();
    let profile = admin_profile();
    let caller = pid("admin_user");

    for req in all_admin_variants() {
        let method = admin_request_method(&req);
        let scope = resolve_admin_scope(&req, &caller);
        let cap = required_capability_for_admin_request(&req, scope);
        authorize(&profile, &groups, &caller, cap)
            .unwrap_or_else(|e| panic!("admin should be allowed {method} ({cap}): {e}"));
    }
}

#[test]
fn agent_group_denies_cross_tenant_admin_topics() {
    let groups = GroupConfig::builtin_only();
    let profile = agent_profile();
    let caller = pid("agent_user");

    for req in all_admin_variants() {
        let method = admin_request_method(&req);
        let scope = resolve_admin_scope(&req, &caller);
        let cap = required_capability_for_admin_request(&req, scope);
        let result = authorize(&profile, &groups, &caller, cap);

        match scope {
            // Self-scoped (QuotaGet/Set with caller == target, AgentList).
            AuthorityScope::Self_ => {
                result.unwrap_or_else(|e| {
                    panic!("agent should be allowed self-scoped {method} ({cap}): {e}");
                });
            },
            AuthorityScope::Global => {
                assert!(
                    result.is_err(),
                    "agent should be denied cross-tenant {method} ({cap})",
                );
            },
        }
    }
}

#[test]
fn restricted_group_denies_everything_without_explicit_grants() {
    let groups = GroupConfig::builtin_only();
    let profile = restricted_profile();
    let caller = pid("restricted_user");

    for req in all_admin_variants() {
        let method = admin_request_method(&req);
        let scope = resolve_admin_scope(&req, &caller);
        let cap = required_capability_for_admin_request(&req, scope);
        assert!(
            authorize(&profile, &groups, &caller, cap).is_err(),
            "restricted should be denied {method} ({cap})",
        );
    }
}

// ── Self-scope resolves from target principal ────────────────────────

#[test]
fn quota_self_scope_requires_caller_equals_target() {
    let caller = pid("alice");

    let self_req = AdminRequestKind::QuotaSet {
        principal: caller.clone(),
        quotas: Quotas::default(),
    };
    assert_eq!(
        required_capability_for_admin_request(&self_req, resolve_admin_scope(&self_req, &caller)),
        "self:quota:set",
    );

    let cross_req = AdminRequestKind::QuotaSet {
        principal: pid("bob"),
        quotas: Quotas::default(),
    };
    assert_eq!(
        required_capability_for_admin_request(&cross_req, resolve_admin_scope(&cross_req, &caller)),
        "quota:set",
    );
}

// ── Agent built-in caps explicitly list self-admin entries ──────────

#[test]
fn agent_builtin_group_exposes_self_quota_get_and_self_agent_list() {
    let groups = GroupConfig::builtin_only();
    let agent = groups.get("agent").expect("agent built-in present");
    assert!(
        agent.capabilities.iter().any(|c| c == "self:quota:get"),
        "agent must carry self:quota:get (issue #672)",
    );
    assert!(
        agent.capabilities.iter().any(|c| c == "self:agent:list"),
        "agent must carry self:agent:list (issue #672)",
    );

    let profile = agent_profile();
    let caller = pid("agent_user");
    authorize(&profile, &groups, &caller, "self:quota:get").unwrap();
    authorize(&profile, &groups, &caller, "self:agent:list").unwrap();
}

// ── Audit method labels ──────────────────────────────────────────────

#[test]
fn admin_request_method_labels_are_namespaced() {
    for req in all_admin_variants() {
        let label = admin_request_method(&req);
        assert!(
            label.starts_with("admin."),
            "method label must start with 'admin.': {label}",
        );
    }
}

#[test]
fn admin_target_principal_matches_wire_shape() {
    // Variants carrying a principal field MUST surface it as the audit
    // target, variants that don't MUST return None.
    assert!(
        admin_target_principal(&AdminRequestKind::CapsGrant {
            principal: pid("alice"),
            capabilities: vec!["self:capsule:install".into()],
            unsafe_admin: false,
        })
        .is_some()
    );
    assert!(admin_target_principal(&AdminRequestKind::AgentList).is_none());
    assert!(admin_target_principal(&AdminRequestKind::GroupList).is_none());
    assert!(
        admin_target_principal(&AdminRequestKind::AgentCreate {
            name: "n".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        })
        .is_none()
    );
}

// ── Wire-format round trips ─────────────────────────────────────────

#[test]
fn admin_kernel_request_roundtrips_through_json_with_request_id() {
    // The wire shape flattens `request_id` next to `method`/`params`:
    // { "request_id": "abc", "method": "CapsGrant", "params": {...} }
    // so clients with multiple in-flight requests can disambiguate
    // responses on the shared response topic.
    let req = AdminKernelRequest::with_request_id(
        "req-abc-123",
        AdminRequestKind::CapsGrant {
            principal: pid("alice"),
            capabilities: vec!["self:capsule:install".into()],
            unsafe_admin: false,
        },
    );
    let v = serde_json::to_value(&req).unwrap();
    assert_eq!(v["request_id"], "req-abc-123");
    assert_eq!(v["method"], "CapsGrant");

    let back: AdminKernelRequest = serde_json::from_value(v).unwrap();
    assert_eq!(back.request_id.as_deref(), Some("req-abc-123"));
    match back.kind {
        AdminRequestKind::CapsGrant {
            principal,
            capabilities,
            unsafe_admin,
        } => {
            assert_eq!(principal, pid("alice"));
            assert_eq!(capabilities, vec!["self:capsule:install".to_string()]);
            assert!(!unsafe_admin);
        },
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn admin_kernel_request_roundtrips_without_request_id() {
    // Single-client deployments may omit request_id entirely. The
    // serialized JSON should not contain the field (skip_serializing_if).
    let req: AdminKernelRequest = AdminRequestKind::AgentList.into();
    let v = serde_json::to_value(&req).unwrap();
    assert!(v.get("request_id").is_none(), "got: {v}");
    assert_eq!(v["method"], "AgentList");

    let back: AdminKernelRequest = serde_json::from_value(v).unwrap();
    assert!(back.request_id.is_none());
    assert!(matches!(back.kind, AdminRequestKind::AgentList));
}

#[test]
fn admin_kernel_response_variants_serialize() {
    let ok = AdminKernelResponse::new(AdminResponseBody::Success(
        serde_json::json!({"status": "ok"}),
    ));
    let v = serde_json::to_value(&ok).unwrap();
    assert_eq!(v["status"], "Success");

    let q = AdminKernelResponse::new(AdminResponseBody::Quotas(Quotas::default()));
    let v = serde_json::to_value(&q).unwrap();
    assert_eq!(v["status"], "Quotas");

    let agents = AdminKernelResponse::new(AdminResponseBody::AgentList(vec![AgentSummary {
        principal: pid("alice"),
        enabled: true,
        groups: vec!["agent".into()],
        grants: Vec::new(),
        revokes: Vec::new(),
    }]));
    let v = serde_json::to_value(&agents).unwrap();
    assert_eq!(v["status"], "AgentList");

    let groups = AdminKernelResponse::new(AdminResponseBody::GroupList(vec![GroupSummary {
        name: "admin".into(),
        capabilities: vec!["*".into()],
        description: Some("admin".into()),
        unsafe_admin: false,
        builtin: true,
    }]));
    let v = serde_json::to_value(&groups).unwrap();
    assert_eq!(v["status"], "GroupList");

    let err = AdminKernelResponse::new(AdminResponseBody::Error("missing capability".into()));
    let v = serde_json::to_value(&err).unwrap();
    assert_eq!(v["status"], "Error");
}

#[test]
fn admin_kernel_response_echoes_request_id() {
    let resp = AdminKernelResponse::for_request(
        Some("req-xyz".into()),
        AdminResponseBody::Success(serde_json::json!({})),
    );
    let v = serde_json::to_value(&resp).unwrap();
    assert_eq!(v["request_id"], "req-xyz");
    assert_eq!(v["status"], "Success");
}

// ── ArcSwap hot-reload viewed from outside the kernel crate ─────────

#[test]
fn arcswap_groupconfig_reload_is_observable_from_subsequent_check() {
    use arc_swap::ArcSwap;
    use astrid_core::groups::{Group, GroupConfig};
    use std::sync::Arc;

    let swap: Arc<ArcSwap<GroupConfig>> =
        Arc::new(ArcSwap::from_pointee(GroupConfig::builtin_only()));
    let mut profile = PrincipalProfile::default();
    profile.groups = vec!["ops".to_string()];
    let caller = pid("ops_user");

    // Pre-swap: unknown group `ops` fails closed.
    assert!(
        authorize(
            &profile,
            swap.load_full().as_ref(),
            &caller,
            "capsule:install"
        )
        .is_err()
    );

    let next = GroupConfig::builtin_only()
        .insert_custom_group(
            "ops".to_string(),
            Group {
                capabilities: vec!["capsule:install".into()],
                description: None,
                unsafe_admin: false,
            },
        )
        .unwrap();
    swap.store(Arc::new(next));

    // Post-swap check sees the new config.
    authorize(
        &profile,
        swap.load_full().as_ref(),
        &caller,
        "capsule:install",
    )
    .unwrap();
}

// ── Revoke precedence: grant-after-revoke does NOT clear the revoke ─

#[test]
fn caps_grant_after_revoke_keeps_revoke_precedence() {
    let groups = GroupConfig::builtin_only();
    let mut profile = admin_profile();
    profile.revokes.push("self:*".into());
    // caps.grant's mutation is `grants.push(cap)` — mimic it.
    profile.grants.push("self:capsule:install".into());

    let caller = pid("admin_user");
    let err = authorize(&profile, &groups, &caller, "self:capsule:install").unwrap_err();
    assert!(
        matches!(err, PermissionError::RevokedCapability { .. }),
        "caps.grant must not silently clear a matching revoke (security invariant): {err:?}",
    );
}

#[test]
fn caps_revoke_on_unheld_capability_is_preemptive() {
    // `caps.revoke` of a cap the principal doesn't hold is not an error —
    // it persists as a pre-emptive deny. A future grant cannot reach it.
    let groups = GroupConfig::builtin_only();
    let mut profile = restricted_profile();
    profile.revokes.push("capsule:install".into());
    profile.grants.push("capsule:install".into());

    let caller = pid("user");
    assert!(
        authorize(&profile, &groups, &caller, "capsule:install").is_err(),
        "pre-emptive revoke must persist and beat a later grant",
    );
}

// ── Built-in group write protection ─────────────────────────────────

#[test]
fn groupconfig_remove_rejects_every_builtin() {
    use astrid_core::groups::GroupConfigError;
    let cfg = GroupConfig::builtin_only();
    for name in ["admin", "agent", "restricted"] {
        let err = cfg.remove_group(name).unwrap_err();
        assert!(
            matches!(err, GroupConfigError::RedefinedBuiltin { .. }),
            "remove_group({name}) must reject with RedefinedBuiltin, got: {err:?}",
        );
    }
}

#[test]
fn groupconfig_modify_rejects_every_builtin() {
    use astrid_core::groups::GroupConfigError;
    let cfg = GroupConfig::builtin_only();
    for name in ["admin", "agent", "restricted"] {
        let err = cfg
            .modify_custom_group(name, Some(vec!["audit:read".into()]), None, None)
            .unwrap_err();
        assert!(
            matches!(err, GroupConfigError::RedefinedBuiltin { .. }),
            "modify_custom_group({name}) must reject with RedefinedBuiltin, got: {err:?}",
        );
    }
}
