//! Unit tests for the Layer 6 admin module (issue #672).
//!
//! Two tiers:
//!
//! 1. **Pure mapping tests** — exhaustiveness of
//!    [`required_capability_for_admin_request`], scope resolution,
//!    audit-method labels, and response-topic construction.
//! 2. **Composition tests** — reassemble the same pieces the runtime
//!    uses ([`GroupConfig`] + [`PrincipalProfile`] +
//!    [`CapabilityCheck`]) and assert the post-condition invariants
//!    (cross-tenant deny for `agent`, `ArcSwap` hot-reload observed by the
//!    next check, cache invalidation reflects on-disk writes,
//!    revoke-precedence preserved across a subsequent grant).

use std::sync::Arc;

use astrid_capabilities::CapabilityCheck;
use astrid_core::principal::PrincipalId;
use astrid_core::{GroupConfig, PrincipalProfile};
use astrid_events::kernel_api::{AdminRequestKind, PairScopeArg};

use super::{
    AuthorityScope, admin_request_method, admin_response_topic, admin_target_principal,
    required_capability_for_admin_request, resolve_admin_scope,
};

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

fn all_admin_variants() -> Vec<AdminRequestKind> {
    vec![
        AdminRequestKind::AgentCreate {
            name: "n".into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
        AdminRequestKind::AgentDelete {
            principal: pid("a"),
        },
        AdminRequestKind::AgentEnable {
            principal: pid("a"),
        },
        AdminRequestKind::AgentDisable {
            principal: pid("a"),
        },
        AdminRequestKind::AgentList,
        AdminRequestKind::QuotaSet {
            principal: pid("a"),
            quotas: astrid_core::profile::Quotas::default(),
        },
        AdminRequestKind::QuotaGet {
            principal: pid("a"),
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
            principal: pid("a"),
            capabilities: vec!["self:capsule:install".into()],
            unsafe_admin: false,
        },
        AdminRequestKind::CapsRevoke {
            principal: pid("a"),
            capabilities: vec!["self:*".into()],
        },
        AdminRequestKind::CapsTokenMint {
            principal: pid("a"),
            resource: "mcp://server:tool".into(),
            permission: None,
            ttl_secs: None,
        },
        AdminRequestKind::CapsTokenRevoke {
            token_id: "00000000-0000-0000-0000-000000000000".into(),
        },
        AdminRequestKind::CapsTokenList {
            principal: pid("a"),
        },
    ]
}

fn agent_profile() -> PrincipalProfile {
    PrincipalProfile {
        groups: vec!["agent".to_string()],
        ..Default::default()
    }
}

fn admin_profile() -> PrincipalProfile {
    PrincipalProfile {
        groups: vec!["admin".to_string()],
        ..Default::default()
    }
}

fn authorize_with(
    profile: &PrincipalProfile,
    groups: &GroupConfig,
    caller: &PrincipalId,
    cap: &str,
) -> bool {
    CapabilityCheck::new(profile, groups, caller.clone())
        .require(cap)
        .is_ok()
}

// ── Pure mapping tests ────────────────────────────────────────────────

#[test]
fn every_variant_has_non_empty_mapping_in_both_scopes() {
    for req in all_admin_variants() {
        for scope in [AuthorityScope::Self_, AuthorityScope::Global] {
            let cap = required_capability_for_admin_request(&req, scope);
            assert!(
                !cap.is_empty(),
                "required_capability_for_admin_request returned empty for \
                 {req:?} at {scope:?}"
            );
        }
    }
}

#[test]
fn quota_self_vs_global_mapping_distinguishes_principal() {
    let req = AdminRequestKind::QuotaSet {
        principal: pid("alice"),
        quotas: astrid_core::profile::Quotas::default(),
    };
    assert_eq!(
        required_capability_for_admin_request(&req, AuthorityScope::Self_),
        "self:quota:set"
    );
    assert_eq!(
        required_capability_for_admin_request(&req, AuthorityScope::Global),
        "quota:set"
    );
}

#[test]
fn agent_list_maps_self_to_self_prefix() {
    assert_eq!(
        required_capability_for_admin_request(&AdminRequestKind::AgentList, AuthorityScope::Self_),
        "self:agent:list"
    );
    assert_eq!(
        required_capability_for_admin_request(&AdminRequestKind::AgentList, AuthorityScope::Global),
        "agent:list"
    );
}

#[test]
fn pair_issue_mapping_requires_admin_only_for_unattenuated_scopes() {
    for scope in [
        PairScopeArg::Full,
        PairScopeArg::Preset {
            name: "full".into(),
        },
        PairScopeArg::Explicit {
            allow: vec!["*".into()],
            deny: vec![],
        },
    ] {
        let request = AdminRequestKind::PairDeviceIssue {
            expires_secs: None,
            label: None,
            scope,
        };
        assert_eq!(
            required_capability_for_admin_request(&request, AuthorityScope::Self_),
            "self:auth:pair:admin"
        );
    }

    let scoped = AdminRequestKind::PairDeviceIssue {
        expires_secs: None,
        label: None,
        scope: PairScopeArg::Preset {
            name: "use-only".into(),
        },
    };
    assert_eq!(
        required_capability_for_admin_request(&scoped, AuthorityScope::Self_),
        "self:auth:pair"
    );
}

#[test]
fn agent_create_mapping_uses_granular_clone_and_inherit_caps() {
    assert_eq!(
        required_capability_for_admin_request(
            &AdminRequestKind::AgentCreate {
                name: "fresh".into(),
                groups: Vec::new(),
                grants: Vec::new(),
                inherit_from: None,
                clone_from: None,
                allow_admin_clone: false,
            },
            AuthorityScope::Global,
        ),
        "agent:create"
    );
    assert_eq!(
        required_capability_for_admin_request(
            &AdminRequestKind::AgentCreate {
                name: "inherited".into(),
                groups: Vec::new(),
                grants: Vec::new(),
                inherit_from: Some(pid("source")),
                clone_from: None,
                allow_admin_clone: false,
            },
            AuthorityScope::Global,
        ),
        "agent:create:inherit"
    );
    assert_eq!(
        required_capability_for_admin_request(
            &AdminRequestKind::AgentCreate {
                name: "cloned".into(),
                groups: Vec::new(),
                grants: Vec::new(),
                inherit_from: None,
                clone_from: Some(pid("source")),
                allow_admin_clone: false,
            },
            AuthorityScope::Global,
        ),
        "agent:create:clone"
    );
}

#[test]
fn every_variant_has_a_method_label() {
    for req in all_admin_variants() {
        let m = admin_request_method(&req);
        assert!(
            m.starts_with("admin."),
            "method must start with admin.: {m}"
        );
    }
}

#[test]
fn resolve_admin_scope_self_when_target_is_caller() {
    let caller = pid("alice");
    let req = AdminRequestKind::QuotaSet {
        principal: caller.clone(),
        quotas: astrid_core::profile::Quotas::default(),
    };
    assert_eq!(resolve_admin_scope(&req, &caller), AuthorityScope::Self_);
}

#[test]
fn resolve_admin_scope_global_when_target_differs() {
    let caller = pid("alice");
    let req = AdminRequestKind::QuotaSet {
        principal: pid("bob"),
        quotas: astrid_core::profile::Quotas::default(),
    };
    assert_eq!(resolve_admin_scope(&req, &caller), AuthorityScope::Global);
}

#[test]
fn admin_target_principal_some_for_cross_tenant_variants() {
    assert!(
        admin_target_principal(&AdminRequestKind::QuotaSet {
            principal: pid("a"),
            quotas: astrid_core::profile::Quotas::default(),
        })
        .is_some()
    );
    assert!(
        admin_target_principal(&AdminRequestKind::CapsGrant {
            principal: pid("a"),
            capabilities: vec!["self:capsule:install".into()],
            unsafe_admin: false,
        })
        .is_some()
    );
}

#[test]
fn admin_target_principal_none_for_self_or_collection_variants() {
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

#[test]
fn admin_response_topic_mirrors_request_prefix() {
    assert_eq!(
        admin_response_topic("astrid.v1.admin.agent.create"),
        "astrid.v1.admin.response.agent.create"
    );
    assert_eq!(
        admin_response_topic("astrid.v1.admin.quota.set"),
        "astrid.v1.admin.response.quota.set"
    );
    // Pass-through when there's no prefix — defensive, shouldn't
    // happen from a well-formed event but avoids panicking.
    assert_eq!(admin_response_topic("other.topic"), "other.topic");
}

// ── Enforcement composition ──────────────────────────────────────────

#[test]
fn agent_denied_cross_tenant_every_admin_topic() {
    let groups = GroupConfig::builtin_only();
    let profile = agent_profile();
    let caller = pid("agent_user");

    for req in all_admin_variants() {
        let method = admin_request_method(&req);
        let scope = resolve_admin_scope(&req, &caller);
        let cap = required_capability_for_admin_request(&req, scope);
        let self_allowed = matches!(scope, AuthorityScope::Self_);

        let allowed = authorize_with(&profile, &groups, &caller, cap);
        if self_allowed {
            assert!(
                allowed,
                "agent should be allowed self-scoped {method} ({cap})",
            );
        } else {
            assert!(
                !allowed,
                "agent should be denied cross-tenant {method} ({cap})",
            );
        }
    }
}

#[test]
fn admin_allowed_every_admin_topic() {
    let groups = GroupConfig::builtin_only();
    let profile = admin_profile();
    let caller = pid("admin_user");

    for req in all_admin_variants() {
        let method = admin_request_method(&req);
        let scope = resolve_admin_scope(&req, &caller);
        let cap = required_capability_for_admin_request(&req, scope);
        assert!(
            authorize_with(&profile, &groups, &caller, cap),
            "admin group should be allowed {method} ({cap})",
        );
    }
}

#[test]
fn agent_holds_self_admin_caps_added_in_layer_6() {
    // The Layer 6 contract bump: built-in `agent` group gains
    // self:quota:get + self:agent:list. Verify both resolve through
    // the group config, not just via `self:*`.
    let groups = GroupConfig::builtin_only();
    let profile = agent_profile();
    let caller = pid("agent_user");

    let agent_group = groups.get("agent").unwrap();
    assert!(
        agent_group
            .capabilities
            .iter()
            .any(|c| c == "self:quota:get")
    );
    assert!(
        agent_group
            .capabilities
            .iter()
            .any(|c| c == "self:agent:list")
    );
    assert!(authorize_with(&profile, &groups, &caller, "self:quota:get"));
    assert!(authorize_with(
        &profile,
        &groups,
        &caller,
        "self:agent:list"
    ));
}

// ── ArcSwap hot-reload design invariant ──────────────────────────────

#[test]
fn arcswap_groups_swap_observed_by_next_check() {
    use arc_swap::ArcSwap;
    use astrid_core::groups::Group;

    let swap: Arc<ArcSwap<GroupConfig>> =
        Arc::new(ArcSwap::from_pointee(GroupConfig::builtin_only()));

    let profile = PrincipalProfile {
        groups: vec!["ops".to_string()],
        ..Default::default()
    };
    let caller = pid("ops_user");

    // Pre-swap: `ops` is unknown → fail-closed deny.
    let before = swap.load_full();
    assert!(!authorize_with(
        &profile,
        before.as_ref(),
        &caller,
        "capsule:install"
    ));

    // Atomically replace with a config that includes `ops`.
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
    let after = swap.load_full();
    assert!(authorize_with(
        &profile,
        after.as_ref(),
        &caller,
        "capsule:install"
    ));

    // And an `Arc` cloned before the swap still sees the OLD config —
    // atomic hand-off is per-load, not per-instance.
    assert!(!authorize_with(
        &profile,
        before.as_ref(),
        &caller,
        "capsule:install"
    ));
}

// ── Cache invalidation design invariant ──────────────────────────────

#[test]
fn profile_cache_invalidation_reflects_on_disk_mutation() {
    use astrid_capsule::profile_cache::PrincipalProfileCache;
    use astrid_core::dirs::AstridHome;

    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());
    let cache = PrincipalProfileCache::with_home(home.clone());
    let principal = pid("alice");

    // First resolve: missing file → Default (enabled=true, no grants).
    let first = cache.resolve(&principal).unwrap();
    assert!(first.enabled);
    assert!(first.grants.is_empty());

    // Write a populated profile to disk behind the cache's back.
    let updated = PrincipalProfile {
        grants: vec!["self:capsule:install".into()],
        ..Default::default()
    };
    let path = PrincipalProfile::path_for(&home, &principal);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    updated.save_to_path(&path).unwrap();

    // Without invalidate, cache returns stale Default.
    let stale = cache.resolve(&principal).unwrap();
    assert!(stale.grants.is_empty());

    // After invalidate, next resolve sees the new grants.
    cache.invalidate(&principal);
    let fresh = cache.resolve(&principal).unwrap();
    assert_eq!(fresh.grants, vec!["self:capsule:install".to_string()]);
}

// ── Revoke precedence across grant/revoke mutations ─────────────────

#[test]
fn caps_grant_preserves_revoke_precedence() {
    // Adversarial: pre-existing `self:*` revoke + a fresh
    // `self:capsule:install` grant → authz check still denies
    // (revoke > grant). This is the sequence
    // `handlers::mutate_caps(_, Grant)` produces when the target
    // profile already has revokes.
    let profile = PrincipalProfile {
        groups: vec!["admin".to_string()],
        revokes: vec!["self:*".to_string()],
        grants: vec!["self:capsule:install".to_string()],
        ..Default::default()
    };

    let groups = GroupConfig::builtin_only();
    let caller = pid("alice");
    let check = CapabilityCheck::new(&profile, &groups, caller);
    let err = check.require("self:capsule:install").unwrap_err();
    assert!(
        matches!(
            err,
            astrid_capabilities::PermissionError::RevokedCapability { .. }
        ),
        "grant must not clear matching revoke: {err:?}"
    );
}

#[test]
fn caps_revoke_of_unheld_capability_is_not_an_error_shape() {
    // Pre-emptive revoke: principal doesn't hold X yet, we revoke X,
    // the revoke vec just appends. Later grants/groups are dominated
    // by the revoke.
    let profile = PrincipalProfile {
        groups: vec!["restricted".to_string()],
        revokes: vec!["capsule:install".to_string()],
        grants: vec!["capsule:install".to_string()],
        ..Default::default()
    };

    let groups = GroupConfig::builtin_only();
    let caller = pid("alice");
    let check = CapabilityCheck::new(&profile, &groups, caller);
    assert!(check.require("capsule:install").is_err(), "revoke wins");
}

// ── redeem audit-outcome fidelity ───────────────────────────────────

#[test]
fn redeem_audit_proof_marks_rejected_token_as_failure() {
    use astrid_audit::{AuditOutcome, AuthorizationProof};
    use astrid_events::kernel_api::AdminResponseBody;

    // A rejected / expired / consumed / forged token returns `Error`. It
    // MUST audit as Denied + Failure so brute-force attempts are visible
    // in the audit log itself, not only in tracing. Before the fix this
    // path was hard-stamped success *before* dispatch, so a failed redeem
    // left a success row.
    let (auth, outcome) =
        super::redeem_audit_proof(&AdminResponseBody::Error("invite token not found".into()));
    assert!(
        matches!(auth, AuthorizationProof::Denied { .. }),
        "rejected redeem must record a Denied authorization proof"
    );
    match outcome {
        AuditOutcome::Failure { error } => assert!(error.contains("not found")),
        AuditOutcome::Success { .. } => panic!("rejected redeem must record a Failure outcome"),
    }

    // A successful mint (any non-Error body) audits as System + Success —
    // the token was the auth and it worked.
    let (auth, outcome) =
        super::redeem_audit_proof(&AdminResponseBody::Success(serde_json::Value::Null));
    assert!(
        matches!(auth, AuthorizationProof::System { .. }),
        "successful redeem keeps the System (token-is-auth) proof"
    );
    assert!(matches!(outcome, AuditOutcome::Success { .. }));
}
