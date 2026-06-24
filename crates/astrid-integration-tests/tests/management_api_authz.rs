//! Management-API authorization integration tests (issue #670).
//!
//! Exercises the enforcement preamble by composing the pieces the kernel
//! assembles at boot —
//! [`GroupConfig`](astrid_core::GroupConfig),
//! [`PrincipalProfile`](astrid_core::PrincipalProfile),
//! [`CapabilityCheck`](astrid_capabilities::CapabilityCheck) — and the
//! pure mapping functions from [`astrid_kernel::kernel_router`]
//! (`required_capability`, `resolve_scope`, `kernel_request_method`).
//!
//! Booting a real [`astrid_kernel::Kernel`] requires `$ASTRID_HOME`,
//! socket binding, and a persistent KV store — too heavy for a unit
//! test. Rebuilding the decision path from its public pieces gives the
//! same coverage as an end-to-end kernel with none of the filesystem /
//! process side effects. If the kernel ever changes the enforcement
//! contract, this test will break compile-wise and flag it.

#![allow(clippy::arithmetic_side_effects, clippy::field_reassign_with_default)]

use astrid_capabilities::{CapabilityCheck, PermissionError};
use astrid_core::kernel_api::KernelRequest;
use astrid_core::principal::PrincipalId;
use astrid_core::{GroupConfig, PrincipalProfile};
use astrid_kernel::kernel_router::{kernel_request_method, required_capability, resolve_scope};

fn admin_principal() -> PrincipalId {
    PrincipalId::new("admin_user").unwrap()
}

fn agent_principal() -> PrincipalId {
    PrincipalId::new("agent_user").unwrap()
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

fn all_requests() -> Vec<KernelRequest> {
    vec![
        KernelRequest::Shutdown { reason: None },
        KernelRequest::GetStatus,
        KernelRequest::ReloadCapsules,
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

fn authorize(
    profile: &PrincipalProfile,
    groups: &GroupConfig,
    caller: &PrincipalId,
    req: &KernelRequest,
) -> Result<(), PermissionError> {
    let scope = resolve_scope(req, caller);
    let cap = required_capability(req, scope);
    CapabilityCheck::new(profile, groups, caller.clone()).require(cap)
}

#[test]
fn admin_group_allows_every_management_request() {
    let groups = GroupConfig::builtin_only();
    let profile = admin_profile();
    let caller = admin_principal();

    for req in all_requests() {
        let method = kernel_request_method(&req);
        authorize(&profile, &groups, &caller, &req)
            .unwrap_or_else(|e| panic!("admin should be allowed {method}: {e}"));
    }
}

#[test]
fn agent_group_denies_system_surface() {
    let groups = GroupConfig::builtin_only();
    let profile = agent_profile();
    let caller = agent_principal();

    // System surface: admin-only in today's mapping.
    assert!(matches!(
        authorize(
            &profile,
            &groups,
            &caller,
            &KernelRequest::Shutdown { reason: None }
        ),
        Err(PermissionError::MissingCapability { .. })
    ));
    assert!(matches!(
        authorize(&profile, &groups, &caller, &KernelRequest::GetStatus),
        Err(PermissionError::MissingCapability { .. })
    ));
}

#[test]
fn agent_group_allows_self_scoped_capsule_surface() {
    let groups = GroupConfig::builtin_only();
    let profile = agent_profile();
    let caller = agent_principal();

    // Self-scoped: agent can drive their own capsule lifecycle.
    for req in [
        KernelRequest::ReloadCapsules,
        KernelRequest::InstallCapsule {
            source: String::new(),
            workspace: false,
        },
        KernelRequest::ListCapsules,
        KernelRequest::GetCommands,
        KernelRequest::GetCapsuleMetadata,
        KernelRequest::ApproveCapability {
            request_id: String::new(),
            signature: String::new(),
        },
    ] {
        let method = kernel_request_method(&req);
        authorize(&profile, &groups, &caller, &req)
            .unwrap_or_else(|e| panic!("agent should be allowed {method}: {e}"));
    }
}

#[test]
fn restricted_group_denies_everything_without_explicit_grants() {
    let groups = GroupConfig::builtin_only();
    let mut profile = PrincipalProfile::default();
    profile.groups = vec!["restricted".to_string()];
    let caller = PrincipalId::new("restricted_user").unwrap();

    for req in all_requests() {
        let method = kernel_request_method(&req);
        assert!(
            authorize(&profile, &groups, &caller, &req).is_err(),
            "restricted should be denied {method}",
        );
    }
}

#[test]
fn revoke_overrides_admin_for_shutdown_only() {
    let groups = GroupConfig::builtin_only();
    let mut profile = admin_profile();
    profile.revokes.push("system:shutdown".into());
    let caller = admin_principal();

    // Shutdown is now denied — revoke overrides `*`.
    let err = authorize(
        &profile,
        &groups,
        &caller,
        &KernelRequest::Shutdown { reason: None },
    )
    .unwrap_err();
    match err {
        PermissionError::RevokedCapability {
            revoke_pattern,
            required,
            ..
        } => {
            assert_eq!(revoke_pattern, "system:shutdown");
            assert_eq!(required, "system:shutdown");
        },
        other => panic!("expected RevokedCapability, got: {other:?}"),
    }

    // Other admin operations still pass.
    authorize(&profile, &groups, &caller, &KernelRequest::GetStatus).unwrap();
}

#[test]
fn grant_elevates_restricted_principal_for_specific_surface() {
    let groups = GroupConfig::builtin_only();
    let mut profile = PrincipalProfile::default();
    profile.groups = vec!["restricted".to_string()];
    profile.grants = vec!["system:status".to_string()];
    let caller = PrincipalId::new("ops_user").unwrap();

    authorize(&profile, &groups, &caller, &KernelRequest::GetStatus).unwrap();
    // Surface the grant didn't cover remains denied.
    assert!(
        authorize(
            &profile,
            &groups,
            &caller,
            &KernelRequest::Shutdown { reason: None }
        )
        .is_err()
    );
}

#[test]
fn nonexistent_group_name_fails_closed() {
    let groups = GroupConfig::builtin_only();
    let mut profile = PrincipalProfile::default();
    profile.groups = vec!["typo-group".to_string()];
    let caller = PrincipalId::new("typo_user").unwrap();

    // No fallback to any group's capabilities — fails closed.
    assert!(
        authorize(
            &profile,
            &groups,
            &caller,
            &KernelRequest::Shutdown { reason: None }
        )
        .is_err()
    );
    assert!(authorize(&profile, &groups, &caller, &KernelRequest::GetStatus).is_err());
}

#[test]
fn custom_group_capabilities_gate_admin_surface() {
    let groups = GroupConfig::from_toml_str(
        r#"
        [groups.ops]
        description = "Deployment operators"
        capabilities = ["capsule:install"]
    "#,
    )
    .unwrap();

    let mut profile = PrincipalProfile::default();
    profile.groups = vec!["ops".to_string()];
    let caller = PrincipalId::new("ops_user").unwrap();

    // Ops group gets cross-agent capsule:install but not self:capsule:install
    // because today's scope defaults to Self_. Still denied until they also
    // belong to agent (self:*) or grant self:capsule:install directly.
    assert!(
        authorize(
            &profile,
            &groups,
            &caller,
            &KernelRequest::InstallCapsule {
                source: String::new(),
                workspace: false
            }
        )
        .is_err()
    );

    // Grant the self:* equivalent and the install goes through.
    profile.grants.push("self:capsule:install".into());
    authorize(
        &profile,
        &groups,
        &caller,
        &KernelRequest::InstallCapsule {
            source: String::new(),
            workspace: false,
        },
    )
    .unwrap();
}

#[test]
fn admin_vs_agent_cross_tenant_matrix() {
    let groups = GroupConfig::builtin_only();
    let admin = admin_profile();
    let agent = agent_profile();

    // Admin can do everything.
    for req in all_requests() {
        authorize(&admin, &groups, &admin_principal(), &req).unwrap();
    }

    // Agent self:* covers capsule lifecycle; system:* stays denied.
    for req in all_requests() {
        let method = kernel_request_method(&req);
        let result = authorize(&agent, &groups, &agent_principal(), &req);
        match req {
            KernelRequest::Shutdown { .. } | KernelRequest::GetStatus => {
                assert!(result.is_err(), "{method} should be denied for agent");
            },
            _ => {
                assert!(result.is_ok(), "{method} should be allowed for agent");
            },
        }
    }
}

#[test]
fn groupconfig_rejects_shell_metachars_in_grants_via_profile_validation() {
    // Parallel to the GroupConfig validation tests: per-principal grants
    // also pass through the capability grammar.
    let mut profile = PrincipalProfile::default();
    profile.groups = vec!["admin".to_string()];
    profile.grants = vec!["system:shutdown;rm".to_string()];
    assert!(profile.validate().is_err());
}

#[test]
fn groupconfig_rejects_custom_star_without_opt_in() {
    let err = GroupConfig::from_toml_str(
        r#"
        [groups.privileged]
        capabilities = ["*"]
    "#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        astrid_core::groups::GroupConfigError::UnsafeUniversalGrant { .. }
    ));
}

#[test]
fn groupconfig_accepts_custom_star_with_unsafe_admin_opt_in() {
    let groups = GroupConfig::from_toml_str(
        r#"
        [groups.privileged]
        unsafe_admin = true
        capabilities = ["*"]
    "#,
    )
    .unwrap();

    let mut profile = PrincipalProfile::default();
    profile.groups = vec!["privileged".to_string()];
    let caller = PrincipalId::new("priv_user").unwrap();

    // privileged now has universal, so every variant goes through.
    for req in all_requests() {
        authorize(&profile, &groups, &caller, &req).unwrap();
    }
}

#[test]
fn groupconfig_rejects_builtin_redefinition() {
    let err = GroupConfig::from_toml_str(
        r#"
        [groups.admin]
        capabilities = ["system:shutdown"]
    "#,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        astrid_core::groups::GroupConfigError::RedefinedBuiltin { .. }
    ));
}

#[test]
fn missing_principal_falls_back_to_default_admin_after_bootstrap() {
    // Simulate post-bootstrap state: the default principal has groups = ["admin"]
    // and the IPC message had no `principal` field set (pre-#658 socket traffic).
    let groups = GroupConfig::builtin_only();
    let mut default_profile = PrincipalProfile::default();
    default_profile.groups = vec!["admin".to_string()];
    let default_principal = PrincipalId::default();

    for req in all_requests() {
        authorize(&default_profile, &groups, &default_principal, &req).unwrap();
    }
}
