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

#[test]
fn known_capabilities_covers_every_admin_request_cap() {
    let p = PrincipalId::default();
    let admin_variants: Vec<AdminRequestKind> = vec![
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
    ];

    let scopes = [AuthorityScope::Self_, AuthorityScope::Global];
    for req in &admin_variants {
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
