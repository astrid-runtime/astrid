use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, KernelRequest, PairScopeArg};
use astrid_core::profile::Quotas;

pub(crate) fn all_kernel_request_variants() -> Vec<KernelRequest> {
    vec![
        KernelRequest::Shutdown { reason: None },
        KernelRequest::GetStatus,
        KernelRequest::ReloadCapsules,
        KernelRequest::ReloadCapsule { id: "x".into() },
        KernelRequest::UnloadCapsule { id: "x".into() },
        KernelRequest::PromoteWorkspace { id: "x".into() },
        KernelRequest::RollbackWorkspace { id: "x".into() },
        KernelRequest::InstallCapsule {
            source: "x".into(),
            workspace: false,
        },
        KernelRequest::ListCapsules,
        KernelRequest::GetCommands,
        KernelRequest::GetCapsuleMetadata,
        KernelRequest::GetAgentReadiness,
        KernelRequest::EnsureTopicReady {
            topic: "service.v1.request".into(),
        },
        KernelRequest::ApproveCapability {
            request_id: "r".into(),
            signature: "s".into(),
        },
    ]
}

pub(crate) fn all_admin_request_variants() -> Vec<AdminRequestKind> {
    let principal = PrincipalId::default();
    identity_and_policy_variants(&principal)
        .into_iter()
        .chain(credential_variants(&principal))
        .collect()
}

fn identity_and_policy_variants(principal: &PrincipalId) -> Vec<AdminRequestKind> {
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
            principal: principal.clone(),
        },
        AdminRequestKind::AgentEnable {
            principal: principal.clone(),
        },
        AdminRequestKind::AgentDisable {
            principal: principal.clone(),
        },
        AdminRequestKind::AgentModify {
            principal: principal.clone(),
            add_groups: vec![],
            remove_groups: vec![],
            add_capsules: vec![],
            remove_capsules: vec![],
        },
        AdminRequestKind::AgentList,
        AdminRequestKind::QuotaSet {
            principal: principal.clone(),
            quotas: Quotas::default(),
        },
        AdminRequestKind::QuotaGet {
            principal: principal.clone(),
        },
        AdminRequestKind::UsageGet {
            principal: principal.clone(),
        },
        AdminRequestKind::GroupCreate {
            name: "group".into(),
            capabilities: vec![],
            description: None,
            unsafe_admin: false,
        },
        AdminRequestKind::GroupDelete {
            name: "group".into(),
        },
        AdminRequestKind::GroupModify {
            name: "group".into(),
            capabilities: None,
            description: None,
            unsafe_admin: None,
        },
        AdminRequestKind::GroupList,
        AdminRequestKind::CapsGrant {
            principal: principal.clone(),
            capabilities: vec![],
            unsafe_admin: false,
        },
        AdminRequestKind::CapsRevoke {
            principal: principal.clone(),
            capabilities: vec![],
        },
    ]
}

fn credential_variants(principal: &PrincipalId) -> Vec<AdminRequestKind> {
    vec![
        AdminRequestKind::CapsTokenMint {
            principal: principal.clone(),
            resource: "mcp://server:tool".into(),
            permission: None,
            ttl_secs: None,
        },
        AdminRequestKind::CapsTokenRevoke {
            token_id: "00000000-0000-0000-0000-000000000000".into(),
        },
        AdminRequestKind::CapsTokenList {
            principal: principal.clone(),
        },
        AdminRequestKind::InviteIssue {
            group: "agent".into(),
            expires_secs: None,
            max_uses: 1,
            metadata: None,
        },
        AdminRequestKind::InviteRedeem {
            token: "token".into(),
            public_key: String::new(),
            display_name: None,
        },
        AdminRequestKind::InviteList,
        AdminRequestKind::InviteRevoke {
            token: "token".into(),
        },
        AdminRequestKind::PairDeviceIssue {
            expires_secs: None,
            label: None,
            scope: PairScopeArg::Full,
        },
        AdminRequestKind::PairDeviceRedeem {
            token: "token".into(),
            public_key: String::new(),
        },
        AdminRequestKind::PairDeviceList {
            principal: principal.clone(),
        },
        AdminRequestKind::PairDeviceRevoke {
            principal: principal.clone(),
            key_id: "key".into(),
        },
    ]
}
