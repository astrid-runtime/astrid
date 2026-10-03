use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, KernelRequest, PairScopeArg};
use astrid_core::profile::Quotas;

pub(crate) fn all_kernel_request_variants() -> Vec<KernelRequest> {
    let reference = native_pair_reference();
    vec![
        KernelRequest::BeginNativePairUpgrade(Box::new(native_pair_begin())),
        KernelRequest::StageNativePairMember(astrid_core::kernel_api::StageNativePairMember {
            lease: reference.clone(),
            member_id: "codewall-enforcer".into(),
            offset: 0,
            total_bytes: 1,
            chunk: vec![0],
            final_chunk: true,
        }),
        KernelRequest::AbortNativePairUpgrade(reference.clone()),
        KernelRequest::GetNativePairUpgrade(reference),
        KernelRequest::Shutdown { reason: None },
        KernelRequest::GetStatus,
        KernelRequest::ReloadCapsules,
        KernelRequest::ReloadCapsule { id: "x".into() },
        KernelRequest::UnloadCapsule { id: "x".into() },
        KernelRequest::PromoteWorkspace { id: "x".into() },
        KernelRequest::RollbackWorkspace { id: "x".into() },
        KernelRequest::BeginCapsuleInstallBatch {
            target_principal: None,
            members: Vec::new(),
        },
        KernelRequest::InstallCapsule {
            source: "x".into(),
            workspace: false,
            target_principal: None,
            provenance: None,
            authority: astrid_core::kernel_api::CapsuleInstallAuthority::default(),
            env: Vec::new(),
            expected_generation: None,
            batch: None,
        },
        KernelRequest::FinishCapsuleInstallBatch {
            batch_id: astrid_core::kernel_api::CapsuleInstallBatchId::new(),
            target_principal: None,
        },
        KernelRequest::GetInstalledCapsuleIdentity { id: "x".into() },
        KernelRequest::GetCapsuleInstallResumeReceipt { id: "x".into() },
        KernelRequest::PutCapsuleInstallResumeReceipt {
            receipt: astrid_core::kernel_api::CapsuleInstallResumeReceipt {
                id: "x".into(),
                archive_digest: "a".repeat(64),
                generation: astrid_core::kernel_api::InstalledCapsuleGeneration {
                    archive: "b".repeat(64),
                    metadata: "c".repeat(64),
                    authority: "d".repeat(64),
                },
            },
        },
        KernelRequest::ListCapsules,
        KernelRequest::GetCommands,
        KernelRequest::GetCapsuleMetadata,
        KernelRequest::GetCapsuleMetadataForPrincipal {
            target_principal: PrincipalId::default(),
        },
        KernelRequest::GetAgentReadiness,
        KernelRequest::GetNativeProtectionCapabilities {
            target_principal: PrincipalId::default(),
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
        AdminRequestKind::UserPrincipalList,
        AdminRequestKind::UserPrincipalClaim {
            principal: principal.clone(),
        },
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
        AdminRequestKind::DistroLockGet {
            principal: principal.clone(),
        },
        AdminRequestKind::DistroLockSet {
            principal: principal.clone(),
            lock: astrid_core::kernel_api::DistroProvenance {
                schema_version: 1,
                distro_id: "test".into(),
                distro_version: "1.0.0".into(),
                resolved_at: "2026-01-01T00:00:00Z".into(),
                capsules: Vec::new(),
                manifest_hash: None,
            },
            expected_hash: None,
        },
        AdminRequestKind::DistroSelfGrant,
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

pub(crate) fn native_pair_reference() -> astrid_core::kernel_api::NativePairLeaseRefV1 {
    astrid_core::kernel_api::NativePairLeaseRefV1 {
        lease_id: uuid::Uuid::new_v4(),
        target_principal: PrincipalId::new("alice").unwrap(),
        principal_uid: astrid_core::identity::PrincipalUid::from_bytes([1; 32]),
        daemon_incarnation: uuid::Uuid::new_v4(),
    }
}
pub(crate) fn native_pair_begin() -> astrid_core::kernel_api::BeginNativePairUpgrade {
    use astrid_core::kernel_api::*;
    let reference = native_pair_reference();
    let identity = |id: &str| InstalledCapsuleIdentity {
        id: id.into(),
        generation: InstalledCapsuleGeneration {
            archive: "a".repeat(64),
            metadata: "b".repeat(64),
            authority: "c".repeat(64),
        },
        archive_digest: "d".repeat(64),
        wasm_hash: Some("e".repeat(64)),
    };
    BeginNativePairUpgrade {
        target_principal: reference.target_principal,
        principal_uid: reference.principal_uid,
        daemon_incarnation: reference.daemon_incarnation,
        expected_old: NativePairIdentityV1 {
            enforcer: identity("codewall-enforcer"),
            protocol: identity("codewall-protocol"),
            enforcer_source: uuid::Uuid::new_v4(),
            protocol_source: uuid::Uuid::new_v4(),
        },
        members: ["codewall-enforcer", "codewall-protocol"].map(|id| NativePairMemberV1 {
            id: id.into(),
            source_digest: "a".repeat(64),
            source_bytes: 1,
            authority: CapsuleInstallAuthority::Automatic,
            env: vec![],
        }),
        expires_at_unix_ms: 1,
        nonce: uuid::Uuid::new_v4(),
        installation_id: uuid::Uuid::new_v4(),
        journal_id: uuid::Uuid::new_v4(),
    }
}
