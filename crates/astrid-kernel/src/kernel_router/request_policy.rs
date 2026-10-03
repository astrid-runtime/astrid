//! Authority, audit, and rate-label policy for management requests.

use astrid_core::{PrincipalId, kernel_api::KernelRequest};

use KernelRequest::{
    GetCapsuleInstallResumeReceipt as G, GetInstalledCapsuleIdentity as I,
    PutCapsuleInstallResumeReceipt as P,
};

/// The authority surface a management request operates over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityScope {
    /// Request operates on the caller's own principal.
    Self_,
    /// Request operates on global or another principal's state.
    Global,
}

/// Return the authority scope the caller is exercising for `request`.
#[must_use]
pub fn resolve_scope(request: &KernelRequest, caller: &PrincipalId) -> AuthorityScope {
    if let Some(target) = native_pair_target(request) {
        return if target == caller {
            AuthorityScope::Self_
        } else {
            AuthorityScope::Global
        };
    }
    match request {
        KernelRequest::ReloadCapsules => AuthorityScope::Global,
        KernelRequest::InstallCapsule {
            target_principal: Some(target),
            ..
        }
        | KernelRequest::BeginCapsuleInstallBatch {
            target_principal: Some(target),
            ..
        }
        | KernelRequest::FinishCapsuleInstallBatch {
            target_principal: Some(target),
            ..
        } if target != caller => AuthorityScope::Global,
        KernelRequest::GetCapsuleMetadataForPrincipal { target_principal }
        | KernelRequest::GetNativeProtectionCapabilities { target_principal }
            if target_principal != caller =>
        {
            AuthorityScope::Global
        },
        _ => AuthorityScope::Self_,
    }
}

/// Return an explicit cross-principal target for audit records.
pub(super) fn request_target_principal(
    request: &KernelRequest,
    caller: &PrincipalId,
) -> Option<PrincipalId> {
    if let Some(target) = native_pair_target(request) {
        return (target != caller).then(|| target.clone());
    }
    match request {
        KernelRequest::InstallCapsule {
            target_principal: Some(target),
            ..
        }
        | KernelRequest::BeginCapsuleInstallBatch {
            target_principal: Some(target),
            ..
        }
        | KernelRequest::FinishCapsuleInstallBatch {
            target_principal: Some(target),
            ..
        } if target != caller => Some(target.clone()),
        KernelRequest::GetCapsuleMetadataForPrincipal { target_principal }
        | KernelRequest::GetNativeProtectionCapabilities { target_principal }
            if target_principal != caller =>
        {
            Some(target_principal.clone())
        },
        _ => None,
    }
}

/// Return the static capability required to satisfy `request` under `scope`.
#[must_use]
pub fn required_capability(request: &KernelRequest, scope: AuthorityScope) -> &'static str {
    if native_pair_target(request).is_some() {
        return if scope == AuthorityScope::Self_ {
            "self:capsule:install"
        } else {
            "capsule:install"
        };
    }
    match (request, scope) {
        (
            KernelRequest::BeginNativePairUpgrade(_)
            | KernelRequest::StageNativePairMember(_)
            | KernelRequest::AbortNativePairUpgrade(_)
            | KernelRequest::GetNativePairUpgrade(_),
            _,
        ) => unreachable!(),
        (KernelRequest::Shutdown { .. }, _) => "system:shutdown",
        (KernelRequest::GetStatus, _) => "system:status",
        (
            KernelRequest::ReloadCapsules | KernelRequest::ReloadCapsule { .. },
            AuthorityScope::Self_,
        ) => "self:capsule:reload",
        (KernelRequest::ReloadCapsules | KernelRequest::ReloadCapsule { .. }, _) => {
            "capsule:reload"
        },
        (
            KernelRequest::UnloadCapsule { .. } | KernelRequest::RemoveCapsule { .. },
            AuthorityScope::Self_,
        ) => "self:capsule:remove",
        (KernelRequest::UnloadCapsule { .. } | KernelRequest::RemoveCapsule { .. }, _) => {
            "capsule:remove"
        },
        (KernelRequest::PromoteWorkspace { .. }, _) => "self:workspace:promote",
        (KernelRequest::RollbackWorkspace { .. }, _) => "self:workspace:rollback",
        (
            KernelRequest::InstallCapsule { .. }
            | KernelRequest::BeginCapsuleInstallBatch { .. }
            | KernelRequest::FinishCapsuleInstallBatch { .. },
            AuthorityScope::Self_,
        )
        | (I { .. } | G { .. } | P { .. }, _) => "self:capsule:install",
        (
            KernelRequest::InstallCapsule { .. }
            | KernelRequest::BeginCapsuleInstallBatch { .. }
            | KernelRequest::FinishCapsuleInstallBatch { .. },
            _,
        ) => "capsule:install",
        (
            KernelRequest::ListCapsules
            | KernelRequest::GetCommands
            | KernelRequest::GetCapsuleMetadata
            | KernelRequest::GetCapsuleMetadataForPrincipal { .. }
            | KernelRequest::GetAgentReadiness
            | KernelRequest::GetNativeProtectionCapabilities { .. },
            AuthorityScope::Self_,
        ) => "self:capsule:list",
        (
            KernelRequest::ListCapsules
            | KernelRequest::GetCommands
            | KernelRequest::GetCapsuleMetadata
            | KernelRequest::GetCapsuleMetadataForPrincipal { .. }
            | KernelRequest::GetAgentReadiness
            | KernelRequest::GetNativeProtectionCapabilities { .. },
            _,
        ) => "capsule:list",
        (KernelRequest::ApproveCapability { .. }, _) => "self:approval:respond",
    }
}

/// Whether a successful liveness probe should omit a durable admin row.
pub(super) fn omit_success_admin_audit(request: &KernelRequest) -> bool {
    matches!(
        request,
        KernelRequest::GetStatus | KernelRequest::GetAgentReadiness
    )
}

/// Short identifier used for rate-limit labels and audit method names.
#[must_use]
pub fn kernel_request_method(request: &KernelRequest) -> &'static str {
    match request {
        KernelRequest::BeginNativePairUpgrade(_) => "BeginNativePairUpgrade",
        KernelRequest::StageNativePairMember(_) => "StageNativePairMember",
        KernelRequest::AbortNativePairUpgrade(_) => "AbortNativePairUpgrade",
        KernelRequest::GetNativePairUpgrade(_) => "GetNativePairUpgrade",
        KernelRequest::ReloadCapsules => "ReloadCapsules",
        KernelRequest::ReloadCapsule { .. } => "ReloadCapsule",
        KernelRequest::UnloadCapsule { .. } => "UnloadCapsule",
        KernelRequest::RemoveCapsule { .. } => "RemoveCapsule",
        KernelRequest::PromoteWorkspace { .. } => "PromoteWorkspace",
        KernelRequest::RollbackWorkspace { .. } => "RollbackWorkspace",
        KernelRequest::BeginCapsuleInstallBatch { .. } => "BeginCapsuleInstallBatch",
        KernelRequest::InstallCapsule { .. } => "InstallCapsule",
        KernelRequest::FinishCapsuleInstallBatch { .. } => "FinishCapsuleInstallBatch",
        KernelRequest::GetInstalledCapsuleIdentity { .. } => "GetInstalledCapsuleIdentity",
        KernelRequest::GetCapsuleInstallResumeReceipt { .. } => "GetCapsuleInstallResumeReceipt",
        KernelRequest::PutCapsuleInstallResumeReceipt { .. } => "PutCapsuleInstallResumeReceipt",
        KernelRequest::ApproveCapability { .. } => "ApproveCapability",
        KernelRequest::ListCapsules => "ListCapsules",
        KernelRequest::GetCommands => "GetCommands",
        KernelRequest::GetCapsuleMetadata => "GetCapsuleMetadata",
        KernelRequest::GetCapsuleMetadataForPrincipal { .. } => "GetCapsuleMetadataForPrincipal",
        KernelRequest::GetAgentReadiness => "GetAgentReadiness",
        KernelRequest::GetNativeProtectionCapabilities { .. } => "GetNativeProtectionCapabilities",
        KernelRequest::Shutdown { .. } => "Shutdown",
        KernelRequest::GetStatus => "GetStatus",
    }
}

fn native_pair_target(request: &KernelRequest) -> Option<&PrincipalId> {
    match request {
        KernelRequest::BeginNativePairUpgrade(request) => Some(&request.target_principal),
        KernelRequest::StageNativePairMember(request) => Some(&request.lease.target_principal),
        KernelRequest::AbortNativePairUpgrade(request)
        | KernelRequest::GetNativePairUpgrade(request) => Some(&request.target_principal),
        _ => None,
    }
}
