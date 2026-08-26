//! Private binding from independently verified boot inputs to selector facts.
//!
//! This module is deliberately crate-private. It accepts only values that have
//! already crossed the system-generation, dual-closure, and authenticated
//! loader-policy verifiers; raw bytes, slot labels, paths, and policy records
//! cannot enter the selector through this boundary.

use astrid_native_closure::{AuthenticatedPolicyHandoff, BoundIdentities};
use astrid_system_generation::VerifiedGeneration;

use crate::policy::SelectionPolicy;
use crate::types::{CandidateFacts, CandidateInput};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// This adapter is intentionally staged before ring-0 wiring and remains
// private to this crate until that consumer is authorized.
#[allow(dead_code)]
pub enum AdapterError {
    ClosureIdentityCollision,
    KernelIdentityMismatch,
    KernelFloorMismatch,
    SysgenFloorMismatch,
    SubordinateKeyMismatch,
}

impl AdapterError {
    #[allow(dead_code)]
    pub const fn as_reason(self) -> &'static str {
        match self {
            Self::ClosureIdentityCollision => "closure_identity_collision",
            Self::KernelIdentityMismatch => "kernel_identity_mismatch",
            Self::KernelFloorMismatch => "kernel_floor_mismatch",
            Self::SysgenFloorMismatch => "sysgen_floor_mismatch",
            Self::SubordinateKeyMismatch => "subordinate_key_mismatch",
        }
    }
}

/// Bind one independently verified descriptor/closure/handoff tuple.
///
/// Descriptor generation and rollback are copied only from the verified
/// manifest. Closure floors are copied only from the independently verified
/// closure table, and the policy epoch is copied only from the authenticated
/// handoff. None of these values is substituted for another.
#[allow(dead_code)]
pub(crate) fn bind_verified_candidate(
    generation: VerifiedGeneration,
    bound: BoundIdentities,
    handoff: AuthenticatedPolicyHandoff,
) -> Result<CandidateFacts, AdapterError> {
    let policy = handoff.policy();
    if policy.kernel_verify() != bound.kernel_verify()
        || policy.sysgen_verify() != bound.sysgen_verify()
    {
        return Err(AdapterError::SubordinateKeyMismatch);
    }

    if !bound.distinct() {
        return Err(AdapterError::ClosureIdentityCollision);
    }

    let manifest = generation.manifest();
    if manifest.kernel_identity().as_bytes() != bound.kernel_identity().as_bytes() {
        return Err(AdapterError::KernelIdentityMismatch);
    }

    if policy.kernel_floor() != bound.kernel_floor() {
        return Err(AdapterError::KernelFloorMismatch);
    }
    if policy.sysgen_floor() != bound.sysgen_floor() {
        return Err(AdapterError::SysgenFloorMismatch);
    }

    Ok(CandidateFacts::from_verified(CandidateInput {
        descriptor_identity: generation.manifest_identity().as_bytes(),
        kernel_identity: manifest.kernel_identity().as_bytes(),
        system_generation_identity: bound.sysgen_identity().as_bytes(),
        plan_digest: manifest.plan_digest().as_bytes(),
        object_root: manifest.object_root().as_bytes(),
        closure_root: manifest.closure_root().as_bytes(),
        generation: manifest.generation().get(),
        rollback_floor: manifest.rollback_floor().get(),
        kernel_floor: bound.kernel_floor().get(),
        sysgen_floor: bound.sysgen_floor().get(),
        policy_generation: policy.policy_generation().get(),
    }))
}

/// Build a selector policy only after the same authenticated tuple has been
/// bound. The five floors remain independent in the resulting policy.
#[allow(dead_code)]
pub(crate) fn authenticated_policy(
    generation: VerifiedGeneration,
    bound: BoundIdentities,
    handoff: AuthenticatedPolicyHandoff,
) -> Result<SelectionPolicy, AdapterError> {
    let facts = bind_verified_candidate(generation, bound, handoff)?;
    Ok(SelectionPolicy::from_authenticated(
        facts.generation(),
        facts.rollback_floor(),
        facts.kernel_floor(),
        facts.sysgen_floor(),
        facts.policy_generation(),
    ))
}
