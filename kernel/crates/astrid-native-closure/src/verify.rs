//! Accept only a distinct, in-floor, correctly bound dual-closure pair.
//!
//! Trust keys and minimum floors come from [`TrustedPolicy`], never from the
//! untrusted table header.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::codec::decode_table;
use crate::error::ClosureError;
use crate::handoff::{AuthenticatedPolicyHandoff, HandoffContext, decode_handoff, encode_unsigned};
use crate::policy::TrustedPolicy;
use crate::root::RootVerifier;
use crate::types::{
    BoundIdentities, ClosureArtifact, ClosureKind, DualClosureTable, signed_message,
};

/// Verify `bytes` against an external trusted policy.
pub fn verify_table(bytes: &[u8], policy: &TrustedPolicy) -> Result<BoundIdentities, ClosureError> {
    if policy.kernel_verify() == policy.sysgen_verify() {
        return Err(ClosureError::SameKey);
    }
    let table = decode_table(bytes)?;
    check_slot_kinds(&table)?;
    check_floors(&table, policy)?;
    check_identities(&table)?;
    check_signatures(&table, policy)?;
    Ok(BoundIdentities {
        kernel_bootstrap: table.kernel.identity,
        system_generation: table.sysgen.identity,
        kernel_floor: table.kernel.floor,
        sysgen_floor: table.sysgen.floor,
    })
}

fn check_slot_kinds(table: &DualClosureTable) -> Result<(), ClosureError> {
    if table.kernel.kind != ClosureKind::KernelBootstrap
        || table.sysgen.kind != ClosureKind::SystemGeneration
    {
        return Err(ClosureError::Swapped);
    }
    Ok(())
}

fn check_floors(table: &DualClosureTable, policy: &TrustedPolicy) -> Result<(), ClosureError> {
    if table.kernel.floor < policy.kernel_min() || table.sysgen.floor < policy.sysgen_min() {
        return Err(ClosureError::Stale);
    }
    Ok(())
}

fn check_identities(table: &DualClosureTable) -> Result<(), ClosureError> {
    if table.kernel.identity == table.sysgen.identity {
        return Err(ClosureError::Collision);
    }
    if table.sysgen.identity != crate::types::MeasuredIdentity::empty_sysgen() {
        return Err(ClosureError::NotEmpty);
    }
    Ok(())
}

fn check_signatures(table: &DualClosureTable, policy: &TrustedPolicy) -> Result<(), ClosureError> {
    let kernel_key = policy.kernel_verify();
    let sysgen_key = policy.sysgen_verify();
    bind_artifact(&table.kernel, &kernel_key, &sysgen_key)?;
    bind_artifact(&table.sysgen, &sysgen_key, &kernel_key)
}

fn bind_artifact(
    artifact: &ClosureArtifact,
    expected_key: &[u8; 32],
    other_key: &[u8; 32],
) -> Result<(), ClosureError> {
    if artifact.signer != *expected_key {
        return Err(ClosureError::CrossBound);
    }
    let msg = signed_message(artifact.kind, artifact.floor, artifact.identity);
    if verifies(expected_key, &msg, &artifact.signature) {
        return Ok(());
    }
    if verifies(other_key, &msg, &artifact.signature) {
        return Err(ClosureError::CrossBound);
    }
    Err(ClosureError::SignatureInvalid)
}

fn verifies(key: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(msg, &sig).is_ok()
}

/// Verify a root-signed loader policy against explicit root and boot context.
///
/// The envelope is untrusted until the root signature passes. Root inputs
/// provide the accepted subordinate keys and independent rollback minima; the
/// caller supplies the live image/table/loader/context bindings to prevent
/// replay into another boot.
pub fn verify_policy_handoff(
    bytes: &[u8],
    root: &RootVerifier,
    expected: &HandoffContext,
) -> Result<AuthenticatedPolicyHandoff, ClosureError> {
    let decoded = decode_handoff(bytes)?;
    if decoded.root_verify != root.root_verify() {
        return Err(ClosureError::RootKeyMismatch);
    }

    let unsigned = encode_unsigned(&decoded.root_verify, &decoded.policy);
    if !verifies(&decoded.root_verify, &unsigned, &decoded.signature) {
        return Err(ClosureError::RootSignatureInvalid);
    }

    let policy = decoded.policy;
    if policy.kernel_verify == policy.sysgen_verify
        || policy.kernel_verify == decoded.root_verify
        || policy.sysgen_verify == decoded.root_verify
    {
        return Err(ClosureError::SameKey);
    }
    if policy.kernel_floor < root.kernel_min() || policy.sysgen_floor < root.sysgen_min() {
        return Err(ClosureError::Stale);
    }
    if policy.policy_generation < root.min_policy_generation() {
        return Err(ClosureError::PolicyGenerationStale);
    }
    if policy.context != *expected {
        return Err(ClosureError::BindingMismatch);
    }

    Ok(AuthenticatedPolicyHandoff {
        root_verify: decoded.root_verify,
        policy,
    })
}
