//! Signature, identity, lifecycle, and rollback admission checks.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::codec::{decode_manifest, signature_message};
use crate::error::GenerationError;
use crate::policy::{TrustedInput, VerifiedGeneration};

pub fn verify_manifest(
    bytes: &[u8],
    trusted: &TrustedInput,
) -> Result<VerifiedGeneration, GenerationError> {
    let signed = decode_manifest(bytes)?;
    if signed.signer() != trusted.signer() {
        return Err(GenerationError::UntrustedSigner);
    }
    verify_signature(&signed, trusted)?;
    let manifest = signed.manifest();
    if manifest.revocation().is_revoked() {
        return Err(GenerationError::Revoked);
    }
    if manifest.generation() < trusted.generation_floor()
        || manifest.rollback_floor().get() < trusted.generation_floor().get()
    {
        return Err(GenerationError::Stale);
    }
    if manifest.expires_at().is_expired(trusted.now_unix_seconds()) {
        return Err(GenerationError::Expired);
    }
    if manifest.kernel_identity() != trusted.kernel_identity() {
        return Err(GenerationError::KernelMismatch);
    }
    if manifest.plan_digest() != trusted.plan_digest() {
        return Err(GenerationError::PlanMismatch);
    }
    if manifest.components() != trusted.components() {
        return Err(GenerationError::ComponentsMismatch);
    }
    if manifest.object_root() != trusted.object_root() {
        return Err(GenerationError::ObjectRootMismatch);
    }
    if manifest.closure_root() != trusted.closure_root() {
        return Err(GenerationError::ClosureRootMismatch);
    }
    if manifest.sizes() != trusted.sizes() {
        return Err(GenerationError::SizeMismatch);
    }
    Ok(VerifiedGeneration::new(signed))
}

fn verify_signature(
    signed: &crate::types::SignedSystemGeneration,
    trusted: &TrustedInput,
) -> Result<(), GenerationError> {
    let key =
        VerifyingKey::from_bytes(&trusted.signer()).map_err(|_| GenerationError::InvalidSigner)?;
    let signature = Signature::from_bytes(&signed.signature);
    key.verify_strict(&signature_message(&signed.manifest()), &signature)
        .map_err(|_| GenerationError::SignatureInvalid)
}
