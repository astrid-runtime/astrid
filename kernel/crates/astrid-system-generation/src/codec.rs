//! Exact fixed-layout canonical encoding for a signed generation.

use crate::error::GenerationError;
use crate::types::{
    ComponentSet, ContentId, DIGEST_LEN, DOMAIN, Expiration, Generation, MAGIC, MANIFEST_LEN,
    ManifestInput, ManifestSizes, REVOKED_FLAG, Revocation, RollbackFloor, SIGNATURE_LEN,
    SIGNATURE_OFFSET, SIGNER_OFFSET, SignedSystemGeneration, SystemGenerationManifest,
    UNSIGNED_LEN, VERSION,
};

pub fn encode_manifest(signed: &SignedSystemGeneration) -> [u8; MANIFEST_LEN] {
    let mut out = [0u8; MANIFEST_LEN];
    encode_unsigned(&signed.manifest, &mut out[..UNSIGNED_LEN]);
    out[SIGNER_OFFSET..SIGNATURE_OFFSET].copy_from_slice(&signed.signer);
    out[SIGNATURE_OFFSET..MANIFEST_LEN].copy_from_slice(&signed.signature);
    out
}

pub fn decode_manifest(bytes: &[u8]) -> Result<SignedSystemGeneration, GenerationError> {
    if bytes.is_empty() {
        return Err(GenerationError::Missing);
    }
    if bytes.len() != MANIFEST_LEN {
        return Err(GenerationError::WrongLength);
    }
    if bytes[..MAGIC.len()] != MAGIC[..] || bytes[8] != VERSION {
        return Err(GenerationError::Malformed);
    }
    let flags = bytes[9];
    if flags & !REVOKED_FLAG != 0 {
        return Err(GenerationError::UnknownFlags);
    }
    if bytes[11] != 0 {
        return Err(GenerationError::Malformed);
    }
    let kernel_identity = decode_id(&bytes[12..44])?;
    let plan_digest = decode_id(&bytes[44..76])?;
    let count = bytes[10];
    let mut raw_components = [0u8; 256];
    raw_components.copy_from_slice(&bytes[76..332]);
    let components = ComponentSet::from_raw(count, raw_components)?;
    let object_root = decode_id(&bytes[332..364])?;
    let closure_root = decode_id(&bytes[364..396])?;
    let generation = read_u64(&bytes[396..404]);
    let rollback_floor = read_u64(&bytes[404..412]);
    let expires_at = read_u64(&bytes[412..420]);
    let sizes = ManifestSizes::new(
        read_u64(&bytes[420..428]),
        read_u64(&bytes[428..436]),
        read_u64(&bytes[436..444]),
        read_u64(&bytes[444..452]),
    );
    let manifest = SystemGenerationManifest::try_new(ManifestInput {
        kernel_identity,
        plan_digest,
        components,
        object_root,
        closure_root,
        generation: Generation::new(generation),
        rollback_floor: RollbackFloor::new(rollback_floor),
        expires_at: Expiration::at(expires_at),
        revocation: if flags & REVOKED_FLAG == 0 {
            Revocation::Active
        } else {
            Revocation::Revoked
        },
        sizes,
    })?;
    let mut signer = [0u8; 32];
    signer.copy_from_slice(&bytes[SIGNER_OFFSET..SIGNATURE_OFFSET]);
    let mut signature = [0u8; SIGNATURE_LEN];
    signature.copy_from_slice(&bytes[SIGNATURE_OFFSET..MANIFEST_LEN]);
    Ok(SignedSystemGeneration {
        manifest,
        signer,
        signature,
    })
}

pub(crate) fn signature_message(
    manifest: &SystemGenerationManifest,
) -> [u8; DOMAIN.len() + UNSIGNED_LEN] {
    let mut out = [0u8; DOMAIN.len() + UNSIGNED_LEN];
    out[..DOMAIN.len()].copy_from_slice(DOMAIN);
    encode_unsigned(manifest, &mut out[DOMAIN.len()..]);
    out
}

pub(crate) fn encode_unsigned(manifest: &SystemGenerationManifest, out: &mut [u8]) {
    debug_assert_eq!(out.len(), UNSIGNED_LEN);
    out[..8].copy_from_slice(MAGIC);
    out[8] = VERSION;
    out[9] = if manifest.revocation().is_revoked() {
        REVOKED_FLAG
    } else {
        0
    };
    out[10] = manifest.components().count_byte();
    out[11] = 0;
    copy_id(manifest.kernel_identity(), &mut out[12..44]);
    copy_id(manifest.plan_digest(), &mut out[44..76]);
    out[76..332].copy_from_slice(&manifest.components().raw_bytes());
    copy_id(manifest.object_root(), &mut out[332..364]);
    copy_id(manifest.closure_root(), &mut out[364..396]);
    write_u64(manifest.generation().get(), &mut out[396..404]);
    write_u64(manifest.rollback_floor().get(), &mut out[404..412]);
    write_u64(manifest.expires_at().get(), &mut out[412..420]);
    let sizes = manifest.sizes();
    write_u64(sizes.kernel_bytes(), &mut out[420..428]);
    write_u64(sizes.plan_bytes(), &mut out[428..436]);
    write_u64(sizes.object_bytes(), &mut out[436..444]);
    write_u64(sizes.closure_bytes(), &mut out[444..452]);
}

fn decode_id(bytes: &[u8]) -> Result<ContentId, GenerationError> {
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(bytes);
    ContentId::try_from_bytes(out)
}

fn copy_id(id: ContentId, out: &mut [u8]) {
    out.copy_from_slice(&id.as_bytes());
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    u64::from_le_bytes(out)
}

fn write_u64(value: u64, out: &mut [u8]) {
    out.copy_from_slice(&value.to_le_bytes());
}
