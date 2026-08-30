//! Rolling BLAKE3 root: the only root algorithm in this slice.
//!
//! `R_0 = BLAKE3(domain-separated genesis)` and
//! `R_n = BLAKE3(tag || R_{n-1} || canonical_frame_n)` where the tag binds
//! the algorithm id, frame-codec version, boot/session identity, and
//! sequence. The previous root also rides inside the canonical frame for
//! authenticity, but the fold consumes `R_{n-1}` directly, so there is no
//! second encoding of the root.

use blake3::Hasher;

use super::types::{BootSessionId, CheckpointAuthContext};

pub(crate) const ROOT_LEN: usize = 32;

pub(crate) const ROOT_ALGORITHM_ID: &[u8] = b"BLAKE3-256";
pub(crate) const ROOT_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-root.v1";
pub(crate) const GENESIS_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-genesis.v1";
pub(crate) const CHECKPOINT_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-checkpoint.v1";
pub(crate) const ACK_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-ack.v1";
pub(crate) const VERIFIER_HANDOFF_DOMAIN_TAG: &[u8] =
    b"astrid.native-kernel.audit-verifier-handoff.v1";

pub(crate) fn genesis(boot: BootSessionId) -> [u8; ROOT_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(GENESIS_DOMAIN_TAG);
    hasher.update(&boot.bytes());
    hasher.update(&super::CODEC_VERSION.to_le_bytes());
    hasher.finalize().into()
}

pub(crate) fn advance(
    previous_root: [u8; ROOT_LEN],
    boot: BootSessionId,
    seq: u64,
    frame: &[u8],
) -> [u8; ROOT_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(ROOT_DOMAIN_TAG);
    hasher.update(ROOT_ALGORITHM_ID);
    hasher.update(&super::CODEC_VERSION.to_le_bytes());
    hasher.update(&boot.bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(&previous_root);
    hasher.update(frame);
    hasher.finalize().into()
}

pub(crate) fn checkpoint_tag(
    boot: BootSessionId,
    seq: u64,
    root: [u8; ROOT_LEN],
    relay_generation: u64,
    context: &CheckpointAuthContext,
) -> [u8; ROOT_LEN] {
    let mut hasher = Hasher::new_keyed(&context.verification_key().bytes());
    hasher.update(CHECKPOINT_DOMAIN_TAG);
    hasher.update(&super::CODEC_VERSION.to_le_bytes());
    hasher.update(&boot.bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(&root);
    hasher.update(&relay_generation.to_le_bytes());
    hasher.update(&context.authority_id().to_le_bytes());
    hasher.finalize().into()
}

/// Binds a verifier receipt to the exact canonical frame and source root it
/// successfully folded. Relay acknowledgements consume this evidence; relay
/// flow control still never becomes root authority.
pub(crate) fn ack_tag(
    boot: BootSessionId,
    relay_generation: u64,
    seq: u64,
    source_root: [u8; ROOT_LEN],
    frame: &[u8],
    context: &CheckpointAuthContext,
) -> [u8; ROOT_LEN] {
    let mut hasher = Hasher::new_keyed(&context.verification_key().bytes());
    hasher.update(ACK_DOMAIN_TAG);
    hasher.update(&super::CODEC_VERSION.to_le_bytes());
    hasher.update(&context.authority_id().to_le_bytes());
    hasher.update(&boot.bytes());
    hasher.update(&relay_generation.to_le_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(&source_root);
    hasher.update(frame);
    hasher.finalize().into()
}

/// Keys the kernel minting tag bound into the untrusted verifier handoff.
/// The verification key never travels inside the handoff; the tag is
/// checkable only by a holder of the independently trusted kernel-origin
/// anchor, so a caller-minted handoff cannot authenticate itself.
pub(crate) fn verifier_handoff_tag(
    boot: BootSessionId,
    authority_id: u64,
    verification_key: &[u8; ROOT_LEN],
) -> [u8; ROOT_LEN] {
    let mut hasher = Hasher::new_keyed(verification_key);
    hasher.update(VERIFIER_HANDOFF_DOMAIN_TAG);
    hasher.update(&super::CODEC_VERSION.to_le_bytes());
    hasher.update(&boot.bytes());
    hasher.update(&authority_id.to_le_bytes());
    hasher.finalize().into()
}
