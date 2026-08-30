//! Private host-side verifier for the native-kernel audit chain (#1759).
//!
//! The kernel is the only authority. This tool independently decodes the
//! frozen canonical frames, folds the rolling BLAKE3 root, checks
//! kernel-authenticated checkpoints, and reports Invalid versus Incomplete.
//! It never writes kernel state and is not a second fact base.

pub mod wire;

#[cfg(test)]
mod tests;

use blake3::Hasher;

/// Frozen canonical frame-codec version this verifier understands.
pub const CODEC_VERSION: u16 = 1;
/// Fixed wire size of the canonical checkpoint form.
pub const CHECKPOINT_WIRE_BYTES: usize = 4 + 2 + 16 + 8 + 32 + 8 + 8 + 32;
/// Fixed size of a kernel-minted opaque verifier handoff.
pub const AUTHORITY_HANDOFF_BYTES: usize = 96;

const ROOT_ALGORITHM_ID: &[u8] = b"BLAKE3-256";
const ROOT_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-root.v1";
const GENESIS_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-genesis.v1";
const CHECKPOINT_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-checkpoint.v1";
const ACK_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-ack.v1";
const VERIFIER_HANDOFF_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-verifier-handoff.v1";

/// Hard decode failure of one input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyFailure {
    Malformed,
    CheckpointMismatch,
    SequenceOverflow,
    StaleRelayGeneration,
}

/// One fold step failure. Invalid means the input contradicts the chain;
/// Incomplete means the truth cannot be established without more evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldFailure {
    Invalid(InvalidReason),
    Incomplete(IncompleteReason),
    SequenceOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    Malformed,
    DuplicateOrReorder,
    ForeignBoot,
    PreviousRootMismatch,
    RootMismatch,
    DenialDisclosure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncompleteReason {
    SequenceGap,
}

/// Opaque evidence that this verifier completed one fold. Relay code may
/// acknowledge only with this receipt plus the same source root; it can never
/// synthesize a retirement from an unfolded frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoldReceipt {
    seq: u64,
    folded_root: [u8; 32],
    ack_tag: [u8; 32],
}

impl FoldReceipt {
    pub const fn seq(self) -> u64 {
        self.seq
    }

    pub const fn folded_root(self) -> [u8; 32] {
        self.folded_root
    }

    pub const fn ack_tag(self) -> [u8; 32] {
        self.ack_tag
    }
}

/// A kernel-authenticated checkpoint view, already tag-verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointView {
    pub boot: [u8; 16],
    pub seq: u64,
    pub root: [u8; 32],
    pub codec_version: u16,
    pub relay_generation: u64,
    pub authority_id: u64,
    pub tag: [u8; 32],
}

/// Opaque kernel-minted verifier context. It can enter this crate only
/// through a sealed handoff; a caller cannot construct a raw authority key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthContext {
    authority_id: u64,
    boot: [u8; 16],
    verification_key: [u8; 32],
}

impl AuthContext {
    /// Accepts only the sealed 96-byte capability minted by the kernel.
    pub fn from_handoff(bytes: &[u8; AUTHORITY_HANDOFF_BYTES]) -> Result<Self, VerifyFailure> {
        if bytes[..8] != *b"ASAUDCTX" {
            return Err(VerifyFailure::Malformed);
        }
        let authority_id = u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .ok()
                .ok_or(VerifyFailure::Malformed)?,
        );
        let boot = bytes[16..32]
            .try_into()
            .ok()
            .filter(|boot: &[u8; 16]| boot.iter().any(|byte| *byte != 0))
            .ok_or(VerifyFailure::Malformed)?;
        let verification_key = bytes[32..64]
            .try_into()
            .ok()
            .filter(|key: &[u8; 32]| key.iter().any(|byte| *byte != 0))
            .ok_or(VerifyFailure::Malformed)?;
        let tag: [u8; 32] = bytes[64..]
            .try_into()
            .map_err(|_| VerifyFailure::Malformed)?;
        if verifier_handoff_tag(boot, authority_id, &verification_key) != tag {
            return Err(VerifyFailure::Malformed);
        }
        Ok(Self {
            authority_id,
            boot,
            verification_key,
        })
    }

    #[cfg(test)]
    fn mint(boot: [u8; 16], seed: u64) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"native-audit-verifier-test-authority");
        hasher.update(&boot);
        hasher.update(&seed.to_le_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Self {
            authority_id: seed | 1,
            boot,
            verification_key: digest,
        }
    }
}

impl core::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthContext(REDACTED)")
    }
}

fn genesis_root(boot: [u8; 16]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(GENESIS_DOMAIN_TAG);
    hasher.update(&boot);
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.finalize().into()
}

fn advance(previous_root: [u8; 32], boot: [u8; 16], seq: u64, frame: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(ROOT_DOMAIN_TAG);
    hasher.update(ROOT_ALGORITHM_ID);
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.update(&boot);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&previous_root);
    hasher.update(frame);
    hasher.finalize().into()
}

fn checkpoint_tag(
    boot: [u8; 16],
    seq: u64,
    root: [u8; 32],
    relay_generation: u64,
    context: &AuthContext,
) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(&context.verification_key);
    hasher.update(CHECKPOINT_DOMAIN_TAG);
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.update(&boot);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&root);
    hasher.update(&relay_generation.to_le_bytes());
    hasher.update(&context.authority_id.to_le_bytes());
    hasher.finalize().into()
}

fn ack_tag(
    boot: [u8; 16],
    relay_generation: u64,
    seq: u64,
    source_root: [u8; 32],
    frame: &[u8],
    context: &AuthContext,
) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(&context.verification_key);
    hasher.update(ACK_DOMAIN_TAG);
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.update(&context.authority_id.to_le_bytes());
    hasher.update(&boot);
    hasher.update(&relay_generation.to_le_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(&source_root);
    hasher.update(frame);
    hasher.finalize().into()
}

fn verifier_handoff_tag(
    boot: [u8; 16],
    authority_id: u64,
    verification_key: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(verification_key);
    hasher.update(VERIFIER_HANDOFF_DOMAIN_TAG);
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.update(&boot);
    hasher.update(&authority_id.to_le_bytes());
    hasher.finalize().into()
}

/// Tag-verifies a canonical checkpoint wire form. A verifier-local cache
/// alone is never trusted; only this kernel-sealed binding is.
pub fn verify_checkpoint(
    wire: &[u8],
    context: &AuthContext,
) -> Result<CheckpointView, VerifyFailure> {
    if wire.len() != CHECKPOINT_WIRE_BYTES {
        return Err(VerifyFailure::Malformed);
    }
    let mut reader = wire::Reader::new(wire).ok_or(VerifyFailure::Malformed)?;
    let total = reader.u32().ok_or(VerifyFailure::Malformed)? as usize;
    if wire.len() - 4 != total {
        return Err(VerifyFailure::Malformed);
    }
    let codec_version = reader.u16().ok_or(VerifyFailure::Malformed)?;
    if codec_version != CODEC_VERSION {
        return Err(VerifyFailure::Malformed);
    }
    let boot = reader
        .bytes(16)
        .ok_or(VerifyFailure::Malformed)?
        .try_into()
        .ok()
        .filter(|boot: &[u8; 16]| boot.iter().any(|byte| *byte != 0))
        .ok_or(VerifyFailure::Malformed)?;
    let seq = reader.u64().ok_or(VerifyFailure::Malformed)?;
    let root = reader
        .bytes(32)
        .ok_or(VerifyFailure::Malformed)?
        .try_into()
        .ok()
        .ok_or(VerifyFailure::Malformed)?;
    let relay_generation = reader.u64().ok_or(VerifyFailure::Malformed)?;
    let authority_id = reader.u64().ok_or(VerifyFailure::Malformed)?;
    let tag = reader
        .bytes(32)
        .ok_or(VerifyFailure::Malformed)?
        .try_into()
        .ok()
        .ok_or(VerifyFailure::Malformed)?;
    if reader.remaining() != 0 {
        return Err(VerifyFailure::Malformed);
    }
    let view = CheckpointView {
        boot,
        seq,
        root,
        codec_version,
        relay_generation,
        authority_id,
        tag,
    };
    if relay_generation == 0 || authority_id != context.authority_id || boot != context.boot {
        return Err(VerifyFailure::Malformed);
    }
    if checkpoint_tag(boot, seq, root, relay_generation, context) != tag {
        return Err(VerifyFailure::CheckpointMismatch);
    }
    Ok(view)
}

/// Independent fold state. Start from genesis or a verified checkpoint,
/// then fold contiguous frames in order.
pub struct AuditVerifier {
    boot: [u8; 16],
    next_seq: u64,
    root: [u8; 32],
    context: AuthContext,
    relay_generation: u64,
}

impl AuditVerifier {
    pub fn genesis(boot: [u8; 16], context: AuthContext) -> Result<Self, VerifyFailure> {
        if boot.iter().all(|byte| *byte == 0) {
            return Err(VerifyFailure::Malformed);
        }
        if boot != context.boot {
            return Err(VerifyFailure::Malformed);
        }
        Ok(Self {
            boot,
            next_seq: 1,
            root: genesis_root(boot),
            context,
            relay_generation: 1,
        })
    }

    pub fn from_checkpoint(wire: &[u8], context: AuthContext) -> Result<Self, VerifyFailure> {
        let checkpoint = verify_checkpoint(wire, &context)?;
        let next_seq = checkpoint
            .seq
            .checked_add(1)
            .ok_or(VerifyFailure::SequenceOverflow)?;
        Ok(Self {
            boot: checkpoint.boot,
            root: checkpoint.root,
            next_seq,
            context,
            relay_generation: checkpoint.relay_generation,
        })
    }

    /// Folds one canonical frame whose source root claim has already been
    /// checked by the caller's handoff record. Contiguity is enforced; a gap
    /// is Incomplete and a duplicate or reorder is Invalid. Never skips.
    pub fn fold(
        &mut self,
        frame: &[u8],
        claimed_root: [u8; 32],
    ) -> Result<FoldReceipt, FoldFailure> {
        let view = wire::decode_frame(frame).map_err(|error| match error {
            wire::WireError::Malformed => FoldFailure::Invalid(InvalidReason::Malformed),
            wire::WireError::DenialDisclosure => {
                FoldFailure::Invalid(InvalidReason::DenialDisclosure)
            },
        })?;
        if view.seq < self.next_seq {
            return Err(FoldFailure::Invalid(InvalidReason::DuplicateOrReorder));
        }
        if view.seq > self.next_seq {
            return Err(FoldFailure::Incomplete(IncompleteReason::SequenceGap));
        }
        if view.boot != self.boot {
            return Err(FoldFailure::Invalid(InvalidReason::ForeignBoot));
        }
        if view.prev_root != Some(self.root) {
            return Err(FoldFailure::Invalid(InvalidReason::PreviousRootMismatch));
        }
        let next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(FoldFailure::SequenceOverflow)?;
        let next_root = advance(self.root, self.boot, view.seq, frame);
        if claimed_root != next_root {
            return Err(FoldFailure::Invalid(InvalidReason::RootMismatch));
        }
        let receipt = FoldReceipt {
            seq: view.seq,
            folded_root: claimed_root,
            ack_tag: ack_tag(
                self.boot,
                self.relay_generation,
                view.seq,
                claimed_root,
                frame,
                &self.context,
            ),
        };
        self.root = next_root;
        self.next_seq = next_seq;
        Ok(receipt)
    }

    /// Confirms a later kernel checkpoint against the folded state: the
    /// source root must match exactly before any acknowledgement range is
    /// trusted across a restart.
    pub fn accept_checkpoint(&self, wire: &[u8]) -> Result<(), VerifyFailure> {
        let checkpoint = verify_checkpoint(wire, &self.context)?;
        let next_seq = checkpoint
            .seq
            .checked_add(1)
            .ok_or(VerifyFailure::SequenceOverflow)?;
        if checkpoint.boot != self.boot || next_seq != self.next_seq || checkpoint.root != self.root
        {
            return Err(VerifyFailure::CheckpointMismatch);
        }
        if checkpoint.relay_generation != self.relay_generation {
            return Err(VerifyFailure::StaleRelayGeneration);
        }
        Ok(())
    }

    /// Accepts exactly one generation-bumped checkpoint after the same state
    /// has been folded. This is the verifier side of explicit resync.
    pub fn accept_resync_checkpoint(&mut self, wire: &[u8]) -> Result<(), VerifyFailure> {
        let checkpoint = verify_checkpoint(wire, &self.context)?;
        let next_seq = checkpoint
            .seq
            .checked_add(1)
            .ok_or(VerifyFailure::SequenceOverflow)?;
        let next_generation = self
            .relay_generation
            .checked_add(1)
            .ok_or(VerifyFailure::Malformed)?;
        if checkpoint.boot != self.boot
            || next_seq != self.next_seq
            || checkpoint.root != self.root
            || checkpoint.relay_generation != next_generation
        {
            return Err(VerifyFailure::CheckpointMismatch);
        }
        self.relay_generation = next_generation;
        Ok(())
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}
