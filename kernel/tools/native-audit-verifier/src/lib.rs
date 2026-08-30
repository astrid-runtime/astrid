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
pub const CHECKPOINT_WIRE_BYTES: usize = 4 + 2 + 16 + 8 + 32 + 8 + 32;

const ROOT_ALGORITHM_ID: &[u8] = b"BLAKE3-256";
const ROOT_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-root.v1";
const GENESIS_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-genesis.v1";
const CHECKPOINT_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-checkpoint.v1";
const ACK_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-ack.v1";

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
    pub tag: [u8; 32],
}

/// Kernel-only checkpoint authentication key. A checkpoint is trusted only
/// when this key authenticates its complete state binding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CheckpointKey([u8; 32]);

impl CheckpointKey {
    pub const fn new(bytes: [u8; 32]) -> Option<Self> {
        let mut index = 0;
        let mut any_nonzero = false;
        while index < bytes.len() {
            if bytes[index] != 0 {
                any_nonzero = true;
            }
            index += 1;
        }
        if any_nonzero { Some(Self(bytes)) } else { None }
    }

    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl core::fmt::Debug for CheckpointKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CheckpointKey(REDACTED)")
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
    auth_key: CheckpointKey,
) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(&auth_key.bytes());
    hasher.update(CHECKPOINT_DOMAIN_TAG);
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.update(&boot);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&root);
    hasher.update(&relay_generation.to_le_bytes());
    hasher.finalize().into()
}

fn ack_tag(seq: u64, source_root: [u8; 32], frame: &[u8], auth_key: CheckpointKey) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(&auth_key.bytes());
    hasher.update(ACK_DOMAIN_TAG);
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(&source_root);
    hasher.update(frame);
    hasher.finalize().into()
}

/// Tag-verifies a canonical checkpoint wire form. A verifier-local cache
/// alone is never trusted; only this kernel-sealed binding is.
pub fn verify_checkpoint(
    wire: &[u8],
    auth_key: CheckpointKey,
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
        tag,
    };
    if relay_generation == 0 {
        return Err(VerifyFailure::Malformed);
    }
    if checkpoint_tag(boot, seq, root, relay_generation, auth_key) != tag {
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
    auth_key: CheckpointKey,
    relay_generation: u64,
}

impl AuditVerifier {
    pub fn genesis(boot: [u8; 16], auth_key: CheckpointKey) -> Result<Self, VerifyFailure> {
        if boot.iter().all(|byte| *byte == 0) {
            return Err(VerifyFailure::Malformed);
        }
        Ok(Self {
            boot,
            next_seq: 1,
            root: genesis_root(boot),
            auth_key,
            relay_generation: 1,
        })
    }

    pub fn from_checkpoint(wire: &[u8], auth_key: CheckpointKey) -> Result<Self, VerifyFailure> {
        let checkpoint = verify_checkpoint(wire, auth_key)?;
        let next_seq = checkpoint
            .seq
            .checked_add(1)
            .ok_or(VerifyFailure::SequenceOverflow)?;
        Ok(Self {
            boot: checkpoint.boot,
            root: checkpoint.root,
            next_seq,
            auth_key,
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
            ack_tag: ack_tag(view.seq, claimed_root, frame, self.auth_key),
        };
        self.root = next_root;
        self.next_seq = next_seq;
        Ok(receipt)
    }

    /// Confirms a later kernel checkpoint against the folded state: the
    /// source root must match exactly before any acknowledgement range is
    /// trusted across a restart.
    pub fn accept_checkpoint(&self, wire: &[u8]) -> Result<(), VerifyFailure> {
        let checkpoint = verify_checkpoint(wire, self.auth_key)?;
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
        let checkpoint = verify_checkpoint(wire, self.auth_key)?;
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
