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

/// Hard decode failure of one input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyFailure {
    Malformed,
    CheckpointMismatch,
}

/// One fold step failure. Invalid means the input contradicts the chain;
/// Incomplete means the truth cannot be established without more evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldFailure {
    Invalid(InvalidReason),
    Incomplete(IncompleteReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    Malformed,
    DuplicateOrReorder,
    RootMismatch,
    DenialDisclosure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncompleteReason {
    SequenceGap,
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

fn checkpoint_tag(boot: [u8; 16], seq: u64, root: [u8; 32], relay_generation: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(CHECKPOINT_DOMAIN_TAG);
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.update(&boot);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&root);
    hasher.update(&relay_generation.to_le_bytes());
    hasher.finalize().into()
}

/// Tag-verifies a canonical checkpoint wire form. A verifier-local cache
/// alone is never trusted; only this kernel-sealed binding is.
pub fn verify_checkpoint(wire: &[u8]) -> Result<CheckpointView, VerifyFailure> {
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
    if checkpoint_tag(boot, seq, root, relay_generation) != tag {
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
}

impl AuditVerifier {
    pub fn genesis(boot: [u8; 16]) -> Result<Self, VerifyFailure> {
        if boot.iter().all(|byte| *byte == 0) {
            return Err(VerifyFailure::Malformed);
        }
        Ok(Self {
            boot,
            next_seq: 1,
            root: genesis_root(boot),
        })
    }

    pub fn from_checkpoint(wire: &[u8]) -> Result<Self, VerifyFailure> {
        let checkpoint = verify_checkpoint(wire)?;
        Ok(Self {
            boot: checkpoint.boot,
            next_seq: checkpoint.seq + 1,
            root: checkpoint.root,
        })
    }

    /// Folds one canonical frame whose source root claim has already been
    /// checked by the caller's handoff record. Contiguity is enforced; a gap
    /// is Incomplete and a duplicate or reorder is Invalid. Never skips.
    pub fn fold(&mut self, frame: &[u8]) -> Result<u64, FoldFailure> {
        self.fold_with_root(frame, None)
    }

    /// Same as [`AuditVerifier::fold`] while also matching the per-record
    /// root carried by the handoff (ack `N` only when the source root
    /// matches).
    pub fn fold_with_root(
        &mut self,
        frame: &[u8],
        claimed_root: Option<[u8; 32]>,
    ) -> Result<u64, FoldFailure> {
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
        let next_root = advance(self.root, self.boot, view.seq, frame);
        if let Some(claimed) = claimed_root
            && claimed != next_root
        {
            return Err(FoldFailure::Invalid(InvalidReason::RootMismatch));
        }
        self.root = next_root;
        self.next_seq += 1;
        Ok(view.seq)
    }

    /// Confirms a later kernel checkpoint against the folded state: the
    /// source root must match exactly before any acknowledgement range is
    /// trusted across a restart.
    pub fn accept_checkpoint(&self, wire: &[u8]) -> Result<(), VerifyFailure> {
        let checkpoint = verify_checkpoint(wire)?;
        if checkpoint.boot != self.boot
            || checkpoint.seq + 1 != self.next_seq
            || checkpoint.root != self.root
        {
            return Err(VerifyFailure::CheckpointMismatch);
        }
        Ok(())
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}
