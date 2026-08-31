//! Private host-side verifier for the native-kernel audit chain (#1759).
//!
//! The kernel is the only authority. This tool independently decodes the
//! frozen canonical frames, folds the rolling BLAKE3 root, checks
//! kernel-authenticated checkpoints, and reports Invalid versus Incomplete.
//! It never writes kernel state and is not a second fact base.
//!
//! Verification material enters only through an explicitly injected,
//! independently trusted kernel-origin anchor. The untrusted verifier
//! handoff carries no key material; it merely binds one boot/session
//! authority instance to that anchor, and no envelope may authenticate
//! itself with material carried inside the same untrusted input.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod wire;

#[cfg(test)]
mod tests;

use blake3::Hasher;
use spin::Mutex;

/// Frozen canonical frame-codec version this verifier understands.
pub const CODEC_VERSION: u16 = 1;
/// Fixed wire size of the canonical checkpoint form.
pub const CHECKPOINT_WIRE_BYTES: usize = 4 + 2 + 16 + 8 + 32 + 8 + 8 + 32;
/// Fixed size of the kernel-minted untrusted handoff binding: magic,
/// authority id, boot/session identity, keyed tag. No verification material.
pub const AUTHORITY_HANDOFF_BYTES: usize = 64;

const ROOT_ALGORITHM_ID: &[u8] = b"BLAKE3-256";
const ROOT_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-root.v1";
const GENESIS_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-genesis.v1";
const CHECKPOINT_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-checkpoint.v1";
const ACK_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-ack.v1";
const VERIFIER_HANDOFF_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-verifier-handoff.v1";

/// Reusable unkeyed fold state owned by one verifier session. It is created
/// when the verifier authority is installed, never on the fold path.
struct RootHasher(Mutex<Hasher>);

impl RootHasher {
    fn new() -> Self {
        Self(Mutex::new(Hasher::new()))
    }

    fn genesis(&self, boot: [u8; 16]) -> [u8; 32] {
        let mut hasher = self.0.lock();
        hasher.update(GENESIS_DOMAIN_TAG);
        hasher.update(&boot);
        hasher.update(&CODEC_VERSION.to_le_bytes());
        hasher.finalize().into()
    }

    fn advance(&self, previous_root: [u8; 32], boot: [u8; 16], seq: u64, frame: &[u8]) -> [u8; 32] {
        let mut hasher = self.0.lock();
        hasher.reset();
        hasher.update(ROOT_DOMAIN_TAG);
        hasher.update(ROOT_ALGORITHM_ID);
        hasher.update(&CODEC_VERSION.to_le_bytes());
        hasher.update(&boot);
        hasher.update(&seq.to_le_bytes());
        hasher.update(&previous_root);
        hasher.update(frame);
        hasher.finalize().into()
    }
}

/// Reusable keyed state owned by one move-only verifier anchor.
struct TagHasher(Mutex<Hasher>);

impl TagHasher {
    fn new(verification_key: &[u8; 32]) -> Self {
        Self(Mutex::new(Hasher::new_keyed(verification_key)))
    }

    fn reset(&self) {
        self.0.lock().reset();
    }

    fn checkpoint_tag(
        &self,
        boot: [u8; 16],
        seq: u64,
        root: [u8; 32],
        relay_generation: u64,
        authority_id: u64,
    ) -> [u8; 32] {
        let mut hasher = self.0.lock();
        hasher.reset();
        hasher.update(CHECKPOINT_DOMAIN_TAG);
        hasher.update(&CODEC_VERSION.to_le_bytes());
        hasher.update(&boot);
        hasher.update(&seq.to_le_bytes());
        hasher.update(&root);
        hasher.update(&relay_generation.to_le_bytes());
        hasher.update(&authority_id.to_le_bytes());
        hasher.finalize().into()
    }

    fn ack_tag(
        &self,
        boot: [u8; 16],
        relay_generation: u64,
        seq: u64,
        source_root: [u8; 32],
        frame: &[u8],
        authority_id: u64,
    ) -> [u8; 32] {
        let mut hasher = self.0.lock();
        hasher.reset();
        hasher.update(ACK_DOMAIN_TAG);
        hasher.update(&CODEC_VERSION.to_le_bytes());
        hasher.update(&authority_id.to_le_bytes());
        hasher.update(&boot);
        hasher.update(&relay_generation.to_le_bytes());
        hasher.update(&seq.to_le_bytes());
        hasher.update(&source_root);
        hasher.update(frame);
        hasher.finalize().into()
    }

    fn verifier_handoff_tag(&self, boot: [u8; 16], authority_id: u64) -> [u8; 32] {
        let mut hasher = self.0.lock();
        hasher.reset();
        hasher.update(VERIFIER_HANDOFF_DOMAIN_TAG);
        hasher.update(&CODEC_VERSION.to_le_bytes());
        hasher.update(&boot);
        hasher.update(&authority_id.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Hard decode failure of one input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyFailure {
    Malformed,
    HandoffUnbound,
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

/// Verifier authority bound to one independently trusted kernel-origin
/// anchor. This is the modeled trusted channel of the unwired first slice:
/// the anchor is injected from outside the untrusted handoff path, and
/// production anchor delivery, provisioning, and key lifecycle are named
/// #1759 residuals. It is the only way verification material enters this
/// crate; there is deliberately no constructor from untrusted handoff
/// bytes, because an envelope cannot authenticate itself with material
/// carried inside it.
pub struct AuthContext {
    authority_id: u64,
    boot: [u8; 16],
    verification_key: [u8; 32],
    tag_hasher: TagHasher,
}

impl AuthContext {
    /// The only trusted-entry constructor. Rejects degenerate anchors so a
    /// zero authority id, zero boot, or zero key can never anchor a session.
    pub fn from_trusted_anchor(
        authority_id: u64,
        boot: [u8; 16],
        verification_key: [u8; 32],
    ) -> Result<Self, VerifyFailure> {
        if authority_id == 0
            || boot.iter().all(|byte| *byte == 0)
            || verification_key.iter().all(|byte| *byte == 0)
        {
            return Err(VerifyFailure::Malformed);
        }
        Ok(Self {
            authority_id,
            boot,
            verification_key,
            tag_hasher: TagHasher::new(&verification_key),
        })
    }

    /// Binds untrusted handoff bytes against this trusted anchor. The
    /// handoff must name the anchored authority id and boot, and its
    /// minting tag must verify under the anchor key it does not carry.
    /// A structurally valid but caller-minted handoff therefore stays
    /// unbound: only the kernel-side key can produce the tag.
    pub fn bind_handoff(&self, bytes: &[u8; AUTHORITY_HANDOFF_BYTES]) -> Result<(), VerifyFailure> {
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
        if authority_id != self.authority_id() || boot != self.boot() {
            return Err(VerifyFailure::HandoffUnbound);
        }
        let tag: [u8; 32] = bytes[32..]
            .try_into()
            .map_err(|_| VerifyFailure::Malformed)?;
        if self.tag_hasher.verifier_handoff_tag(boot, authority_id) != tag {
            return Err(VerifyFailure::HandoffUnbound);
        }
        Ok(())
    }

    const fn authority_id(&self) -> u64 {
        self.authority_id
    }

    const fn boot(&self) -> [u8; 16] {
        self.boot
    }

    fn erase(&mut self) {
        self.tag_hasher.reset();
        self.verification_key.fill(0);
    }
}

impl core::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthContext(REDACTED)")
    }
}

impl Drop for AuthContext {
    fn drop(&mut self) {
        self.erase();
    }
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
    if relay_generation == 0 || authority_id != context.authority_id() || boot != context.boot() {
        return Err(VerifyFailure::Malformed);
    }
    if context
        .tag_hasher
        .checkpoint_tag(boot, seq, root, relay_generation, context.authority_id())
        != tag
    {
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
    root_hasher: RootHasher,
    context: AuthContext,
    relay_generation: u64,
}

impl AuditVerifier {
    /// Starts from genesis only after binding the untrusted handoff against
    /// the trusted anchor for the same boot.
    pub fn genesis(
        boot: [u8; 16],
        context: AuthContext,
        handoff: &[u8; AUTHORITY_HANDOFF_BYTES],
    ) -> Result<Self, VerifyFailure> {
        if boot.iter().all(|byte| *byte == 0) {
            return Err(VerifyFailure::Malformed);
        }
        if boot != context.boot() {
            return Err(VerifyFailure::Malformed);
        }
        context.bind_handoff(handoff)?;
        let root_hasher = RootHasher::new();
        let root = root_hasher.genesis(boot);
        Ok(Self {
            boot,
            next_seq: 1,
            root,
            root_hasher,
            context,
            relay_generation: 1,
        })
    }

    /// Restarts from a kernel-sealed checkpoint only after binding the
    /// untrusted handoff against the trusted anchor.
    pub fn from_checkpoint(
        wire: &[u8],
        context: AuthContext,
        handoff: &[u8; AUTHORITY_HANDOFF_BYTES],
    ) -> Result<Self, VerifyFailure> {
        context.bind_handoff(handoff)?;
        let checkpoint = verify_checkpoint(wire, &context)?;
        let next_seq = checkpoint
            .seq
            .checked_add(1)
            .ok_or(VerifyFailure::SequenceOverflow)?;
        Ok(Self {
            boot: checkpoint.boot,
            root: checkpoint.root,
            next_seq,
            root_hasher: RootHasher::new(),
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
        let next_root = self
            .root_hasher
            .advance(self.root, self.boot, view.seq, frame);
        if claimed_root != next_root {
            return Err(FoldFailure::Invalid(InvalidReason::RootMismatch));
        }
        let receipt = FoldReceipt {
            seq: view.seq,
            folded_root: claimed_root,
            ack_tag: self.context.tag_hasher.ack_tag(
                self.boot,
                self.relay_generation,
                view.seq,
                claimed_root,
                frame,
                self.context.authority_id(),
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

impl Drop for AuditVerifier {
    fn drop(&mut self) {
        // The field's own Drop performs the erase; this explicit hook documents
        // that destroying the fold state also destroys the verification anchor.
        self.context.erase();
    }
}
