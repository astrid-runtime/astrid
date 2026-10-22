//! The atomic mutation-side transition: one call commits the canonical
//! frame, the checked `audit_seq` advance, and the rolling-root advance
//! together, or fails before any state changes.

use super::codec::{Frame, MAX_FRAME_BYTES};
use super::live::LiveVerifier;
use super::relay::AuditRelay;
use super::root;
use super::types::{
    AuditAuthority, AuditCheckpoint, AuditError, AuditEvent, BootSessionId, KernelSecretEntropy,
};
use core::mem::MaybeUninit;

pub(crate) struct AuditChain {
    boot: BootSessionId,
    authority: AuditAuthority,
    root_hasher: root::RootHasher,
    seq: u64,
    root: [u8; root::ROOT_LEN],
    relay: AuditRelay,
    live: LiveVerifier,
    record_scratch: RecordScratch,
    frame_scratch: MaybeUninit<Frame>,
}

/// Chain-owned canonical frame scratch. Keeping this in the static runtime
/// (rather than in a large live-call frame) bounds the small IPC stack while
/// retaining the single-authority mutation transition.
#[derive(Clone, Copy)]
struct RecordScratch {
    encoded: [u8; MAX_FRAME_BYTES],
    encoded_len: usize,
    seq: u64,
    class: super::types::AuditClass,
}

impl RecordScratch {
    const fn staged() -> Self {
        Self {
            encoded: [0; MAX_FRAME_BYTES],
            encoded_len: 0,
            seq: 0,
            class: super::types::AuditClass::DomainCreate,
        }
    }

    fn frame(&self) -> &[u8] {
        &self.encoded[..self.encoded_len]
    }

    fn mandatory(&self) -> bool {
        self.class.is_terminal_or_invalidation()
    }
}

/// One successfully observed and retired public audit position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuditObservation {
    pub(super) seq: u64,
    pub(super) class: super::types::AuditClass,
    pub(super) root: [u8; root::ROOT_LEN],
}

impl AuditObservation {
    pub(crate) const fn seq(&self) -> u64 {
        self.seq
    }

    pub(crate) const fn class(&self) -> super::types::AuditClass {
        self.class
    }

    pub(crate) const fn root(&self) -> &[u8; root::ROOT_LEN] {
        &self.root
    }
}

impl AuditChain {
    /// Starts a new boot/session chain at the domain-separated genesis root.
    pub fn genesis(boot: BootSessionId, secret: KernelSecretEntropy) -> Result<Self, AuditError> {
        let authority = AuditAuthority::mint(boot, secret).ok_or(AuditError::MalformedFrame)?;
        Self::genesis_custodied(boot, authority)
    }

    /// Starts from an already-minted authority. The live verifier derives the
    /// chain's genesis root, so there is exactly one genesis-root authority.
    pub(crate) fn genesis_custodied(
        boot: BootSessionId,
        authority: AuditAuthority,
    ) -> Result<Self, AuditError> {
        if authority.boot() != boot {
            return Err(AuditError::CheckpointMismatch);
        }
        let live = LiveVerifier::genesis(boot, &authority)?;
        let root = live.cursor().1;
        Ok(Self {
            boot,
            authority,
            root_hasher: root::RootHasher::new(),
            seq: 0,
            root,
            relay: AuditRelay::new(boot),
            live,
            record_scratch: RecordScratch::staged(),
            frame_scratch: MaybeUninit::uninit(),
        })
    }

    pub const fn boot(&self) -> BootSessionId {
        self.boot
    }

    pub(crate) const fn authority(&self) -> &AuditAuthority {
        &self.authority
    }

    pub const fn seq(&self) -> u64 {
        self.seq
    }

    pub const fn root(&self) -> &[u8; root::ROOT_LEN] {
        &self.root
    }

    pub const fn relay(&self) -> &AuditRelay {
        &self.relay
    }

    pub fn relay_mut(&mut self) -> &mut AuditRelay {
        &mut self.relay
    }

    /// Encodes the candidate in chain-owned scratch without moving either
    /// authoritative cursor. The live verifier owns the live-path root fold.
    #[inline(never)]
    fn stage_record(&mut self, event: &AuditEvent, next: u64) -> Result<(), AuditError> {
        let prev_root = Some(self.root);
        let frame = Frame::write_new(&mut self.frame_scratch, self.boot, next, event, prev_root)?;
        let encoded_len = frame.encode(&mut self.record_scratch.encoded)?.len();

        self.record_scratch.encoded_len = encoded_len;
        self.record_scratch.seq = next;
        self.record_scratch.class = event.class();
        Ok(())
    }

    /// Acknowledges through the chain's kernel-owned authentication context;
    /// callers can present only the retained verifier's successful-fold
    /// receipt.
    pub fn ack(
        &mut self,
        seq: u64,
        folded_root: [u8; root::ROOT_LEN],
        receipt_tag: [u8; root::ROOT_LEN],
    ) -> Result<(), AuditError> {
        self.relay
            .ack(seq, folded_root, receipt_tag, self.authority.context())
    }

    /// Generation-bumps the relay and seals recovery with the same
    /// kernel-owned authority.
    pub fn resync(&mut self) -> Result<AuditCheckpoint, AuditError> {
        let current_root = self.root;
        let current_seq = self.seq;
        self.relay
            .resync(current_root, current_seq, self.authority.context())
    }

    /// Appends one event as one atomic retained-evidence transition. All
    /// fallible steps complete before the single commit; a failure leaves
    /// sequence, root, and relay untouched. Relay publication is downstream
    /// evidence only and can never rewrite the already-rooted event.
    pub fn append(&mut self, event: AuditEvent) -> Result<u64, AuditError> {
        let next = self
            .seq
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
        self.stage_record(&event, next)?;
        let next_root =
            self.root_hasher
                .advance(self.root, self.boot, next, self.record_scratch.frame());

        // The relay is mandatory for the retained-evidence mutation path.
        // The fallible publish performs every check before mutating a slot or
        // cursor, so no rooted record is stranded outside the bounded proof.
        self.relay.publish(
            next,
            self.record_scratch.frame(),
            next_root,
            event.class().is_terminal_or_invalidation(),
        )?;

        // Commit: frame, checked seq, rolling root, and relay handoff all
        // advance together after every fallible step has succeeded.
        self.seq = next;
        self.root = next_root;
        Ok(next)
    }

    /// Stages one event in chain-owned scratch, folds the exact canonical
    /// frame through the kernel-private live verifier, authenticates its
    /// privately minted receipt, and retires it before return.
    #[inline(never)]
    pub(crate) fn append_verified(
        &mut self,
        event: &AuditEvent,
    ) -> Result<AuditObservation, AuditError> {
        let next = self
            .seq
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
        self.stage_record(event, next)?;

        // Immediate-retire mode is exclusive of buffered/in-flight records.
        // Checking here prevents live custody from advancing before the
        // transaction can be handed to an empty relay.
        self.relay.require_empty_for_immediate_retire()?;
        self.relay
            .can_publish(next, self.record_scratch.mandatory())?;

        let relay_generation = self.relay.generation();
        let reservation = self.live.reserve(&self.authority, next)?;
        let prepared = {
            // SAFETY: `stage_record` returned success immediately above, and
            // `Frame::write_new` fully initialized the slot before encoding.
            let decoded = unsafe { self.frame_scratch.assume_init_ref() };
            let live = &mut self.live;
            let frame = self.record_scratch.frame();
            let context = self.authority.context();
            live.finish(reservation, decoded, frame, relay_generation, context)?
        };
        let observation = prepared.commit(&mut self.relay, self.authority.context())?;
        self.seq = observation.seq;
        self.root = observation.root;
        Ok(observation)
    }

    /// Kernel-authenticated checkpoint bound to the exact current state.
    pub fn checkpoint(&self) -> AuditCheckpoint {
        self.relay
            .checkpoint(self.root, self.seq, self.authority.context())
    }
}
