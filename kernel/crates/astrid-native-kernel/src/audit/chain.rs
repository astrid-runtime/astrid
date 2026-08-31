//! The atomic mutation-side transition: one call commits the canonical
//! frame, the checked `audit_seq` advance, and the rolling-root advance
//! together, or fails before any state changes.

use super::codec::{Frame, MAX_FRAME_BYTES};
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
    root: [u8; root::ROOT_LEN],
    class: super::types::AuditClass,
}

impl RecordScratch {
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
    seq: u64,
    class: super::types::AuditClass,
    root: [u8; root::ROOT_LEN],
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

    /// Starts from an already-minted authority so boot provisioning can create
    /// exactly one signer custodian and one verifier-anchor custodian.
    pub(crate) fn genesis_custodied(
        boot: BootSessionId,
        authority: AuditAuthority,
    ) -> Result<Self, AuditError> {
        if authority.boot() != boot {
            return Err(AuditError::CheckpointMismatch);
        }
        let root_hasher = root::RootHasher::new();
        let root = root_hasher.genesis(boot);
        Ok(Self {
            boot,
            authority,
            root_hasher,
            seq: 0,
            root,
            relay: AuditRelay::new(boot),
            record_scratch: RecordScratch {
                encoded: [0; MAX_FRAME_BYTES],
                encoded_len: 0,
                seq: 0,
                root: [0; root::ROOT_LEN],
                class: super::types::AuditClass::DomainCreate,
            },
            frame_scratch: MaybeUninit::uninit(),
        })
    }

    /// Restores from a previously sealed trusted checkpoint. The checkpoint
    /// itself binds boot/session, exact sequence, root, codec/version, and
    /// relay generation; the relay generation is preserved rather than reset.
    pub(crate) fn restore(
        checkpoint: AuditCheckpoint,
        authority: AuditAuthority,
    ) -> Result<Self, AuditError> {
        if checkpoint.boot() != authority.boot() {
            return Err(AuditError::CheckpointMismatch);
        }
        if checkpoint.codec_version() != super::CODEC_VERSION
            || !checkpoint.verify_tag(authority.context())
            || checkpoint.relay_generation() == 0
        {
            return Err(AuditError::CheckpointMismatch);
        }
        let next_seq = checkpoint
            .seq()
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
        let relay =
            AuditRelay::restore(checkpoint.boot(), checkpoint.relay_generation(), next_seq)?;
        Ok(Self {
            boot: checkpoint.boot(),
            authority,
            root_hasher: root::RootHasher::new(),
            seq: checkpoint.seq(),
            root: checkpoint.root(),
            relay,
            record_scratch: RecordScratch {
                encoded: [0; MAX_FRAME_BYTES],
                encoded_len: 0,
                seq: 0,
                root: [0; root::ROOT_LEN],
                class: super::types::AuditClass::DomainCreate,
            },
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

    /// Encodes and roots the candidate in chain-owned scratch without moving
    /// either authoritative cursor.
    fn stage_record(
        &mut self,
        event: &AuditEvent,
        next: u64,
    ) -> Result<[u8; root::ROOT_LEN], AuditError> {
        let prev_root = Some(self.root);
        let frame = Frame::write_new(&mut self.frame_scratch, self.boot, next, event, prev_root)?;
        let encoded_len = frame.encode(&mut self.record_scratch.encoded)?.len();
        let next_root = self.root_hasher.advance(
            self.root,
            self.boot,
            next,
            &self.record_scratch.encoded[..encoded_len],
        );

        self.record_scratch.encoded_len = encoded_len;
        self.record_scratch.seq = next;
        self.record_scratch.root = next_root;
        self.record_scratch.class = event.class();
        Ok(next_root)
    }

    /// Acknowledges through the chain's kernel-owned authentication context;
    /// callers can present only the verifier's successful-fold receipt.
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

    /// Appends one mandatory event as one atomic transition. All fallible
    /// steps complete on temporaries before the single commit; a failure
    /// leaves sequence, root, and relay untouched. Relay publication is
    /// downstream evidence only: its overflow is an explicit handoff state
    /// and can never omit or rewrite the already-rooted event.
    pub fn append(&mut self, event: AuditEvent) -> Result<u64, AuditError> {
        let next = self
            .seq
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
        let next_root = self.stage_record(&event, next)?;

        // The relay is mandatory for this first-slice mutation transition.
        // A reserve or window failure returns before either authoritative
        // cursor advances, so no rooted record is stranded outside the
        // bounded handoff proof. The fallible relay publish performs every
        // check before mutating a slot or cursor.
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

    /// Roots and stages one event in chain-owned scratch, invokes the
    /// independent verifier, and retires it before return. The callable keeps
    /// the verifier out of this method's static type while the large frame
    /// stays off the live IPC stack.
    #[inline(never)]
    pub(crate) fn append_verified<F>(
        &mut self,
        event: &AuditEvent,
        verify: &mut F,
    ) -> Result<AuditObservation, AuditError>
    where
        F: FnMut(&[u8], &[u8; root::ROOT_LEN]) -> Result<[u8; root::ROOT_LEN], AuditError>,
    {
        let next = self
            .seq
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
        self.stage_record(event, next)?;

        // Immediate-retire mode is exclusive. Any buffered/in-flight record
        // means the caller must use the retained-evidence path; checking here
        // prevents the verifier from advancing before the transaction fails.
        self.relay.require_empty_for_immediate_retire()?;
        self.relay
            .can_publish(next, event.class().is_terminal_or_invalidation())?;
        let receipt_tag = verify(self.record_scratch.frame(), &self.record_scratch.root)?;
        let seq = self.record_scratch.seq;
        let root = self.record_scratch.root;
        let class = self.record_scratch.class;
        self.relay.publish_retired(
            seq,
            self.record_scratch.frame(),
            root,
            self.record_scratch.mandatory(),
            receipt_tag,
            self.authority.context(),
        )?;

        self.seq = seq;
        self.root = root;
        Ok(AuditObservation { seq, class, root })
    }

    /// Kernel-authenticated checkpoint bound to the exact current state.
    pub fn checkpoint(&self) -> AuditCheckpoint {
        self.relay
            .checkpoint(self.root, self.seq, self.authority.context())
    }
}
