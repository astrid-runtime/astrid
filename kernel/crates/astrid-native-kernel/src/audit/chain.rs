//! The atomic mutation-side transition: one call commits the canonical
//! frame, the checked `audit_seq` advance, and the rolling-root advance
//! together, or fails before any state changes.

use super::codec::{Frame, MAX_FRAME_BYTES};
use super::relay::AuditRelay;
use super::root;
use super::types::{
    AuditAuthority, AuditCheckpoint, AuditError, AuditEvent, BootSessionId, KernelSecretEntropy,
};

pub(crate) struct AuditChain {
    boot: BootSessionId,
    authority: AuditAuthority,
    seq: u64,
    root: [u8; root::ROOT_LEN],
    relay: AuditRelay,
}

impl AuditChain {
    /// Starts a new boot/session chain at the domain-separated genesis root.
    pub fn genesis(boot: BootSessionId, secret: KernelSecretEntropy) -> Result<Self, AuditError> {
        let authority = AuditAuthority::mint(boot, secret).ok_or(AuditError::MalformedFrame)?;
        Ok(Self {
            boot,
            authority,
            seq: 0,
            root: root::genesis(boot),
            relay: AuditRelay::new(boot),
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
            seq: checkpoint.seq(),
            root: checkpoint.root(),
            relay,
        })
    }

    pub const fn boot(&self) -> BootSessionId {
        self.boot
    }

    pub(crate) const fn authority(&self) -> AuditAuthority {
        self.authority
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
        let prev_root = Some(self.root);
        let frame = Frame::new(self.boot, next, &event, prev_root)?;
        let mut buf = [0; MAX_FRAME_BYTES];
        let encoded = frame.encode(&mut buf)?;
        let next_root = root::advance(self.root, self.boot, next, encoded);

        // The relay is mandatory for this first-slice mutation transition.
        // A reserve or window failure returns before either authoritative
        // cursor advances, so no rooted record is stranded outside the
        // bounded handoff proof. The fallible relay publish performs every
        // check before mutating a slot or cursor.
        self.relay.publish(
            next,
            encoded,
            next_root,
            event.class().is_terminal_or_invalidation(),
        )?;

        // Commit: frame, checked seq, rolling root, and relay handoff all
        // advance together after every fallible step has succeeded.
        self.seq = next;
        self.root = next_root;
        Ok(next)
    }

    /// Kernel-authenticated checkpoint bound to the exact current state.
    pub fn checkpoint(&self) -> AuditCheckpoint {
        self.relay
            .checkpoint(self.root, self.seq, self.authority.context())
    }
}
