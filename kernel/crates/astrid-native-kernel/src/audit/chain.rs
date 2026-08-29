//! The atomic mutation-side transition: one call commits the canonical
//! frame, the checked `audit_seq` advance, and the rolling-root advance
//! together, or fails before any state changes.

use super::codec::{Frame, MAX_FRAME_BYTES};
use super::relay::AuditRelay;
use super::root;
use super::types::{AuditCheckpoint, AuditError, AuditEvent, BootSessionId};

pub(crate) struct AuditChain {
    boot: BootSessionId,
    seq: u64,
    root: [u8; root::ROOT_LEN],
    relay: AuditRelay,
}

impl AuditChain {
    /// Starts a new boot/session chain at the domain-separated genesis root.
    pub fn genesis(boot: BootSessionId) -> Self {
        Self {
            boot,
            seq: 0,
            root: root::genesis(boot),
            relay: AuditRelay::new(boot),
        }
    }

    /// Restores a chain from previously sealed trusted state. Crate-private
    /// until a later slice wires checkpoint restore into a consumer.
    pub(crate) fn restore(boot: BootSessionId, seq: u64, root: [u8; root::ROOT_LEN]) -> Self {
        Self {
            boot,
            seq,
            root,
            relay: AuditRelay::new(boot),
        }
    }

    pub const fn boot(&self) -> BootSessionId {
        self.boot
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
        let prev_root = if self.seq == 0 { None } else { Some(self.root) };
        let frame = Frame::new(self.boot, next, &event, prev_root);
        let mut buf = [0; MAX_FRAME_BYTES];
        let encoded = frame.encode(&mut buf)?;
        let next_root = root::advance(self.root, self.boot, next, encoded);

        // Commit: frame, checked seq, and rolling root advance together.
        self.seq = next;
        self.root = next_root;

        // Downstream only. A window overflow latches the relay; later
        // publishes fail until an explicit resync rebinds it. The committed
        // record above is authoritative regardless.
        let _ = self.relay.publish(next, encoded, next_root);
        Ok(next)
    }

    /// Kernel-authenticated checkpoint bound to the exact current state.
    pub fn checkpoint(&self) -> AuditCheckpoint {
        self.relay.checkpoint(self.root, self.seq)
    }
}
