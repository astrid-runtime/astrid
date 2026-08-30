//! Kernel-owned bounded audit relay: preallocated slots, checked cursors,
//! credits/acks, bounded redelivery, and no dynamic allocation. Relay state
//! is flow control only; it is never authority and never a root input.

use super::codec::MAX_FRAME_BYTES;
use super::root;
use super::types::{
    AuditCheckpoint, AuditError, BootSessionId, CheckpointAuthKey, MAX_TERMINAL_RECORDS_PER_BATCH,
};

/// Distinct from the #1758 32-entry relation delta rings and their two
/// reader slots. The window statically reserves capacity for at least one
/// full admitted atomic batch of mandatory terminal/invalidation records.
pub(crate) const AUDIT_RELAY_SLOTS: usize = 64;

const _: () = assert!(
    AUDIT_RELAY_SLOTS >= MAX_TERMINAL_RECORDS_PER_BATCH,
    "audit relay must reserve a full admitted batch of terminal records",
);

/// One retained, already-rooted record handed downstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayRecord {
    seq: u64,
    root: [u8; root::ROOT_LEN],
    frame_len: usize,
    frame: [u8; MAX_FRAME_BYTES],
}

impl RelayRecord {
    pub(crate) fn new(seq: u64, root: [u8; root::ROOT_LEN], frame: &[u8]) -> Self {
        let mut stored = [0; MAX_FRAME_BYTES];
        stored[..frame.len()].copy_from_slice(frame);
        Self {
            seq,
            root,
            frame_len: frame.len(),
            frame: stored,
        }
    }

    pub const fn seq(self) -> u64 {
        self.seq
    }

    pub const fn root(self) -> [u8; root::ROOT_LEN] {
        self.root
    }

    pub fn frame(&self) -> &[u8] {
        &self.frame[..self.frame_len]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Buffered,
    InFlight,
}

#[derive(Clone, Copy)]
struct Slot {
    record: RelayRecord,
    state: SlotState,
}

/// Fixed-capacity handoff window for already-rooted records. Overflow is an
/// explicit `HandoffIncomplete`/`ResyncRequired` state: the authoritative
/// chain is untouched, nothing is silently omitted, and recovery is a
/// generation-bumped resync from a trusted checkpoint.
pub struct AuditRelay {
    boot: BootSessionId,
    generation: u64,
    next_seq: u64,
    oldest_seq: u64,
    outstanding: usize,
    credits: u64,
    slots: [Option<Slot>; AUDIT_RELAY_SLOTS],
}

impl AuditRelay {
    pub(super) fn new(boot: BootSessionId) -> Self {
        Self {
            boot,
            generation: 1,
            next_seq: 1,
            oldest_seq: 1,
            outstanding: 0,
            credits: 0,
            slots: [None; AUDIT_RELAY_SLOTS],
        }
    }

    /// Restores flow-control state from a trusted checkpoint without losing
    /// its relay generation. Outstanding evidence is explicitly not carried
    /// across the restart; a verifier restarts from this checkpoint.
    pub(super) fn restore(
        boot: BootSessionId,
        generation: u64,
        next_seq: u64,
    ) -> Result<Self, AuditError> {
        if generation == 0 {
            return Err(AuditError::MalformedFrame);
        }
        Ok(Self {
            boot,
            generation,
            next_seq,
            oldest_seq: next_seq,
            outstanding: 0,
            credits: 0,
            slots: [None; AUDIT_RELAY_SLOTS],
        })
    }

    /// Publishes one already-rooted record. Window overflow keeps the
    /// authoritative event rooted but downstream-invisible until a resync.
    pub(super) fn publish(
        &mut self,
        seq: u64,
        frame: &[u8],
        root: [u8; root::ROOT_LEN],
        mandatory: bool,
    ) -> Result<(), AuditError> {
        if seq != self.next_seq {
            return Err(AuditError::RelayInvalidCursor);
        }
        let next_seq = seq.checked_add(1).ok_or(AuditError::SequenceOverflow)?;
        if self.outstanding == AUDIT_RELAY_SLOTS {
            return Err(AuditError::HandoffIncomplete);
        }
        if !mandatory && self.outstanding >= AUDIT_RELAY_SLOTS - MAX_TERMINAL_RECORDS_PER_BATCH {
            return Err(AuditError::HandoffIncomplete);
        }
        let index = Self::slot_index(seq);
        self.slots[index] = Some(Slot {
            record: RelayRecord::new(seq, root, frame),
            state: SlotState::Buffered,
        });
        self.next_seq = next_seq;
        self.outstanding += 1;
        Ok(())
    }

    pub fn grant_credits(&mut self, credits: u64) -> Result<(), AuditError> {
        self.credits = self
            .credits
            .checked_add(credits)
            .ok_or(AuditError::RelayInvalidCursor)?;
        Ok(())
    }

    /// Non-blocking take of the oldest buffered record, consuming one credit.
    pub fn take(&mut self) -> Option<RelayRecord> {
        if self.credits == 0 {
            return None;
        }
        let index = self.oldest_buffered_index()?;
        if let Some(slot) = self.slots[index].as_mut() {
            slot.state = SlotState::InFlight;
        }
        self.credits -= 1;
        self.slots[index].map(|slot| slot.record)
    }

    /// Bounded redelivery of every outstanding record in sequence order
    /// (lost ack). Never rewrites or omits an already-rooted event.
    pub fn redeliver(&self) -> impl Iterator<Item = RelayRecord> + '_ {
        (0..self.outstanding).filter_map(move |offset| {
            let seq = self.oldest_seq + offset as u64;
            let index = Self::slot_index(seq);
            self.slots[index].map(|slot| slot.record)
        })
    }

    /// Retires exactly the oldest in-flight record. Besides contiguity and
    /// source-root equality, the caller must present the keyed receipt emitted
    /// only by a successful independent fold of this exact canonical frame.
    pub fn ack(
        &mut self,
        seq: u64,
        folded_root: [u8; root::ROOT_LEN],
        receipt_tag: [u8; root::ROOT_LEN],
        auth_key: CheckpointAuthKey,
    ) -> Result<(), AuditError> {
        if self.outstanding == 0 || seq != self.oldest_seq {
            return Err(AuditError::RelayStaleCursor);
        }
        let index = Self::slot_index(seq);
        let next_oldest = seq.checked_add(1).ok_or(AuditError::SequenceOverflow)?;
        let Some(slot) = self.slots[index] else {
            return Err(AuditError::RelayInvalidCursor);
        };
        if slot.state != SlotState::InFlight {
            return Err(AuditError::RelayNotInFlight);
        }
        if slot.record.root() != folded_root {
            return Err(AuditError::RootMismatch);
        }
        if root::ack_tag(
            slot.record.seq(),
            slot.record.root(),
            slot.record.frame(),
            &auth_key,
        ) != receipt_tag
        {
            return Err(AuditError::RootMismatch);
        }
        self.slots[index] = None;
        self.oldest_seq = next_oldest;
        self.outstanding -= 1;
        Ok(())
    }

    /// Window-overflow recovery: bump the relay generation, drop buffered
    /// evidence, and return a trusted checkpoint for verifier restart. The
    /// kernel root is untouched.
    pub fn resync(
        &mut self,
        current_root: [u8; root::ROOT_LEN],
        current_seq: u64,
        auth_key: CheckpointAuthKey,
    ) -> Result<AuditCheckpoint, AuditError> {
        let next_seq = current_seq
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(AuditError::RelayGenerationOverflow)?;
        self.slots = [None; AUDIT_RELAY_SLOTS];
        self.outstanding = 0;
        self.next_seq = next_seq;
        self.oldest_seq = self.next_seq;
        self.credits = 0;
        Ok(self.checkpoint(current_root, current_seq, auth_key))
    }

    /// Trusted checkpoint bound to boot/session, exact seq, root, codec
    /// version, and relay generation.
    pub fn checkpoint(
        &self,
        current_root: [u8; root::ROOT_LEN],
        current_seq: u64,
        auth_key: CheckpointAuthKey,
    ) -> AuditCheckpoint {
        AuditCheckpoint::seal(
            self.boot,
            current_seq,
            current_root,
            self.generation,
            auth_key,
        )
        .expect("current relay generation is nonzero")
    }

    pub(super) const fn generation(&self) -> u64 {
        self.generation
    }

    fn slot_index(seq: u64) -> usize {
        ((seq - 1) % AUDIT_RELAY_SLOTS as u64) as usize
    }

    fn oldest_buffered_index(&self) -> Option<usize> {
        (0..self.outstanding)
            .map(|offset| Self::slot_index(self.oldest_seq + offset as u64))
            .find(|index| {
                matches!(
                    self.slots[*index],
                    Some(Slot {
                        state: SlotState::Buffered,
                        ..
                    })
                )
            })
    }
}
