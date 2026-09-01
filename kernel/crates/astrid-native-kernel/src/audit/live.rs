//! Kernel-private live verifier custody and consuming fold transaction.
//!
//! The host `native-audit-verifier` is retained/offline only. This verifier is
//! the sole live authority, is owned by `AuditChain`, and commits only after
//! relay authentication succeeds. Its post-relay tail deliberately contains
//! assignments and the infallible observation return: there is no encode, tag
//! check, allocation, checked operation, assert, or panic after the relay has
//! accepted retirement.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

use super::relay::AuditRelay;
use super::root;
use super::types::{
    AuditAuthority, AuditCheckpoint, AuditClass, AuditError, BootSessionId, CheckpointAuthContext,
};

/// Process-scoped identity allocation. There is intentionally no reset or
/// replacement entry point; test runtime reset changes custody, never this
/// counter.
static NEXT_LIVE_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AuthorityInstance {
    id: NonZeroU64,
    boot: BootSessionId,
    authority_id: u64,
}

impl AuthorityInstance {
    #[cfg(test)]
    pub(super) fn checked_id_for_test(observed: u64) -> Result<NonZeroU64, AuditError> {
        Self::checked_id(observed)
    }

    fn checked_id(observed: u64) -> Result<NonZeroU64, AuditError> {
        observed
            .checked_add(1)
            .ok_or(AuditError::LiveInstanceOverflow)?;
        NonZeroU64::new(observed).ok_or(AuditError::LiveInstanceOverflow)
    }

    fn allocate() -> Result<NonZeroU64, AuditError> {
        let mut observed = NEXT_LIVE_INSTANCE_ID.load(Ordering::Acquire);
        loop {
            let next = observed
                .checked_add(1)
                .ok_or(AuditError::LiveInstanceOverflow)?;
            let _ = Self::checked_id(observed)?;
            match NEXT_LIVE_INSTANCE_ID.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return NonZeroU64::new(observed).ok_or(AuditError::LiveInstanceOverflow);
                },
                Err(updated) => observed = updated,
            }
        }
    }
}

/// Kernel-private fold state for the immediately retired audit path. Move
/// only by construction: cloning this custody would create a second live
/// authority without a second anchor.
pub(super) struct LiveVerifier {
    instance: AuthorityInstance,
    next_seq: u64,
    root: [u8; root::ROOT_LEN],
    context: CheckpointAuthContext,
    next_transaction_id: u64,
}

#[derive(Clone, Copy)]
pub(super) struct LiveReservation {
    instance: AuthorityInstance,
    transaction_id: NonZeroU64,
    next_seq: u64,
}

/// A staged, consuming live transaction. The mutable verifier borrow makes
/// simultaneous transactions unspellable, and the private fields make this
/// state unconstructable outside this module. Dropping without commit leaves
/// the verifier cursor unchanged; a rejected reservation may burn its ID.
pub(super) struct PreparedLive<'a> {
    verifier: &'a mut LiveVerifier,
    frame: &'a [u8],
    transaction_id: NonZeroU64,
    seq: u64,
    next_seq: u64,
    root: [u8; root::ROOT_LEN],
    class: AuditClass,
    receipt_tag: [u8; root::ROOT_LEN],
}

impl LiveVerifier {
    pub(super) fn genesis(
        boot: BootSessionId,
        authority: &AuditAuthority,
    ) -> Result<Self, AuditError> {
        if authority.boot() != boot {
            return Err(AuditError::CheckpointMismatch);
        }
        let root = root::RootHasher::new().genesis(boot);
        Self::new(boot, authority, root, 1)
    }

    pub(super) fn restore(
        checkpoint: &AuditCheckpoint,
        authority: &AuditAuthority,
    ) -> Result<Self, AuditError> {
        if checkpoint.boot() != authority.boot()
            || checkpoint.codec_version() != super::CODEC_VERSION
            || !checkpoint.verify_tag(authority.context())
            || checkpoint.relay_generation() == 0
        {
            return Err(AuditError::CheckpointMismatch);
        }
        let next_seq = checkpoint
            .seq()
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
        Self::new(checkpoint.boot(), authority, checkpoint.root(), next_seq)
    }

    fn new(
        boot: BootSessionId,
        authority: &AuditAuthority,
        root: [u8; root::ROOT_LEN],
        next_seq: u64,
    ) -> Result<Self, AuditError> {
        if authority.boot() != boot || next_seq == 0 {
            return Err(AuditError::CheckpointMismatch);
        }
        let instance = AuthorityInstance {
            id: AuthorityInstance::allocate()?,
            boot,
            authority_id: authority.context().authority_id(),
        };
        Ok(Self {
            instance,
            next_seq,
            root,
            context: authority
                .live_context()
                .ok_or(AuditError::CheckpointMismatch)?,
            next_transaction_id: 1,
        })
    }

    pub(super) fn cursor(&self) -> (u64, [u8; root::ROOT_LEN]) {
        (self.next_seq, self.root)
    }

    #[cfg(test)]
    pub(super) fn transaction_id(&self) -> u64 {
        self.next_transaction_id
    }

    #[cfg(test)]
    pub(super) fn force_transaction_overflow_for_test(&mut self) {
        self.next_transaction_id = u64::MAX;
    }

    /// Reserves the transaction identity before all later preparation checks.
    /// A burned reservation is the only authoritative-live state changed by a
    /// rejection; the verifier cursor, chain cursor, and relay slots do not
    /// move.
    fn reserve_transaction(&mut self) -> Result<NonZeroU64, AuditError> {
        let transaction_id = self
            .next_transaction_id
            .checked_add(1)
            .ok_or(AuditError::LiveTransactionOverflow)?;
        self.next_transaction_id = transaction_id;
        NonZeroU64::new(transaction_id).ok_or(AuditError::LiveTransactionOverflow)
    }

    pub(super) fn reserve(
        &mut self,
        authority: &AuditAuthority,
        expected_seq: u64,
    ) -> Result<LiveReservation, AuditError> {
        let instance = AuthorityInstance {
            id: self.instance.id,
            boot: authority.boot(),
            authority_id: authority.context().authority_id(),
        };
        if self.instance != instance || expected_seq != self.next_seq {
            return Err(AuditError::CheckpointMismatch);
        }
        let transaction_id = self.reserve_transaction()?;
        Ok(LiveReservation {
            instance,
            transaction_id,
            next_seq: expected_seq
                .checked_add(1)
                .ok_or(AuditError::SequenceOverflow)?,
        })
    }

    pub(super) fn finish<'chain>(
        &'chain mut self,
        reservation: LiveReservation,
        frame: &'chain [u8],
        root: [u8; root::ROOT_LEN],
        class: AuditClass,
        receipt_tag: [u8; root::ROOT_LEN],
    ) -> Result<PreparedLive<'chain>, AuditError> {
        if reservation.instance != self.instance
            || reservation.transaction_id.get() != self.next_transaction_id
        {
            return Err(AuditError::CheckpointMismatch);
        }
        let seq = self.next_seq;
        Ok(PreparedLive {
            verifier: self,
            frame,
            transaction_id: reservation.transaction_id,
            seq,
            next_seq: reservation.next_seq,
            root,
            class,
            receipt_tag,
        })
    }
}

impl<'a> PreparedLive<'a> {
    /// Authentication and retirement are the only fallible mutation. Success
    /// leaves only assignment-shaped verifier and chain-tail commits.
    pub(super) fn commit(
        self,
        relay: &mut AuditRelay,
        context: &CheckpointAuthContext,
    ) -> Result<super::chain::AuditObservation, AuditError> {
        match relay.publish_retired(
            self.seq,
            self.frame,
            self.root,
            self.class.is_terminal_or_invalidation(),
            self.receipt_tag,
            context,
        ) {
            Ok(()) => {},
            Err(error) => return Err(error),
        }

        let verifier = self.verifier;
        verifier.next_seq = self.next_seq;
        verifier.root = self.root;
        Ok(super::chain::AuditObservation {
            seq: self.seq,
            class: self.class,
            root: self.root,
        })
    }

    #[cfg(test)]
    pub(super) fn transaction_id(&self) -> NonZeroU64 {
        self.transaction_id
    }

    #[cfg(test)]
    pub(super) fn set_raw_receipt_tag_for_test(&mut self, tag: [u8; root::ROOT_LEN]) {
        self.receipt_tag = tag;
    }
}
