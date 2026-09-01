//! Kernel-private live verifier custody and consuming fold transaction.
//!
//! The host `native-audit-verifier` is retained/offline only. This verifier is
//! the sole live authority, is owned by `AuditChain`, and commits only after
//! relay authentication succeeds. It owns the unkeyed canonical root state;
//! the authority's verification key is never cloned into live custody.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

use super::codec::Frame;
use super::relay::AuditRelay;
use super::root::{self, RootHasher};
use super::types::{AuditAuthority, AuditClass, AuditError, BootSessionId, CheckpointAuthContext};

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

/// Kernel-private fold state for the immediately retired audit path. The
/// authority's keyed context is borrowed only while minting a receipt; this
/// struct is therefore not a second verification-key custodian.
pub(super) struct LiveVerifier {
    instance: AuthorityInstance,
    next_seq: u64,
    root: [u8; root::ROOT_LEN],
    root_hasher: RootHasher,
    next_transaction_id: u64,
}

/// A one-shot reservation. There is deliberately no `Clone` or `Copy`: the
/// consuming `finish` call is the only way to turn it into prepared custody.
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
        let root_hasher = RootHasher::new();
        let root = root_hasher.genesis(boot);
        Self::new(boot, authority, root_hasher, root, 1)
    }

    fn new(
        boot: BootSessionId,
        authority: &AuditAuthority,
        root_hasher: RootHasher,
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
            root_hasher,
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
    #[inline(never)]
    fn reserve_transaction(&mut self) -> Result<NonZeroU64, AuditError> {
        let transaction_id = self
            .next_transaction_id
            .checked_add(1)
            .ok_or(AuditError::LiveTransactionOverflow)?;
        self.next_transaction_id = transaction_id;
        NonZeroU64::new(transaction_id).ok_or(AuditError::LiveTransactionOverflow)
    }

    #[inline(never)]
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

    /// Derives the sole canonical rolling root and receipt candidate from this
    /// verifier's authoritative previous root and the staged canonical frame.
    /// `decoded` is chain scratch initialized by `stage_record`; `frame` is
    /// its exact canonical encoding. Their embedded boot, sequence, and
    /// previous root are checked so a stale byte string cannot fold as if it
    /// were current.
    #[inline(never)]
    pub(super) fn finish<'chain>(
        &'chain mut self,
        reservation: LiveReservation,
        decoded: &Frame,
        frame: &'chain [u8],
        relay_generation: u64,
        context: &CheckpointAuthContext,
    ) -> Result<PreparedLive<'chain>, AuditError> {
        if reservation.instance != self.instance
            || reservation.transaction_id.get() != self.next_transaction_id
            || context.boot() != self.instance.boot
            || context.authority_id() != self.instance.authority_id
            || relay_generation == 0
        {
            return Err(AuditError::CheckpointMismatch);
        }
        if decoded.boot() != self.instance.boot
            || decoded.seq() != self.next_seq
            || decoded.prev_root() != Some(self.root)
        {
            return Err(AuditError::CheckpointMismatch);
        }

        let root = self
            .root_hasher
            .advance(self.root, self.instance.boot, self.next_seq, frame);
        let receipt_tag = context.ack_tag(
            self.instance.boot,
            relay_generation,
            self.next_seq,
            root,
            frame,
        );
        let seq = self.next_seq;
        Ok(PreparedLive {
            verifier: self,
            frame,
            transaction_id: reservation.transaction_id,
            seq,
            next_seq: reservation.next_seq,
            root,
            class: decoded.class(),
            receipt_tag,
        })
    }
}

impl<'a> PreparedLive<'a> {
    /// Authentication and retirement are the only fallible mutation. Success
    /// leaves only assignment-shaped verifier and chain-tail commits.
    #[inline(never)]
    pub(super) fn commit(
        self,
        relay: &mut AuditRelay,
        context: &CheckpointAuthContext,
    ) -> Result<super::chain::AuditObservation, AuditError> {
        relay.publish_retired(
            self.seq,
            self.frame,
            self.root,
            self.class.is_terminal_or_invalidation(),
            self.receipt_tag,
            context,
        )?;

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
}
