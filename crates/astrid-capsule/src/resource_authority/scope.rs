//! Host-only scope, reservation, and authority values for the table.

use std::{collections::BTreeSet, time::Instant};

use astrid_core::PrincipalUid;
use astrid_resource_types::{
    AccountId, AuthorityEpoch, BudgetId, ObjectGeneration, OwnerId, ResourceErrorCode, ResourceId,
    ResourceKind, Rights, TransferClass,
};

/// Hard DoS bound for a host-admitted object subset. This is a table invariant,
/// not an operator policy knob: scope admission must remain bounded even when
/// an untrusted request is converted into a host-side selector.
pub(super) const MAX_SCOPE_OBJECTS: usize = 64;

/// A bounded, host-only set of semantic-object identities.
///
/// This type intentionally has no path, string, byte-decoding, or serde
/// constructor. A scope describes an already admitted object subset; it never
/// grants access by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResourceScope {
    pub(super) identities: BTreeSet<ResourceId>,
}

impl ResourceScope {
    /// Build the smallest scope that contains one admitted object identity.
    #[must_use]
    pub(crate) fn singleton(identity: ResourceId) -> Self {
        Self {
            identities: BTreeSet::from([identity]),
        }
    }

    /// Build a bounded host selector from already typed identities.
    ///
    /// The ceiling is raw input cardinality, not unique-set size.
    pub(crate) fn from_identities<I>(identities: I) -> Result<Self, ResourceErrorCode>
    where
        I: IntoIterator<Item = ResourceId>,
    {
        let mut admitted = BTreeSet::new();
        // Bound raw input cardinality, not unique-set size, so a repeating or
        // unbounded iterator still trips the DoS ceiling.
        let mut raw_count = 0usize;
        for identity in identities {
            raw_count = raw_count
                .checked_add(1)
                .ok_or(ResourceErrorCode::InvalidDescriptor)?;
            if raw_count > MAX_SCOPE_OBJECTS {
                return Err(ResourceErrorCode::InvalidDescriptor);
            }
            admitted.insert(identity);
        }
        Ok(Self {
            identities: admitted,
        })
    }

    pub(super) fn contains(&self, identity: ResourceId) -> bool {
        self.identities.contains(&identity)
    }

    pub(super) fn is_subset_of(&self, admitted: &Self) -> bool {
        self.identities.is_subset(&admitted.identities)
    }
}

/// A host reservation linked to a descriptor identity and a remaining unit
/// envelope. The descriptor IDs are labels only; this wrapper is the live
/// reservation held by the authority table.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Reservation {
    pub(super) account: AccountId,
    pub(super) budget: BudgetId,
    pub(super) remaining: u64,
}

impl Reservation {
    /// Reserve units under an already admitted accounting and budget domain.
    ///
    /// The constructor is crate-private so a guest cannot deserialize or mint
    /// a live envelope from an [`AccountId`] or [`BudgetId`].
    #[must_use]
    pub(crate) const fn new(account: AccountId, budget: BudgetId, units: u64) -> Self {
        Self {
            account,
            budget,
            remaining: units,
        }
    }
}

/// A selector for a host revocation domain. It is not a bearer token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RevocationSelector(pub(super) u64);

impl RevocationSelector {
    /// Construct a selector at a trusted host boundary.
    #[must_use]
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Host-side admission options that carry authority-bearing checks.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AdmissionOptions {
    pub(super) rights: Rights,
    pub(super) authority_epoch: AuthorityEpoch,
    pub(super) expiry: Option<Instant>,
    pub(super) revocation: Option<RevocationSelector>,
}

impl AdmissionOptions {
    /// Construct options from a current host epoch and optional invalidators.
    #[must_use]
    pub(crate) const fn new(
        rights: Rights,
        authority_epoch: AuthorityEpoch,
        expiry: Option<Instant>,
        revocation: Option<RevocationSelector>,
    ) -> Self {
        Self {
            rights,
            authority_epoch,
            expiry,
            revocation,
        }
    }
}

/// Opaque table-local handle bound to an object generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ResourceHandle {
    pub(super) slot: usize,
    pub(super) generation: ObjectGeneration,
}

impl ResourceHandle {
    #[cfg(test)]
    pub(super) fn generation(self) -> ObjectGeneration {
        self.generation
    }
}

/// Live authority resolved by [`ResourceAuthorityTable::lookup`].
///
/// This type has no serialization or public constructor. Its reservation,
/// scope, principal, and revocation state are all table-owned.
#[derive(Debug)]
pub(crate) struct ResourceAuthority {
    pub(super) kind: ResourceKind,
    pub(super) identity: ResourceId,
    pub(super) scope: ResourceScope,
    pub(super) reservation: Reservation,
    pub(super) rights: Rights,
    pub(super) owner: OwnerId,
    pub(super) principal: PrincipalUid,
    pub(super) initiator: PrincipalUid,
    pub(super) authority_epoch: AuthorityEpoch,
    pub(super) transfer_class: TransferClass,
    pub(super) expiry: Option<Instant>,
    pub(super) revocation: Option<RevocationSelector>,
    pub(super) revoked: bool,
    pub(super) parent: Option<ResourceHandle>,
    pub(super) resource: SemanticObject,
}

impl ResourceAuthority {
    #[must_use]
    pub(crate) const fn kind(&self) -> ResourceKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> ResourceId {
        self.identity
    }

    #[must_use]
    pub(crate) const fn rights(&self) -> Rights {
        self.rights
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> OwnerId {
        self.owner
    }

    #[must_use]
    pub(crate) const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    #[must_use]
    pub(crate) const fn transfer_class(&self) -> TransferClass {
        self.transfer_class
    }

    #[must_use]
    pub(crate) const fn remaining_budget(&self) -> u64 {
        self.reservation.remaining
    }

    #[must_use]
    pub(crate) const fn budget_id(&self) -> BudgetId {
        self.reservation.budget
    }

    #[must_use]
    pub(crate) const fn account_id(&self) -> AccountId {
        self.reservation.account
    }

    #[must_use]
    pub(crate) const fn scope(&self) -> &ResourceScope {
        &self.scope
    }

    #[must_use]
    pub(crate) const fn principal(&self) -> PrincipalUid {
        self.principal
    }

    #[must_use]
    pub(crate) const fn initiator(&self) -> PrincipalUid {
        self.initiator
    }

    #[must_use]
    pub(crate) const fn parent(&self) -> Option<ResourceHandle> {
        self.parent
    }
}

/// Private in-memory fixture payload for the one admitted kind.
#[derive(Debug)]
pub(super) struct SemanticObject {
    pub(super) identity: ResourceId,
}
