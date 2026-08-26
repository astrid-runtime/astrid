//! Slot table and live preflight enforcement.

use std::{borrow::Borrow, collections::BTreeSet, time::Instant};

use astrid_resource_types::{
    AccountId, AuthorityEpoch, BudgetId, ObjectGeneration, OwnerId, ResourceErrorCode, ResourceId,
    ResourceKind, Rights, TransferClass,
};

use crate::stamp::StampedInvocation;

use super::scope::{
    AdmissionOptions, MAX_SCOPE_OBJECTS, Reservation, ResourceAuthority, ResourceHandle,
    ResourceScope, RevocationSelector, SemanticObject,
};

/// Maximum delegation depth checked while resolving a live child.
const MAX_LINEAGE_DEPTH: usize = 64;
/// Reuse the existing per-scope object ceiling as the per-table live ceiling.
///
/// This is a host-side containment bound, not an operator policy knob.
const MAX_LIVE_AUTHORITY_SLOTS: usize = MAX_SCOPE_OBJECTS;
/// A distinct invalidator may address every bounded live authority once.
const MAX_REVOCATION_SELECTORS: usize = MAX_SCOPE_OBJECTS;

#[derive(Debug)]
struct Slot {
    generation: ObjectGeneration,
    authority: Option<ResourceAuthority>,
    retired: bool,
}

impl Slot {
    const fn new() -> Self {
        Self {
            generation: ObjectGeneration::INITIAL,
            authority: None,
            retired: false,
        }
    }
}

/// Host-owned live authority table for invocation-scoped semantic objects.
#[derive(Debug)]
pub(crate) struct ResourceAuthorityTable {
    slots: Vec<Slot>,
    authority_epoch: AuthorityEpoch,
    active_reserved_units: u128,
    released_reserved_units: u128,
    revoked_selectors: BTreeSet<RevocationSelector>,
}

impl Default for ResourceAuthorityTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceAuthorityTable {
    /// Start an empty table at the initial authority epoch.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::new_at_epoch(AuthorityEpoch::INITIAL)
    }

    /// Start an empty table at a trusted current authority epoch.
    #[must_use]
    pub(crate) fn new_at_epoch(authority_epoch: AuthorityEpoch) -> Self {
        Self {
            slots: Vec::new(),
            authority_epoch,
            active_reserved_units: 0,
            released_reserved_units: 0,
            revoked_selectors: BTreeSet::new(),
        }
    }

    #[must_use]
    pub(crate) const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    #[must_use]
    pub(crate) const fn active_reserved_units(&self) -> u128 {
        self.active_reserved_units
    }

    #[must_use]
    pub(crate) const fn released_reserved_units(&self) -> u128 {
        self.released_reserved_units
    }

    /// Number of table-local slot records allocated by this instance.
    #[must_use]
    pub(crate) const fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Number of retained selector tombstones in this instance.
    #[must_use]
    pub(crate) fn revoked_selector_count(&self) -> usize {
        self.revoked_selectors.len()
    }

    /// Admit one invocation-scoped [`ResourceKind::SemanticObject`].
    pub(crate) fn admit(
        &mut self,
        stamp: &StampedInvocation,
        kind: ResourceKind,
        identity: ResourceId,
        scope: ResourceScope,
        reservation: Reservation,
        options: AdmissionOptions,
    ) -> Result<ResourceHandle, ResourceErrorCode> {
        self.validate_admission(kind, identity, &scope, &options, reservation.remaining)?;
        self.reserve_units(reservation.remaining)?;
        let handle = self.allocate_slot();
        let authority = ResourceAuthority {
            kind,
            identity,
            scope,
            reservation,
            rights: options.rights,
            owner: OwnerId::from(stamp.principal()),
            principal: stamp.principal(),
            initiator: stamp.principal(),
            authority_epoch: options.authority_epoch,
            transfer_class: TransferClass::None,
            expiry: options.expiry,
            revocation: options.revocation,
            revoked: false,
            parent: None,
            resource: SemanticObject { identity },
        };
        self.slot_mut(handle)?.authority = Some(authority);
        Ok(handle)
    }

    /// Resolve a live authority for the stamped acting principal.
    pub(crate) fn lookup(
        &self,
        stamp: &StampedInvocation,
        handle: ResourceHandle,
    ) -> Result<&ResourceAuthority, ResourceErrorCode> {
        let authority = self.slot_authority(handle)?;
        self.validate_live(stamp, authority)?;
        Ok(authority)
    }

    /// Check one operation against the live authority without consuming it.
    pub(crate) fn preflight<S>(
        &self,
        stamp: &StampedInvocation,
        handle: ResourceHandle,
        requested_right: Rights,
        requested_scope: S,
        requested_budget: u64,
    ) -> Result<(), ResourceErrorCode>
    where
        S: Borrow<ResourceScope>,
    {
        let authority = self.lookup(stamp, handle)?;
        let requested_scope = requested_scope.borrow();
        if !authority.rights.contains(requested_right) {
            return Err(ResourceErrorCode::MissingRight);
        }
        if !requested_scope.is_subset_of(&authority.scope) {
            return Err(ResourceErrorCode::InvalidDescriptor);
        }
        if requested_budget > authority.reservation.remaining {
            return Err(ResourceErrorCode::Exhausted);
        }
        Ok(())
    }

    /// Create a child authority with an inherited expiry.
    pub(crate) fn attenuate<S>(
        &mut self,
        stamp: &StampedInvocation,
        parent: ResourceHandle,
        rights: Rights,
        scope: S,
        budget: u64,
    ) -> Result<ResourceHandle, ResourceErrorCode>
    where
        S: Borrow<ResourceScope>,
    {
        let expiry = self.lookup(stamp, parent)?.expiry;
        self.attenuate_with_expiry(stamp, parent, rights, scope, budget, expiry)
    }

    /// Create a child authority while enforcing the parent's expiry bound.
    pub(crate) fn attenuate_with_expiry<S>(
        &mut self,
        stamp: &StampedInvocation,
        parent: ResourceHandle,
        rights: Rights,
        scope: S,
        budget: u64,
        expiry: Option<Instant>,
    ) -> Result<ResourceHandle, ResourceErrorCode>
    where
        S: Borrow<ResourceScope>,
    {
        let requested_scope = scope.borrow().clone();
        let snapshot = self.delegation_snapshot(stamp, parent)?;
        self.validate_delegation(&snapshot, rights, &requested_scope, budget, expiry)?;
        let handle = self.allocate_slot();
        self.debit_parent(parent, budget)?;
        let authority = ResourceAuthority {
            kind: snapshot.kind,
            identity: snapshot.identity,
            scope: requested_scope,
            reservation: Reservation::new(snapshot.account, snapshot.budget, budget),
            rights,
            owner: OwnerId::from(stamp.principal()),
            principal: stamp.principal(),
            initiator: stamp.principal(),
            authority_epoch: snapshot.authority_epoch,
            transfer_class: snapshot.transfer_class,
            expiry,
            revocation: snapshot.revocation,
            revoked: false,
            parent: Some(parent),
            resource: SemanticObject {
                identity: snapshot.identity,
            },
        };
        self.slot_mut(handle)?.authority = Some(authority);
        Ok(handle)
    }

    /// Reclaim one live handle and advance its table generation.
    pub(crate) fn reclaim(
        &mut self,
        stamp: &StampedInvocation,
        handle: ResourceHandle,
    ) -> Result<(), ResourceErrorCode> {
        let (parent, reservation) = self.reclaim_snapshot(stamp, handle)?;
        let refund_parent = self.can_refund_parent(parent, &reservation);
        if !refund_parent {
            self.ensure_external_release(reservation.remaining)?;
        }
        let authority = self.slot_mut(handle)?.authority.take();
        if authority.is_none() {
            return Err(ResourceErrorCode::StaleGeneration);
        }
        self.advance_slot(handle)?;
        if refund_parent {
            self.refund_parent(parent, &reservation)?;
        } else {
            self.release_external(reservation.remaining)?;
        }
        Ok(())
    }

    /// Alias used by host drop paths; it retains the stamp boundary.
    pub(crate) fn drop_handle(
        &mut self,
        stamp: &StampedInvocation,
        handle: ResourceHandle,
    ) -> Result<(), ResourceErrorCode> {
        self.reclaim(stamp, handle)
    }

    /// Revoke one live handle without changing its slot generation.
    pub(crate) fn revoke(&mut self, handle: ResourceHandle) -> Result<(), ResourceErrorCode> {
        let authority = self.slot_authority_mut(handle)?;
        authority.revoked = true;
        Ok(())
    }

    /// Revoke one handle after checking the stamped owner.
    pub(crate) fn revoke_for(
        &mut self,
        stamp: &StampedInvocation,
        handle: ResourceHandle,
    ) -> Result<(), ResourceErrorCode> {
        self.reclaim_owner(stamp, handle)?;
        self.revoke(handle)
    }

    /// Revoke every authority carrying a selector from this table.
    pub(crate) fn revoke_selector(
        &mut self,
        selector: RevocationSelector,
    ) -> Result<(), ResourceErrorCode> {
        if self.revoked_selectors.contains(&selector) {
            return Ok(());
        }
        if self.revoked_selectors.len() >= MAX_REVOCATION_SELECTORS {
            return Err(ResourceErrorCode::Exhausted);
        }
        self.revoked_selectors.insert(selector);
        Ok(())
    }

    /// Advance the current epoch; entries from older epochs fail closed.
    pub(crate) fn advance_authority_epoch(&mut self) -> Result<AuthorityEpoch, ResourceErrorCode> {
        let next = self
            .authority_epoch
            .checked_next()
            .map_err(|_| ResourceErrorCode::Internal)?;
        self.authority_epoch = next;
        Ok(next)
    }

    fn validate_admission(
        &self,
        kind: ResourceKind,
        identity: ResourceId,
        scope: &ResourceScope,
        options: &AdmissionOptions,
        units: u64,
    ) -> Result<(), ResourceErrorCode> {
        if kind != ResourceKind::SemanticObject || !scope.contains(identity) {
            return Err(ResourceErrorCode::InvalidDescriptor);
        }
        if options.authority_epoch != self.authority_epoch {
            return Err(ResourceErrorCode::Revoked);
        }
        if options
            .expiry
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            return Err(ResourceErrorCode::Revoked);
        }
        if options
            .revocation
            .is_some_and(|selector| self.revoked_selectors.contains(&selector))
        {
            return Err(ResourceErrorCode::Revoked);
        }
        if self
            .active_reserved_units
            .checked_add(u128::from(units))
            .is_none()
        {
            return Err(ResourceErrorCode::Exhausted);
        }
        if self.live_authority_count() >= MAX_LIVE_AUTHORITY_SLOTS {
            return Err(ResourceErrorCode::Exhausted);
        }
        Ok(())
    }

    fn live_authority_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| !slot.retired && slot.authority.is_some())
            .count()
    }

    fn reserve_units(&mut self, units: u64) -> Result<(), ResourceErrorCode> {
        self.active_reserved_units = self
            .active_reserved_units
            .checked_add(u128::from(units))
            .ok_or(ResourceErrorCode::Exhausted)?;
        Ok(())
    }

    fn allocate_slot(&mut self) -> ResourceHandle {
        if let Some((slot, entry)) = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, entry)| !entry.retired && entry.authority.is_none())
        {
            return ResourceHandle {
                slot,
                generation: entry.generation,
            };
        }
        let slot = self.slots.len();
        self.slots.push(Slot::new());
        ResourceHandle {
            slot,
            generation: ObjectGeneration::INITIAL,
        }
    }

    fn slot_authority(
        &self,
        handle: ResourceHandle,
    ) -> Result<&ResourceAuthority, ResourceErrorCode> {
        let slot = self
            .slots
            .get(handle.slot)
            .ok_or(ResourceErrorCode::StaleGeneration)?;
        if slot.retired || slot.generation != handle.generation {
            return Err(ResourceErrorCode::StaleGeneration);
        }
        slot.authority
            .as_ref()
            .ok_or(ResourceErrorCode::StaleGeneration)
    }

    fn slot_authority_mut(
        &mut self,
        handle: ResourceHandle,
    ) -> Result<&mut ResourceAuthority, ResourceErrorCode> {
        let slot = self
            .slots
            .get_mut(handle.slot)
            .ok_or(ResourceErrorCode::StaleGeneration)?;
        if slot.retired || slot.generation != handle.generation {
            return Err(ResourceErrorCode::StaleGeneration);
        }
        slot.authority
            .as_mut()
            .ok_or(ResourceErrorCode::StaleGeneration)
    }

    fn slot_mut(&mut self, handle: ResourceHandle) -> Result<&mut Slot, ResourceErrorCode> {
        self.slots
            .get_mut(handle.slot)
            .ok_or(ResourceErrorCode::StaleGeneration)
    }

    fn validate_live(
        &self,
        stamp: &StampedInvocation,
        authority: &ResourceAuthority,
    ) -> Result<(), ResourceErrorCode> {
        if authority.resource.identity != authority.identity {
            return Err(ResourceErrorCode::Internal);
        }
        if authority.principal != stamp.principal() || authority.initiator != stamp.principal() {
            return Err(ResourceErrorCode::WrongOwner);
        }
        if authority.authority_epoch != self.authority_epoch {
            return Err(ResourceErrorCode::Revoked);
        }
        if authority.revoked
            || authority
                .revocation
                .is_some_and(|selector| self.revoked_selectors.contains(&selector))
        {
            return Err(ResourceErrorCode::Revoked);
        }
        if authority
            .expiry
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            return Err(ResourceErrorCode::Revoked);
        }
        if !self.lineage_is_live(authority.parent) {
            return Err(ResourceErrorCode::Revoked);
        }
        Ok(())
    }

    fn lineage_is_live(&self, mut parent: Option<ResourceHandle>) -> bool {
        for _ in 0..=MAX_LINEAGE_DEPTH {
            let Some(handle) = parent else {
                return true;
            };
            let Ok(authority) = self.slot_authority(handle) else {
                return false;
            };
            if authority.authority_epoch != self.authority_epoch
                || authority.revoked
                || authority
                    .revocation
                    .is_some_and(|selector| self.revoked_selectors.contains(&selector))
                || authority
                    .expiry
                    .is_some_and(|deadline| deadline <= Instant::now())
            {
                return false;
            }
            parent = authority.parent;
        }
        false
    }

    fn delegation_snapshot(
        &self,
        stamp: &StampedInvocation,
        parent: ResourceHandle,
    ) -> Result<DelegationSnapshot, ResourceErrorCode> {
        let authority = self.lookup(stamp, parent)?;
        Ok(DelegationSnapshot {
            kind: authority.kind,
            identity: authority.identity,
            parent_rights: authority.rights,
            parent_scope: authority.scope.clone(),
            account: authority.reservation.account,
            budget: authority.reservation.budget,
            remaining: authority.reservation.remaining,
            authority_epoch: authority.authority_epoch,
            transfer_class: authority.transfer_class,
            expiry: authority.expiry,
            revocation: authority.revocation,
        })
    }

    fn validate_delegation(
        &self,
        snapshot: &DelegationSnapshot,
        rights: Rights,
        scope: &ResourceScope,
        budget: u64,
        expiry: Option<Instant>,
    ) -> Result<(), ResourceErrorCode> {
        if snapshot.kind != ResourceKind::SemanticObject {
            return Err(ResourceErrorCode::Unsupported);
        }
        if !snapshot.parent_rights.contains(Rights::DELEGATE)
            || !rights.is_subset(snapshot.parent_rights)
        {
            return Err(ResourceErrorCode::MissingRight);
        }
        if !scope.is_subset_of(&snapshot.parent_scope) {
            return Err(ResourceErrorCode::InvalidDescriptor);
        }
        if budget > snapshot.remaining {
            return Err(ResourceErrorCode::Exhausted);
        }
        if (snapshot.expiry.is_some() && expiry.is_none())
            || matches!((snapshot.expiry, expiry), (Some(parent), Some(child)) if child > parent)
        {
            return Err(ResourceErrorCode::InvalidDescriptor);
        }
        if expiry.is_some_and(|deadline| deadline <= Instant::now()) {
            return Err(ResourceErrorCode::Revoked);
        }
        if snapshot
            .revocation
            .is_some_and(|selector| self.revoked_selectors.contains(&selector))
        {
            return Err(ResourceErrorCode::Revoked);
        }
        Ok(())
    }

    fn debit_parent(
        &mut self,
        parent: ResourceHandle,
        budget: u64,
    ) -> Result<(), ResourceErrorCode> {
        let authority = self.slot_authority_mut(parent)?;
        authority.reservation.remaining = authority
            .reservation
            .remaining
            .checked_sub(budget)
            .ok_or(ResourceErrorCode::Exhausted)?;
        Ok(())
    }

    fn reclaim_snapshot(
        &self,
        stamp: &StampedInvocation,
        handle: ResourceHandle,
    ) -> Result<(Option<ResourceHandle>, ReservationSnapshot), ResourceErrorCode> {
        let authority = self.slot_authority(handle)?;
        if authority.principal != stamp.principal() {
            return Err(ResourceErrorCode::WrongOwner);
        }
        Ok((
            authority.parent,
            ReservationSnapshot {
                account: authority.reservation.account,
                budget: authority.reservation.budget,
                remaining: authority.reservation.remaining,
            },
        ))
    }

    fn reclaim_owner(
        &self,
        stamp: &StampedInvocation,
        handle: ResourceHandle,
    ) -> Result<(), ResourceErrorCode> {
        let authority = self.slot_authority(handle)?;
        if authority.principal != stamp.principal() {
            return Err(ResourceErrorCode::WrongOwner);
        }
        Ok(())
    }

    fn can_refund_parent(
        &self,
        parent: Option<ResourceHandle>,
        reservation: &ReservationSnapshot,
    ) -> bool {
        let Some(parent) = parent else {
            return false;
        };
        let Ok(authority) = self.slot_authority(parent) else {
            return false;
        };
        authority.reservation.account == reservation.account
            && authority.reservation.budget == reservation.budget
            && authority
                .reservation
                .remaining
                .checked_add(reservation.remaining)
                .is_some()
    }

    fn refund_parent(
        &mut self,
        parent: Option<ResourceHandle>,
        reservation: &ReservationSnapshot,
    ) -> Result<(), ResourceErrorCode> {
        let Some(parent) = parent else {
            return Err(ResourceErrorCode::Internal);
        };
        let authority = self.slot_authority_mut(parent)?;
        if authority.reservation.account != reservation.account
            || authority.reservation.budget != reservation.budget
        {
            return Err(ResourceErrorCode::Internal);
        }
        authority.reservation.remaining = authority
            .reservation
            .remaining
            .checked_add(reservation.remaining)
            .ok_or(ResourceErrorCode::Internal)?;
        Ok(())
    }

    fn ensure_external_release(&self, units: u64) -> Result<(), ResourceErrorCode> {
        if self.active_reserved_units < u128::from(units)
            || self
                .released_reserved_units
                .checked_add(u128::from(units))
                .is_none()
        {
            return Err(ResourceErrorCode::Internal);
        }
        Ok(())
    }

    fn release_external(&mut self, units: u64) -> Result<(), ResourceErrorCode> {
        self.ensure_external_release(units)?;
        self.active_reserved_units -= u128::from(units);
        self.released_reserved_units += u128::from(units);
        Ok(())
    }

    fn advance_slot(&mut self, handle: ResourceHandle) -> Result<(), ResourceErrorCode> {
        let slot = self.slot_mut(handle)?;
        match slot.generation.checked_next() {
            Ok(next) => slot.generation = next,
            Err(_) => slot.retired = true,
        }
        Ok(())
    }
}

struct DelegationSnapshot {
    kind: ResourceKind,
    identity: ResourceId,
    parent_rights: Rights,
    parent_scope: ResourceScope,
    account: AccountId,
    budget: BudgetId,
    remaining: u64,
    authority_epoch: AuthorityEpoch,
    transfer_class: TransferClass,
    expiry: Option<Instant>,
    revocation: Option<RevocationSelector>,
}

struct ReservationSnapshot {
    account: AccountId,
    budget: BudgetId,
    remaining: u64,
}
