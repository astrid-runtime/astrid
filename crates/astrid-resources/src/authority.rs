//! Hierarchical resident-memory accounting and admission.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

use crate::lease::ReclaimSignal;
use crate::{
    LogicalLeaseSnapshot, LogicalMemoryLease, MemoryAuthorityError, MemoryAuthoritySnapshot,
    MemoryClass, MemoryPressure, MemorySubsystem, PhysicalLeaseSnapshot, PhysicalMemoryLease,
    PrincipalMemorySnapshot, ResidentMemoryLease,
};

mod state;

pub(crate) use state::AuthorityInner;
use state::{AuthorityState, LogicalRecord, PhysicalRecord, PrincipalAccount};

/// Shared authority over host-resident memory materialized for principals.
///
/// Physical reservations enforce the operator pool. Logical charges enforce
/// principal and ancestor limits independently of physical sharing.
#[derive(Clone)]
pub struct ResidentMemoryAuthority<P: Ord> {
    inner: Arc<AuthorityInner<P>>,
}

impl<P> ResidentMemoryAuthority<P>
where
    P: Clone + Ord,
{
    /// Construct an empty authority with an explicit physical pool ceiling.
    #[must_use]
    pub fn new(physical_limit_bytes: u64) -> Self {
        Self {
            inner: Arc::new(AuthorityInner {
                state: Mutex::new(AuthorityState {
                    physical_limit_bytes,
                    physical_reserved_bytes: 0,
                    next_lease_id: 1,
                    principals: BTreeMap::new(),
                    physical_leases: BTreeMap::new(),
                    logical_leases: BTreeMap::new(),
                }),
            }),
        }
    }

    /// Register a root or attenuated child principal.
    ///
    /// Re-registering the same principal updates its limit live. Changing its
    /// parent is allowed only while it has no reservations or descendants.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown parent, an ancestry cycle, or a busy
    /// account whose parent would change.
    pub fn register_principal(
        &self,
        principal: P,
        parent: Option<P>,
        logical_limit_bytes: u64,
    ) -> Result<(), MemoryAuthorityError> {
        let mut state = self.inner.state.lock();
        if let Some(parent) = &parent {
            if parent == &principal {
                return Err(MemoryAuthorityError::PrincipalCycle);
            }
            if !state.principals.contains_key(parent) {
                return Err(MemoryAuthorityError::UnknownPrincipal);
            }
            let mut cursor = Some(parent.clone());
            while let Some(current) = cursor {
                if current == principal {
                    return Err(MemoryAuthorityError::PrincipalCycle);
                }
                cursor = state
                    .principals
                    .get(&current)
                    .and_then(|account| account.parent.clone());
            }
        }
        if let Some(existing) = state.principals.get(&principal)
            && existing.parent != parent
        {
            let has_children = state
                .principals
                .values()
                .any(|account| account.parent.as_ref() == Some(&principal));
            let has_leases = state
                .logical_leases
                .values()
                .any(|record| record.principal == principal)
                || state
                    .physical_leases
                    .values()
                    .any(|record| record.owner.as_ref() == Some(&principal));
            if existing.subtree_logical_bytes != 0 || has_children || has_leases {
                return Err(MemoryAuthorityError::PrincipalBusy);
            }
        }
        state
            .principals
            .entry(principal)
            .and_modify(|account| {
                account.parent.clone_from(&parent);
                account.logical_limit_bytes = logical_limit_bytes;
            })
            .or_insert(PrincipalAccount {
                parent,
                logical_limit_bytes,
                direct_logical_bytes: 0,
                subtree_logical_bytes: 0,
            });
        AuthorityInner::recompute_logical_targets(&state);
        Ok(())
    }

    /// Update one principal's live logical subtree ceiling.
    ///
    /// Existing reservations remain accounted. Evictable leases in the
    /// affected subtree receive shrink targets, while non-evictable usage
    /// becomes unreclaimable pressure and no further growth is admitted.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryAuthorityError::UnknownPrincipal`] when no policy is
    /// registered for `principal`.
    pub fn set_principal_limit(
        &self,
        principal: &P,
        logical_limit_bytes: u64,
    ) -> Result<MemoryPressure, MemoryAuthorityError> {
        let mut state = self.inner.state.lock();
        let account = state
            .principals
            .get_mut(principal)
            .ok_or(MemoryAuthorityError::UnknownPrincipal)?;
        account.logical_limit_bytes = logical_limit_bytes;
        let actual = account.subtree_logical_bytes;
        let requested = AuthorityInner::recompute_logical_targets(&state)
            .get(principal)
            .copied()
            .unwrap_or_default();
        let excess = actual.saturating_sub(logical_limit_bytes);
        let remaining = requested.saturating_sub(logical_limit_bytes);
        Ok(MemoryPressure {
            excess_bytes: excess,
            reclaim_requested_bytes: excess.saturating_sub(remaining),
            unreclaimable_bytes: remaining,
        })
    }

    /// Remove an unused principal policy.
    ///
    /// # Errors
    ///
    /// Returns an error while the principal has live charges or children.
    pub fn remove_principal(&self, principal: &P) -> Result<(), MemoryAuthorityError> {
        let mut state = self.inner.state.lock();
        let account = state
            .principals
            .get(principal)
            .ok_or(MemoryAuthorityError::UnknownPrincipal)?;
        let has_children = state
            .principals
            .values()
            .any(|candidate| candidate.parent.as_ref() == Some(principal));
        let has_leases = state
            .logical_leases
            .values()
            .any(|record| &record.principal == principal)
            || state
                .physical_leases
                .values()
                .any(|record| record.owner.as_ref() == Some(principal));
        if account.subtree_logical_bytes != 0 || has_children || has_leases {
            return Err(MemoryAuthorityError::PrincipalInUse);
        }
        state.principals.remove(principal);
        Ok(())
    }

    /// Reserve actual host-resident bytes.
    ///
    /// Shared operator pools use `owner = None`; principal-owned allocations
    /// name their responsible principal for diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an error for zero bytes, an unknown owner, identifier
    /// exhaustion, or physical pool exhaustion.
    pub fn reserve_physical(
        &self,
        owner: Option<P>,
        subsystem: MemorySubsystem,
        class: MemoryClass,
        bytes: u64,
    ) -> Result<PhysicalMemoryLease<P>, MemoryAuthorityError> {
        if bytes == 0 {
            return Err(MemoryAuthorityError::ZeroReservation);
        }
        let mut state = self.inner.state.lock();
        if owner
            .as_ref()
            .is_some_and(|principal| !state.principals.contains_key(principal))
        {
            return Err(MemoryAuthorityError::UnknownPrincipal);
        }
        let available = state
            .physical_limit_bytes
            .saturating_sub(state.physical_reserved_bytes);
        if bytes > available {
            return Err(MemoryAuthorityError::PhysicalExhausted {
                requested: bytes,
                available,
            });
        }
        let id = AuthorityInner::allocate_id(&mut state)?;
        let signal = Arc::new(ReclaimSignal::new(bytes));
        state.physical_reserved_bytes = state.physical_reserved_bytes.saturating_add(bytes);
        state.physical_leases.insert(
            id,
            PhysicalRecord {
                owner,
                subsystem,
                class,
                reserved_bytes: bytes,
                signal: Arc::downgrade(&signal),
                created_at: Instant::now(),
            },
        );
        Ok(PhysicalMemoryLease::new(
            id,
            Arc::downgrade(&self.inner),
            signal,
        ))
    }

    /// Charge one principal logically, independently of physical sharing.
    ///
    /// The charge also consumes every ancestor's subtree allowance.
    ///
    /// # Errors
    ///
    /// Returns an error for zero bytes, unknown principal, identifier
    /// exhaustion, or any exhausted authority in the ancestry.
    pub fn reserve_logical(
        &self,
        principal: P,
        subsystem: MemorySubsystem,
        class: MemoryClass,
        bytes: u64,
    ) -> Result<LogicalMemoryLease<P>, MemoryAuthorityError> {
        if bytes == 0 {
            return Err(MemoryAuthorityError::ZeroReservation);
        }
        let mut state = self.inner.state.lock();
        AuthorityInner::ensure_logical_capacity(&state, &principal, bytes)?;
        let id = AuthorityInner::allocate_id(&mut state)?;
        let signal = Arc::new(ReclaimSignal::new(bytes));
        AuthorityInner::apply_logical_delta(&mut state, &principal, bytes, true)?;
        state.logical_leases.insert(
            id,
            LogicalRecord {
                principal,
                subsystem,
                class,
                charged_bytes: bytes,
                signal: Arc::downgrade(&signal),
                created_at: Instant::now(),
            },
        );
        Ok(LogicalMemoryLease::new(
            id,
            Arc::downgrade(&self.inner),
            signal,
        ))
    }

    /// Atomically acquire physical and logical leases for one non-shared
    /// allocation.
    ///
    /// # Errors
    ///
    /// Returns the first physical or logical admission error.
    pub fn reserve(
        &self,
        principal: P,
        subsystem: MemorySubsystem,
        class: MemoryClass,
        physical_bytes: u64,
        logical_bytes: u64,
    ) -> Result<ResidentMemoryLease<P>, MemoryAuthorityError> {
        if physical_bytes == 0 || logical_bytes == 0 {
            return Err(MemoryAuthorityError::ZeroReservation);
        }
        let mut state = self.inner.state.lock();
        let physical_available = state
            .physical_limit_bytes
            .saturating_sub(state.physical_reserved_bytes);
        if physical_bytes > physical_available {
            return Err(MemoryAuthorityError::PhysicalExhausted {
                requested: physical_bytes,
                available: physical_available,
            });
        }
        AuthorityInner::ensure_logical_capacity(&state, &principal, logical_bytes)?;
        let physical_id = AuthorityInner::allocate_id(&mut state)?;
        let logical_id = AuthorityInner::allocate_id(&mut state)?;
        let physical_signal = Arc::new(ReclaimSignal::new(physical_bytes));
        let logical_signal = Arc::new(ReclaimSignal::new(logical_bytes));

        state.physical_reserved_bytes =
            state.physical_reserved_bytes.saturating_add(physical_bytes);
        state.physical_leases.insert(
            physical_id,
            PhysicalRecord {
                owner: Some(principal.clone()),
                subsystem,
                class,
                reserved_bytes: physical_bytes,
                signal: Arc::downgrade(&physical_signal),
                created_at: Instant::now(),
            },
        );
        AuthorityInner::apply_logical_delta(&mut state, &principal, logical_bytes, true)?;
        state.logical_leases.insert(
            logical_id,
            LogicalRecord {
                principal,
                subsystem,
                class,
                charged_bytes: logical_bytes,
                signal: Arc::downgrade(&logical_signal),
                created_at: Instant::now(),
            },
        );
        drop(state);

        let physical =
            PhysicalMemoryLease::new(physical_id, Arc::downgrade(&self.inner), physical_signal);
        let logical =
            LogicalMemoryLease::new(logical_id, Arc::downgrade(&self.inner), logical_signal);
        Ok(ResidentMemoryLease { physical, logical })
    }

    /// Replace the operator-wide physical pool ceiling and request reclaim
    /// from evictable leases when current reservations exceed it.
    ///
    /// Reclaim requests never decrement accounting. A consumer first discards
    /// bytes, then acknowledges its actual footprint through the lease.
    #[must_use]
    pub fn set_physical_limit(&self, physical_limit_bytes: u64) -> MemoryPressure {
        let mut state = self.inner.state.lock();
        state.physical_limit_bytes = physical_limit_bytes;
        AuthorityInner::recompute_physical_targets(&state)
    }

    /// Return an operator-only reconciliation snapshot.
    #[must_use]
    pub fn snapshot(&self) -> MemoryAuthoritySnapshot<P> {
        let state = self.inner.state.lock();
        let requested_subtrees = AuthorityInner::recompute_logical_targets(&state);
        MemoryAuthoritySnapshot {
            physical_limit_bytes: state.physical_limit_bytes,
            physical_reserved_bytes: state.physical_reserved_bytes,
            principals: state
                .principals
                .iter()
                .map(|(principal, account)| PrincipalMemorySnapshot {
                    principal: principal.clone(),
                    parent: account.parent.clone(),
                    logical_limit_bytes: account.logical_limit_bytes,
                    direct_logical_bytes: account.direct_logical_bytes,
                    subtree_logical_bytes: account.subtree_logical_bytes,
                    requested_subtree_logical_bytes: requested_subtrees
                        .get(principal)
                        .copied()
                        .unwrap_or_default(),
                })
                .collect(),
            physical_leases: state
                .physical_leases
                .iter()
                .map(|(id, record)| PhysicalLeaseSnapshot {
                    id: *id,
                    owner: record.owner.clone(),
                    subsystem: record.subsystem,
                    class: record.class,
                    reserved_bytes: record.reserved_bytes,
                    requested_bytes: record
                        .signal
                        .upgrade()
                        .map_or(record.reserved_bytes, |signal| signal.requested()),
                    held_for: record.created_at.elapsed(),
                })
                .collect(),
            logical_leases: state
                .logical_leases
                .iter()
                .map(|(id, record)| LogicalLeaseSnapshot {
                    id: *id,
                    principal: record.principal.clone(),
                    subsystem: record.subsystem,
                    class: record.class,
                    charged_bytes: record.charged_bytes,
                    requested_bytes: record
                        .signal
                        .upgrade()
                        .map_or(record.charged_bytes, |signal| signal.requested()),
                    held_for: record.created_at.elapsed(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests;
