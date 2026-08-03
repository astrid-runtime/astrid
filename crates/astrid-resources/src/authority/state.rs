//! Internal ledger state and reclaim-target computation.

use std::collections::BTreeMap;
use std::sync::Weak;
use std::time::Instant;

use parking_lot::Mutex;

use crate::lease::ReclaimSignal;
use crate::{LeaseId, MemoryAuthorityError, MemoryClass, MemoryPressure, MemorySubsystem};

pub(super) struct PrincipalAccount<P> {
    pub(super) parent: Option<P>,
    pub(super) logical_limit_bytes: u64,
    pub(super) direct_logical_bytes: u64,
    pub(super) subtree_logical_bytes: u64,
}

pub(super) struct PhysicalRecord<P: Ord> {
    pub(super) owner: Option<P>,
    pub(super) subsystem: MemorySubsystem,
    pub(super) class: MemoryClass,
    pub(super) reserved_bytes: u64,
    pub(super) signal: Weak<ReclaimSignal>,
    pub(super) created_at: Instant,
}

pub(super) struct LogicalRecord<P> {
    pub(super) principal: P,
    pub(super) subsystem: MemorySubsystem,
    pub(super) class: MemoryClass,
    pub(super) charged_bytes: u64,
    pub(super) signal: Weak<ReclaimSignal>,
    pub(super) created_at: Instant,
}

pub(super) struct AuthorityState<P: Ord> {
    pub(super) physical_limit_bytes: u64,
    pub(super) physical_reserved_bytes: u64,
    pub(super) next_lease_id: u64,
    pub(super) principals: BTreeMap<P, PrincipalAccount<P>>,
    pub(super) physical_leases: BTreeMap<LeaseId, PhysicalRecord<P>>,
    pub(super) logical_leases: BTreeMap<LeaseId, LogicalRecord<P>>,
}

pub(crate) struct AuthorityInner<P: Ord> {
    pub(super) state: Mutex<AuthorityState<P>>,
}

impl<P> AuthorityInner<P>
where
    P: Clone + Ord,
{
    pub(super) fn allocate_id(
        state: &mut AuthorityState<P>,
    ) -> Result<LeaseId, MemoryAuthorityError> {
        let id = LeaseId(state.next_lease_id);
        state.next_lease_id = state
            .next_lease_id
            .checked_add(1)
            .ok_or(MemoryAuthorityError::LeaseIdExhausted)?;
        Ok(id)
    }

    pub(super) fn recompute_physical_targets(state: &AuthorityState<P>) -> MemoryPressure {
        let excess = state
            .physical_reserved_bytes
            .saturating_sub(state.physical_limit_bytes);
        let mut remaining = excess;
        for record in state.physical_leases.values() {
            if let Some(signal) = record.signal.upgrade() {
                signal.set_requested(record.reserved_bytes);
            }
        }
        for record in state.physical_leases.values() {
            if remaining == 0 {
                break;
            }
            if record.class != MemoryClass::Evictable {
                continue;
            }
            let Some(signal) = record.signal.upgrade() else {
                continue;
            };
            let reclaim = remaining.min(record.reserved_bytes);
            signal.set_requested(record.reserved_bytes.saturating_sub(reclaim));
            remaining = remaining.saturating_sub(reclaim);
        }
        MemoryPressure {
            excess_bytes: excess,
            reclaim_requested_bytes: excess.saturating_sub(remaining),
            unreclaimable_bytes: remaining,
        }
    }

    pub(crate) fn release_physical(&self, id: LeaseId) {
        let mut state = self.state.lock();
        if let Some(record) = state.physical_leases.remove(&id) {
            state.physical_reserved_bytes = state
                .physical_reserved_bytes
                .saturating_sub(record.reserved_bytes);
            Self::recompute_physical_targets(&state);
        }
    }

    pub(crate) fn resize_physical(
        &self,
        id: LeaseId,
        bytes: u64,
        signal: &ReclaimSignal,
    ) -> Result<(), MemoryAuthorityError> {
        let mut state = self.state.lock();
        let current = state
            .physical_leases
            .get(&id)
            .ok_or(MemoryAuthorityError::LeaseReleased)?
            .reserved_bytes;
        if bytes > current {
            let growth = bytes.saturating_sub(current);
            let available = state
                .physical_limit_bytes
                .saturating_sub(state.physical_reserved_bytes);
            if growth > available {
                return Err(MemoryAuthorityError::PhysicalExhausted {
                    requested: growth,
                    available,
                });
            }
            state.physical_reserved_bytes = state.physical_reserved_bytes.saturating_add(growth);
        } else {
            state.physical_reserved_bytes = state
                .physical_reserved_bytes
                .saturating_sub(current.saturating_sub(bytes));
        }
        let record = state
            .physical_leases
            .get_mut(&id)
            .ok_or(MemoryAuthorityError::LeaseReleased)?;
        record.reserved_bytes = bytes;
        signal.set_current(bytes);
        Self::recompute_physical_targets(&state);
        Ok(())
    }

    pub(crate) fn release_logical(&self, id: LeaseId) {
        let mut state = self.state.lock();
        let Some((principal, charged_bytes)) = state
            .logical_leases
            .get(&id)
            .map(|record| (record.principal.clone(), record.charged_bytes))
        else {
            return;
        };
        if Self::apply_logical_delta(&mut state, &principal, charged_bytes, false).is_ok() {
            state.logical_leases.remove(&id);
            Self::recompute_logical_targets(&state);
        }
    }

    pub(crate) fn resize_logical(
        &self,
        id: LeaseId,
        bytes: u64,
        signal: &ReclaimSignal,
    ) -> Result<(), MemoryAuthorityError> {
        let mut state = self.state.lock();
        let (principal, current) = state
            .logical_leases
            .get(&id)
            .map(|record| (record.principal.clone(), record.charged_bytes))
            .ok_or(MemoryAuthorityError::LeaseReleased)?;
        if bytes > current {
            let growth = bytes.saturating_sub(current);
            Self::ensure_logical_capacity(&state, &principal, growth)?;
            Self::apply_logical_delta(&mut state, &principal, growth, true)?;
        } else {
            Self::apply_logical_delta(
                &mut state,
                &principal,
                current.saturating_sub(bytes),
                false,
            )?;
        }
        let record = state
            .logical_leases
            .get_mut(&id)
            .ok_or(MemoryAuthorityError::LeaseReleased)?;
        record.charged_bytes = bytes;
        signal.set_current(bytes);
        Self::recompute_logical_targets(&state);
        Ok(())
    }

    pub(super) fn lineage(
        state: &AuthorityState<P>,
        principal: &P,
    ) -> Result<Vec<P>, MemoryAuthorityError> {
        let mut lineage = Vec::new();
        let mut cursor = Some(principal.clone());
        while let Some(current) = cursor.take() {
            if lineage.contains(&current) {
                return Err(MemoryAuthorityError::PrincipalCycle);
            }
            let account = state
                .principals
                .get(&current)
                .ok_or(MemoryAuthorityError::UnknownPrincipal)?;
            lineage.push(current);
            cursor.clone_from(&account.parent);
        }
        Ok(lineage)
    }

    pub(super) fn ensure_logical_capacity(
        state: &AuthorityState<P>,
        principal: &P,
        growth: u64,
    ) -> Result<(), MemoryAuthorityError> {
        for authority in Self::lineage(state, principal)? {
            let account = state
                .principals
                .get(&authority)
                .ok_or(MemoryAuthorityError::UnknownPrincipal)?;
            let available = account
                .logical_limit_bytes
                .saturating_sub(account.subtree_logical_bytes);
            if growth > available {
                return Err(MemoryAuthorityError::LogicalExhausted {
                    requested: growth,
                    available,
                });
            }
        }
        Ok(())
    }

    pub(super) fn apply_logical_delta(
        state: &mut AuthorityState<P>,
        principal: &P,
        bytes: u64,
        add: bool,
    ) -> Result<(), MemoryAuthorityError> {
        let lineage = Self::lineage(state, principal)?;
        for authority in lineage {
            let account = state
                .principals
                .get_mut(&authority)
                .ok_or(MemoryAuthorityError::UnknownPrincipal)?;
            if add {
                account.subtree_logical_bytes = account.subtree_logical_bytes.saturating_add(bytes);
            } else {
                account.subtree_logical_bytes = account.subtree_logical_bytes.saturating_sub(bytes);
            }
        }
        let account = state
            .principals
            .get_mut(principal)
            .ok_or(MemoryAuthorityError::UnknownPrincipal)?;
        if add {
            account.direct_logical_bytes = account.direct_logical_bytes.saturating_add(bytes);
        } else {
            account.direct_logical_bytes = account.direct_logical_bytes.saturating_sub(bytes);
        }
        Ok(())
    }

    pub(super) fn recompute_logical_targets(state: &AuthorityState<P>) -> BTreeMap<P, u64> {
        let mut requested_subtrees = state
            .principals
            .keys()
            .cloned()
            .map(|principal| (principal, 0_u64))
            .collect::<BTreeMap<_, _>>();
        let leases = state
            .logical_leases
            .values()
            .filter_map(|record| {
                let signal = record.signal.upgrade()?;
                signal.set_requested(record.charged_bytes);
                let lineage = Self::lineage(state, &record.principal).ok()?;
                for authority in &lineage {
                    if let Some(bytes) = requested_subtrees.get_mut(authority) {
                        *bytes = bytes.saturating_add(record.charged_bytes);
                    }
                }
                Some((lineage, record.class, signal))
            })
            .collect::<Vec<_>>();
        let mut principals = state
            .principals
            .keys()
            .filter_map(|principal| {
                Some((
                    Self::lineage(state, principal).ok()?.len(),
                    principal.clone(),
                ))
            })
            .collect::<Vec<_>>();
        principals.sort_by(|left, right| right.cmp(left));

        for (_, principal) in principals {
            let limit = state
                .principals
                .get(&principal)
                .map_or(0, |account| account.logical_limit_bytes);
            let mut excess = requested_subtrees
                .get(&principal)
                .copied()
                .unwrap_or_default()
                .saturating_sub(limit);
            for (lineage, class, signal) in &leases {
                if excess == 0 {
                    break;
                }
                if *class != MemoryClass::Evictable || !lineage.contains(&principal) {
                    continue;
                }
                let current_target = signal.requested();
                let reclaim = excess.min(current_target);
                signal.set_requested(current_target.saturating_sub(reclaim));
                for authority in lineage {
                    if let Some(bytes) = requested_subtrees.get_mut(authority) {
                        *bytes = bytes.saturating_sub(reclaim);
                    }
                }
                excess = excess.saturating_sub(reclaim);
            }
        }
        requested_subtrees
    }
}
