//! Lifecycle bookkeeping for invocation-scoped semantic-object authorities.

use crate::resource_authority::{ResourceAuthorityTable, ResourceHandle};
use crate::stamp::StampedInvocation;

/// One live authority paired with the exact host stamp that admitted it.
#[derive(Debug)]
struct TrackedAuthority {
    stamp: StampedInvocation,
    handle: ResourceHandle,
}

/// [`crate::engine::wasm::host_state::HostState`]-owned authority cleanup.
///
/// A repeating principal alias is not proof of a continuing invocation, so
/// cleanup keeps the admission-time stamp instead of borrowing the current one.
#[derive(Debug, Default)]
pub(crate) struct HostStateSemanticAuthorities {
    table: ResourceAuthorityTable,
    tracked: Vec<TrackedAuthority>,
    released_units: u128,
}

impl HostStateSemanticAuthorities {
    /// Drain child-first, then replace the bounded table unconditionally.
    pub(crate) fn prepare_for_replacement(&mut self) {
        // Children are appended after parents, so reverse consumption follows
        // delegation lineage and lets each refund land on its live parent.
        while let Some(tracked) = self.tracked.pop() {
            let releases_before = self.table.released_reserved_units();
            let result = self.table.drop_handle(&tracked.stamp, tracked.handle);
            self.record_release(releases_before);
            debug_assert!(
                result.is_ok(),
                "exact-stamp reverse drain must reclaim a tracked entry"
            );
        }
        self.table = ResourceAuthorityTable::default();
    }

    fn record_release(&mut self, previous_released_units: u128) {
        let latest_released_units = self.table.released_reserved_units();
        if let Some(delta_released_units) =
            latest_released_units.checked_sub(previous_released_units)
            && let Some(total_released_units) =
                self.released_units.checked_add(delta_released_units)
        {
            self.released_units = total_released_units;
        } else {
            // Overflow would mean inconsistent table accounting; saturating
            // prevents corruption from looking like available release capacity.
            self.released_units = u128::MAX;
        }
    }
}

#[cfg(test)]
impl HostStateSemanticAuthorities {
    /// Admit one fixture SemanticObject and retain its cleanup pair.
    pub(crate) fn admit(
        &mut self,
        stamp: &StampedInvocation,
        kind: astrid_resource_types::ResourceKind,
        identity: astrid_resource_types::ResourceId,
        scope: crate::resource_authority::ResourceScope,
        reservation: crate::resource_authority::Reservation,
        options: crate::resource_authority::AdmissionOptions,
    ) -> Result<ResourceHandle, astrid_resource_types::ResourceErrorCode> {
        let handle = self
            .table
            .admit(stamp, kind, identity, scope, reservation, options)?;
        self.tracked.push(TrackedAuthority {
            stamp: stamp.clone(),
            handle,
        });
        Ok(handle)
    }

    /// Preflight against the admission-time stamp, not an equivalent alias.
    pub(crate) fn preflight(
        &self,
        stamp: &StampedInvocation,
        handle: ResourceHandle,
        requested_right: astrid_resource_types::Rights,
        requested_scope: &crate::resource_authority::ResourceScope,
        requested_budget: u64,
    ) -> Result<(), astrid_resource_types::ResourceErrorCode> {
        self.table.preflight(
            stamp,
            handle,
            requested_right,
            requested_scope,
            requested_budget,
        )
    }

    /// Create a child authority and retain it behind its parent in cleanup.
    pub(crate) fn attenuate(
        &mut self,
        stamp: &StampedInvocation,
        parent: ResourceHandle,
        rights: astrid_resource_types::Rights,
        scope: crate::resource_authority::ResourceScope,
        budget: u64,
    ) -> Result<ResourceHandle, astrid_resource_types::ResourceErrorCode> {
        let handle = self.table.attenuate(stamp, parent, rights, scope, budget)?;
        self.tracked.push(TrackedAuthority {
            stamp: stamp.clone(),
            handle,
        });
        Ok(handle)
    }

    /// Reclaim a live or invalidated entry through its admission stamp.
    pub(crate) fn reclaim(
        &mut self,
        stamp: &StampedInvocation,
        handle: ResourceHandle,
    ) -> Result<(), astrid_resource_types::ResourceErrorCode> {
        let releases_before = self.table.released_reserved_units();
        self.table.reclaim(stamp, handle)?;
        self.tracked.retain(|tracked| tracked.handle != handle);
        self.record_release(releases_before);
        Ok(())
    }

    /// Mark an entry invalid while retaining its cleanup reservation.
    pub(crate) fn revoke(
        &mut self,
        handle: ResourceHandle,
    ) -> Result<(), astrid_resource_types::ResourceErrorCode> {
        self.table.revoke(handle)
    }

    /// Invalidate entries carrying a selector; replacement clears tombstones.
    pub(crate) fn revoke_selector(
        &mut self,
        selector: crate::resource_authority::RevocationSelector,
    ) -> Result<(), astrid_resource_types::ResourceErrorCode> {
        self.table.revoke_selector(selector)
    }

    /// Invalidate reservations from an older authority epoch.
    pub(crate) fn advance_authority_epoch(
        &mut self,
    ) -> Result<astrid_resource_types::AuthorityEpoch, astrid_resource_types::ResourceErrorCode>
    {
        self.table.advance_authority_epoch()
    }

    pub(crate) const fn tracked_count(&self) -> usize {
        self.tracked.len()
    }

    pub(crate) fn tracks_handle(&self, handle: ResourceHandle) -> bool {
        self.tracked.iter().any(|tracked| tracked.handle == handle)
    }

    pub(crate) const fn active_reserved_units(&self) -> u128 {
        self.table.active_reserved_units()
    }

    pub(crate) const fn released_reserved_units(&self) -> u128 {
        self.released_units
    }

    pub(crate) fn revoked_selector_count(&self) -> usize {
        self.table.revoked_selector_count()
    }

    pub(crate) const fn allocated_slot_count(&self) -> usize {
        self.table.slot_count()
    }
}

impl Drop for HostStateSemanticAuthorities {
    fn drop(&mut self) {
        while let Some(tracked) = self.tracked.pop() {
            // Store teardown must never panic on a backstop race. Dropping the
            // finite table frees an entry whose stale-generation reclaim fails.
            let releases_before = self.table.released_reserved_units();
            let _unused = self.table.drop_handle(&tracked.stamp, tracked.handle);
            self.record_release(releases_before);
        }
    }
}
