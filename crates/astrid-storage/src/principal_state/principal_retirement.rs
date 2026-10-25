//! Privileged immutable-UID reclamation after identity/capability fences.

use astrid_core::{FleetUid, PrincipalUid};

use super::{RuntimePrincipalStore, StateOwner};
use crate::WorkspaceBranchStore;
use crate::error::{StorageError, StorageResult};

impl RuntimePrincipalStore {
    /// Retire all state bound to one captured executable principal UID.
    ///
    /// Callers must hold the durable ownership deletion reservation and drain
    /// that identity's writers. This removes UID-bound branches and completion
    /// receipts in every surviving fleet (including former owners), followed
    /// by the whole principal root: KV, package registry and private content.
    /// Alias resolution is never used. Shared content and explicit read leases
    /// remain subject to the ordinary compaction retention proof.
    ///
    /// The operation is retry-safe across owner roots. Partial failure leaves
    /// the deletion reservation with the caller; it must not release the alias
    /// until reclamation succeeds. Ordinary unload must never call this API.
    ///
    /// # Errors
    ///
    /// Returns a storage error if any authoritative lookup or CAS fails.
    pub fn purge_principal_state(&self, uid: PrincipalUid) -> StorageResult<bool> {
        let branches = WorkspaceBranchStore::new(self.content());
        // StateOwner's Fleet range is disjoint from System/Principal. This
        // avoids copying or scanning the ten thousand unrelated private roots.
        let fleets = self
            .engine
            .roots_in_range(
                StateOwner::Fleet(FleetUid::from_bytes([0; 32]))
                    ..=StateOwner::Fleet(FleetUid::from_bytes([u8::MAX; 32])),
            )
            .map_err(retirement_error)?;
        let mut changed = false;
        for (owner, _) in fleets {
            for binding in branches
                .list_bindings_by_uid(&owner, uid)
                .map_err(retirement_error)?
            {
                branches
                    .drop(&owner, binding.branch_id())
                    .map_err(retirement_error)?;
                changed = true;
            }
        }
        let owner = StateOwner::Principal(uid);
        if let Some(root) = self.engine.root(&owner).map_err(retirement_error)? {
            self.engine
                .remove_root(&owner, root)
                .map_err(retirement_error)?;
            changed = true;
        }
        // A removed root must not be replaced by an empty KV commit merely to
        // clear optional accelerators. In-flight checkpoint guards also mark
        // their eventual completion for forgetting, preserving the same fence.
        self.runtime_kv.forget_retired_owner(&owner);
        self.content.forget_owner_projection_state(&owner);
        Ok(changed)
    }
}

fn retirement_error(error: impl std::fmt::Display) -> StorageError {
    StorageError::Internal(format!("retire immutable principal state: {error}"))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod retry_tests;

#[cfg(test)]
mod scale_tests;

#[cfg(test)]
mod system_retention_tests;
