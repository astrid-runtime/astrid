//! Consumed rollback authority for one not-yet-published derived identity.

use super::{DerivedPrincipalOwnership, OwnershipError, OwnershipStore};
use crate::ownership::{EnrolledAuthority, PrincipalDeletionGuard, PrincipalDeletionReservation};
use astrid_core::{PrincipalId, PrincipalOwnership, PrincipalUid, UserUid};
use std::sync::Arc;

/// Exact assignment made by a single provisioning attempt, never guest authority.
/// Dropping it preserves the assigned identity; it does not perform async cleanup.
#[derive(Debug)]
#[must_use = "retain until readiness succeeds or rollback completes"]
pub struct DerivedPrincipalProvision {
    child: PrincipalUid,
    alias: PrincipalId,
    owner: PrincipalOwnership,
    payer: UserUid,
    authority: EnrolledAuthority,
}

impl DerivedPrincipalProvision {
    pub(super) fn new(
        child: PrincipalUid,
        alias: PrincipalId,
        captured: &DerivedPrincipalOwnership,
    ) -> Self {
        Self {
            child,
            alias,
            owner: PrincipalOwnership {
                principal_uid: child,
                fleet_uid: captured.creator.fleet_uid,
                assigned_by: captured.creator.assigned_by,
            },
            payer: captured.accountable_user,
            authority: captured.authority.clone(),
        }
    }
}

impl OwnershipStore {
    /// Consume provisional authority into the existing durable deletion barrier.
    /// No historical creator or device-free general deletion permission is inferred.
    /// The caller must retain the returned guard through exact identity cleanup.
    ///
    /// # Errors
    /// Any changed identity, assignment, payer, enrollment, device binding or
    /// existing deletion reservation refuses without removing ownership.
    pub async fn guard_derived_principal_rollback(
        &self,
        provision: DerivedPrincipalProvision,
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        let guard = Arc::clone(&self.mutation_lock).lock_owned().await;
        self.mutate_unlocked(|graph| {
            self.validate_authority(graph, &provision.authority)?;
            if self
                .principals
                .uid_for(&provision.alias)
                .map_err(|_| OwnershipError::PrincipalNotFound(provision.child))?
                != provision.child
                || self
                    .principals
                    .alias_for(provision.child)
                    .map_err(|_| OwnershipError::PrincipalNotFound(provision.child))?
                    != provision.alias
                || graph.principal_owner(provision.child) != Some(&provision.owner)
                || graph.accountable_user(provision.child) != Some(provision.payer)
                || graph
                    .user_bindings
                    .iter()
                    .any(|binding| binding.for_principal(provision.child))
                || graph.principal_deletions.contains_key(&provision.child)
                || graph
                    .principal_deletions
                    .values()
                    .any(|pending| pending.alias.as_ref() == Some(&provision.alias))
            {
                return Err(OwnershipError::IdentityConflict(
                    "provisional derived rollback",
                    provision.child.to_string(),
                ));
            }
            graph.principal_deletions.insert(
                provision.child,
                PrincipalDeletionReservation {
                    alias: Some(provision.alias.clone()),
                    fleet: Some(provision.owner.fleet_uid),
                },
            );
            graph.principal_ownership.remove(&provision.child);
            graph.accountable_users.remove(&provision.child);
            Ok(())
        })
        .await?;
        Ok(PrincipalDeletionGuard {
            store: self.clone(),
            principal_uid: provision.child,
            authority: provision.authority,
            _guard: guard,
        })
    }
}

#[cfg(test)]
mod tests;
