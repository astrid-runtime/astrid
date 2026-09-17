//! Fleet inheritance for capability-authorized agent spawning.

use astrid_core::{PrincipalOwnership, PrincipalUid};

use super::{OwnershipError, OwnershipStore};

#[cfg(test)]
mod tests;

/// Pinned ownership of an authenticated spawning principal, not a human login.
/// Capturing this does not authorize spawning; the kernel must separately
/// enforce `agent:create:inherit`. The historical assigning user is retained
/// only as provenance, never consulted as current permission or impersonation.
#[derive(Clone, Debug)]
pub struct DerivedPrincipalOwnership {
    creator: PrincipalOwnership,
}

impl OwnershipStore {
    /// Pin the caller's fleet before provisioning a derived principal.
    ///
    /// # Errors
    /// Rejects an unowned, missing or retiring caller and invalid storage.
    pub async fn capture_derived_ownership(
        &self,
        creator: PrincipalUid,
    ) -> Result<DerivedPrincipalOwnership, OwnershipError> {
        let graph = self.load().await?;
        if graph.principal_deletions.contains_key(&creator) {
            return Err(OwnershipError::PrincipalDeletionInProgress(creator));
        }
        if !self.principals.contains_uid(creator) {
            return Err(OwnershipError::PrincipalNotFound(creator));
        }
        let creator = graph
            .principal_owner(creator)
            .ok_or(OwnershipError::PrincipalNotOwned(creator))?
            .clone();
        Ok(DerivedPrincipalOwnership { creator })
    }

    /// Assign a fresh child to the spawning caller's still-current fleet.
    /// No user-device delegation, membership or capability is copied. The
    /// caller must independently authorize the spawn operation. CAS retries
    /// recheck the pinned creator, and cannot silently adopt a transferred caller.
    ///
    /// # Errors
    /// Rejects changed creator ownership, retiring/missing identities, an
    /// already-owned child, and invalid or unavailable storage.
    pub async fn assign_derived_principal(
        &self,
        child: PrincipalUid,
        ownership: &DerivedPrincipalOwnership,
    ) -> Result<(), OwnershipError> {
        self.mutate(|graph| {
            let creator = ownership.creator.principal_uid;
            for uid in [creator, child] {
                if graph.principal_deletions.contains_key(&uid) {
                    return Err(OwnershipError::PrincipalDeletionInProgress(uid));
                }
                if !self.principals.contains_uid(uid) {
                    return Err(OwnershipError::PrincipalNotFound(uid));
                }
            }
            if graph.principal_owner(creator) != Some(&ownership.creator) {
                return Err(OwnershipError::IdentityConflict(
                    "spawn ownership",
                    creator.to_string(),
                ));
            }
            if let Some(owner) = graph.principal_owner(child) {
                return Err(OwnershipError::PrincipalAlreadyOwned {
                    principal: child,
                    fleet: owner.fleet_uid,
                });
            }
            graph.principal_ownership.insert(
                child,
                PrincipalOwnership {
                    principal_uid: child,
                    fleet_uid: ownership.creator.fleet_uid,
                    assigned_by: ownership.creator.assigned_by,
                },
            );
            Ok(())
        })
        .await
    }
}
