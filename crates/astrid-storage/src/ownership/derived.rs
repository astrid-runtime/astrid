//! Fleet inheritance for capability-authorized agent spawning.

use astrid_core::{PrincipalId, PrincipalOwnership, PrincipalUid, UserUid};

use super::{OwnershipError, OwnershipStore, PrincipalDeletionGuard};

#[cfg(test)]
mod tests;

/// Pinned ownership of an authenticated spawning principal, not a human login.
/// Capturing this does not authorize spawning; the kernel must separately
/// enforce `agent:create:inherit`. The historical assigning user is retained
/// only as provenance, never consulted as current permission or impersonation.
#[derive(Clone, Debug)]
pub struct DerivedPrincipalOwnership {
    creator: PrincipalOwnership,
    accountable_user: UserUid,
}

/// Ephemeral rollback authority for one successfully assigned fresh child.
///
/// This receipt does not delegate user or device authority. Dropping it after
/// initialization leaves the assignment intact. It cannot be constructed or
/// cloned by a caller, or redirected to a peer. Reservation checks that the
/// child still has the captured ownership and accountability assignment.
#[derive(Debug)]
pub struct DerivedPrincipalInitialization {
    store: OwnershipStore,
    child: PrincipalOwnership,
    accountable_user: UserUid,
}

impl DerivedPrincipalInitialization {
    /// Immutable child identity whose failed initialization may be retired.
    #[must_use]
    pub const fn principal_uid(&self) -> PrincipalUid {
        self.child.principal_uid
    }

    /// Reserve rollback of this exact assignment before reclaiming identity.
    ///
    /// # Errors
    /// Rejects changed ownership/accountability, alias conflicts, an unknown
    /// child, and invalid storage. Reservation and removal commit atomically.
    pub async fn reserve_rollback(
        &self,
        alias: PrincipalId,
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        self.store
            .guard_principal_deletion_checked(self.child.principal_uid, Some(alias), |graph| {
                if graph.principal_owner(self.child.principal_uid) != Some(&self.child)
                    || graph.accountable_user(self.child.principal_uid)
                        != Some(self.accountable_user)
                {
                    return Err(OwnershipError::IdentityConflict(
                        "derived initialization rollback",
                        self.child.principal_uid.to_string(),
                    ));
                }
                Ok(Some(self.child.fleet_uid))
            })
            .await
    }
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
        let accountable_user = graph.accountable_user(creator.principal_uid).ok_or(
            OwnershipError::AccountableUserRequired(creator.principal_uid),
        )?;
        Ok(DerivedPrincipalOwnership {
            creator,
            accountable_user,
        })
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
        self.assign_derived_principal_for_initialization(child, ownership)
            .await?;
        Ok(())
    }

    /// Assign a fresh child and retain child-specific initialization rollback.
    /// The same spawn authorization and stale-creator checks as
    /// [`Self::assign_derived_principal`] apply; this is not deletion authority
    /// over an existing principal.
    ///
    /// # Errors
    /// Returns the assignment errors documented on `assign_derived_principal`.
    pub async fn assign_derived_principal_for_initialization(
        &self,
        child: PrincipalUid,
        ownership: &DerivedPrincipalOwnership,
    ) -> Result<DerivedPrincipalInitialization, OwnershipError> {
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
            if graph.principal_owner(creator) != Some(&ownership.creator)
                || graph.accountable_user(creator) != Some(ownership.accountable_user)
            {
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
            graph
                .accountable_users
                .insert(child, ownership.accountable_user);
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
        .await?;
        Ok(DerivedPrincipalInitialization {
            store: self.clone(),
            child: PrincipalOwnership {
                principal_uid: child,
                fleet_uid: ownership.creator.fleet_uid,
                assigned_by: ownership.creator.assigned_by,
            },
            accountable_user: ownership.accountable_user,
        })
    }
}
