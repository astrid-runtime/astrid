//! Assignment-specific rollback authority for unpublished principal initialization.

use super::{OwnershipError, OwnershipStore, PrincipalDeletionGuard};
use astrid_core::{PrincipalId, PrincipalOwnership, PrincipalUid, UserUid};

/// Ephemeral rollback authority for one successfully assigned fresh principal.
///
/// This receipt does not delegate user or device authority. Dropping it after
/// initialization leaves the assignment intact. It cannot be constructed or
/// cloned by a caller, or redirected to a peer. Reservation checks that the
/// child still has the captured ownership and accountability assignment.
#[derive(Debug)]
pub struct PrincipalInitialization {
    store: OwnershipStore,
    child: PrincipalOwnership,
    accountable_user: UserUid,
}

impl PrincipalInitialization {
    pub(super) fn new(
        store: OwnershipStore,
        child: PrincipalOwnership,
        accountable_user: UserUid,
    ) -> Self {
        Self {
            store,
            child,
            accountable_user,
        }
    }

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
                        "principal initialization rollback",
                        self.child.principal_uid.to_string(),
                    ));
                }
                Ok(Some(self.child.fleet_uid))
            })
            .await
    }
}
