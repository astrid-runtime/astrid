//! Resource accountability is independent of fleet access and assignment history.

use astrid_core::{PrincipalUid, UserUid};

use super::{OwnershipError, OwnershipSnapshot, OwnershipStore};

#[cfg(test)]
mod tests;

impl OwnershipSnapshot {
    /// User whose allocation pays for this principal, including background work.
    /// Missing means legacy attribution has not yet been explicitly resolved;
    /// it must not be interpreted as unlimited or inferred from `assigned_by`.
    #[must_use]
    pub fn accountable_user(&self, principal: PrincipalUid) -> Option<UserUid> {
        self.accountable_users.get(&principal).copied()
    }

    pub(super) fn validate_accountable_users(&self) -> Result<(), OwnershipError> {
        for (principal, user) in &self.accountable_users {
            if !self.principal_ownership.contains_key(principal) || !self.users.contains_key(user) {
                return Err(OwnershipError::CorruptGraph(format!(
                    "resource accountability for principal {principal} references missing ownership or user {user}"
                )));
            }
        }
        Ok(())
    }
}

impl OwnershipStore {
    /// Set a principal's accountable user after independent operator authorization.
    ///
    /// This is not a fleet-member operation: fleet management alone does not
    /// authorize spending another user's allocation. The caller must verify
    /// resource-administration authority before invoking this storage primitive.
    /// A stale expected owner is rejected; fleet transfer never calls this.
    ///
    /// # Errors
    /// Rejects absent identities, retirement, stale attribution and storage errors.
    pub async fn assign_accountable_user(
        &self,
        principal: PrincipalUid,
        expected: Option<UserUid>,
        user: UserUid,
    ) -> Result<(), OwnershipError> {
        self.mutate(|graph| {
            if graph.principal_deletions.contains_key(&principal) {
                return Err(OwnershipError::PrincipalDeletionInProgress(principal));
            }
            if graph.principal_owner(principal).is_none() {
                return Err(OwnershipError::PrincipalNotOwned(principal));
            }
            if graph.user(user).is_none() {
                return Err(OwnershipError::CorruptGraph(format!(
                    "accountable user {user} is absent"
                )));
            }
            if graph.accountable_user(principal) != expected {
                return Err(OwnershipError::IdentityConflict(
                    "accountable user",
                    principal.to_string(),
                ));
            }
            graph.accountable_users.insert(principal, user);
            Ok(())
        })
        .await
    }

    /// Upgrade legacy attribution only for the unambiguous bound local operator.
    ///
    /// Existing explicit assignments are never changed. Multiple users/fleets
    /// or a missing/revoked device binding leave attribution unresolved. The
    /// returned UIDs need an explicit operator assignment, not a new home.
    ///
    /// # Errors
    /// Propagates graph integrity and persistence failures.
    pub async fn reconcile_local_accountable_users(
        &self,
        principal: PrincipalUid,
        public_key: &[u8; 32],
    ) -> Result<Vec<PrincipalUid>, OwnershipError> {
        self.mutate(|graph| {
            if let Some((user, fleet)) =
                super::upgrade::bound_local_operator(graph, principal, public_key)
                && graph.users.len() == 1
                && graph.fleets.len() == 1
                && graph
                    .principal_ownership
                    .values()
                    .all(|owner| owner.fleet_uid == fleet)
            {
                for principal in graph.principal_ownership.keys() {
                    graph.accountable_users.entry(*principal).or_insert(user);
                }
            }
            Ok(graph
                .principal_ownership
                .keys()
                .filter(|principal| !graph.accountable_users.contains_key(principal))
                .copied()
                .collect())
        })
        .await
    }
}
