//! First assignment using current creator ownership and current human authority.

use astrid_core::{PrincipalOwnership, PrincipalUid, UserUid};

use super::{OwnershipError, OwnershipSnapshot, OwnershipStore};

impl OwnershipStore {
    /// Assign a new principal to its creator's current fleet atomically.
    ///
    /// The caller must independently authenticate `actor` and authorize the
    /// creation operation. This store checks current fleet-manager membership;
    /// it does not treat the supplied UID as proof of authentication.
    /// Creator lookup, membership check and assignment share one CAS mutation,
    /// so a retry re-evaluates authority rather than reusing a stale snapshot.
    /// Clone source and historical `assigned_by` never determine authority.
    ///
    /// # Errors
    ///
    /// Rejects unknown/deleting principals, an unowned creator, insufficient
    /// current authority and implicit transfer of an already-owned principal.
    pub async fn assign_created_principal(
        &self,
        created: PrincipalUid,
        creator: PrincipalUid,
        actor: UserUid,
    ) -> Result<(), OwnershipError> {
        self.mutate(|graph| self.assign_creation_in_graph(graph, created, creator, actor))
            .await
    }

    /// Assign using an explicitly bound, already-authenticated creator device.
    /// Delegation, membership and ownership are checked in the same mutation.
    /// The caller must still verify that the transport key is registered and
    /// the principal/device has permission to create.
    ///
    /// # Errors
    /// Rejects absent/revoked delegation and all first-assignment failures.
    pub async fn assign_created_principal_for_device(
        &self,
        created: PrincipalUid,
        creator: PrincipalUid,
        public_key: &[u8; 32],
    ) -> Result<(), OwnershipError> {
        self.mutate(|graph| {
            let actor = graph
                .user_for_device(creator, public_key)
                .ok_or(OwnershipError::UserDeviceNotBound(creator))?;
            self.assign_creation_in_graph(graph, created, creator, actor)
        })
        .await
    }

    pub(super) fn assign_creation_in_graph(
        &self,
        graph: &mut OwnershipSnapshot,
        created: PrincipalUid,
        creator: PrincipalUid,
        actor: UserUid,
    ) -> Result<(), OwnershipError> {
        for principal in [created, creator] {
            if graph.principal_deletions.contains_key(&principal) {
                return Err(OwnershipError::PrincipalDeletionInProgress(principal));
            }
            if !self.principals.contains_uid(principal) {
                return Err(OwnershipError::PrincipalNotFound(principal));
            }
        }
        let fleet_uid = graph
            .principal_ownership
            .get(&creator)
            .ok_or(OwnershipError::PrincipalNotOwned(creator))?
            .fleet_uid;
        let fleet = graph
            .fleets
            .get(&fleet_uid)
            .ok_or(OwnershipError::FleetNotFound(fleet_uid))?;
        Self::require_manager(fleet, actor)?;
        match graph.principal_ownership.get(&created) {
            Some(existing) if existing.fleet_uid == fleet_uid => Ok(()),
            Some(existing) => Err(OwnershipError::PrincipalAlreadyOwned {
                principal: created,
                fleet: existing.fleet_uid,
            }),
            None => {
                graph.principal_ownership.insert(
                    created,
                    PrincipalOwnership {
                        principal_uid: created,
                        fleet_uid,
                        assigned_by: actor,
                    },
                );
                Ok(())
            },
        }
    }
}
