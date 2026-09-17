//! Durable principal retirement with current fleet authorization.

use std::sync::Arc;

use astrid_core::{FleetUid, PrincipalId, PrincipalUid};

use super::{
    OwnershipError, OwnershipSnapshot, OwnershipStore, PrincipalDeletionGuard,
    PrincipalDeletionReservation,
};

#[cfg(test)]
mod tests;

impl OwnershipStore {
    /// Reserve an unowned principal for durable identity deletion.
    ///
    /// The reservation changes the graph's CAS version, so a writer that read
    /// the unowned graph before this call must retry and observe the deletion.
    /// Call [`PrincipalDeletionGuard::finish`] only after durable identity
    /// removal succeeds. Dropping the guard leaves the reservation in place so
    /// a partial deletion fails closed and can be retried safely.
    ///
    /// # Errors
    ///
    /// Rejects a principal that already belongs to a fleet and fails closed on
    /// invalid or unavailable ownership state.
    pub async fn guard_principal_deletion(
        &self,
        principal_uid: PrincipalUid,
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        self.guard_principal_deletion_inner(principal_uid, None, None)
            .await
    }

    /// Reserve an unowned principal and retain its alias for crash recovery.
    ///
    /// The alias allows a later deletion retry to remove the reservation even
    /// when the durable identity record and live directory entry were already
    /// deleted.
    ///
    /// # Errors
    ///
    /// Rejects an owned or unknown principal, a conflicting retry alias, and
    /// invalid or unavailable ownership state.
    pub async fn guard_principal_deletion_for_alias(
        &self,
        principal_uid: PrincipalUid,
        alias: PrincipalId,
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        self.guard_principal_deletion_inner(principal_uid, Some(alias), None)
            .await
    }

    /// Reserve deletion using a registered, transport-authenticated device.
    /// Current delegation and target fleet management are checked in the same
    /// CAS as ownership removal and reservation. The caller must independently
    /// enforce the device's deletion capability. No authority comes from a UID
    /// or historical `assigned_by` field alone.
    ///
    /// # Errors
    /// Rejects missing delegation, foreign/non-manager users, alias conflicts,
    /// missing principals and unavailable storage without changing ownership.
    pub async fn guard_principal_deletion_for_device(
        &self,
        principal_uid: PrincipalUid,
        alias: PrincipalId,
        caller: PrincipalUid,
        public_key: &[u8; 32],
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        self.guard_principal_deletion_inner(principal_uid, Some(alias), Some((caller, public_key)))
            .await
    }

    /// Reserve an alias whose legacy identity generation is already missing.
    ///
    /// Recovery code uses this before touching alias-keyed files so a failed
    /// cleanup cannot make an old key, home, or secret tree available to a new
    /// identity. The synthetic UID exists only as the durable map key for this
    /// reservation and is derived in a separate domain from real identities.
    ///
    /// # Errors
    ///
    /// Fails closed if the alias is already reserved, the synthetic key
    /// collides with a live principal, or the ownership graph cannot be saved.
    pub async fn guard_legacy_alias_deletion(
        &self,
        alias: PrincipalId,
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        let mut hasher =
            blake3::Hasher::new_derive_key("astrid legacy alias deletion reservation v1");
        hasher.update(alias.as_str().as_bytes());
        let reservation_uid = PrincipalUid::from_bytes(*hasher.finalize().as_bytes());
        let guard = Arc::clone(&self.mutation_lock).lock_owned().await;
        self.mutate_unlocked(|graph| {
            if self.principals.contains_uid(reservation_uid) {
                return Err(OwnershipError::CorruptGraph(format!(
                    "legacy deletion reservation for alias {alias} collides with live principal {reservation_uid}"
                )));
            }
            if let Some((principal, _)) = graph
                .principal_deletions
                .iter()
                .find(|(_, reservation)| reservation.alias.as_ref() == Some(&alias))
            {
                if *principal != reservation_uid {
                    return Err(OwnershipError::DeletionAliasReserved {
                        alias: alias.clone(),
                        principal: *principal,
                    });
                }
            } else {
                graph.principal_deletions.insert(
                    reservation_uid,
                    PrincipalDeletionReservation {
                        alias: Some(alias.clone()),
                        fleet: None,
                    },
                );
            }
            Ok(())
        })
        .await?;
        Ok(PrincipalDeletionGuard {
            store: self.clone(),
            principal_uid: reservation_uid,
            _guard: guard,
        })
    }

    /// Finish a previously interrupted deletion using its durable alias.
    ///
    /// Returns `true` when a matching reservation was removed and `false`
    /// when no interrupted deletion exists for this alias.
    ///
    /// # Errors
    ///
    /// Fails closed when the graph cannot be read, validated, or atomically
    /// updated.
    pub async fn finish_principal_deletion_by_alias(
        &self,
        alias: &PrincipalId,
    ) -> Result<bool, OwnershipError> {
        let alias = alias.clone();
        self.mutate(|graph| {
            let principal_uid = graph
                .principal_deletions
                .iter()
                .find_map(|(uid, reservation)| {
                    (reservation.alias.as_ref() == Some(&alias)).then_some(*uid)
                });
            if let Some(uid) = principal_uid
                && self.principals.contains_uid(uid)
            {
                return Err(OwnershipError::PrincipalDeletionStillLive(uid));
            }
            Ok(principal_uid
                .and_then(|uid| graph.principal_deletions.remove(&uid))
                .is_some())
        })
        .await
    }

    /// Reacquire an interrupted deletion reservation by its retained alias.
    ///
    /// Unlike [`finish_principal_deletion_by_alias`](Self::finish_principal_deletion_by_alias),
    /// this does not remove the reservation. The caller must first finish all
    /// generation-scoped reclamation and then call [`PrincipalDeletionGuard::finish`].
    ///
    /// # Errors
    ///
    /// Returns an ownership error if the graph cannot be loaded or the retired
    /// principal is unexpectedly live again.
    pub async fn resume_principal_deletion_by_alias(
        &self,
        alias: &PrincipalId,
    ) -> Result<Option<PrincipalDeletionGuard>, OwnershipError> {
        self.resume_deletion_inner(alias, None).await
    }

    /// Resume cleanup after identity removal, rechecking the reservation's fleet.
    /// The caller must authenticate the key and enforce deletion capability.
    ///
    /// # Errors
    /// Rejects revoked delegation or insufficient current fleet authority, a
    /// still-live identity, and invalid or unavailable storage.
    pub async fn resume_principal_deletion_for_device(
        &self,
        alias: &PrincipalId,
        caller: PrincipalUid,
        public_key: &[u8; 32],
    ) -> Result<Option<PrincipalDeletionGuard>, OwnershipError> {
        self.resume_deletion_inner(alias, Some((caller, public_key)))
            .await
    }

    async fn resume_deletion_inner(
        &self,
        alias: &PrincipalId,
        authority: Option<(PrincipalUid, &[u8; 32])>,
    ) -> Result<Option<PrincipalDeletionGuard>, OwnershipError> {
        let guard = Arc::clone(&self.mutation_lock).lock_owned().await;
        let graph = self.load().await?;
        let principal_uid = graph
            .principal_deletions
            .iter()
            .find_map(|(uid, reservation)| {
                (reservation.alias.as_ref() == Some(alias)).then_some(*uid)
            });
        let Some(principal_uid) = principal_uid else {
            return Ok(None);
        };
        Self::authorize_deletion(&graph, principal_uid, authority)?;
        if self.principals.contains_uid(principal_uid) {
            return Err(OwnershipError::PrincipalDeletionStillLive(principal_uid));
        }
        Ok(Some(PrincipalDeletionGuard {
            store: self.clone(),
            principal_uid,
            _guard: guard,
        }))
    }

    /// Reject creation while an interrupted deletion still owns `alias`.
    ///
    /// # Errors
    ///
    /// Returns an ownership error if the graph cannot be loaded or `alias` is
    /// still reserved by an incomplete deletion.
    pub async fn ensure_alias_available(&self, alias: &PrincipalId) -> Result<(), OwnershipError> {
        let graph = self.load().await?;
        if let Some((principal, _)) = graph
            .principal_deletions
            .iter()
            .find(|(_, reservation)| reservation.alias.as_ref() == Some(alias))
        {
            return Err(OwnershipError::DeletionAliasReserved {
                alias: alias.clone(),
                principal: *principal,
            });
        }
        Ok(())
    }

    async fn guard_principal_deletion_inner(
        &self,
        principal_uid: PrincipalUid,
        alias: Option<PrincipalId>,
        authority: Option<(PrincipalUid, &[u8; 32])>,
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        let guard = Arc::clone(&self.mutation_lock).lock_owned().await;
        self.mutate_unlocked(|graph| {
            let fleet = Self::authorize_deletion(graph, principal_uid, authority)?;
            if let Some(requested) = &alias
                && let Ok(live_alias) = self.principals.alias_for(principal_uid)
                && &live_alias != requested
            {
                return Err(OwnershipError::DeletionReservationConflict {
                    principal: principal_uid,
                    alias: live_alias,
                });
            }
            if let Some(reservation) = graph.principal_deletions.get_mut(&principal_uid) {
                match (&reservation.alias, &alias) {
                    (Some(existing), Some(requested)) if existing != requested => {
                        return Err(OwnershipError::DeletionReservationConflict {
                            principal: principal_uid,
                            alias: existing.clone(),
                        });
                    },
                    (None, Some(requested)) => reservation.alias = Some(requested.clone()),
                    _ => {},
                }
            } else {
                if !self.principals.contains_uid(principal_uid) {
                    return Err(OwnershipError::PrincipalNotFound(principal_uid));
                }
                if let Some(requested) = &alias
                    && let Some((reserved_uid, _)) = graph
                        .principal_deletions
                        .iter()
                        .find(|(_, reservation)| reservation.alias.as_ref() == Some(requested))
                {
                    return Err(OwnershipError::DeletionAliasReserved {
                        alias: requested.clone(),
                        principal: *reserved_uid,
                    });
                }
                graph.principal_deletions.insert(
                    principal_uid,
                    PrincipalDeletionReservation {
                        alias: alias.clone(),
                        fleet,
                    },
                );
            }
            // Ownership removal and retirement commit together. Retaining the
            // fleet on the reservation protects retries after identity removal.
            graph.principal_ownership.remove(&principal_uid);
            graph
                .user_bindings
                .retain(|binding| !binding.for_principal(principal_uid));
            Ok(())
        })
        .await?;
        Ok(PrincipalDeletionGuard {
            store: self.clone(),
            principal_uid,
            _guard: guard,
        })
    }

    fn authorize_deletion(
        graph: &OwnershipSnapshot,
        principal: PrincipalUid,
        authority: Option<(PrincipalUid, &[u8; 32])>,
    ) -> Result<Option<FleetUid>, OwnershipError> {
        let fleet = graph
            .principal_owner(principal)
            .map(|owner| owner.fleet_uid)
            .or_else(|| {
                graph
                    .principal_deletions
                    .get(&principal)
                    .and_then(|pending| pending.fleet)
            });
        if let Some(fleet_uid) = fleet {
            let (caller, key) = authority.ok_or(OwnershipError::PrincipalAlreadyOwned {
                principal,
                fleet: fleet_uid,
            })?;
            let user = graph
                .user_for_device(caller, key)
                .ok_or(OwnershipError::UserDeviceNotBound(caller))?;
            let record = graph
                .fleet(fleet_uid)
                .ok_or(OwnershipError::FleetNotFound(fleet_uid))?;
            Self::require_manager(record, user)?;
        }
        Ok(fleet)
    }
}
