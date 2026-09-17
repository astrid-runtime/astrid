//! Explicit delegated user authority for already-authenticated device keys.

use std::collections::BTreeSet;

use astrid_core::{FleetUid, PrincipalUid, UserUid};
use serde::{Deserialize, Serialize};

use super::{OwnershipError, OwnershipSnapshot, OwnershipStore, PrincipalDirectory};

#[cfg(test)]
mod tests;

mod enrollment;
pub use enrollment::CreationDelegation;

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if requires a borrowed field"
)]
pub(super) fn not_initialized(value: &bool) -> bool {
    !value
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UserDeviceBinding {
    generation: uuid::Uuid,
    principal: PrincipalUid,
    public_key: [u8; 32],
    user: UserUid,
    fleet: FleetUid,
    granted_by: UserUid,
}

impl UserDeviceBinding {
    pub(super) fn belongs_to(&self, user: UserUid, fleet: FleetUid) -> bool {
        self.user == user && self.fleet == fleet
    }

    pub(super) fn for_principal(&self, principal: PrincipalUid) -> bool {
        self.principal == principal
    }
}

impl OwnershipSnapshot {
    /// Resolve an explicitly delegated user for an already-verified device.
    ///
    /// This does not verify a signature. The caller must establish possession
    /// of this exact key, ensure it is still registered/enabled for the
    /// principal, and preserve device capability attenuation. A snapshot is
    /// point-in-time evidence, not authority to retain after revocation.
    #[must_use]
    pub fn user_for_device(
        &self,
        principal: PrincipalUid,
        public_key: &[u8; 32],
    ) -> Option<UserUid> {
        if self.principal_deletions.contains_key(&principal) {
            return None;
        }
        let owner = self.principal_owner(principal)?;
        let binding = self
            .user_bindings
            .iter()
            .find(|binding| binding.principal == principal && &binding.public_key == public_key)?;
        if binding.fleet != owner.fleet_uid || self.user(binding.user).is_none() {
            return None;
        }
        self.fleet(binding.fleet)?.membership(binding.user)?;
        Some(binding.user)
    }

    pub(super) fn validate_user_bindings(
        &self,
        principals: &PrincipalDirectory,
    ) -> Result<(), OwnershipError> {
        let mut seen = BTreeSet::new();
        for binding in &self.user_bindings {
            if !seen.insert((binding.principal, binding.public_key))
                || !principals.contains_uid(binding.principal)
                || !self.users.contains_key(&binding.user)
                || !self.users.contains_key(&binding.granted_by)
                || !self.fleets.contains_key(&binding.fleet)
            {
                return Err(OwnershipError::CorruptGraph(
                    "invalid user-device binding".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl OwnershipStore {
    /// Initialize the trusted local operator's delegation once per runtime.
    ///
    /// Only trusted boot code may call this with the durable local-root
    /// identity and credential. It is not a login or pairing endpoint.
    /// A transferred root or demoted owner is not adopted. The durable marker
    /// prevents later boots from recreating a revoked delegation.
    ///
    /// # Errors
    /// Returns storage/integrity failures or a conflicting existing binding.
    pub async fn initialize_local_user_device(
        &self,
        principal: PrincipalUid,
        public_key: [u8; 32],
        user: UserUid,
        expected_fleet: FleetUid,
    ) -> Result<(), OwnershipError> {
        self.mutate(|graph| {
            if graph.local_user_binding_initialized {
                return Ok(());
            }
            let eligible = graph
                .principal_owner(principal)
                .is_some_and(|owner| owner.fleet_uid == expected_fleet)
                && graph
                    .fleet(expected_fleet)
                    .and_then(|fleet| fleet.membership(user))
                    .is_some_and(|member| member.role.can_manage());
            if eligible {
                if let Some(existing) = graph.user_bindings.iter().find(|binding| {
                    binding.principal == principal && binding.public_key == public_key
                }) {
                    if existing.user != user || existing.fleet != expected_fleet {
                        return Err(OwnershipError::IdentityConflict(
                            "local user-device binding",
                            principal.to_string(),
                        ));
                    }
                } else {
                    graph.user_bindings.push(UserDeviceBinding {
                        generation: uuid::Uuid::new_v4(),
                        principal,
                        public_key,
                        user,
                        fleet: expected_fleet,
                        granted_by: user,
                    });
                }
            }
            graph.local_user_binding_initialized = true;
            Ok(())
        })
        .await
    }

    /// Delegate a principal/device credential to a current fleet member.
    ///
    /// Trusted management callers must authenticate `actor` independently.
    /// This checks current manager authority and target membership atomically;
    /// it does not authenticate the actor or register the key for transport use.
    /// Existing bindings cannot be silently repointed to another user/fleet.
    ///
    /// # Errors
    /// Rejects missing identities, non-manager actors, foreign users and
    /// conflicting bindings. Revoke an old binding explicitly before replacing it.
    pub async fn bind_user_device(
        &self,
        principal: PrincipalUid,
        public_key: [u8; 32],
        user: UserUid,
        actor: UserUid,
    ) -> Result<(), OwnershipError> {
        self.mutate(|graph| {
            let fleet_uid = graph
                .principal_owner(principal)
                .ok_or(OwnershipError::PrincipalNotOwned(principal))?
                .fleet_uid;
            let fleet = graph
                .fleet(fleet_uid)
                .ok_or(OwnershipError::FleetNotFound(fleet_uid))?;
            Self::require_manager(fleet, actor)?;
            if graph.user(user).is_none() {
                return Err(OwnershipError::UserNotFound(user));
            }
            if fleet.membership(user).is_none() {
                return Err(OwnershipError::NotFleetMember {
                    user,
                    fleet: fleet_uid,
                });
            }
            if let Some(existing) = graph
                .user_bindings
                .iter()
                .find(|binding| binding.principal == principal && binding.public_key == public_key)
            {
                if existing.user == user && existing.fleet == fleet_uid {
                    return Ok(());
                }
                return Err(OwnershipError::IdentityConflict(
                    "user-device binding",
                    principal.to_string(),
                ));
            }
            graph.user_bindings.push(UserDeviceBinding {
                generation: uuid::Uuid::new_v4(),
                principal,
                public_key,
                user,
                fleet: fleet_uid,
                granted_by: actor,
            });
            Ok(())
        })
        .await
    }

    /// Revoke one delegation under current principal-fleet management authority.
    /// This does not remove the transport key or revoke other delegations.
    ///
    /// # Errors
    /// Rejects an unowned principal or an actor without current manager authority.
    pub async fn revoke_user_device(
        &self,
        principal: PrincipalUid,
        public_key: [u8; 32],
        actor: UserUid,
    ) -> Result<(), OwnershipError> {
        self.mutate(|graph| {
            let fleet_uid = graph
                .principal_owner(principal)
                .ok_or(OwnershipError::PrincipalNotOwned(principal))?
                .fleet_uid;
            Self::require_manager(
                graph
                    .fleet(fleet_uid)
                    .ok_or(OwnershipError::FleetNotFound(fleet_uid))?,
                actor,
            )?;
            graph.user_bindings.retain(|binding| {
                binding.principal != principal || binding.public_key != public_key
            });
            Ok(())
        })
        .await
    }
}
