//! Atomic persistence for Astrid's human-to-fleet ownership graph.
//!
//! The complete graph is stored behind one compare-and-swap key. This keeps
//! cross-record invariants crash-safe: a fleet and its initial owner appear
//! together, and a principal can never be observed in two fleets. The format
//! can be sharded behind the same API if graph size later warrants it.

use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_core::{
    FirstOwnerGeneration, FleetIdentity, FleetMembership, FleetRole, FleetUid, PrincipalId,
    PrincipalOwnership, PrincipalUid, UserIdentity, UserUid,
};
use astrid_resource_types::AuthorityEpoch;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::{KvStore, PrincipalDirectory, ScopedKvStore};

#[path = "first_owner.rs"]
mod first_owner;
pub use first_owner::{FirstOwnerEnrollment, FirstOwnerError};
#[path = "error.rs"]
mod ownership_error;
pub use ownership_error::OwnershipError;
#[path = "helpers.rs"]
mod ownership_helpers;

/// Namespace reserved for the authoritative ownership graph.
pub const OWNERSHIP_NAMESPACE: &str = "system:ownership";
const GRAPH_KEY: &str = "graph-v1";
const GRAPH_FORMAT_VERSION: u16 = 2;
const LEGACY_GRAPH_FORMAT_VERSION: u16 = 1;
const MAX_CAS_ATTEMPTS: usize = 64;

/// One fleet identity and all current human memberships.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetRecord {
    identity: FleetIdentity,
    memberships: BTreeMap<UserUid, FleetMembership>,
}

impl FleetRecord {
    /// Fleet's immutable identity.
    #[must_use]
    pub const fn identity(&self) -> &FleetIdentity {
        &self.identity
    }

    /// Look up one user's current membership.
    #[must_use]
    pub fn membership(&self, user_uid: UserUid) -> Option<&FleetMembership> {
        self.memberships.get(&user_uid)
    }

    /// Iterate over current memberships in stable UID order.
    pub fn memberships(&self) -> impl Iterator<Item = &FleetMembership> {
        self.memberships.values()
    }
}

/// Validated point-in-time view of all ownership state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipSnapshot {
    format_version: u16,
    users: BTreeMap<UserUid, UserIdentity>,
    fleets: BTreeMap<FleetUid, FleetRecord>,
    principal_ownership: BTreeMap<PrincipalUid, PrincipalOwnership>,
    #[serde(default)]
    principal_deletions: BTreeMap<PrincipalUid, PrincipalDeletionReservation>,
    /// First-owner enrollment is optional only while reading an empty v1
    /// legacy graph. New writes always materialize the state explicitly.
    #[serde(default)]
    enrollment: Option<FirstOwnerEnrollment>,
    /// Current durable authority epoch. It advances whenever a pending claim
    /// is cancelled or expires and is checked by every enrolled capability.
    #[serde(default = "default_authority_epoch")]
    authority_epoch: AuthorityEpoch,
    /// Current durable enrollment generation. It is independent from the
    /// authority epoch so stale claims cannot become valid after reopen.
    #[serde(default = "default_authority_generation")]
    authority_generation: FirstOwnerGeneration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalDeletionReservation {
    alias: Option<PrincipalId>,
}

impl Default for OwnershipSnapshot {
    fn default() -> Self {
        Self {
            format_version: GRAPH_FORMAT_VERSION,
            users: BTreeMap::new(),
            fleets: BTreeMap::new(),
            principal_ownership: BTreeMap::new(),
            principal_deletions: BTreeMap::new(),
            enrollment: Some(FirstOwnerEnrollment::Unenrolled),
            authority_epoch: default_authority_epoch(),
            authority_generation: default_authority_generation(),
        }
    }
}

const fn default_authority_epoch() -> AuthorityEpoch {
    AuthorityEpoch::INITIAL
}

const fn default_authority_generation() -> FirstOwnerGeneration {
    FirstOwnerGeneration::INITIAL
}

impl OwnershipSnapshot {
    /// Look up one human identity.
    #[must_use]
    pub fn user(&self, uid: UserUid) -> Option<&UserIdentity> {
        self.users.get(&uid)
    }

    /// Look up one fleet.
    #[must_use]
    pub fn fleet(&self, uid: FleetUid) -> Option<&FleetRecord> {
        self.fleets.get(&uid)
    }

    /// Resolve the sole fleet owner of an executable principal.
    #[must_use]
    pub fn principal_owner(&self, uid: PrincipalUid) -> Option<&PrincipalOwnership> {
        self.principal_ownership.get(&uid)
    }

    /// Iterate over users in stable UID order.
    pub fn users(&self) -> impl Iterator<Item = &UserIdentity> {
        self.users.values()
    }

    /// Iterate over fleets in stable UID order.
    pub fn fleets(&self) -> impl Iterator<Item = &FleetRecord> {
        self.fleets.values()
    }

    /// Iterate over principal assignments in stable UID order.
    pub fn principal_owners(&self) -> impl Iterator<Item = &PrincipalOwnership> {
        self.principal_ownership.values()
    }

    /// Current durable authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Current durable enrollment generation.
    #[must_use]
    pub const fn authority_generation(&self) -> FirstOwnerGeneration {
        self.authority_generation
    }

    fn validate(&self, principals: &PrincipalDirectory) -> Result<(), OwnershipError> {
        if self.format_version != GRAPH_FORMAT_VERSION {
            return Err(OwnershipError::UnsupportedFormat(self.format_version));
        }
        self.validate_first_owner()?;
        for (uid, identity) in &self.users {
            identity.validate()?;
            if *uid != identity.uid {
                return Err(OwnershipError::CorruptGraph(format!(
                    "user map key {uid} does not match record {}",
                    identity.uid
                )));
            }
        }
        for (uid, fleet) in &self.fleets {
            fleet.identity.validate()?;
            if *uid != fleet.identity.uid {
                return Err(OwnershipError::CorruptGraph(format!(
                    "fleet map key {uid} does not match record {}",
                    fleet.identity.uid
                )));
            }
            if !self.users.contains_key(&fleet.identity.genesis.created_by) {
                return Err(OwnershipError::CorruptGraph(format!(
                    "fleet {uid} creator {} is absent",
                    fleet.identity.genesis.created_by
                )));
            }
            let mut owner_count = 0_usize;
            for (member_uid, membership) in &fleet.memberships {
                if *member_uid != membership.user_uid || membership.fleet_uid != *uid {
                    return Err(OwnershipError::CorruptGraph(format!(
                        "membership index disagrees inside fleet {uid}"
                    )));
                }
                if !self.users.contains_key(member_uid)
                    || !self.users.contains_key(&membership.granted_by)
                {
                    return Err(OwnershipError::CorruptGraph(format!(
                        "membership in fleet {uid} references an absent user"
                    )));
                }
                if membership.role == FleetRole::Owner {
                    owner_count = owner_count.checked_add(1).ok_or_else(|| {
                        OwnershipError::CorruptGraph(format!(
                            "fleet {uid} owner count exceeds platform limits"
                        ))
                    })?;
                }
            }
            if owner_count == 0 {
                return Err(OwnershipError::CorruptGraph(format!(
                    "fleet {uid} has no owner"
                )));
            }
        }
        for (principal_uid, ownership) in &self.principal_ownership {
            if *principal_uid != ownership.principal_uid {
                return Err(OwnershipError::CorruptGraph(format!(
                    "principal ownership key {principal_uid} disagrees with its record"
                )));
            }
            if !principals.contains_uid(*principal_uid) {
                return Err(OwnershipError::CorruptGraph(format!(
                    "principal {principal_uid} is absent from the admitted principal directory"
                )));
            }
            if !self.fleets.contains_key(&ownership.fleet_uid)
                || !self.users.contains_key(&ownership.assigned_by)
            {
                return Err(OwnershipError::CorruptGraph(format!(
                    "principal {principal_uid} ownership references an absent identity"
                )));
            }
        }
        let mut deletion_aliases = BTreeMap::new();
        for (principal_uid, reservation) in &self.principal_deletions {
            if self.principal_ownership.contains_key(principal_uid) {
                return Err(OwnershipError::CorruptGraph(format!(
                    "principal {principal_uid} is both owned and reserved for deletion"
                )));
            }
            if let Some(alias) = &reservation.alias
                && let Some(existing_uid) =
                    deletion_aliases.insert(alias.as_str().to_owned(), *principal_uid)
            {
                return Err(OwnershipError::CorruptGraph(format!(
                    "principal deletion alias {alias} is reserved by both {existing_uid} and {principal_uid}"
                )));
            }
        }
        Ok(())
    }
}

/// Persistent, optimistic-concurrency owner of the Astrid ownership graph.
#[derive(Clone, Debug)]
pub struct OwnershipStore {
    storage: ScopedKvStore,
    principals: PrincipalDirectory,
    mutation_lock: Arc<AsyncMutex<()>>,
    authority_binding: Arc<AuthorityBinding>,
}

#[derive(Debug)]
struct AuthorityBinding;

/// Opaque proof that the caller obtained authority from this enrolled store.
///
/// The private binding prevents construction by callers outside this crate;
/// every mutation rechecks the persisted epoch and generation before CAS.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct EnrolledAuthority {
    binding: Arc<AuthorityBinding>,
    epoch: AuthorityEpoch,
    generation: FirstOwnerGeneration,
    user_uid: UserUid,
}

/// Exclusive barrier held while an unowned principal is removed from the
/// durable identity directory.
///
/// Dropping this guard allows ownership mutations to resume. Callers must keep
/// it alive until identity removal has either completed or been abandoned.
#[derive(Debug)]
#[must_use = "dropping the guard permits concurrent ownership assignment"]
pub struct PrincipalDeletionGuard {
    store: OwnershipStore,
    principal_uid: PrincipalUid,
    authority: EnrolledAuthority,
    _guard: OwnedMutexGuard<()>,
}

impl PrincipalDeletionGuard {
    /// Immutable principal generation protected by this reservation.
    #[must_use]
    pub const fn principal_uid(&self) -> PrincipalUid {
        self.principal_uid
    }

    /// Remove the durable reservation after identity removal completes.
    ///
    /// # Errors
    ///
    /// Fails closed when the latest graph cannot be read, validated, or
    /// atomically updated. On failure the reservation remains durable.
    pub async fn finish(self) -> Result<(), OwnershipError> {
        let principal_uid = self.principal_uid;
        let authority = self.authority.clone();
        self.store
            .mutate_unlocked(|graph| {
                self.store.validate_authority(graph, &authority)?;
                graph.principal_deletions.remove(&principal_uid);
                Ok(())
            })
            .await
    }
}

impl OwnershipStore {
    /// Construct an ownership store over a raw Astrid KV backend.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError::Storage`] if the reserved namespace is invalid.
    pub fn new(
        storage: Arc<dyn KvStore>,
        principals: PrincipalDirectory,
    ) -> Result<Self, OwnershipError> {
        Ok(Self {
            storage: ScopedKvStore::new(storage, OWNERSHIP_NAMESPACE)?,
            principals,
            mutation_lock: Arc::new(AsyncMutex::new(())),
            authority_binding: Arc::new(AuthorityBinding),
        })
    }

    /// Mint an opaque mutation capability from the currently enrolled state.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError::AuthorityNotEnrolled`] when the persisted
    /// graph is not in a current enrolled state, or another error when the
    /// graph cannot be loaded and validated.
    pub async fn enrolled_authority(&self) -> Result<EnrolledAuthority, OwnershipError> {
        let graph = self.load().await?;
        let enrollment = graph.first_owner_state();
        let Some(claim) = enrollment.claim() else {
            return Err(OwnershipError::AuthorityNotEnrolled);
        };
        if !enrollment.is_enrolled()
            || claim.authority_epoch() != graph.authority_epoch
            || claim.authority_generation() != graph.authority_generation
        {
            return Err(OwnershipError::AuthorityNotEnrolled);
        }
        Ok(EnrolledAuthority {
            binding: Arc::clone(&self.authority_binding),
            epoch: graph.authority_epoch,
            generation: graph.authority_generation,
            user_uid: claim.user_uid(),
        })
    }

    /// Load and validate the latest ownership snapshot.
    ///
    /// # Errors
    ///
    /// Fails closed on storage errors, malformed bytes, or broken invariants.
    pub async fn load(&self) -> Result<OwnershipSnapshot, OwnershipError> {
        let raw = self.storage.get(GRAPH_KEY).await?;
        self.decode(raw.as_deref())
    }

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
        let authority = self.enrolled_authority().await?;
        self.guard_principal_deletion_inner(&authority, principal_uid, None)
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
        let authority = self.enrolled_authority().await?;
        self.guard_principal_deletion_inner(&authority, principal_uid, Some(alias))
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
        let authority = self.enrolled_authority().await?;
        let mut hasher =
            blake3::Hasher::new_derive_key("astrid legacy alias deletion reservation v1");
        hasher.update(alias.as_str().as_bytes());
        let reservation_uid = PrincipalUid::from_bytes(*hasher.finalize().as_bytes());
        let guard = Arc::clone(&self.mutation_lock).lock_owned().await;
        self.mutate_unlocked(|graph| {
            self.validate_authority(graph, &authority)?;
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
                    },
                );
            }
            Ok(())
        })
        .await?;
        Ok(PrincipalDeletionGuard {
            store: self.clone(),
            principal_uid: reservation_uid,
            authority,
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
        let authority = self.enrolled_authority().await?;
        self.mutate_with_authority(&authority, |graph| {
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
        let authority = self.enrolled_authority().await?;
        let guard = Arc::clone(&self.mutation_lock).lock_owned().await;
        let graph = self.load().await?;
        self.validate_authority(&graph, &authority)?;
        let principal_uid = graph
            .principal_deletions
            .iter()
            .find_map(|(uid, reservation)| {
                (reservation.alias.as_ref() == Some(alias)).then_some(*uid)
            });
        let Some(principal_uid) = principal_uid else {
            return Ok(None);
        };
        if self.principals.contains_uid(principal_uid) {
            return Err(OwnershipError::PrincipalDeletionStillLive(principal_uid));
        }
        Ok(Some(PrincipalDeletionGuard {
            store: self.clone(),
            principal_uid,
            authority,
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
        authority: &EnrolledAuthority,
        principal_uid: PrincipalUid,
        alias: Option<PrincipalId>,
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        let guard = Arc::clone(&self.mutation_lock).lock_owned().await;
        self.mutate_unlocked(|graph| {
            self.validate_authority(graph, authority)?;
            if let Some(ownership) = graph.principal_owner(principal_uid) {
                return Err(OwnershipError::PrincipalAlreadyOwned {
                    principal: principal_uid,
                    fleet: ownership.fleet_uid,
                });
            }
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
                    },
                );
            }
            Ok(())
        })
        .await?;
        Ok(PrincipalDeletionGuard {
            store: self.clone(),
            principal_uid,
            authority: authority.clone(),
            _guard: guard,
        })
    }

    /// Register one durable human identity, idempotently.
    ///
    /// # Errors
    ///
    /// Rejects invalid identity material and persistence conflicts.
    pub async fn create_user(&self, identity: UserIdentity) -> Result<(), OwnershipError> {
        let authority = self.enrolled_authority().await?;
        identity.validate()?;
        self.mutate_with_authority(&authority, |graph| match graph.users.get(&identity.uid) {
            Some(existing) if existing == &identity => Ok(()),
            Some(_) => Err(OwnershipError::IdentityConflict(
                "user",
                identity.uid.to_string(),
            )),
            None => {
                graph.users.insert(identity.uid, identity.clone());
                Ok(())
            },
        })
        .await
    }

    /// Create a fleet and its initial owner in one atomic mutation.
    ///
    /// The fleet's genesis creator must already be a registered user.
    ///
    /// # Errors
    ///
    /// Rejects unknown creators, invalid identities, and UID conflicts.
    pub async fn create_fleet(&self, identity: FleetIdentity) -> Result<(), OwnershipError> {
        let authority = self.enrolled_authority().await?;
        identity.validate()?;
        self.mutate_with_authority(&authority, |graph| {
            let creator = identity.genesis.created_by;
            if !graph.users.contains_key(&creator) {
                return Err(OwnershipError::UserNotFound(creator));
            }
            if let Some(existing) = graph.fleets.get(&identity.uid) {
                return if existing.identity == identity {
                    Ok(())
                } else {
                    Err(OwnershipError::IdentityConflict(
                        "fleet",
                        identity.uid.to_string(),
                    ))
                };
            }
            let owner = FleetMembership {
                fleet_uid: identity.uid,
                user_uid: creator,
                role: FleetRole::Owner,
                granted_by: creator,
            };
            graph.fleets.insert(
                identity.uid,
                FleetRecord {
                    identity: identity.clone(),
                    memberships: BTreeMap::from([(creator, owner)]),
                },
            );
            Ok(())
        })
        .await
    }

    /// Add a user to a fleet or change their role.
    ///
    /// Owners and administrators may perform this operation. Demoting the
    /// fleet's last owner is rejected.
    ///
    /// # Errors
    ///
    /// Rejects unknown identities, insufficient authority, and last-owner loss.
    pub async fn set_membership(
        &self,
        fleet_uid: FleetUid,
        user_uid: UserUid,
        role: FleetRole,
        actor: UserUid,
    ) -> Result<(), OwnershipError> {
        let authority = self.enrolled_authority().await?;
        self.mutate_with_authority(&authority, |graph| {
            if !graph.users.contains_key(&user_uid) {
                return Err(OwnershipError::UserNotFound(user_uid));
            }
            let fleet = graph
                .fleets
                .get_mut(&fleet_uid)
                .ok_or(OwnershipError::FleetNotFound(fleet_uid))?;
            Self::require_manager(fleet, actor)?;
            let existing_role = fleet
                .memberships
                .get(&user_uid)
                .map(|membership| membership.role);
            if (role == FleetRole::Owner || existing_role == Some(FleetRole::Owner))
                && Self::role(fleet, actor) != Some(FleetRole::Owner)
            {
                return Err(OwnershipError::OwnerAuthorityRequired(fleet_uid));
            }
            if existing_role == Some(FleetRole::Owner)
                && role != FleetRole::Owner
                && Self::owner_count(fleet) == 1
            {
                return Err(OwnershipError::LastOwner(fleet_uid));
            }
            fleet.memberships.insert(
                user_uid,
                FleetMembership {
                    fleet_uid,
                    user_uid,
                    role,
                    granted_by: actor,
                },
            );
            Ok(())
        })
        .await
    }

    /// Remove one user from a fleet.
    ///
    /// # Errors
    ///
    /// Rejects insufficient authority and removal of the fleet's last owner.
    pub async fn remove_member(
        &self,
        fleet_uid: FleetUid,
        user_uid: UserUid,
        actor: UserUid,
    ) -> Result<bool, OwnershipError> {
        let authority = self.enrolled_authority().await?;
        self.mutate_with_authority(&authority, |graph| {
            let fleet = graph
                .fleets
                .get_mut(&fleet_uid)
                .ok_or(OwnershipError::FleetNotFound(fleet_uid))?;
            Self::require_manager(fleet, actor)?;
            let existing_role = fleet
                .memberships
                .get(&user_uid)
                .map(|membership| membership.role);
            if existing_role == Some(FleetRole::Owner)
                && Self::role(fleet, actor) != Some(FleetRole::Owner)
            {
                return Err(OwnershipError::OwnerAuthorityRequired(fleet_uid));
            }
            if existing_role == Some(FleetRole::Owner) && Self::owner_count(fleet) == 1 {
                return Err(OwnershipError::LastOwner(fleet_uid));
            }
            Ok(fleet.memberships.remove(&user_uid).is_some())
        })
        .await
    }

    /// Assign a previously unowned executable principal to a fleet.
    ///
    /// Repeating the same assignment is idempotent. Moving a principal uses
    /// [`transfer_principal`](Self::transfer_principal), which checks both
    /// ownership boundaries explicitly.
    ///
    /// # Errors
    ///
    /// Rejects insufficient authority and any implicit reassignment.
    pub async fn assign_principal(
        &self,
        ownership: PrincipalOwnership,
    ) -> Result<(), OwnershipError> {
        let authority = self.enrolled_authority().await?;
        self.mutate_with_authority(&authority, |graph| {
            if graph
                .principal_deletions
                .contains_key(&ownership.principal_uid)
            {
                return Err(OwnershipError::PrincipalDeletionInProgress(
                    ownership.principal_uid,
                ));
            }
            if !self.principals.contains_uid(ownership.principal_uid) {
                return Err(OwnershipError::PrincipalNotFound(ownership.principal_uid));
            }
            let fleet = graph
                .fleets
                .get(&ownership.fleet_uid)
                .ok_or(OwnershipError::FleetNotFound(ownership.fleet_uid))?;
            Self::require_manager(fleet, ownership.assigned_by)?;
            match graph.principal_ownership.get(&ownership.principal_uid) {
                Some(existing) if existing.fleet_uid == ownership.fleet_uid => Ok(()),
                Some(existing) => Err(OwnershipError::PrincipalAlreadyOwned {
                    principal: ownership.principal_uid,
                    fleet: existing.fleet_uid,
                }),
                None => {
                    graph
                        .principal_ownership
                        .insert(ownership.principal_uid, ownership.clone());
                    Ok(())
                },
            }
        })
        .await
    }

    /// Move a principal between fleets with authority in both boundaries.
    ///
    /// # Errors
    ///
    /// Rejects missing assignments, stale source fleets, or insufficient
    /// authority in either fleet.
    pub async fn transfer_principal(
        &self,
        principal_uid: PrincipalUid,
        source_fleet: FleetUid,
        destination_fleet: FleetUid,
        actor: UserUid,
    ) -> Result<(), OwnershipError> {
        let authority = self.enrolled_authority().await?;
        self.mutate_with_authority(&authority, |graph| {
            let current = graph
                .principal_ownership
                .get(&principal_uid)
                .ok_or(OwnershipError::PrincipalNotOwned(principal_uid))?;
            if current.fleet_uid != source_fleet {
                return Err(OwnershipError::PrincipalAlreadyOwned {
                    principal: principal_uid,
                    fleet: current.fleet_uid,
                });
            }
            let source = graph
                .fleets
                .get(&source_fleet)
                .ok_or(OwnershipError::FleetNotFound(source_fleet))?;
            Self::require_manager(source, actor)?;
            let destination = graph
                .fleets
                .get(&destination_fleet)
                .ok_or(OwnershipError::FleetNotFound(destination_fleet))?;
            Self::require_manager(destination, actor)?;
            graph.principal_ownership.insert(
                principal_uid,
                PrincipalOwnership {
                    principal_uid,
                    fleet_uid: destination_fleet,
                    assigned_by: actor,
                },
            );
            Ok(())
        })
        .await
    }

    async fn mutate<T, F>(&self, apply: F) -> Result<T, OwnershipError>
    where
        T: Clone,
        F: Fn(&mut OwnershipSnapshot) -> Result<T, OwnershipError>,
    {
        let _guard = self.mutation_lock.lock().await;
        self.mutate_unlocked(apply).await
    }

    fn validate_authority(
        &self,
        graph: &OwnershipSnapshot,
        authority: &EnrolledAuthority,
    ) -> Result<(), OwnershipError> {
        if !Arc::ptr_eq(&self.authority_binding, &authority.binding) {
            return Err(OwnershipError::AuthorityScope);
        }
        let Some(claim) = graph.first_owner_state().claim() else {
            return Err(OwnershipError::AuthorityNotEnrolled);
        };
        if !graph.first_owner_state().is_enrolled()
            || authority.epoch != graph.authority_epoch
            || authority.generation != graph.authority_generation
            || claim.user_uid() != authority.user_uid
            || claim.authority_epoch() != authority.epoch
            || claim.authority_generation() != authority.generation
        {
            return Err(OwnershipError::AuthorityStale);
        }
        Ok(())
    }

    async fn mutate_with_authority<T, F>(
        &self,
        authority: &EnrolledAuthority,
        apply: F,
    ) -> Result<T, OwnershipError>
    where
        T: Clone,
        F: Fn(&mut OwnershipSnapshot) -> Result<T, OwnershipError>,
    {
        let _guard = self.mutation_lock.lock().await;
        self.mutate_unlocked(|graph| {
            self.validate_authority(graph, authority)?;
            apply(graph)
        })
        .await
    }

    async fn mutate_unlocked<T, F>(&self, apply: F) -> Result<T, OwnershipError>
    where
        T: Clone,
        F: Fn(&mut OwnershipSnapshot) -> Result<T, OwnershipError>,
    {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let current = self.storage.get(GRAPH_KEY).await?;
            let mut graph = self.decode(current.as_deref())?;
            let output = apply(&mut graph)?;
            graph.validate(&self.principals)?;
            let encoded = serde_json::to_vec(&graph)
                .map_err(|error| OwnershipError::Serialization(error.to_string()))?;
            if self
                .storage
                .compare_and_swap(GRAPH_KEY, current.as_deref(), encoded)
                .await?
            {
                return Ok(output);
            }
        }
        Err(OwnershipError::ConcurrentModification)
    }

    fn decode(&self, raw: Option<&[u8]>) -> Result<OwnershipSnapshot, OwnershipError> {
        let mut graph = raw.map_or_else(
            || Ok(OwnershipSnapshot::default()),
            |bytes| {
                serde_json::from_slice(bytes)
                    .map_err(|error| OwnershipError::Serialization(error.to_string()))
            },
        )?;
        if graph.format_version == LEGACY_GRAPH_FORMAT_VERSION {
            if graph.has_legacy_authority() {
                return Err(OwnershipError::LegacyOwnershipRequiresEnrollment);
            }
            graph.format_version = GRAPH_FORMAT_VERSION;
            graph.enrollment = Some(FirstOwnerEnrollment::Unenrolled);
        } else if graph.format_version != GRAPH_FORMAT_VERSION {
            return Err(OwnershipError::UnsupportedFormat(graph.format_version));
        } else if graph.enrollment.is_none() {
            if graph.has_legacy_authority() {
                return Err(OwnershipError::LegacyOwnershipRequiresEnrollment);
            }
            graph.enrollment = Some(FirstOwnerEnrollment::Unenrolled);
        }
        graph.validate(&self.principals)?;
        Ok(graph)
    }
}

#[cfg(test)]
#[path = "first_owner_tests.rs"]
mod first_owner_tests;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
