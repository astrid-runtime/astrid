//! Atomic persistence for Astrid's human-to-fleet ownership graph.
//!
//! The complete graph is stored behind one compare-and-swap key. This keeps
//! cross-record invariants crash-safe: a fleet and its initial owner appear
//! together, and a principal can never be observed in two fleets. The format
//! can be sharded behind the same API if graph size later warrants it.

use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_core::{
    FleetIdentity, FleetMembership, FleetRole, FleetUid, OwnershipIdentityError, PrincipalId,
    PrincipalOwnership, PrincipalUid, UserIdentity, UserUid,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::{KvStore, PrincipalDirectory, ScopedKvStore, StorageError};

/// Namespace reserved for the authoritative ownership graph.
pub const OWNERSHIP_NAMESPACE: &str = "system:ownership";
const GRAPH_KEY: &str = "graph-v1";
const GRAPH_FORMAT_VERSION: u16 = 1;
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
        }
    }
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

    fn validate(&self, principals: &PrincipalDirectory) -> Result<(), OwnershipError> {
        if self.format_version != GRAPH_FORMAT_VERSION {
            return Err(OwnershipError::UnsupportedFormat(self.format_version));
        }
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
    _guard: OwnedMutexGuard<()>,
}

impl PrincipalDeletionGuard {
    /// Remove the durable reservation after identity removal completes.
    ///
    /// # Errors
    ///
    /// Fails closed when the latest graph cannot be read, validated, or
    /// atomically updated. On failure the reservation remains durable.
    pub async fn finish(self) -> Result<(), OwnershipError> {
        let principal_uid = self.principal_uid;
        self.store
            .mutate_unlocked(|graph| {
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
        self.guard_principal_deletion_inner(principal_uid, None)
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
        self.guard_principal_deletion_inner(principal_uid, Some(alias))
            .await
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
            Ok(principal_uid
                .and_then(|uid| graph.principal_deletions.remove(&uid))
                .is_some())
        })
        .await
    }

    async fn guard_principal_deletion_inner(
        &self,
        principal_uid: PrincipalUid,
        alias: Option<PrincipalId>,
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        let guard = Arc::clone(&self.mutation_lock).lock_owned().await;
        self.mutate_unlocked(|graph| {
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
            _guard: guard,
        })
    }

    /// Register one durable human identity, idempotently.
    ///
    /// # Errors
    ///
    /// Rejects invalid identity material and persistence conflicts.
    pub async fn create_user(&self, identity: UserIdentity) -> Result<(), OwnershipError> {
        identity.validate()?;
        self.mutate(|graph| match graph.users.get(&identity.uid) {
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
        identity.validate()?;
        self.mutate(|graph| {
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
        self.mutate(|graph| {
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
        self.mutate(|graph| {
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
        self.mutate(|graph| {
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
        self.mutate(|graph| {
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
        let graph = raw.map_or_else(
            || Ok(OwnershipSnapshot::default()),
            |bytes| {
                serde_json::from_slice(bytes)
                    .map_err(|error| OwnershipError::Serialization(error.to_string()))
            },
        )?;
        graph.validate(&self.principals)?;
        Ok(graph)
    }

    fn require_manager(fleet: &FleetRecord, actor: UserUid) -> Result<(), OwnershipError> {
        let role = Self::role(fleet, actor);
        if role.is_some_and(FleetRole::can_manage) {
            Ok(())
        } else {
            Err(OwnershipError::NotFleetManager {
                user: actor,
                fleet: fleet.identity.uid,
            })
        }
    }

    fn role(fleet: &FleetRecord, user: UserUid) -> Option<FleetRole> {
        fleet
            .memberships
            .get(&user)
            .map(|membership| membership.role)
    }

    fn owner_count(fleet: &FleetRecord) -> usize {
        fleet
            .memberships
            .values()
            .filter(|membership| membership.role == FleetRole::Owner)
            .count()
    }
}

/// Rejection from ownership graph persistence or invariant enforcement.
#[derive(Debug, thiserror::Error)]
pub enum OwnershipError {
    /// Canonical identity material was invalid.
    #[error(transparent)]
    Identity(#[from] OwnershipIdentityError),
    /// Raw persistence failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// JSON encoding or decoding failed.
    #[error("ownership graph serialization failed: {0}")]
    Serialization(String),
    /// Stored graph uses an unknown format.
    #[error("unsupported ownership graph format version {0}")]
    UnsupportedFormat(u16),
    /// Persisted relationships failed invariant validation.
    #[error("corrupt ownership graph: {0}")]
    CorruptGraph(String),
    /// A UID was reused with different genesis identity.
    #[error("conflicting {0} identity for uid {1}")]
    IdentityConflict(&'static str, String),
    /// A referenced user does not exist.
    #[error("user not found: {0}")]
    UserNotFound(UserUid),
    /// A referenced fleet does not exist.
    #[error("fleet not found: {0}")]
    FleetNotFound(FleetUid),
    /// The acting user cannot administer the fleet.
    #[error("user {user} is not a manager of fleet {fleet}")]
    NotFleetManager {
        /// User that attempted the mutation.
        user: UserUid,
        /// Fleet whose ownership boundary rejected it.
        fleet: FleetUid,
    },
    /// A mutation would leave a fleet without an owner.
    #[error("fleet {0} must retain at least one owner")]
    LastOwner(FleetUid),
    /// A fleet ownership transition was attempted by a non-owner manager.
    #[error("only a fleet owner may change owner membership in fleet {0}")]
    OwnerAuthorityRequired(FleetUid),
    /// A principal already belongs to a different fleet.
    #[error("principal {principal} is already owned by fleet {fleet}")]
    PrincipalAlreadyOwned {
        /// Principal whose exclusive assignment blocked the mutation.
        principal: PrincipalUid,
        /// Current owning fleet.
        fleet: FleetUid,
    },
    /// A principal has no current fleet assignment.
    #[error("principal has no fleet owner: {0}")]
    PrincipalNotOwned(PrincipalUid),
    /// A principal UID is not present in the admitted durable directory.
    #[error("principal not found: {0}")]
    PrincipalNotFound(PrincipalUid),
    /// A principal cannot be assigned while durable identity deletion is active.
    #[error("principal deletion is in progress: {0}")]
    PrincipalDeletionInProgress(PrincipalUid),
    /// A retry attempted to bind one deletion reservation to another alias.
    #[error("principal deletion reservation for {principal} belongs to alias {alias}")]
    DeletionReservationConflict {
        /// Reserved durable principal UID.
        principal: PrincipalUid,
        /// Alias retained by the original deletion attempt.
        alias: PrincipalId,
    },
    /// An alias already identifies another interrupted deletion.
    #[error("principal deletion alias {alias} is already reserved for {principal}")]
    DeletionAliasReserved {
        /// Alias retained by the interrupted deletion.
        alias: PrincipalId,
        /// Durable UID owned by the existing reservation.
        principal: PrincipalUid,
    },
    /// Sustained concurrent writes prevented an atomic commit.
    #[error("ownership graph changed concurrently too many times")]
    ConcurrentModification,
}

#[cfg(test)]
#[path = "ownership_tests.rs"]
mod tests;
