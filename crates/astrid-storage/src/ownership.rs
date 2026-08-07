//! Atomic persistence for Astrid's human-to-fleet ownership graph.
//!
//! The complete graph is stored behind one compare-and-swap key. This keeps
//! cross-record invariants crash-safe: a fleet and its initial owner appear
//! together, and a principal can never be observed in two fleets. The format
//! can be sharded behind the same API if graph size later warrants it.

use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_core::{
    FleetIdentity, FleetMembership, FleetRole, FleetUid, OwnershipIdentityError,
    PrincipalOwnership, PrincipalUid, UserIdentity, UserUid,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedMutexGuard};

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
}

impl Default for OwnershipSnapshot {
    fn default() -> Self {
        Self {
            format_version: GRAPH_FORMAT_VERSION,
            users: BTreeMap::new(),
            fleets: BTreeMap::new(),
            principal_ownership: BTreeMap::new(),
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
        Ok(())
    }
}

/// Persistent, optimistic-concurrency owner of the Astrid ownership graph.
#[derive(Clone, Debug)]
pub struct OwnershipStore {
    storage: ScopedKvStore,
    principals: PrincipalDirectory,
    mutation_lock: Arc<Mutex<()>>,
}

/// Exclusive barrier held while an unowned principal is removed from the
/// durable identity directory.
///
/// Dropping this guard allows ownership mutations to resume. Callers must keep
/// it alive until identity removal has either completed or been abandoned.
#[derive(Debug)]
#[must_use = "dropping the guard permits concurrent ownership assignment"]
pub struct PrincipalDeletionGuard {
    _guard: OwnedMutexGuard<()>,
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
            mutation_lock: Arc::new(Mutex::new(())),
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

    /// Exclude ownership mutations while an unowned principal is deleted.
    ///
    /// The returned guard must remain alive through removal from the durable
    /// identity store. This closes the check-to-delete race with concurrent
    /// assignment through another clone of this store.
    ///
    /// # Errors
    ///
    /// Rejects a principal that already belongs to a fleet and fails closed on
    /// invalid or unavailable ownership state.
    pub async fn guard_principal_deletion(
        &self,
        principal_uid: PrincipalUid,
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        let guard = Arc::clone(&self.mutation_lock).lock_owned().await;
        if let Some(ownership) = self.load().await?.principal_owner(principal_uid) {
            return Err(OwnershipError::PrincipalAlreadyOwned {
                principal: principal_uid,
                fleet: ownership.fleet_uid,
            });
        }
        Ok(PrincipalDeletionGuard { _guard: guard })
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
    /// Sustained concurrent writes prevented an atomic commit.
    #[error("ownership graph changed concurrently too many times")]
    ConcurrentModification,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};
    use tokio::sync::Barrier;
    use uuid::Uuid;

    use super::*;
    use crate::MemoryKvStore;
    use astrid_core::{FleetGenesis, PrincipalGenesis, PrincipalIdentity, UserGenesis};

    #[derive(Debug)]
    struct ReadBarrierKv {
        inner: MemoryKvStore,
        barrier: Barrier,
        armed: AtomicBool,
        ownership_reads: AtomicUsize,
    }

    impl ReadBarrierKv {
        fn new() -> Self {
            Self {
                inner: MemoryKvStore::new(),
                barrier: Barrier::new(2),
                armed: AtomicBool::new(false),
                ownership_reads: AtomicUsize::new(0),
            }
        }

        fn arm(&self) {
            self.ownership_reads.store(0, Ordering::SeqCst);
            self.armed.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl KvStore for ReadBarrierKv {
        async fn get(&self, namespace: &str, key: &str) -> crate::StorageResult<Option<Vec<u8>>> {
            let value = self.inner.get(namespace, key).await?;
            if self.armed.load(Ordering::SeqCst)
                && namespace == OWNERSHIP_NAMESPACE
                && key == GRAPH_KEY
                && self.ownership_reads.fetch_add(1, Ordering::SeqCst) < 2
            {
                self.barrier.wait().await;
            }
            Ok(value)
        }

        async fn set(
            &self,
            namespace: &str,
            key: &str,
            value: Vec<u8>,
        ) -> crate::StorageResult<()> {
            self.inner.set(namespace, key, value).await
        }

        async fn delete(&self, namespace: &str, key: &str) -> crate::StorageResult<bool> {
            self.inner.delete(namespace, key).await
        }

        async fn exists(&self, namespace: &str, key: &str) -> crate::StorageResult<bool> {
            self.inner.exists(namespace, key).await
        }

        async fn list_keys(&self, namespace: &str) -> crate::StorageResult<Vec<String>> {
            self.inner.list_keys(namespace).await
        }

        async fn compare_and_swap(
            &self,
            namespace: &str,
            key: &str,
            expected: Option<&[u8]>,
            new: Vec<u8>,
        ) -> crate::StorageResult<bool> {
            self.inner
                .compare_and_swap(namespace, key, expected, new)
                .await
        }

        async fn clear_namespace(&self, namespace: &str) -> crate::StorageResult<u64> {
            self.inner.clear_namespace(namespace).await
        }
    }

    fn at(seconds: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).single().unwrap()
    }

    fn user(id: u128, key: u8) -> UserIdentity {
        UserIdentity::from_genesis(UserGenesis::from_parts(
            Uuid::from_u128(id),
            at(1_700_000_000),
            [key; 32],
        ))
        .unwrap()
    }

    fn fleet(id: u128, creator: UserUid) -> FleetIdentity {
        FleetIdentity::from_genesis(FleetGenesis::from_parts(
            Uuid::from_u128(id),
            at(1_700_000_001),
            creator,
        ))
        .unwrap()
    }

    fn principal(id: u128, key: u8) -> PrincipalUid {
        PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
            Uuid::from_u128(id),
            at(1_700_000_002),
            [key; 32],
        ))
        .unwrap()
        .uid
    }

    fn store() -> (OwnershipStore, PrincipalDirectory) {
        let principals = PrincipalDirectory::default();
        (
            OwnershipStore::new(Arc::new(MemoryKvStore::new()), principals.clone()).unwrap(),
            principals,
        )
    }

    fn admit_principal(directory: &PrincipalDirectory, alias: &str, uid: PrincipalUid) {
        directory
            .register(astrid_core::PrincipalId::new(alias).unwrap(), uid)
            .unwrap();
    }

    #[tokio::test]
    async fn fleet_creation_atomically_bootstraps_its_owner() {
        let (store, _) = store();
        let owner = user(1, 1);
        let owned_fleet = fleet(10, owner.uid);
        store.create_user(owner.clone()).await.unwrap();
        store.create_fleet(owned_fleet.clone()).await.unwrap();

        let graph = store.load().await.unwrap();
        let membership = graph
            .fleet(owned_fleet.uid)
            .unwrap()
            .membership(owner.uid)
            .unwrap();
        assert_eq!(membership.role, FleetRole::Owner);
        assert_eq!(membership.granted_by, owner.uid);
    }

    #[tokio::test]
    async fn principal_cannot_be_silently_reassigned() {
        let (store, principals) = store();
        let owner = user(1, 1);
        let first = fleet(10, owner.uid);
        let second = fleet(11, owner.uid);
        let principal_uid = principal(20, 2);
        admit_principal(&principals, "test-principal", principal_uid);
        store.create_user(owner.clone()).await.unwrap();
        store.create_fleet(first.clone()).await.unwrap();
        store.create_fleet(second.clone()).await.unwrap();
        store
            .assign_principal(PrincipalOwnership {
                principal_uid,
                fleet_uid: first.uid,
                assigned_by: owner.uid,
            })
            .await
            .unwrap();

        let error = store
            .assign_principal(PrincipalOwnership {
                principal_uid,
                fleet_uid: second.uid,
                assigned_by: owner.uid,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            OwnershipError::PrincipalAlreadyOwned { .. }
        ));
        assert_eq!(
            store
                .load()
                .await
                .unwrap()
                .principal_owner(principal_uid)
                .unwrap()
                .fleet_uid,
            first.uid
        );
    }

    #[tokio::test]
    async fn explicit_transfer_requires_management_of_both_fleets() {
        let (store, principals) = store();
        let first_owner = user(1, 1);
        let second_owner = user(2, 2);
        let first = fleet(10, first_owner.uid);
        let second = fleet(11, second_owner.uid);
        let principal_uid = principal(20, 3);
        admit_principal(&principals, "test-principal", principal_uid);
        store.create_user(first_owner.clone()).await.unwrap();
        store.create_user(second_owner.clone()).await.unwrap();
        store.create_fleet(first.clone()).await.unwrap();
        store.create_fleet(second.clone()).await.unwrap();
        store
            .assign_principal(PrincipalOwnership {
                principal_uid,
                fleet_uid: first.uid,
                assigned_by: first_owner.uid,
            })
            .await
            .unwrap();

        let denied = store
            .transfer_principal(principal_uid, first.uid, second.uid, first_owner.uid)
            .await
            .unwrap_err();
        assert!(matches!(denied, OwnershipError::NotFleetManager { .. }));

        store
            .set_membership(
                second.uid,
                first_owner.uid,
                FleetRole::Administrator,
                second_owner.uid,
            )
            .await
            .unwrap();
        store
            .transfer_principal(principal_uid, first.uid, second.uid, first_owner.uid)
            .await
            .unwrap();
        assert_eq!(
            store
                .load()
                .await
                .unwrap()
                .principal_owner(principal_uid)
                .unwrap()
                .fleet_uid,
            second.uid
        );
    }

    #[tokio::test]
    async fn last_owner_cannot_be_demoted_or_removed() {
        let (store, _) = store();
        let owner = user(1, 1);
        let owned_fleet = fleet(10, owner.uid);
        store.create_user(owner.clone()).await.unwrap();
        store.create_fleet(owned_fleet.clone()).await.unwrap();

        assert!(matches!(
            store
                .set_membership(owned_fleet.uid, owner.uid, FleetRole::Member, owner.uid)
                .await,
            Err(OwnershipError::LastOwner(_))
        ));
        assert!(matches!(
            store
                .remove_member(owned_fleet.uid, owner.uid, owner.uid)
                .await,
            Err(OwnershipError::LastOwner(_))
        ));
    }

    #[tokio::test]
    async fn administrator_cannot_escalate_to_owner_or_remove_one() {
        let (store, _) = store();
        let owner = user(1, 1);
        let administrator = user(2, 2);
        let owned_fleet = fleet(10, owner.uid);
        store.create_user(owner.clone()).await.unwrap();
        store.create_user(administrator.clone()).await.unwrap();
        store.create_fleet(owned_fleet.clone()).await.unwrap();
        store
            .set_membership(
                owned_fleet.uid,
                administrator.uid,
                FleetRole::Administrator,
                owner.uid,
            )
            .await
            .unwrap();

        assert!(matches!(
            store
                .set_membership(
                    owned_fleet.uid,
                    administrator.uid,
                    FleetRole::Owner,
                    administrator.uid,
                )
                .await,
            Err(OwnershipError::OwnerAuthorityRequired(_))
        ));
        assert!(matches!(
            store
                .remove_member(owned_fleet.uid, owner.uid, administrator.uid)
                .await,
            Err(OwnershipError::OwnerAuthorityRequired(_))
        ));
    }

    #[tokio::test]
    async fn malformed_persisted_graph_fails_closed() {
        let backend = Arc::new(MemoryKvStore::new());
        let raw: Arc<dyn KvStore> = backend.clone();
        let store = OwnershipStore::new(raw, PrincipalDirectory::default()).unwrap();
        backend
            .set(OWNERSHIP_NAMESPACE, GRAPH_KEY, b"not-json".to_vec())
            .await
            .unwrap();
        assert!(matches!(
            store.load().await,
            Err(OwnershipError::Serialization(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_principal_assignments_do_not_lose_updates() {
        let backend = Arc::new(ReadBarrierKv::new());
        let raw: Arc<dyn KvStore> = backend.clone();
        let principals = PrincipalDirectory::default();
        let store = OwnershipStore::new(raw, principals.clone()).unwrap();
        let owner = user(1, 1);
        let owned_fleet = fleet(10, owner.uid);
        let first = principal(20, 2);
        let second = principal(21, 3);
        admit_principal(&principals, "first-principal", first);
        admit_principal(&principals, "second-principal", second);
        store.create_user(owner.clone()).await.unwrap();
        store.create_fleet(owned_fleet.clone()).await.unwrap();

        let first_store = OwnershipStore::new(backend.clone(), principals.clone()).unwrap();
        let second_store = OwnershipStore::new(backend.clone(), principals.clone()).unwrap();
        backend.arm();
        let (first_result, second_result) = tokio::join!(
            first_store.assign_principal(PrincipalOwnership {
                principal_uid: first,
                fleet_uid: owned_fleet.uid,
                assigned_by: owner.uid,
            }),
            second_store.assign_principal(PrincipalOwnership {
                principal_uid: second,
                fleet_uid: owned_fleet.uid,
                assigned_by: owner.uid,
            })
        );
        first_result.unwrap();
        second_result.unwrap();

        let graph = store.load().await.unwrap();
        assert_eq!(
            graph.principal_owner(first).unwrap().fleet_uid,
            owned_fleet.uid
        );
        assert_eq!(
            graph.principal_owner(second).unwrap().fleet_uid,
            owned_fleet.uid
        );
    }

    #[tokio::test]
    async fn unknown_principals_are_rejected_on_assignment_and_reopen() {
        let backend = Arc::new(MemoryKvStore::new());
        let admitted = PrincipalDirectory::default();
        let raw: Arc<dyn KvStore> = backend.clone();
        let store = OwnershipStore::new(raw, admitted.clone()).unwrap();
        let owner = user(1, 1);
        let owned_fleet = fleet(10, owner.uid);
        let principal_uid = principal(20, 2);
        store.create_user(owner.clone()).await.unwrap();
        store.create_fleet(owned_fleet.clone()).await.unwrap();

        assert!(matches!(
            store
                .assign_principal(PrincipalOwnership {
                    principal_uid,
                    fleet_uid: owned_fleet.uid,
                    assigned_by: owner.uid,
                })
                .await,
            Err(OwnershipError::PrincipalNotFound(uid)) if uid == principal_uid
        ));

        admit_principal(&admitted, "admitted-principal", principal_uid);
        store
            .assign_principal(PrincipalOwnership {
                principal_uid,
                fleet_uid: owned_fleet.uid,
                assigned_by: owner.uid,
            })
            .await
            .unwrap();

        let reopened = OwnershipStore::new(backend, PrincipalDirectory::default()).unwrap();
        assert!(matches!(
            reopened.load().await,
            Err(OwnershipError::CorruptGraph(message))
                if message.contains("absent from the admitted principal directory")
        ));
    }

    #[tokio::test]
    async fn deletion_guard_serializes_assignment_with_directory_removal() {
        let (store, principals) = store();
        let owner = user(1, 1);
        let owned_fleet = fleet(10, owner.uid);
        let principal_uid = principal(20, 2);
        let alias = astrid_core::PrincipalId::new("deleting-principal").unwrap();
        principals.register(alias.clone(), principal_uid).unwrap();
        store.create_user(owner.clone()).await.unwrap();
        store.create_fleet(owned_fleet.clone()).await.unwrap();

        let deletion_guard = store.guard_principal_deletion(principal_uid).await.unwrap();
        let assigning_store = store.clone();
        let mut assignment = tokio::spawn(async move {
            assigning_store
                .assign_principal(PrincipalOwnership {
                    principal_uid,
                    fleet_uid: owned_fleet.uid,
                    assigned_by: owner.uid,
                })
                .await
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut assignment)
                .await
                .is_err(),
            "assignment must wait while principal deletion owns the mutation barrier"
        );
        principals.unregister(&alias, principal_uid);
        drop(deletion_guard);

        assert!(matches!(
            assignment.await.unwrap(),
            Err(OwnershipError::PrincipalNotFound(uid)) if uid == principal_uid
        ));
        assert!(
            store
                .load()
                .await
                .unwrap()
                .principal_owner(principal_uid)
                .is_none()
        );
    }
}
