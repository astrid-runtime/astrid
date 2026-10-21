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

mod deletion;
mod derived;
mod hosted;
mod provision;
mod resources;
pub use derived::DerivedPrincipalOwnership;
pub use hosted::{HostedOwnerCompletion, HostedOwnerRecord};
mod upgrade;
pub use upgrade::{UnownedPrincipalDeferral, UnownedPrincipalReconciliation};
mod user_bindings;
pub use user_bindings::CreationDelegation;

/// Namespace reserved for the authoritative ownership graph.
pub const OWNERSHIP_NAMESPACE: &str = "system:ownership";
const GRAPH_KEY: &str = "graph-v1";
const GRAPH_FORMAT_VERSION: u16 = 2;
const HOSTED_GRAPH_FORMAT_VERSION: u16 = 3;
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    accountable_users: BTreeMap<PrincipalUid, UserUid>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    user_bindings: Vec<user_bindings::UserDeviceBinding>,
    #[serde(default, skip_serializing_if = "user_bindings::not_initialized")]
    local_user_binding_initialized: bool,
    /// Presence fences old readers before the first hosted Pending write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hosted: Option<HostedOwnerRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalDeletionReservation {
    alias: Option<PrincipalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fleet: Option<FleetUid>,
}

impl Default for OwnershipSnapshot {
    fn default() -> Self {
        Self {
            format_version: GRAPH_FORMAT_VERSION,
            users: BTreeMap::new(),
            fleets: BTreeMap::new(),
            principal_ownership: BTreeMap::new(),
            accountable_users: BTreeMap::new(),
            principal_deletions: BTreeMap::new(),
            enrollment: Some(FirstOwnerEnrollment::Unenrolled),
            authority_epoch: default_authority_epoch(),
            authority_generation: default_authority_generation(),
            user_bindings: Vec::new(),
            local_user_binding_initialized: false,
            hosted: None,
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

    /// Iterate over active assignments in fleets containing this user.
    ///
    /// This is a point-in-time ownership query, not authentication or a grant
    /// to act as a principal. Callers must authenticate the user independently
    /// and check operation/device permissions at use time. Reload the snapshot
    /// after membership changes; never treat a cached picker row as authority.
    /// Unknown users and principals being deleted are excluded.
    pub fn principal_owners_for_user(
        &self,
        user: UserUid,
    ) -> impl Iterator<Item = &PrincipalOwnership> {
        self.principal_ownership.values().filter(move |ownership| {
            self.users.contains_key(&user)
                && !self
                    .principal_deletions
                    .contains_key(&ownership.principal_uid)
                && self
                    .fleets
                    .get(&ownership.fleet_uid)
                    .is_some_and(|fleet| fleet.membership(user).is_some())
        })
    }

    fn validate(&self, principals: &PrincipalDirectory) -> Result<(), OwnershipError> {
        self.validate_accountable_users()?;
        self.validate_user_bindings(principals)?;
        if !matches!(
            self.format_version,
            GRAPH_FORMAT_VERSION | HOSTED_GRAPH_FORMAT_VERSION
        ) {
            return Err(OwnershipError::UnsupportedFormat(self.format_version));
        }
        self.validate_first_owner()?;
        self.validate_hosted()?;
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
        self.validate_principal_ownership(principals)?;
        let mut deletion_aliases = BTreeMap::new();
        for (principal_uid, reservation) in &self.principal_deletions {
            if let Some(fleet) = reservation.fleet
                && !self.fleets.contains_key(&fleet)
            {
                return Err(OwnershipError::FleetNotFound(fleet));
            }
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

    fn validate_principal_ownership(
        &self,
        principals: &PrincipalDirectory,
    ) -> Result<(), OwnershipError> {
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
        self.authority_from_snapshot(&graph)
    }

    fn authority_from_snapshot(
        &self,
        graph: &OwnershipSnapshot,
    ) -> Result<EnrolledAuthority, OwnershipError> {
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
            let removed = fleet.memberships.remove(&user_uid).is_some();
            graph
                .user_bindings
                .retain(|binding| !binding.belongs_to(user_uid, fleet_uid));
            Ok(removed)
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
                        .accountable_users
                        .insert(ownership.principal_uid, ownership.assigned_by);
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
            if source_fleet != destination_fleet {
                graph
                    .user_bindings
                    .retain(|binding| !binding.for_principal(principal_uid));
            }
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

    // Capture authority once, then revalidate that original proof on each CAS
    // attempt. First-owner transitions deliberately keep the raw mutation path.
    async fn mutate_enrolled<T, F>(&self, apply: F) -> Result<T, OwnershipError>
    where
        T: Clone,
        F: Fn(&mut OwnershipSnapshot) -> Result<T, OwnershipError>,
    {
        let authority = self.enrolled_authority().await?;
        self.mutate_with_authority(&authority, apply).await
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
        } else if !matches!(
            graph.format_version,
            GRAPH_FORMAT_VERSION | HOSTED_GRAPH_FORMAT_VERSION
        ) {
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
mod test_support;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
