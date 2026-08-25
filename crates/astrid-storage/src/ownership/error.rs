use astrid_core::{FleetUid, OwnershipIdentityError, PrincipalId, PrincipalUid, UserUid};

use crate::StorageError;

use super::FirstOwnerError;

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
    /// A legacy graph already containing ownership cannot be guessed into a
    /// first-owner enrollment state.
    #[error("legacy ownership graph contains authority but no first-owner enrollment")]
    LegacyOwnershipRequiresEnrollment,
    /// First-owner enrollment failed closed.
    #[error(transparent)]
    FirstOwner(#[from] FirstOwnerError),
    /// A mutation was attempted without an enrolled authority.
    #[error("ownership mutation requires an enrolled authority")]
    AuthorityNotEnrolled,
    /// The capability came from a different ownership store instance.
    #[error("ownership authority belongs to a different store")]
    AuthorityScope,
    /// The capability epoch or generation is stale or revoked.
    #[error("ownership authority is stale, expired, or revoked")]
    AuthorityStale,
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
    /// Recovery cannot clear a reservation while its identity remains live.
    #[error("principal deletion identity is still live: {0}")]
    PrincipalDeletionStillLive(PrincipalUid),
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
        /// Durable UID owned by the existing deletion.
        principal: PrincipalUid,
    },
    /// Sustained concurrent writes prevented an atomic commit.
    #[error("ownership graph changed concurrently too many times")]
    ConcurrentModification,
}
