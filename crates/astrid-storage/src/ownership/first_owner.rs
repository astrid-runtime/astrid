//! Durable first-owner enrollment and authority capability state.
//!
//! A pending claim is authenticated evidence, not authority. Only the commit
//! CAS may publish the first fleet/principal graph edges. After enrollment,
//! mutations require an opaque capability bound to this store instance and
//! the persisted authority epoch/generation.

use std::time::{SystemTime, UNIX_EPOCH};

use astrid_core::{
    FirstOwnerClaim, FleetIdentity, FleetMembership, FleetRole, PrincipalOwnership, UserIdentity,
};

use super::{FleetRecord, OwnershipError, OwnershipSnapshot, PrincipalDirectory};

/// Durable phase of the one-shot first-owner ceremony.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FirstOwnerEnrollment {
    /// No first-owner request has been accepted.
    #[default]
    Unenrolled,
    /// A signed request is durable, but it grants no authority.
    Pending {
        /// Authenticated request retained until the owner graph is committed.
        claim: FirstOwnerClaim,
    },
    /// The request and its ownership graph edges were atomically committed.
    Enrolled {
        /// Authenticated request that produced the initial owner graph.
        claim: FirstOwnerClaim,
    },
    /// A pending request was explicitly cancelled or expired.
    Cancelled {
        /// The revoked request, retained to prevent silent replay.
        claim: FirstOwnerClaim,
    },
}

impl FirstOwnerEnrollment {
    /// Return the claim carried by a pending, enrolled, or cancelled state.
    #[must_use]
    pub const fn claim(self) -> Option<FirstOwnerClaim> {
        match self {
            Self::Unenrolled => None,
            Self::Pending { claim } | Self::Enrolled { claim } | Self::Cancelled { claim } => {
                Some(claim)
            },
        }
    }

    /// Return whether this state is already enrolled.
    #[must_use]
    pub const fn is_enrolled(self) -> bool {
        matches!(self, Self::Enrolled { .. })
    }

    /// Return whether this state is a durable pending request.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    /// Return whether this state retains a cancelled request.
    #[must_use]
    pub const fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }
}

/// Failure from first-owner state transition or validation.
#[derive(Debug, thiserror::Error)]
pub enum FirstOwnerError {
    /// The signed claim failed cryptographic validation.
    #[error(transparent)]
    Claim(#[from] astrid_core::FirstOwnerClaimError),
    /// A second request differs from the durable one-shot request.
    #[error("first-owner replay differs from the durable claim")]
    Replay,
    /// The claim's epoch or generation is stale for the current state.
    #[error("first-owner claim is stale for the current authority counters")]
    StaleClaim,
    /// A commit was attempted without a matching pending request.
    #[error("first-owner commit requires the matching pending claim")]
    MissingPending,
    /// The durable state is already enrolled with a different claim.
    #[error("first-owner enrollment is already committed")]
    AlreadyEnrolled,
    /// A claim expired before it could be committed.
    #[error("first-owner claim has expired")]
    Expired,
    /// A cancellation was attempted without a matching pending request.
    #[error("first-owner cancellation requires the matching pending claim")]
    NotPending,
    /// Authority counters cannot advance without wrapping.
    #[error("first-owner authority counter exhausted")]
    CounterExhausted,
    /// A claim field did not match the immutable identity supplied at commit.
    #[error("first-owner identity mismatch for {0}")]
    IdentityMismatch(&'static str),
    /// The principal is not currently admitted in the live directory.
    #[error("first-owner principal is not present in the admitted directory")]
    PrincipalNotAdmitted,
    /// The principal has a durable deletion reservation.
    #[error("first-owner principal deletion is in progress")]
    PrincipalDeletionInProgress,
    /// The existing fleet does not have the exact requested owner membership.
    #[error("first-owner fleet membership does not match the signed claim")]
    MembershipMismatch,
    /// The graph had a conflicting identity record.
    #[error("first-owner graph identity conflicts with the signed claim for {0}")]
    GraphIdentityConflict(&'static str),
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |duration| duration.as_secs())
}

impl OwnershipSnapshot {
    pub(super) fn validate_first_owner(&self) -> Result<(), OwnershipError> {
        let Some(enrollment) = self.enrollment else {
            return Ok(());
        };
        if let Some(claim) = enrollment.claim() {
            claim
                .verify_signature()
                .map_err(|error| OwnershipError::FirstOwner(FirstOwnerError::Claim(error)))?;
            if matches!(
                enrollment,
                FirstOwnerEnrollment::Pending { .. } | FirstOwnerEnrollment::Enrolled { .. }
            ) && (claim.authority_epoch() != self.authority_epoch
                || claim.authority_generation() != self.authority_generation)
            {
                return Err(OwnershipError::FirstOwner(FirstOwnerError::StaleClaim));
            }
        }
        match enrollment {
            FirstOwnerEnrollment::Unenrolled | FirstOwnerEnrollment::Cancelled { .. }
                if !self.fleets.is_empty() || !self.principal_ownership.is_empty() =>
            {
                return Err(OwnershipError::CorruptGraph(
                    "unenrolled first-owner state cannot carry authority edges".to_owned(),
                ));
            },
            FirstOwnerEnrollment::Pending { .. }
                if !self.fleets.is_empty() || !self.principal_ownership.is_empty() =>
            {
                return Err(OwnershipError::CorruptGraph(
                    "pending first-owner enrollment cannot carry authority edges".to_owned(),
                ));
            },
            FirstOwnerEnrollment::Enrolled { claim } => {
                // The signed claim is the one-shot bootstrap witness, not a
                // permanent pin on the principal's current fleet.  Once the
                // graph is Enrolled, normal authority mutations may transfer
                // or retire that principal; revalidating the original edge
                // here would make every legitimate transfer unrecoverable.
                let Some(user) = self.users.get(&claim.user_uid()) else {
                    return Err(OwnershipError::CorruptGraph(
                        "enrolled first-owner claim references an absent user".to_owned(),
                    ));
                };
                if user.genesis.initial_public_key != *claim.initial_user_public_key() {
                    return Err(OwnershipError::CorruptGraph(
                        "enrolled first-owner claim disagrees with user key".to_owned(),
                    ));
                }
                let Some(fleet) = self.fleets.get(&claim.fleet_uid()) else {
                    return Err(OwnershipError::CorruptGraph(
                        "enrolled first-owner claim references an absent fleet".to_owned(),
                    ));
                };
                let Some(membership) = fleet.membership(claim.user_uid()) else {
                    return Err(OwnershipError::CorruptGraph(
                        "enrolled first-owner claim has no owner membership".to_owned(),
                    ));
                };
                if membership.role != FleetRole::Owner || membership.granted_by != claim.user_uid()
                {
                    return Err(OwnershipError::CorruptGraph(
                        "enrolled first-owner claim has a non-owner membership".to_owned(),
                    ));
                }
                if self
                    .principal_deletions
                    .contains_key(&claim.principal_uid())
                {
                    return Err(OwnershipError::CorruptGraph(
                        "enrolled first-owner principal is reserved for deletion".to_owned(),
                    ));
                }
            },
            _ => {},
        }
        Ok(())
    }

    pub(super) fn first_owner_state(&self) -> FirstOwnerEnrollment {
        self.enrollment.unwrap_or_default()
    }

    pub(super) fn set_first_owner_state(&mut self, state: &FirstOwnerEnrollment) {
        self.enrollment = Some(*state);
    }

    pub(super) fn has_legacy_authority(&self) -> bool {
        !self.fleets.is_empty() || !self.principal_ownership.is_empty()
    }
}

impl super::OwnershipStore {
    /// Return the durable first-owner state.
    ///
    /// # Errors
    ///
    /// Returns an error if the persisted ownership graph is unavailable or
    /// fails validation.
    pub async fn first_owner_state(&self) -> Result<FirstOwnerEnrollment, OwnershipError> {
        Ok(self.load().await?.first_owner_state())
    }

    /// Begin first-owner enrollment using the current clock.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid, expired, stale, replayed, or already
    /// enrolled claim, or when the ownership graph cannot be persisted.
    pub async fn begin_first_owner(
        &self,
        claim: FirstOwnerClaim,
    ) -> Result<FirstOwnerEnrollment, OwnershipError> {
        self.begin_first_owner_at(claim, now_unix_seconds()).await
    }

    /// Begin first-owner enrollment at an explicit timestamp for deterministic
    /// recovery tests.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid, expired, stale, replayed, or already
    /// enrolled claim, or when the ownership graph cannot be persisted.
    pub async fn begin_first_owner_at(
        &self,
        claim: FirstOwnerClaim,
        now: u64,
    ) -> Result<FirstOwnerEnrollment, OwnershipError> {
        claim.verify_signature().map_err(FirstOwnerError::from)?;
        if claim.is_expired_at(now) {
            return Err(FirstOwnerError::Expired.into());
        }
        self.mutate(|graph| {
            let state = graph.first_owner_state();
            match state {
                FirstOwnerEnrollment::Unenrolled | FirstOwnerEnrollment::Cancelled { .. } => {
                    if claim.authority_epoch() != graph.authority_epoch
                        || claim.authority_generation() != graph.authority_generation
                    {
                        return Err(FirstOwnerError::StaleClaim.into());
                    }
                    graph.set_first_owner_state(&FirstOwnerEnrollment::Pending { claim });
                    Ok(graph.first_owner_state())
                },
                FirstOwnerEnrollment::Pending { claim: existing } if existing == claim => Ok(state),
                FirstOwnerEnrollment::Pending { .. } => Err(FirstOwnerError::Replay.into()),
                FirstOwnerEnrollment::Enrolled { claim: existing } if existing == claim => {
                    Ok(state)
                },
                FirstOwnerEnrollment::Enrolled { .. } => {
                    Err(FirstOwnerError::AlreadyEnrolled.into())
                },
            }
        })
        .await
    }

    /// Cancel and durably revoke a pending claim.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or non-pending claim, counter
    /// exhaustion, or a persistence/validation failure.
    pub async fn cancel_first_owner(
        &self,
        claim: FirstOwnerClaim,
    ) -> Result<FirstOwnerEnrollment, OwnershipError> {
        claim.verify_signature().map_err(FirstOwnerError::from)?;
        self.mutate(|graph| {
            if !matches!(
                graph.first_owner_state(),
                FirstOwnerEnrollment::Pending {
                    claim: existing
                } if existing == claim
            ) {
                return Err(FirstOwnerError::NotPending.into());
            }
            Self::advance_counters(graph)?;
            graph.set_first_owner_state(&FirstOwnerEnrollment::Cancelled { claim });
            Ok(graph.first_owner_state())
        })
        .await
    }

    /// Expire and durably revoke a pending claim at the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when the pending claim is not expired, counters cannot
    /// advance, or the ownership graph cannot be persisted.
    pub async fn expire_first_owner_at(
        &self,
        now: u64,
    ) -> Result<FirstOwnerEnrollment, OwnershipError> {
        self.mutate(|graph| {
            let FirstOwnerEnrollment::Pending { claim } = graph.first_owner_state() else {
                return Ok(graph.first_owner_state());
            };
            if !claim.is_expired_at(now) {
                return Err(FirstOwnerError::Expired.into());
            }
            Self::advance_counters(graph)?;
            graph.set_first_owner_state(&FirstOwnerEnrollment::Cancelled { claim });
            Ok(graph.first_owner_state())
        })
        .await
    }

    fn advance_counters(graph: &mut OwnershipSnapshot) -> Result<(), OwnershipError> {
        graph.authority_epoch = graph
            .authority_epoch
            .checked_next()
            .map_err(|_| OwnershipError::FirstOwner(FirstOwnerError::CounterExhausted))?;
        graph.authority_generation =
            graph
                .authority_generation
                .checked_next()
                .ok_or(OwnershipError::FirstOwner(
                    FirstOwnerError::CounterExhausted,
                ))?;
        Ok(())
    }

    /// Atomically publish Enrolled state and the initial owner graph edges.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid, expired, stale, replayed, or mismatched
    /// claim/identity, a missing principal, or a persistence/validation failure.
    pub async fn commit_first_owner(
        &self,
        claim: FirstOwnerClaim,
        user: UserIdentity,
        fleet: FleetIdentity,
    ) -> Result<FirstOwnerEnrollment, OwnershipError> {
        claim.verify_signature().map_err(FirstOwnerError::from)?;
        if claim.is_expired_at(now_unix_seconds()) {
            return Err(FirstOwnerError::Expired.into());
        }
        user.validate()?;
        fleet.validate()?;
        if user.uid != claim.user_uid()
            || user.genesis.initial_public_key != *claim.initial_user_public_key()
        {
            return Err(FirstOwnerError::IdentityMismatch("user").into());
        }
        if fleet.uid != claim.fleet_uid() || fleet.genesis.created_by != user.uid {
            return Err(FirstOwnerError::IdentityMismatch("fleet").into());
        }
        let principals = &self.principals;
        self.mutate(|graph| {
            Self::apply_first_owner_commit(principals, graph, &claim, &user, &fleet)
        })
        .await
    }

    fn apply_first_owner_commit(
        principals: &PrincipalDirectory,
        graph: &mut OwnershipSnapshot,
        claim: &FirstOwnerClaim,
        user: &UserIdentity,
        fleet: &FleetIdentity,
    ) -> Result<FirstOwnerEnrollment, OwnershipError> {
        match graph.first_owner_state() {
            FirstOwnerEnrollment::Pending { claim: existing } if existing == *claim => {},
            FirstOwnerEnrollment::Pending { .. } => return Err(FirstOwnerError::Replay.into()),
            FirstOwnerEnrollment::Enrolled { claim: existing } if existing == *claim => {
                return Ok(graph.first_owner_state());
            },
            FirstOwnerEnrollment::Enrolled { .. } => {
                return Err(FirstOwnerError::AlreadyEnrolled.into());
            },
            _ => return Err(FirstOwnerError::MissingPending.into()),
        }
        if claim.authority_epoch() != graph.authority_epoch
            || claim.authority_generation() != graph.authority_generation
        {
            return Err(FirstOwnerError::StaleClaim.into());
        }
        if !principals.contains_uid(claim.principal_uid()) {
            return Err(FirstOwnerError::PrincipalNotAdmitted.into());
        }
        if graph
            .principal_deletions
            .contains_key(&claim.principal_uid())
        {
            return Err(FirstOwnerError::PrincipalDeletionInProgress.into());
        }
        match graph.users.get(&user.uid) {
            Some(existing) if existing == user => {},
            Some(_) => return Err(FirstOwnerError::GraphIdentityConflict("user").into()),
            None => {
                graph.users.insert(user.uid, user.clone());
            },
        }
        let membership = FleetMembership {
            fleet_uid: fleet.uid,
            user_uid: user.uid,
            role: FleetRole::Owner,
            granted_by: user.uid,
        };
        if let Some(existing) = graph.fleets.get(&fleet.uid) {
            if existing.identity != *fleet {
                return Err(FirstOwnerError::GraphIdentityConflict("fleet").into());
            }
            if existing.membership(user.uid) != Some(&membership) {
                return Err(FirstOwnerError::MembershipMismatch.into());
            }
        } else {
            graph.fleets.insert(
                fleet.uid,
                FleetRecord {
                    identity: fleet.clone(),
                    memberships: std::collections::BTreeMap::from([(user.uid, membership)]),
                },
            );
        }
        let ownership = PrincipalOwnership {
            principal_uid: claim.principal_uid(),
            fleet_uid: fleet.uid,
            assigned_by: user.uid,
        };
        if let Some(existing) = graph.principal_ownership.get(&claim.principal_uid()) {
            if existing != &ownership {
                return Err(FirstOwnerError::GraphIdentityConflict("principal").into());
            }
        } else {
            graph
                .principal_ownership
                .insert(claim.principal_uid(), ownership);
        }
        graph.set_first_owner_state(&FirstOwnerEnrollment::Enrolled { claim: *claim });
        Ok(graph.first_owner_state())
    }
}
