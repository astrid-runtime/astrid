//! Test-only ownership planner and production-path regressions.
//!
//! Production creation resolves explicit device delegation; invitations pin
//! its generation; capability-authorized spawning inherits the caller's fleet
//! without impersonating a human. This pure planner documents the ordinary
//! creation policy but is not the production authentication path. Integration
//! tests exercise the real handlers and ownership transactions.

use astrid_core::{FleetUid, PrincipalOwnership, PrincipalUid, UserUid};
use astrid_storage::FleetRecord;

/// Human actor authenticated independently of a principal alias.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AuthenticatedHuman {
    /// Live human identity presented by the request, not inferred later.
    pub user_uid: UserUid,
}

/// Inputs required to decide ownership for a created principal.
#[derive(Clone, Copy, Debug)]
pub(super) struct CreatedPrincipalOwnershipRequest<'a> {
    /// Principal that was just provisioned or is being healed.
    pub created: PrincipalUid,
    /// Current assignment, if any. Already-owned records are preserved.
    pub existing: Option<&'a PrincipalOwnership>,
    /// Creating principal's current fleet assignment.
    pub creator_ownership: Option<&'a PrincipalOwnership>,
    /// Authenticated human. Historical `assigned_by` is not a substitute.
    pub actor: Option<AuthenticatedHuman>,
    /// Fleet record for the creating principal's current fleet.
    pub creator_fleet: Option<&'a FleetRecord>,
}

/// Decision produced by [`plan_created_principal_ownership`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum OwnershipPlan {
    /// Existing assignment is left untouched.
    Unchanged,
    /// First assignment onto the creating principal's fleet.
    Assign(PrincipalOwnership),
}

/// Why assignment cannot proceed without inventing authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum OwnershipPlanningError {
    /// No authenticated human was supplied on the request.
    MissingAuthenticatedHuman,
    /// The creating principal has no fleet to inherit.
    CreatorPrincipalUnowned,
    /// The authenticated human is not a live manager of the creator fleet.
    ActorNotLiveManager {
        /// Human that was presented.
        user: UserUid,
        /// Fleet that required a manager.
        fleet: FleetUid,
    },
}

/// Plan ownership for a created principal without inventing a human actor.
///
/// Clone-source fleets are intentionally not an input. Global root is not a
/// default. A historical `assigned_by` is used only when it is the
/// authenticated actor and still a live manager.
pub(super) fn plan_created_principal_ownership(
    request: CreatedPrincipalOwnershipRequest<'_>,
) -> Result<OwnershipPlan, OwnershipPlanningError> {
    if request.existing.is_some() {
        return Ok(OwnershipPlan::Unchanged);
    }

    let Some(actor) = request.actor else {
        return Err(OwnershipPlanningError::MissingAuthenticatedHuman);
    };
    let Some(creator) = request.creator_ownership else {
        return Err(OwnershipPlanningError::CreatorPrincipalUnowned);
    };
    let Some(fleet) = request.creator_fleet else {
        return Err(OwnershipPlanningError::CreatorPrincipalUnowned);
    };
    if fleet.identity().uid != creator.fleet_uid {
        return Err(OwnershipPlanningError::CreatorPrincipalUnowned);
    }
    if !fleet
        .membership(actor.user_uid)
        .is_some_and(|membership| membership.role.can_manage())
    {
        return Err(OwnershipPlanningError::ActorNotLiveManager {
            user: actor.user_uid,
            fleet: creator.fleet_uid,
        });
    }

    Ok(OwnershipPlan::Assign(PrincipalOwnership {
        principal_uid: request.created,
        fleet_uid: creator.fleet_uid,
        assigned_by: actor.user_uid,
    }))
}

#[cfg(test)]
mod tests;
