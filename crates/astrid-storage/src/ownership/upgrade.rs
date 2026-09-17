//! Local-operator repair for released unowned principals.
//!
//! Native boot may invoke this only after the durable CLI-root device is bound
//! as the local operator. A singleton graph is a refusal rail, not proof that
//! historical principals are personal. Released homes have no
//! personal-versus-hosted marker; extra users, fleets, or foreign assignments
//! stay unowned and remain assignable by named confirmation.

use std::collections::BTreeSet;

use astrid_core::{FleetUid, PrincipalOwnership, PrincipalUid, UserUid};

use super::{OwnershipError, OwnershipSnapshot, OwnershipStore};

/// Outcome of attempting to assign released unowned principals locally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnownedPrincipalReconciliation {
    adopted: Vec<PrincipalUid>,
    deferred: Vec<PrincipalUid>,
    deferral: Option<UnownedPrincipalDeferral>,
}

impl UnownedPrincipalReconciliation {
    fn none() -> Self {
        Self {
            adopted: Vec::new(),
            deferred: Vec::new(),
            deferral: None,
        }
    }

    fn with_deferral(deferred: Vec<PrincipalUid>, deferral: UnownedPrincipalDeferral) -> Self {
        if deferred.is_empty() {
            Self::none()
        } else {
            Self {
                adopted: Vec::new(),
                deferred,
                deferral: Some(deferral),
            }
        }
    }

    /// Principals assigned to the local operator fleet by this mutation.
    #[must_use]
    pub fn adopted(&self) -> &[PrincipalUid] {
        &self.adopted
    }

    /// Admitted principals left unowned because authority was not established.
    #[must_use]
    pub fn deferred(&self) -> &[PrincipalUid] {
        &self.deferred
    }

    /// Why deferred principals were not assigned.
    #[must_use]
    pub const fn deferral(&self) -> Option<UnownedPrincipalDeferral> {
        self.deferral
    }
}

/// Why unowned principals were not assigned to the local operator fleet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnownedPrincipalDeferral {
    /// The graph already contains another user, fleet, or foreign assignment.
    ///
    /// Assigning those identities to the CLI root would invent hosted ownership
    /// from a local-root assumption. They remain unowned until an explicit
    /// authorized assignment.
    AmbiguousAuthority,
    /// The caller is not the current local-operator device on this principal.
    ///
    /// Possession of a singleton graph is not enough. The durable CLI-root
    /// credential must currently resolve to a managing user of the principal's
    /// fleet. Leftovers stay unowned until that binding exists or a named
    /// assignment is made.
    LocalOperatorNotBound,
}

impl OwnershipStore {
    /// Assign released unowned principals for a currently bound local operator.
    ///
    /// The authenticated credential is the principal plus device public key.
    /// `user_for_device` must resolve to a current manager of that principal's
    /// fleet; a singleton graph is then required as a refusal rail, not as
    /// proof of personal ownership. Missing or revoked local-operator
    /// delegation defers leftovers instead of failing the caller.
    ///
    /// # Errors
    ///
    /// Propagates storage/integrity failures from the graph mutation.
    pub async fn reconcile_bound_local_operator_unowned_principals(
        &self,
        principal: PrincipalUid,
        public_key: &[u8; 32],
    ) -> Result<UnownedPrincipalReconciliation, OwnershipError> {
        self.mutate(
            |graph| match bound_local_operator(graph, principal, public_key) {
                Some((actor, fleet_uid)) => {
                    self.reconcile_local_operator_unowned_in_graph(graph, actor, fleet_uid)
                },
                None => Ok(UnownedPrincipalReconciliation::with_deferral(
                    unowned_admitted_principals(graph, &self.principals),
                    UnownedPrincipalDeferral::LocalOperatorNotBound,
                )),
            },
        )
        .await
    }

    /// Assign released unowned principals only after explicit operator authority.
    ///
    /// Layout origin is not authority. Packed and layout-one homes use the same
    /// rule: adopt only when this graph still contains exactly the actor, exactly
    /// the actor's fleet, and no assignment to any other fleet. Existing
    /// assignments are never moved. A graph with additional users or fleets
    /// leaves unowned principals unowned.
    ///
    /// Callers must independently authenticate the actor. Automatic local
    /// upgrade uses [`Self::reconcile_bound_local_operator_unowned_principals`]
    /// so a singleton graph is never sufficient on its own.
    ///
    /// # Errors
    ///
    /// Rejects a missing fleet or an actor without current manager authority.
    pub async fn reconcile_local_operator_unowned_principals(
        &self,
        actor: UserUid,
        fleet_uid: FleetUid,
    ) -> Result<UnownedPrincipalReconciliation, OwnershipError> {
        self.mutate(|graph| self.reconcile_local_operator_unowned_in_graph(graph, actor, fleet_uid))
            .await
    }

    fn reconcile_local_operator_unowned_in_graph(
        &self,
        graph: &mut OwnershipSnapshot,
        actor: UserUid,
        fleet_uid: FleetUid,
    ) -> Result<UnownedPrincipalReconciliation, OwnershipError> {
        let fleet = graph
            .fleets
            .get(&fleet_uid)
            .ok_or(OwnershipError::FleetNotFound(fleet_uid))?;
        Self::require_manager(fleet, actor)?;
        let candidates = unowned_admitted_principals(graph, &self.principals);
        if candidates.is_empty() {
            return Ok(UnownedPrincipalReconciliation::none());
        }
        if !is_single_local_operator_graph(graph, actor, fleet_uid) {
            return Ok(UnownedPrincipalReconciliation::with_deferral(
                candidates,
                UnownedPrincipalDeferral::AmbiguousAuthority,
            ));
        }
        for principal_uid in &candidates {
            graph.principal_ownership.insert(
                *principal_uid,
                PrincipalOwnership {
                    principal_uid: *principal_uid,
                    fleet_uid,
                    assigned_by: actor,
                },
            );
        }
        Ok(UnownedPrincipalReconciliation {
            adopted: candidates,
            deferred: Vec::new(),
            deferral: None,
        })
    }
}

fn bound_local_operator(
    graph: &OwnershipSnapshot,
    principal: PrincipalUid,
    public_key: &[u8; 32],
) -> Option<(UserUid, FleetUid)> {
    let actor = graph.user_for_device(principal, public_key)?;
    let owner = graph.principal_owner(principal)?;
    graph
        .fleet(owner.fleet_uid)?
        .membership(actor)
        .is_some_and(|membership| membership.role.can_manage())
        .then_some((actor, owner.fleet_uid))
}

fn unowned_admitted_principals(
    graph: &OwnershipSnapshot,
    principals: &crate::PrincipalDirectory,
) -> Vec<PrincipalUid> {
    principals
        .bindings()
        .into_iter()
        .map(|(_, uid)| uid)
        .filter(|uid| {
            !graph.principal_deletions.contains_key(uid) && graph.principal_owner(*uid).is_none()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn is_single_local_operator_graph(
    graph: &OwnershipSnapshot,
    actor: UserUid,
    fleet_uid: FleetUid,
) -> bool {
    graph.users.len() == 1
        && graph.users.contains_key(&actor)
        && graph.fleets.len() == 1
        && graph.fleets.contains_key(&fleet_uid)
        && graph
            .principal_ownership
            .values()
            .all(|ownership| ownership.fleet_uid == fleet_uid)
}

#[cfg(test)]
mod tests;
