//! Scope-partitioned routed subscription table.
//!
//! One authoritative store for publish-side selection. Candidate membership
//! is by [`RouteAdmission`]; [`RouteEntry::accepts_event`] remains the authz
//! fence after a candidate is chosen.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::route::entry::{PrincipalKey, RouteAdmission, RouteEntry, RouteKey};

pub(crate) type RouteHandle = Arc<Mutex<RouteEntry>>;

/// Authoritative routed-subscription table, partitioned by admission scope.
#[derive(Debug, Default)]
pub(crate) struct RouteTable {
    exact: HashMap<PrincipalKey, HashMap<RouteKey, RouteHandle>>,
    principal_or_system: HashMap<String, HashMap<RouteKey, RouteHandle>>,
    unscoped: HashMap<RouteKey, RouteHandle>,
    /// Running membership count so [`len`](Self::len) stays O(1).
    route_count: usize,
}

impl RouteTable {
    pub(crate) fn insert(&mut self, key: RouteKey, route: RouteHandle, scope: RouteAdmission) {
        let replaced = match scope {
            RouteAdmission::All => self.unscoped.insert(key, route),
            RouteAdmission::Exact(principal) => {
                self.exact.entry(principal).or_default().insert(key, route)
            },
            RouteAdmission::PrincipalOrSystem(principal) => self
                .principal_or_system
                .entry(principal)
                .or_default()
                .insert(key, route),
        };
        if replaced.is_none() {
            self.route_count = self.route_count.saturating_add(1);
        }
    }

    pub(crate) fn remove(&mut self, key: &RouteKey, scope: &RouteAdmission) -> Option<RouteHandle> {
        let removed = match scope {
            RouteAdmission::All => self.unscoped.remove(key),
            RouteAdmission::Exact(principal) => {
                let removed = self
                    .exact
                    .get_mut(principal)
                    .and_then(|bucket| bucket.remove(key));
                if let Some(bucket) = self.exact.get(principal)
                    && bucket.is_empty()
                {
                    self.exact.remove(principal);
                }
                removed
            },
            RouteAdmission::PrincipalOrSystem(principal) => {
                let removed = self
                    .principal_or_system
                    .get_mut(principal)
                    .and_then(|bucket| bucket.remove(key));
                if let Some(bucket) = self.principal_or_system.get(principal)
                    && bucket.is_empty()
                {
                    self.principal_or_system.remove(principal);
                }
                removed
            },
        };
        if removed.is_some() {
            self.route_count = self.route_count.saturating_sub(1);
        }
        removed
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.route_count
    }

    /// Borrowing iterator over candidate handles for `publisher`.
    ///
    /// Foreign exact / principal-or-system buckets are not visited. System
    /// publishes (`publisher == None`) still see every principal-or-system
    /// route because those routes admit kernel/system events by contract.
    /// Does not clone handles; callers clone only after admission + topic match.
    pub(crate) fn candidates<'a>(
        &'a self,
        publisher: &'a PrincipalKey,
    ) -> impl Iterator<Item = &'a RouteHandle> + 'a {
        // Standard lazy combinators: take(0) never advances foreign PoS
        // buckets for a concrete publisher; take(len) walks every PoS
        // bucket for system publishes. No temporary Vec.
        let exact = self
            .exact
            .get(publisher)
            .into_iter()
            .flat_map(HashMap::values);
        let principal_or_system = self
            .principal_or_system
            .values()
            .take(if publisher.is_none() {
                self.principal_or_system.len()
            } else {
                0
            })
            .chain(
                publisher
                    .as_ref()
                    .and_then(|principal| self.principal_or_system.get(principal)),
            )
            .flat_map(HashMap::values);
        exact
            .chain(principal_or_system)
            .chain(self.unscoped.values())
    }

    /// Flat scan of every stored route. Test/red instrumentation only.
    #[cfg(test)]
    pub(crate) fn iter_all(&self) -> impl Iterator<Item = &RouteHandle> {
        self.exact
            .values()
            .flat_map(HashMap::values)
            .chain(self.principal_or_system.values().flat_map(HashMap::values))
            .chain(self.unscoped.values())
    }
}
