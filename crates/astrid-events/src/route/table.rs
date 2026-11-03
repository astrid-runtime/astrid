//! Scope-partitioned routed subscription table.
//!
//! One authoritative store for publish-side selection. Candidate membership
//! is by admission scope; [`RouteEntry::accepts_event`] remains the authz
//! fence after a candidate is chosen.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::route::entry::{PrincipalKey, RouteEntry, RouteKey};

pub(crate) type RouteHandle = Arc<Mutex<RouteEntry>>;

/// Partition key used to place and select routes without a second index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum RouteSelectionScope {
    /// Unscoped firehose (`RouteAdmission::All`).
    All,
    /// Exact publisher principal, including `Exact(None)` for system-only.
    Exact(PrincipalKey),
    /// Persistent principal runtime that also admits kernel/system publishes.
    PrincipalOrSystem(String),
}

/// Authoritative routed-subscription table, partitioned by admission scope.
#[derive(Debug, Default)]
pub(crate) struct RouteTable {
    exact: HashMap<PrincipalKey, HashMap<RouteKey, RouteHandle>>,
    principal_or_system: HashMap<String, HashMap<RouteKey, RouteHandle>>,
    unscoped: HashMap<RouteKey, RouteHandle>,
}

impl RouteTable {
    pub(crate) fn insert(&mut self, key: RouteKey, route: RouteHandle, scope: RouteSelectionScope) {
        match scope {
            RouteSelectionScope::All => {
                self.unscoped.insert(key, route);
            },
            RouteSelectionScope::Exact(principal) => {
                self.exact.entry(principal).or_default().insert(key, route);
            },
            RouteSelectionScope::PrincipalOrSystem(principal) => {
                self.principal_or_system
                    .entry(principal)
                    .or_default()
                    .insert(key, route);
            },
        }
    }

    pub(crate) fn remove(
        &mut self,
        key: &RouteKey,
        scope: &RouteSelectionScope,
    ) -> Option<RouteHandle> {
        match scope {
            RouteSelectionScope::All => self.unscoped.remove(key),
            RouteSelectionScope::Exact(principal) => {
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
            RouteSelectionScope::PrincipalOrSystem(principal) => {
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
        }
    }

    pub(crate) fn len(&self) -> usize {
        let exact = self.exact.values().map(HashMap::len).sum::<usize>();
        let principal_or_system = self
            .principal_or_system
            .values()
            .map(HashMap::len)
            .sum::<usize>();
        exact
            .saturating_add(principal_or_system)
            .saturating_add(self.unscoped.len())
    }

    /// Collect candidate route handles for `publisher` without locking them.
    ///
    /// Foreign exact / principal-or-system buckets are not visited. System
    /// publishes (`publisher == None`) still see every principal-or-system
    /// route because those routes admit kernel/system events by contract.
    pub(crate) fn candidates_for(&self, publisher: &PrincipalKey) -> Vec<RouteHandle> {
        let mut out = Vec::new();
        if let Some(bucket) = self.exact.get(publisher) {
            out.extend(bucket.values().cloned());
        }
        match publisher {
            Some(principal) => {
                if let Some(bucket) = self.principal_or_system.get(principal) {
                    out.extend(bucket.values().cloned());
                }
            },
            None => {
                for bucket in self.principal_or_system.values() {
                    out.extend(bucket.values().cloned());
                }
            },
        }
        out.extend(self.unscoped.values().cloned());
        out
    }
}
