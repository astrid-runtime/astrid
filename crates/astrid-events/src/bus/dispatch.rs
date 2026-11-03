//! Scope admission precedes topic matching and route snapshot allocation.

use std::sync::Arc;

use super::EventBus;
use crate::event::AstridEvent;
use crate::route::{MAX_SUBSCRIPTION_BUDGET_BYTES, PrincipalKey, RouteHandle};

impl EventBus {
    pub(super) fn dispatch_to_routes(&self, event: &Arc<AstridEvent>) {
        let AstridEvent::Ipc { message, .. } = &**event else {
            return;
        };
        let matched = self.matching_routes(event, &message.principal);
        Self::enqueue_routes(matched, event, &message.principal);
    }

    fn matching_routes(&self, event: &AstridEvent, principal: &PrincipalKey) -> Vec<RouteHandle> {
        // Candidate membership comes from the scope-partitioned table. Foreign
        // scopes are not visited or locked. `accepts_event` remains the authz
        // fence for gate / receipt / request-owner restrictions, and topic
        // match stays exact. Release the table lock before enqueue so a slow
        // receiver cannot prevent a concurrent subscription or sibling
        // publisher from making progress.
        let candidates = self.routes.read().candidates_for(principal);
        candidates
            .into_iter()
            .filter_map(|entry| {
                #[cfg(test)]
                self.selection_visits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let route = entry.lock();
                (route.accepts_event(principal, event) && route.matcher.matches(event))
                    .then(|| Arc::clone(&entry))
            })
            .collect()
    }

    fn enqueue_routes(
        matched: Vec<RouteHandle>,
        event: &Arc<AstridEvent>,
        principal: &PrincipalKey,
    ) {
        for entry_arc in matched {
            let mut entry = entry_arc.lock();
            // A runtime may retire after the matching snapshot. Keep the
            // final fence before both queue mutation and notification; an
            // empty rejected push must not wake a retired receiver.
            if !entry.accepts_event(principal, event) {
                continue;
            }
            entry.push_with_eviction(
                Arc::clone(event),
                principal.clone(),
                MAX_SUBSCRIPTION_BUDGET_BYTES,
            );
            let notify = Arc::clone(&entry.notify);
            drop(entry);
            notify.notify_one();
        }
    }
}

#[cfg(test)]
mod tests;
