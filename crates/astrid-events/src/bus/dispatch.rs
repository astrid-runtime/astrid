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
        // Hold the table read guard while borrowing candidate buckets.
        // Foreign scopes are not visited. Clone a handle only after
        // accepts_event + topic match succeed, preserving the #2203 rule that
        // temporary ownership scales with admitted recipients. Release the
        // table lock before enqueue so a slow receiver cannot stall subscribe.
        let table = self.routes.read();
        let mut matched = Vec::new();
        for entry in table.candidates(principal) {
            #[cfg(test)]
            self.selection_visits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let route = entry.lock();
            if route.accepts_event(principal, event) && route.matcher.matches(event) {
                matched.push(Arc::clone(entry));
            }
        }
        drop(table);
        matched
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
