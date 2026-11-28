//! Scope admission precedes topic matching and route snapshot allocation.

use std::sync::Arc;

use super::EventBus;
use crate::event::AstridEvent;
use crate::route::{MAX_SUBSCRIPTION_BUDGET_BYTES, RouteEntry};

type Route = Arc<parking_lot::Mutex<RouteEntry>>;

impl EventBus {
    pub(super) fn dispatch_to_routes(&self, event: &Arc<AstridEvent>) {
        let AstridEvent::Ipc { .. } = &**event else {
            return;
        };
        let matched = self.matching_routes(event);
        Self::enqueue_routes(matched, event);
    }

    fn matching_routes(&self, event: &AstridEvent) -> Vec<Route> {
        // Snapshot only admitted routes under the read lock. Foreign scopes
        // need neither topic parsing nor temporary Arc/key ownership. Release
        // the table lock before enqueue so a slow receiver cannot prevent a
        // concurrent subscription or a sibling publisher from making progress.
        self.routes
            .read()
            .values()
            .filter_map(|entry| {
                let route = entry.lock();
                (route.admitted_message(event).is_some() && route.matcher.matches(event))
                    .then(|| Arc::clone(entry))
            })
            .collect()
    }

    fn enqueue_routes(matched: Vec<Route>, event: &Arc<AstridEvent>) {
        for entry_arc in matched {
            let mut entry = entry_arc.lock();
            // A runtime may retire after the matching snapshot. Keep the
            // final fence before both queue mutation and notification; an
            // empty rejected push must not wake a retired receiver.
            if entry.admitted_message(event).is_none() {
                continue;
            }
            entry.push_with_eviction(Arc::clone(event), MAX_SUBSCRIPTION_BUDGET_BYTES);
            let notify = Arc::clone(&entry.notify);
            drop(entry);
            notify.notify_one();
        }
    }
}

#[cfg(test)]
mod tests;
