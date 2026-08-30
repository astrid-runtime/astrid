//! Exact evidence gate for same-lock IPC relation projections.

use super::{all_bools, u64_field};
use serde_json::Value;

const RELATION_PROJECTIONS: &[(u64, u64, u64, usize, usize)] = &[
    (1, 7, 3, 3, 3),
    (2, 3, 6, 6, 6),
    (1, 8, 3, 3, 3),
    (1, 9, 3, 3, 3),
];

pub(super) fn relations_projection_holds(events: &[Value]) -> bool {
    named_relation_events(events)
        .into_iter()
        .map(|event| {
            (
                u64_field(event, "id").unwrap_or_default(),
                u64_field(event, "generation").unwrap_or_default(),
                u64_field(event, "epoch").unwrap_or_default(),
                u64_field(event, "rows").unwrap_or_default() as usize,
                u64_field(event, "fold_rows").unwrap_or_default() as usize,
            )
        })
        .eq(RELATION_PROJECTIONS.iter().copied())
        && all_bools(events, "relations.projection", "same_lock", true)
        && all_bools(events, "relations.projection", "fold_matches", true)
        && named_relation_events(events)
            .into_iter()
            .all(|event| u64_field(event, "epoch") == u64_field(event, "fold_epoch"))
}

fn named_relation_events(events: &[Value]) -> Vec<&Value> {
    events
        .iter()
        .filter(|event| event.get("ev").and_then(Value::as_str) == Some("relations.projection"))
        .collect()
}
