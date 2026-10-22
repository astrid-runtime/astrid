//! Routed queue state-machine regressions.

use super::*;
use crate::event::EventMetadata;
use crate::ipc::{IpcMessage, IpcPayload, Topic};
use serde_json::json;
use uuid::Uuid;

fn ipc(topic: &str, principal: Option<&str>) -> Arc<AstridEvent> {
    let mut msg = IpcMessage::new(
        Topic::from_raw(topic),
        IpcPayload::RawJson(json!({})),
        Uuid::nil(),
    );
    msg.principal = principal.map(String::from);
    Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: msg,
    })
}

fn ipc_sized(topic: &str, principal: Option<&str>, payload_bytes: usize) -> Arc<AstridEvent> {
    let blob = "x".repeat(payload_bytes);
    let mut msg = IpcMessage::new(
        Topic::from_raw(topic),
        IpcPayload::RawJson(json!({ "p": blob })),
        Uuid::nil(),
    );
    msg.principal = principal.map(String::from);
    Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: msg,
    })
}

#[test]
fn push_and_drain_single_principal() {
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    for _ in 0..3 {
        entry.push_with_eviction(
            ipc("t.x", Some("alice")),
            Some("alice".into()),
            MAX_SUBSCRIPTION_BUDGET_BYTES,
        );
    }
    let mut out = Vec::new();
    entry.drr_drain(&mut out, MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(out.len(), 3);
    assert_eq!(entry.fanout.len(), 0);
    assert_eq!(entry.total_bytes, 0);
}

#[test]
fn pop_one_takes_exactly_one_and_keeps_the_rest() {
    // Regression: the receive fast-path takes ONE event and leaves the rest
    // for `try_drain`/`drr_drain`. The old fast-path drained the whole batch
    // and returned only its first element, silently discarding (losing) the
    // remainder — so a fan-out burst lost all-but-one per recv.
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    for _ in 0..3 {
        entry.push_with_eviction(
            ipc("t.x", Some("alice")),
            Some("alice".into()),
            MAX_SUBSCRIPTION_BUDGET_BYTES,
        );
    }
    // One pop yields exactly one event...
    assert!(entry.drr_pop_one().is_some());
    // ...and the other two are STILL queued — not discarded.
    let mut out = Vec::new();
    entry.drr_drain(&mut out, MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(
        out.len(),
        2,
        "the two un-popped events must remain, not be lost"
    );
    assert_eq!(entry.total_bytes, 0);
    assert_eq!(entry.fanout.len(), 0);
}

#[test]
fn pop_one_serves_each_principal_without_loss() {
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    entry.push_with_eviction(
        ipc("t.x", Some("alice")),
        Some("alice".into()),
        MAX_SUBSCRIPTION_BUDGET_BYTES,
    );
    entry.push_with_eviction(
        ipc("t.x", Some("bob")),
        Some("bob".into()),
        MAX_SUBSCRIPTION_BUDGET_BYTES,
    );
    // Two single-pops serve both queued events (round-robin), losing nothing.
    assert!(entry.drr_pop_one().is_some());
    assert!(entry.drr_pop_one().is_some());
    assert!(
        entry.drr_pop_one().is_none(),
        "only two events were queued; the third pop must be empty"
    );
    assert_eq!(entry.total_bytes, 0);
    assert_eq!(entry.fanout.len(), 0);
}

#[test]
fn drr_two_principals_yield_equal_counts() {
    // With the quantum floor of 4 KiB and tiny payloads, a single
    // round drains every queue completely. Cross-principal
    // fairness is therefore measured by equal *counts* delivered,
    // not strict per-message interleaving — DRR semantics, not
    // pure round-robin. Both principals should each see 2 events.
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    for _ in 0..2 {
        entry.push_with_eviction(
            ipc("t.x", Some("alice")),
            Some("alice".into()),
            MAX_SUBSCRIPTION_BUDGET_BYTES,
        );
        entry.push_with_eviction(
            ipc("t.x", Some("bob")),
            Some("bob".into()),
            MAX_SUBSCRIPTION_BUDGET_BYTES,
        );
    }
    let mut out = Vec::new();
    entry.drr_drain(&mut out, MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(out.len(), 4);
    let mut alice_count = 0;
    let mut bob_count = 0;
    for ev in &out {
        if let AstridEvent::Ipc { message, .. } = &**ev {
            match message.principal.as_deref() {
                Some("alice") => alice_count += 1,
                Some("bob") => bob_count += 1,
                _ => {},
            }
        }
    }
    assert_eq!(alice_count, 2);
    assert_eq!(bob_count, 2);
}

#[test]
fn drr_interleaves_when_quantum_caps_per_round() {
    // Tight budget = small per-principal quantum, so each round
    // serves one message per principal before rotating. Inserted
    // alice (large), bob (large) — drain visits alice, then bob,
    // interleaved.
    let payload_size = 8 * 1024; // 8 KiB > DRR_QUANTUM_MIN_BYTES/2
    let budget = payload_size * 4 + 1024;
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    entry.push_with_eviction(
        ipc_sized("t.x", Some("alice"), payload_size),
        Some("alice".into()),
        budget,
    );
    entry.push_with_eviction(
        ipc_sized("t.x", Some("bob"), payload_size),
        Some("bob".into()),
        budget,
    );
    entry.push_with_eviction(
        ipc_sized("t.x", Some("alice"), payload_size),
        Some("alice".into()),
        budget,
    );
    entry.push_with_eviction(
        ipc_sized("t.x", Some("bob"), payload_size),
        Some("bob".into()),
        budget,
    );

    let mut out = Vec::new();
    // Drain with budget = payload_size * 4 so 4 messages can be served.
    entry.drr_drain(&mut out, budget);
    // Both principals must each see 2 messages — fairness held.
    let mut alice_count = 0;
    let mut bob_count = 0;
    for ev in &out {
        if let AstridEvent::Ipc { message, .. } = &**ev {
            match message.principal.as_deref() {
                Some("alice") => alice_count += 1,
                Some("bob") => bob_count += 1,
                _ => {},
            }
        }
    }
    assert_eq!(alice_count, 2, "alice fairness");
    assert_eq!(bob_count, 2, "bob fairness");
}

#[test]
fn drr_isolates_principals_under_burst() {
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    for _ in 0..200 {
        entry.push_with_eviction(
            ipc("t.x", Some("alice")),
            Some("alice".into()),
            MAX_SUBSCRIPTION_BUDGET_BYTES,
        );
    }
    // Only alice; bob has zero entries — demand-allocation invariant.
    assert_eq!(entry.fanout.len(), 1);
    assert!(entry.fanout.contains_key(&Some("alice".into())));
}

#[test]
fn eviction_drops_oldest_head_under_budget() {
    // Budget tuned to ~3 large messages; pushing 4 forces eviction
    // of the oldest head (alice's first), not bob's later message.
    let payload_size = 64 * 1024;
    let budget = payload_size * 3 + 4096;
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);

    for _ in 0..3 {
        entry.push_with_eviction(
            ipc_sized("t.alice", Some("alice"), payload_size),
            Some("alice".into()),
            budget,
        );
    }
    // Sanity: alice now holds 3 entries.
    assert_eq!(
        entry
            .fanout
            .get(&Some("alice".into()))
            .map(|q| q.queue.len()),
        Some(3)
    );

    // Push bob — fits without eviction.
    entry.push_with_eviction(
        ipc_sized("t.bob.terminator", Some("bob"), payload_size / 4),
        Some("bob".into()),
        budget,
    );

    // Force budget overflow by pushing a new large alice.
    entry.push_with_eviction(
        ipc_sized("t.alice.new", Some("alice"), payload_size),
        Some("alice".into()),
        budget,
    );

    // Alice's earliest head must have been evicted; bob's tail
    // (the terminator) must still be present.
    let alice_q = entry
        .fanout
        .get(&Some("alice".into()))
        .expect("alice queue");
    let bob_q = entry.fanout.get(&Some("bob".into())).expect("bob queue");
    assert!(bob_q.queue.iter().any(|e| match &**e {
        AstridEvent::Ipc { message, .. } => message.topic == "t.bob.terminator",
        _ => false,
    }));
    // Alice should have evicted at least one of its earlier
    // entries to make room.
    assert!(
        alice_q.queue.len() < 4,
        "alice queue should have shed at least one head"
    );
}

#[test]
fn pathological_message_alone_is_rejected() {
    // budget = 1 KiB; message > 1 KiB → rejected, queue unchanged.
    let small_budget = 1024;
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    entry.push_with_eviction(
        ipc_sized("t.alice", Some("alice"), 4096),
        Some("alice".into()),
        small_budget,
    );
    assert_eq!(entry.fanout.len(), 0);
    assert_eq!(entry.total_bytes, 0);
}

#[test]
fn fairness_under_5000_principals_makes_progress() {
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    for i in 0..5000 {
        let p = format!("p{i}");
        entry.push_with_eviction(ipc("t.x", Some(&p)), Some(p), MAX_SUBSCRIPTION_BUDGET_BYTES);
    }
    let mut out = Vec::new();
    entry.drr_drain(&mut out, MAX_SUBSCRIPTION_BUDGET_BYTES);
    // Every principal had exactly one tiny message; one round
    // should drain all of them under the quantum floor.
    assert_eq!(out.len(), 5000);
    assert_eq!(entry.fanout.len(), 0);
}

// ── Self-scope (Option B route-level audit scoping) ──────────────

#[test]
fn accepts_predicate_authz_rule() {
    // Scoped to alice: only alice's publisher key is admitted.
    let scoped = RouteEntry::new(
        TopicMatcher::new("t.*"),
        "capsule-a".into(),
        Some(Some("alice".into())),
    );
    assert!(scoped.accepts(&Some("alice".into())));
    assert!(!scoped.accepts(&Some("bob".into())));
    // The system/kernel (None) bucket is foreign to a user-scoped route.
    assert!(!scoped.accepts(&None));

    // Unscoped: every publisher (including system None) is admitted.
    let unscoped = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    assert!(unscoped.accepts(&Some("alice".into())));
    assert!(unscoped.accepts(&Some("bob".into())));
    assert!(unscoped.accepts(&None));
}

#[test]
fn scoped_drops_foreign_at_enqueue() {
    // A route scoped to alice must drop bob's events at enqueue: bob's
    // bytes never enter total_bytes, bob gets no fanout bucket, and a
    // drain yields only alice.
    let mut entry = RouteEntry::new(
        TopicMatcher::new("t.*"),
        "capsule-a".into(),
        Some(Some("alice".into())),
    );
    for _ in 0..3 {
        entry.push_with_eviction(
            ipc("t.x", Some("alice")),
            Some("alice".into()),
            MAX_SUBSCRIPTION_BUDGET_BYTES,
        );
    }
    for _ in 0..5 {
        let evicted = entry.push_with_eviction(
            ipc("t.x", Some("bob")),
            Some("bob".into()),
            MAX_SUBSCRIPTION_BUDGET_BYTES,
        );
        assert_eq!(evicted, 0, "foreign push is a no-op, never evicts");
    }
    // Only alice's bucket exists; bob's bytes never accrued.
    assert_eq!(entry.fanout.len(), 1);
    assert!(entry.fanout.contains_key(&Some("alice".into())));
    assert!(!entry.fanout.contains_key(&Some("bob".into())));

    let mut out = Vec::new();
    entry.drr_drain(&mut out, MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(out.len(), 3, "only alice's three events drain");
    for ev in &out {
        if let AstridEvent::Ipc { message, .. } = &**ev {
            assert_eq!(message.principal.as_deref(), Some("alice"));
        }
    }
}

#[test]
fn scoped_budget_not_evictable_by_foreign_burst() {
    // THE Option-B completeness guarantee: a foreign-principal burst far
    // past the budget can NEVER evict the owner's entries, because the
    // foreign bytes never enter the budget in the first place. A
    // drain-time-filter design would FAIL this — bob's bytes would
    // occupy the shared budget and head-evict alice before any filter.
    let payload_size = 64 * 1024;
    let budget = payload_size * 3 + 4096;
    let mut entry = RouteEntry::new(
        TopicMatcher::new("t.*"),
        "capsule-a".into(),
        Some(Some("alice".into())),
    );
    // Alice writes one entry well within budget.
    entry.push_with_eviction(
        ipc_sized("t.alice.keep", Some("alice"), payload_size),
        Some("alice".into()),
        budget,
    );
    // Bob floods far past the budget.
    for _ in 0..100 {
        entry.push_with_eviction(
            ipc_sized("t.bob.flood", Some("bob"), payload_size),
            Some("bob".into()),
            budget,
        );
    }
    // Alice's single entry is intact; bob never entered.
    let alice_q = entry
        .fanout
        .get(&Some("alice".into()))
        .expect("alice queue survives");
    assert_eq!(alice_q.queue.len(), 1, "alice's entry never evicted");
    assert!(!entry.fanout.contains_key(&Some("bob".into())));
    assert_eq!(entry.total_bytes, alice_q.bytes);
}

#[test]
fn high_rate_tiny_stream_under_cap_is_not_dropped() {
    // Regression for #1158: a fast LLM token stream publishes one tiny
    // event per token. At the old 256-message cap a burst of ~1000 tokens
    // dropped the oldest events — corrupting the stream, or losing the
    // terminal `Done` and hanging the turn. 1000 tiny empty-payload events
    // stay far under the 1 MiB byte budget, so ONLY the count cap could
    // drop them; at the raised cap none may be. This test fails at cap 256.
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    for _ in 0..1000 {
        let evicted = entry.push_with_eviction(
            ipc("t.tok", Some("alice")),
            Some("alice".into()),
            MAX_SUBSCRIPTION_BUDGET_BYTES,
        );
        assert_eq!(
            evicted, 0,
            "no event may be evicted under the cap and budget"
        );
    }
    let bucket = entry
        .fanout
        .get(&Some("alice".into()))
        .expect("alice bucket exists");
    assert_eq!(bucket.queue.len(), 1000, "all 1000 stream events retained");
}

#[test]
fn per_principal_count_cap_drops_oldest_beyond_fallback() {
    // The count cap is the tiny-message backstop. Isolate it from the byte
    // budget with an effectively unbounded budget, then push
    // PENDING_PER_PRINCIPAL_FALLBACK + 1 tiny events for one principal: the
    // bucket caps at the constant and the OLDEST (FIFO head) is the drop.
    let mut entry = RouteEntry::new(TopicMatcher::new("t.*"), "capsule-a".into(), None);
    entry.push_with_eviction(
        ipc("t.oldest", Some("alice")),
        Some("alice".into()),
        usize::MAX,
    );
    for _ in 0..PENDING_PER_PRINCIPAL_FALLBACK {
        entry.push_with_eviction(
            ipc("t.rest", Some("alice")),
            Some("alice".into()),
            usize::MAX,
        );
    }
    let bucket = entry
        .fanout
        .get(&Some("alice".into()))
        .expect("alice bucket exists");
    assert_eq!(
        bucket.queue.len(),
        PENDING_PER_PRINCIPAL_FALLBACK,
        "bucket is capped at the fallback; exactly one event dropped"
    );
    let has_oldest = bucket
        .queue
        .iter()
        .any(|ev| matches!(&**ev, AstridEvent::Ipc { message, .. } if message.topic == "t.oldest"));
    assert!(!has_oldest, "the FIFO head (oldest) was the evicted event");
}
