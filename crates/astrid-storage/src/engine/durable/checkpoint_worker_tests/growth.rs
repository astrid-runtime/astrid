//! Drive real checkpoint admission and publication in worker regressions.

use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use super::{Engine, transaction};
use crate::engine::durable::{LIFECYCLE_USABLE, checkpoint_worker};

fn checkpoint_progress(engine: &Engine) -> (bool, u64, u64) {
    let inner = engine.inner.lock();
    let store = checkpoint_worker::lock_representations(inner.representations.as_ref()).unwrap();
    (
        store.should_checkpoint_representations_metadata(),
        store.journal_generation_for_test(),
        store.resident_map_node_count(),
    )
}

#[track_caller]
pub(in crate::engine::durable) fn grow_until_checkpoint_eligible(engine: &Engine) {
    let mut expected = engine.root(&"alice".to_owned()).unwrap();
    // Reopened cycles must create history rather than deduplicate the same
    // immutable objects from a previous call's sequence. Reserve zero for the
    // fresh principal, whose first committed generation is also zero.
    let generation = expected.map_or(0, |root| root.generation.get().strict_add(1));
    let (_, before, resident) = checkpoint_progress(engine);
    // Later reopened cycles start with larger maps. Scale the finite fixture
    // workload with that captured arena so it can cross the existing amortized
    // collection boundary; a fixed fresh-store input count need not do so.
    let input_budget = resident.max(2048);
    let arbiter = engine.checkpoint_arbiter_for_test();
    for sequence in 0_u64..input_budget {
        let mut payload = generation.to_le_bytes().to_vec();
        payload.extend(sequence.to_le_bytes());
        payload.extend([b'y'; 256]);
        let (_, txn) = transaction("alice", expected, &payload);
        expected = Some(engine.commit(txn).unwrap().root());
        let (eligible, current, _) = checkpoint_progress(engine);
        // Eligibility can disappear after the admitted worker publishes. Stop
        // feeding as soon as that real job exists, before a preparation gate's
        // fail-safe expires; the caller still verifies its actual gate/close.
        let admitted = matches!(
            arbiter.lock().worker,
            checkpoint_worker::CheckpointWorkerSlot::Preparing { .. }
        );
        if eligible || current > before || admitted {
            return;
        }
    }
    let inner = engine.inner.lock();
    let store = checkpoint_worker::lock_representations(inner.representations.as_ref()).unwrap();
    panic!(
        "fixture must grow checkpoint-eligible history: namespace={generation} budget={input_budget} before={before} frames={} resident={} journal={}",
        store.map_frame_count(),
        store.resident_map_node_count(),
        store.journal_generation_for_test()
    );
}

/// Wait for an admitted ordinary job without taking its join away from close.
/// Stop feeding while it works, then keep the real Published close outcome.
fn finish_scheduled_checkpoint(engine: &Engine) {
    use checkpoint_worker::CheckpointWorkerSlot;
    let arbiter = engine.checkpoint_arbiter_for_test();
    loop {
        let pending = {
            let state = arbiter.lock();
            match &state.worker {
                CheckpointWorkerSlot::Idle => false,
                CheckpointWorkerSlot::Preparing { control, join } => {
                    assert!(!control.is_draining() && !control.is_cancelled());
                    !join.is_finished()
                },
            }
        };
        if !pending {
            assert_eq!(
                engine.lifecycle_for_test().load(Ordering::Acquire),
                LIFECYCLE_USABLE,
                "ordinary publication must finish without recovery"
            );
            return;
        }
        // Observation cadence only; no completion deadline or product timeout.
        thread::sleep(Duration::from_millis(1));
    }
}

pub(super) fn commit_until_generation_advances(engine: &Engine, before: u64, marker: u8) -> u64 {
    let mut expected = engine.root(&"alice".to_owned()).unwrap();
    for sequence in 0_u64..2048 {
        finish_scheduled_checkpoint(engine);
        let (_, generation, _) = checkpoint_progress(engine);
        if generation > before {
            return generation;
        }
        let mut payload = sequence.to_le_bytes().to_vec();
        payload.push(marker);
        payload.extend([b'x'; 64]);
        let (_, txn) = transaction("alice", expected, &payload);
        expected = Some(engine.commit(txn).unwrap().root());
    }
    panic!("fixture must admit an ordinary checkpoint before exhausting its input");
}
