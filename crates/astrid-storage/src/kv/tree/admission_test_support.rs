//! Complete, settled admission accounting for single-principal KV tests.

use super::*;
use std::time::Duration;

#[derive(Default)]
pub(super) struct AdmissionCensus {
    objects: BTreeMap<ObjectId, u64>,
    commits: u64,
}

impl AdmissionCensus {
    // Complete logical wire-size growth, including later checkpoint commits.
    // This test engine performs no physical disk I/O.
    pub(super) fn logical_wire_growth(&self, before: &Self) -> u64 {
        for (id, bytes) in &before.objects {
            assert_eq!(self.objects.get(id), Some(bytes), "seed history changed");
        }
        let object_bytes = self
            .objects
            .iter()
            .filter(|(id, _)| !before.objects.contains_key(id))
            .try_fold(0_u64, |sum, (_, bytes)| sum.checked_add(*bytes))
            .unwrap();
        let transitions = self.commits.checked_sub(before.commits).unwrap();
        let later = root_frame_bytes(b"alice", true).unwrap();
        let roots = if before.commits == 0 && transitions != 0 {
            root_frame_bytes(b"alice", false)
                .unwrap()
                .checked_add((transitions - 1).checked_mul(later).unwrap())
                .unwrap()
        } else {
            transitions.checked_mul(later).unwrap()
        };
        object_bytes.checked_add(roots).unwrap()
    }
}

// Exactly one foreground store and this engine Arc are retained by these tests.
// All scheduled checkpoint clones hold another engine Arc until they finish.
pub(super) async fn settled_admission_census(engine: &Arc<MeasuringEngine>) -> AdmissionCensus {
    drain_checkpoint_tasks(engine).await;
    let mut census = AdmissionCensus::default();
    let root = engine.inner.root(&"alice".to_owned());
    let mut pending = root.map(|state| vec![state.commit]).unwrap_or_default();
    while let Some(id) = pending.pop() {
        if census.objects.contains_key(&id) {
            continue;
        }
        let record = engine
            .inner
            .object(id)
            .expect("missing admitted history object");
        census.objects.insert(id, object_frame_bytes(&record));
        if record.kind() == ObjectKind::Commit {
            census.commits = census.commits.checked_add(1).unwrap();
        }
        for reference in record.references() {
            assert!(matches!(
                reference.kind(),
                ReferenceKind::Owns | ReferenceKind::Lineage
            ));
            pending.push(reference.target());
        }
    }
    assert_eq!(
        census.objects.len(),
        engine.inner.object_count(),
        "disconnected admitted object"
    );
    assert_eq!(
        census.commits,
        root.map_or(0, |state| state.generation.get().checked_add(1).unwrap())
    );
    census
}

#[test]
fn complete_admission_growth_includes_edit_and_later_checkpoint() {
    let before = AdmissionCensus {
        objects: BTreeMap::from([(ObjectId::new([1; 32]), 300)]),
        commits: 1,
    };
    let after = AdmissionCensus {
        objects: BTreeMap::from([
            (ObjectId::new([1; 32]), 300),
            (ObjectId::new([2; 32]), 80_000),
            (ObjectId::new([3; 32]), 1_025),
        ]),
        commits: 3,
    };
    assert_eq!(
        after.logical_wire_growth(&before),
        81_025 + 2 * root_frame_bytes(b"alice", true).unwrap()
    );
    assert_eq!(
        before.logical_wire_growth(&before),
        0,
        "rejected attempts admit nothing"
    );
}

// The fixture retains only its foreground store and its explicit engine Arc.
pub(super) async fn drain_checkpoint_tasks<E>(engine: &Arc<E>) {
    let started = Instant::now();
    while Arc::strong_count(engine) != 2 {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "owned checkpoint did not drain"
        );
        tokio::task::yield_now().await;
    }
}
