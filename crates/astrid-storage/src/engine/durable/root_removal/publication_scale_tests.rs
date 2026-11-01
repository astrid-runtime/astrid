//! Explicit publication-map cost probe; timings are not a CI performance gate.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::super::PublishedRoots;
use crate::storage_model::{ObjectId, RootGeneration, RootState};

static KEY_CLONES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Principal(u32);

impl Clone for Principal {
    fn clone(&self) -> Self {
        KEY_CLONES.fetch_add(1, Ordering::Relaxed);
        Self(self.0)
    }
}

#[test]
#[ignore = "explicit 10000-principal publication-map cost probe"]
fn published_roots_ten_thousand_insert_update_remove_cost() {
    let roots = PublishedRoots::new(&BTreeMap::new());
    let root = RootState {
        generation: RootGeneration::INITIAL,
        commit: ObjectId::new([0x41; 32]),
    };
    KEY_CLONES.store(0, Ordering::Relaxed);
    let started = Instant::now();
    for index in 0..10_000 {
        roots.publish(&Principal(index), root);
    }
    println!(
        "published=10000;seconds={:.6};key_clones={}",
        started.elapsed().as_secs_f64(),
        KEY_CLONES.swap(0, Ordering::Relaxed)
    );
    let started = Instant::now();
    for index in 0..10_000 {
        roots.publish(&Principal(index), root);
        assert_eq!(roots.get(&Principal(index)), Some(root));
    }
    println!(
        "updated=10000;seconds={:.6};key_clones={}",
        started.elapsed().as_secs_f64(),
        KEY_CLONES.swap(0, Ordering::Relaxed)
    );
    let started = Instant::now();
    for index in 0..10_000 {
        roots.remove(&Principal(index));
        assert_eq!(roots.get(&Principal(index)), None);
    }
    println!(
        "removed=10000;seconds={:.6};key_clones={}",
        started.elapsed().as_secs_f64(),
        KEY_CLONES.load(Ordering::Relaxed)
    );
    assert!(roots.entries.load().is_empty());
}
