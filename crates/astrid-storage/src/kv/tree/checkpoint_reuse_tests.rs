//! Sealed-leaf fence reuse regressions for System-owner KV checkpoints.
//!
//! Old left-pack rebuilds every later leaf after a middle delete. Fence reuse
//! must keep unaffected sealed metadata leaf `ObjectId`s and still coalesce when
//! survivors fit one page.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::*;
use crate::kv::{KvBatchMutation, KvEntryKey, KvMutationBatch, MAX_KV_BATCH_OPERATIONS};

const OWNER: &str = "alice";
const NAMESPACE: &str = "alice:capsule:build";
const SEED_ROWS: u32 = 4_096;
const SURVIVOR_KEYS: u32 = 32;

#[tokio::test]
async fn middle_delete_reuses_unaffected_sealed_leaf_pages() {
    let engine = Arc::new(MeasuringEngine::new());
    let store = TreeKvStore::<String, TestIdentity, Resolver, MeasuringEngine>::from_engine(
        Arc::clone(&engine),
        Resolver,
    );
    store
        .seed_sorted_for_test(OWNER.to_owned(), seed_entries(SEED_ROWS))
        .unwrap();

    let seeded = settled_admission_census(&engine).await;
    let seed_checkpoint_bytes = seeded.logical_wire_growth(&AdmissionCensus::default());
    let seed_tree = active_tree_root(&store);
    let seed_leaves = active_metadata_kv_leaf_ids(&engine, seed_tree);
    assert!(
        seed_leaves.len() >= 8,
        "fixture must seal multiple metadata leaves, got {}",
        seed_leaves.len()
    );
    let seed_snapshot = engine
        .inner
        .snapshot(&OWNER.to_owned())
        .unwrap()
        .expect("seeded principal snapshot");

    let middle = format!("{:08}", SEED_ROWS / 2);
    assert!(store.delete(NAMESPACE, &middle).await.unwrap());
    assert!(store.checkpoint_for_test(OWNER.to_owned()).unwrap());
    let after = settled_admission_census(&engine).await;

    for (id, record) in seed_snapshot.records() {
        assert_eq!(
            engine.inner.object(*id).as_ref(),
            Some(record),
            "seed history object {id:?} changed"
        );
    }

    let after_tree = active_tree_root(&store);
    let after_leaves = active_metadata_kv_leaf_ids(&engine, after_tree);
    let reused = seed_leaves
        .intersection(&after_leaves)
        .copied()
        .collect::<BTreeSet<_>>();
    let rewritten = seed_leaves.difference(&after_leaves).count();
    assert!(
        rewritten <= 2,
        "expected at most two sealed leaves rewritten after one middle delete; \
         seed={} after={} reused={} rewritten={rewritten}",
        seed_leaves.len(),
        after_leaves.len(),
        reused.len()
    );
    assert!(
        reused.len() + 2 >= seed_leaves.len(),
        "unaffected sealed leaf ObjectIds must remain reachable"
    );

    let growth = after.logical_wire_growth(&seeded);
    // Seed wire covers every sealed leaf/branch page. One-key fence reuse should
    // admit only the touched leaf window plus a short branch spine/commit path,
    // which stays well under 1/16 of that bulk seed admission.
    assert!(
        growth < seed_checkpoint_bytes / 16,
        "middle-delete checkpoint growth {growth} must stay << seed checkpoint \
         wire {seed_checkpoint_bytes} when sealed leaves are reused"
    );

    assert_eq!(store.get(NAMESPACE, &middle).await.unwrap(), None);
    for value in [
        0_u32,
        1,
        SEED_ROWS / 2 - 1,
        SEED_ROWS / 2 + 1,
        SEED_ROWS - 1,
    ] {
        let key = format!("{value:08}");
        assert_eq!(
            store.get(NAMESPACE, &key).await.unwrap(),
            Some(value.to_le_bytes().to_vec()),
            "remaining key {key}"
        );
    }
}

#[tokio::test]
async fn coalescing_checkpoint_collapses_sparse_survivors_to_one_leaf() {
    let engine = Arc::new(MeasuringEngine::new());
    let store = TreeKvStore::<String, TestIdentity, Resolver, MeasuringEngine>::from_engine(
        Arc::clone(&engine),
        Resolver,
    );
    store
        .seed_sorted_for_test(OWNER.to_owned(), seed_entries(SEED_ROWS))
        .unwrap();
    let _seeded = settled_admission_census(&engine).await;
    let seed_leaves = active_metadata_kv_leaf_ids(&engine, active_tree_root(&store));
    assert!(
        seed_leaves.len() >= 8,
        "coalesce fixture needs many sealed leaves, got {}",
        seed_leaves.len()
    );

    let survivors = (0..SURVIVOR_KEYS)
        .map(|index| index.strict_mul(SEED_ROWS / SURVIVOR_KEYS))
        .collect::<BTreeSet<_>>();
    let mut doomed = (0..SEED_ROWS)
        .filter(|value| !survivors.contains(value))
        .collect::<Vec<_>>();
    while !doomed.is_empty() {
        let take = doomed.len().min(MAX_KV_BATCH_OPERATIONS);
        let chunk = doomed.split_off(doomed.len().strict_sub(take));
        let mutations = chunk
            .into_iter()
            .map(|value| KvBatchMutation::Delete {
                key: KvEntryKey::new(NAMESPACE, format!("{value:08}")).unwrap(),
            })
            .collect::<Vec<_>>();
        let batch = KvMutationBatch::new(std::iter::empty(), mutations).unwrap();
        assert!(store.apply_batch(&batch).await.unwrap().applied);
    }

    assert!(store.checkpoint_for_test(OWNER.to_owned()).unwrap());
    let _after = settled_admission_census(&engine).await;
    let after_leaves = active_metadata_kv_leaf_ids(&engine, active_tree_root(&store));
    assert_eq!(
        after_leaves.len(),
        1,
        "32 tiny survivors must coalesce into one metadata leaf; got {}",
        after_leaves.len()
    );

    for value in survivors {
        let key = format!("{value:08}");
        assert_eq!(
            store.get(NAMESPACE, &key).await.unwrap(),
            Some(value.to_le_bytes().to_vec()),
            "survivor {key}"
        );
    }
    assert_eq!(
        store.get(NAMESPACE, "00000001").await.unwrap(),
        None,
        "retired non-survivor must stay absent"
    );
}

fn seed_entries(rows: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..rows)
        .map(|value| {
            (
                format!("{NAMESPACE}\0{value:08}").into_bytes(),
                value.to_le_bytes().to_vec(),
            )
        })
        .collect()
}

fn active_tree_root(
    store: &TreeKvStore<String, TestIdentity, Resolver, MeasuringEngine>,
) -> ObjectId {
    let _ = store.delta_depth_for_test(OWNER.to_owned()).unwrap();
    store
        .cached_checkpoint_for_test(&OWNER.to_owned())
        .1
        .expect("active checkpoint tree root")
}

fn active_metadata_kv_leaf_ids(engine: &MeasuringEngine, tree: ObjectId) -> BTreeSet<ObjectId> {
    let mut pending = vec![tree];
    let mut seen = BTreeSet::new();
    let mut leaves = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let record = engine
            .inner
            .object(id)
            .expect("active tree object must remain admitted");
        match (record.kind(), record.class()) {
            (ObjectKind::KvLeaf, ObjectClass::Metadata) => {
                leaves.insert(id);
            },
            (ObjectKind::KvBranch, ObjectClass::Metadata) => {
                for reference in record.references() {
                    if reference.kind() == ReferenceKind::Owns {
                        pending.push(reference.target());
                    }
                }
            },
            _ => panic!(
                "active KV tree walked unexpected object kind={:?} class={:?}",
                record.kind(),
                record.class()
            ),
        }
    }
    leaves
}
