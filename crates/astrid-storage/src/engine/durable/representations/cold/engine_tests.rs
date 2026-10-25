//! Exercise actual operator policy and recovery fences through the full engine.

use super::*;
use crate::engine::durable::tests::{TestIdentity, Utf8Codec, limits};
use crate::engine::durable::{DurableEngine, DurableEnginePolicy, EngineOpenOptions, NoFaults};
use crate::engine::{GroupCommitPolicy, ObjectCacheConfig, RecoveryRetryPolicy};
use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectKind, ObjectRecord, PhysicalMapDomain, PhysicalMapKey,
};
use std::num::NonZeroU64;

fn open(
    path: &std::path::Path,
    budget: LocationIndexMemoryBudget,
) -> DurableEngine<String, TestIdentity, Utf8Codec> {
    DurableEngine::open_with_options(
        path,
        TestIdentity,
        Utf8Codec,
        limits(),
        EngineOpenOptions {
            policy: DurableEnginePolicy::new(
                GroupCommitPolicy::default(),
                RecoveryRetryPolicy::immediate(),
                ObjectCacheConfig::disabled(),
            )
            .with_location_index_memory(budget),
            faults: Arc::new(NoFaults),
        },
    )
    .unwrap()
}

fn assert_shared_budget(
    engine: &DurableEngine<String, TestIdentity, Utf8Codec>,
    budget: LocationIndexMemoryBudget,
) {
    let inner = engine.inner.lock();
    let nodes = &inner.representations.as_ref().unwrap().persisted_map_nodes;
    assert_eq!(nodes.budget(), budget);
    let resident = inner
        .index
        .resident_capacity_bytes()
        .strict_add(nodes.staging_capacity_bytes());
    assert!(
        resident as u64 <= budget.bytes().get(),
        "shared locator staging used {resident} bytes"
    );
}

fn staged_node(byte: u8) -> PhysicalMapNode {
    PhysicalMapNode::leaf(
        PhysicalMapDomain::Representation,
        PhysicalMapKey::new([byte; 32]),
        vec![byte],
    )
}

#[test]
fn operator_budget_controls_all_locators_and_cold_scratch_failure_recovers_exact_state() {
    let directory = tempfile::tempdir().unwrap();
    let budget = LocationIndexMemoryBudget::new(
        NonZeroU64::new(LocationIndexMemoryBudget::MIN_BYTES.strict_mul(24)).unwrap(),
    )
    .unwrap();
    let engine = open(directory.path(), budget);
    let mut objects = Vec::new();
    for number in 0..64_u64 {
        let record = ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            number.to_le_bytes().to_vec(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let (id, _) = engine.persist_standalone_object(&record).unwrap();
        objects.push((id, record));
    }
    engine
        .ensure_direct_representation_catalogue(objects[0].0, &[objects[0].0])
        .unwrap();
    let mut nodes = engine
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .persisted_map_nodes
        .clone();
    for byte in 1..32 {
        let node = staged_node(byte);
        nodes
            .put(node.identify(&Blake3PhysicalIdentity).unwrap(), node)
            .unwrap();
    }
    assert!(nodes.0.lock().staged.is_some());
    assert_shared_budget(&engine, budget);
    let smaller = LocationIndexMemoryBudget::new(
        NonZeroU64::new(LocationIndexMemoryBudget::MIN_BYTES.strict_mul(6)).unwrap(),
    )
    .unwrap();
    engine.set_location_index_memory(smaller).unwrap();
    assert_shared_budget(&engine, smaller);
    for byte in 1..32 {
        let node = staged_node(byte);
        assert_eq!(
            nodes
                .node(node.identify(&Blake3PhysicalIdentity).unwrap())
                .unwrap()
                .unwrap()
                .as_ref(),
            &node
        );
    }
    // Unpublished scratch nodes are not persisted and confer no authority.
    nodes.finish_staging();
    engine.close().unwrap();
    drop(engine);
    let engine = open(directory.path(), smaller);
    assert_shared_budget(&engine, smaller);
    {
        let inner = engine.inner.lock();
        let store = inner.representations.as_ref().unwrap();
        store
            .persisted_map_nodes
            .0
            .lock()
            .locations
            .truncate_test_run();
        assert!(
            objects
                .iter()
                .any(|(id, _)| store.contains_direct(*id).is_err())
        );
    }
    assert!(engine.recover_if_required().unwrap());
    assert!(!engine.recover_if_required().unwrap());
    assert_shared_budget(&engine, smaller);
    let specification = objects[0].0;
    for (id, record) in objects {
        assert_eq!(engine.object(id).unwrap(), Some(record));
        if id != specification {
            assert!(
                engine
                    .inner
                    .lock()
                    .representations
                    .as_ref()
                    .unwrap()
                    .contains_direct(id)
                    .unwrap()
            );
        }
    }
}
