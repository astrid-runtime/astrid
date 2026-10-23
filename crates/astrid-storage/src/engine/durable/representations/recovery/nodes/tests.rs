use super::*;
use crate::engine::durable::DurableIo;
use crate::engine::durable::representations::activation::CompleteNodes;
use crate::storage_model::{PhysicalMapDomain, PhysicalMapKey};
use std::num::NonZeroU64;

fn map(value: u8) -> CanonicalPhysicalMap {
    CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        (0_u32..32)
            .map(|n| {
                (
                    PhysicalMapKey::new(*blake3::hash(&n.to_be_bytes()).as_bytes()),
                    vec![value; 128],
                )
            })
            .collect(),
    )
    .unwrap()
}

fn reader(file: &DurableFile) -> RecoveredNodes {
    let budget = LocationIndexMemoryBudget::new(NonZeroU64::new(352).unwrap()).unwrap();
    RecoveredNodes::new(file, RecoveryLimits::process_addressable(), budget).unwrap()
}

fn append(file: &mut DurableFile, nodes: &mut RecoveredNodes, node: &PhysicalMapNode) {
    let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node).unwrap();
    let payload = frame.encode().unwrap();
    let location = crate::engine::durable::append_frame(file, METADATA_MAGIC, &payload).unwrap();
    nodes.admit(location.offset, &payload, &frame).unwrap();
}

#[test]
fn active_map_handoff_consolidates_runs_without_losing_nodes_or_trusting_journal_proofs() {
    let maps = [map(6), map(7), map(8)];
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut nodes = reader(&file);
    let mut expected = std::collections::BTreeMap::new();
    for node in maps[..2]
        .iter()
        .flat_map(|map| map.nodes().values())
        .chain(maps[2].nodes().values().take(1))
    {
        append(&mut file, &mut nodes, node);
        expected.insert(
            node.identify(&Blake3PhysicalIdentity).unwrap(),
            node.clone(),
        );
    }
    assert!(nodes.locations.test_spilled_run_count() > 1);
    nodes.begin_journal().unwrap();
    assert!(super::super::map_closure_complete(maps[0].root(), &mut nodes).unwrap());
    *nodes.page_memo.get_mut() = AuthenticatedPageMemo::default();
    let control = super::super::super::residency::recover_active_map(
        PhysicalMapDomain::Placement,
        maps[0].root(),
        &nodes,
    )
    .unwrap();
    let (control_hits, control_misses) = nodes.page_memo.borrow().test_hit_miss();
    nodes.prepare_active_maps().unwrap();
    assert_eq!(nodes.page_memo.borrow().test_hit_miss(), (0, 0));
    let recovered = super::super::super::residency::recover_active_map(
        PhysicalMapDomain::Placement,
        maps[0].root(),
        &nodes,
    )
    .unwrap();
    let (consolidated_hits, consolidated_misses) = nodes.page_memo.borrow().test_hit_miss();
    assert!(
        consolidated_misses > 0,
        "replacement pages must still be authenticated"
    );
    assert!(
        consolidated_hits + consolidated_misses < control_hits + control_misses,
        "consolidation removes cross-run page probes, even when tiny runs fit one page"
    );
    assert_eq!(recovered.root(), control.root());
    assert_eq!(recovered.nodes(), control.nodes());
    assert_eq!(nodes.locations.test_spilled_run_count(), 1);
    assert_eq!(nodes.len(), expected.len());
    assert!(nodes.resident_capacity_bytes() <= 352);
    for (id, node) in &expected {
        assert_eq!(nodes.node(*id).unwrap().unwrap().as_ref(), node);
        assert!(!nodes.complete(id).unwrap());
    }
    assert!(super::super::map_closure_complete(maps[0].root(), &mut nodes).unwrap());
    assert!(nodes.complete(&maps[0].root().unwrap()).unwrap());
    nodes.begin_journal().unwrap();
    assert_eq!(nodes.locations.test_spilled_run_count(), 1);
    assert_eq!(nodes.page_memo.borrow().test_hit_miss(), (0, 0));
    for id in expected.keys() {
        assert!(!nodes.complete(id).unwrap());
    }
}

#[test]
fn active_map_handoff_rejects_damaged_runs_even_with_a_warm_memo() {
    let map = map(9);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut nodes = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut nodes, node);
    }
    assert!(nodes.node(map.root().unwrap()).unwrap().is_some());
    nodes.locations.truncate_test_run();
    assert!(nodes.prepare_active_maps().is_err());
    assert!(nodes.locations.failed());
    assert!(nodes.prepare_active_maps().is_err());
}

#[test]
fn paged_reachability_never_memoizes_missing_descendants_or_promotes_historical_proofs() {
    let active = map(1);
    let historical = map(2);
    let root = historical.root().unwrap();
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut nodes = reader(&file);
    nodes.begin_journal().unwrap();
    append(&mut file, &mut nodes, &historical.nodes()[&root]);
    assert!(!super::super::map_closure_complete(Some(root), &mut nodes).unwrap());
    assert!(!nodes.complete(&root).unwrap());
    for (id, node) in historical.nodes() {
        if *id != root {
            append(&mut file, &mut nodes, node);
        }
    }
    for node in active.nodes().values() {
        append(&mut file, &mut nodes, node);
    }
    assert!(super::super::map_closure_complete(Some(root), &mut nodes).unwrap());
    for id in historical.nodes().keys() {
        assert!(nodes.complete(id).unwrap());
    }
    assert!(nodes.resident_capacity_bytes() <= 352);
    // Reuse within this replay may skip authenticated immutable subtrees.
    assert!(super::super::map_closure_complete(Some(root), &mut nodes).unwrap());
    let cold = nodes.into_cold(&[&active]).unwrap();
    for id in historical.nodes().keys() {
        assert!(!cold.complete(id).unwrap());
    }
    for id in active.nodes().keys() {
        assert!(cold.complete(id).unwrap());
    }
}

#[test]
fn failed_media_reads_do_not_publish_reachability_proofs() {
    let map = map(3);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut nodes = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut nodes, node);
    }
    nodes.begin_journal().unwrap();
    file.durable_set_len(0).unwrap();
    assert!(super::super::map_closure_complete(map.root(), &mut nodes).is_err());
    for id in map.nodes().keys() {
        assert!(!nodes.complete(id).unwrap());
    }
}

#[test]
fn reachability_proof_write_failure_is_an_error_and_fences_replay() {
    let map = map(4);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut nodes = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut nodes, node);
    }
    nodes.begin_journal().unwrap();
    nodes.locations.damage_run_after_inserts(0);
    assert!(super::super::map_closure_complete(map.root(), &mut nodes).is_err());
    assert!(nodes.locations.failed());
    assert!(nodes.begin_journal().is_err());
}

#[test]
fn recovery_reuses_locator_page_evidence_but_always_authenticates_node_media() {
    let map = map(5);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut nodes = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut nodes, node);
    }
    nodes.begin_journal().unwrap();
    let id = map.root().unwrap();
    assert!(nodes.node(id).unwrap().is_some());
    let first = nodes.page_memo.borrow().test_hit_miss();
    assert!(first.1 > 0);
    assert!(nodes.node(id).unwrap().is_some());
    let second = nodes.page_memo.borrow().test_hit_miss();
    assert!(second.0 > first.0);
    assert_eq!(
        second.1, first.1,
        "unchanged immutable pages need no repeat authentication"
    );
    file.durable_set_len(0).unwrap();
    assert!(
        nodes.node(id).is_err(),
        "page evidence must never cache the canonical body"
    );
    nodes.begin_journal().unwrap();
    assert_eq!(nodes.page_memo.borrow().test_hit_miss(), (0, 0));
}
