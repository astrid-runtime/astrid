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

fn reader(file: &DurableFile) -> NodeAdmission {
    let budget = LocationIndexMemoryBudget::new(NonZeroU64::new(352).unwrap()).unwrap();
    NodeAdmission::new(file, RecoveryLimits::process_addressable(), budget).unwrap()
}

fn fragment(nodes: &mut RecoveredNodes) {
    use crate::engine::durable::locations::LocationLookup;
    let mut locations = PagedLocations::new(nodes.budget.durable_entries());
    for row in nodes.locations.locations() {
        let (id, location) = row.unwrap();
        locations.insert(id, location).unwrap();
    }
    nodes.locations = locations;
    *nodes.page_memo.get_mut() = AuthenticatedPageMemo::default();
}

fn append(file: &mut DurableFile, nodes: &mut NodeAdmission, node: &PhysicalMapNode) {
    let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node).unwrap();
    let payload = frame.encode().unwrap();
    let location = crate::engine::durable::append_frame(file, METADATA_MAGIC, &payload).unwrap();
    nodes.admit(location.offset, &payload, &frame).unwrap();
}

#[test]
fn journal_admission_consolidates_runs_preserving_historical_nodes() {
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
    let mut nodes = nodes.finish().unwrap();
    // Exercise the journal boundary with a deliberately fragmented, validated
    // locator as well as the consolidated result returned by admission.
    fragment(&mut nodes);
    assert!(nodes.locations.test_spilled_run_count() > 1);
    nodes.reset_proofs().unwrap();
    assert_eq!(nodes.locations.test_spilled_run_count(), 1);
    assert_eq!(nodes.len(), expected.len());
    assert!(nodes.resident_capacity_bytes() <= 352);
    for (id, node) in &expected {
        assert_eq!(nodes.node(*id).unwrap().unwrap().as_ref(), node);
        assert!(!nodes.complete(id).unwrap());
    }
    assert!(super::super::map_closure_complete(maps[0].root(), &mut nodes).unwrap());
    assert!(nodes.complete(&maps[0].root().unwrap()).unwrap());
    nodes.reset_proofs().unwrap();
    assert_eq!(nodes.locations.test_spilled_run_count(), 1);
    assert_eq!(nodes.page_memo.borrow().test_hit_miss(), (0, 0));
    for id in expected.keys() {
        assert!(!nodes.complete(id).unwrap());
    }
}

#[test]
fn journal_admission_rejects_damaged_runs_even_with_a_warm_memo() {
    let map = map(9);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut nodes = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut nodes, node);
    }
    let mut nodes = nodes.finish().unwrap();
    assert!(nodes.node(map.root().unwrap()).unwrap().is_some());
    nodes.locations.truncate_test_run();
    assert!(nodes.reset_proofs().is_err());
    assert!(nodes.locations.failed());
    assert!(nodes.reset_proofs().is_err());
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
    let mut nodes = nodes.finish().unwrap();
    // Exercise the journal boundary with a deliberately fragmented, validated
    // locator as well as the consolidated result returned by admission.
    fragment(&mut nodes);
    assert!(nodes.locations.test_spilled_run_count() > 1);
    nodes.reset_proofs().unwrap();
    assert!(super::super::map_closure_complete(maps[0].root(), &mut nodes).unwrap());
    *nodes.page_memo.get_mut() = AuthenticatedPageMemo::default();
    let control = super::super::super::residency::recover_active_map(
        PhysicalMapDomain::Placement,
        maps[0].root(),
        &nodes,
    )
    .unwrap();
    let (control_hits, control_misses) = nodes.page_memo.borrow().test_hit_miss();
    nodes.reset_proofs().unwrap();
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
    nodes.reset_proofs().unwrap();
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
    let mut nodes = nodes.finish().unwrap();
    assert!(nodes.node(map.root().unwrap()).unwrap().is_some());
    nodes.locations.truncate_test_run();
    assert!(nodes.reset_proofs().is_err());
    assert!(nodes.locations.failed());
    assert!(nodes.reset_proofs().is_err());
}

#[test]
fn paged_reachability_never_memoizes_missing_descendants_or_promotes_historical_proofs() {
    let active = map(1);
    let historical = map(2);
    let root = historical.root().unwrap();
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut nodes = reader(&file);
    append(&mut file, &mut nodes, &historical.nodes()[&root]);
    let mut partial = nodes.finish().unwrap();
    partial.reset_proofs().unwrap();
    assert!(!super::super::map_closure_complete(Some(root), &mut partial).unwrap());
    assert!(!partial.complete(&root).unwrap());
    let mut nodes = reader(&file);
    append(&mut file, &mut nodes, &historical.nodes()[&root]);
    for (id, node) in historical.nodes() {
        if *id != root {
            append(&mut file, &mut nodes, node);
        }
    }
    for node in active.nodes().values() {
        append(&mut file, &mut nodes, node);
    }
    let mut nodes = nodes.finish().unwrap();
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
    let mut nodes = nodes.finish().unwrap();
    nodes.reset_proofs().unwrap();
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
    let mut nodes = nodes.finish().unwrap();
    nodes.reset_proofs().unwrap();
    nodes.locations.damage_run_after_inserts(0);
    assert!(super::super::map_closure_complete(map.root(), &mut nodes).is_err());
    assert!(nodes.locations.failed());
    assert!(nodes.reset_proofs().is_err());
}

#[test]
fn recovery_reuses_locator_page_evidence_but_always_authenticates_node_media() {
    let map = map(5);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut nodes = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut nodes, node);
    }
    let mut nodes = nodes.finish().unwrap();
    nodes.reset_proofs().unwrap();
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
    nodes.reset_proofs().unwrap();
    assert_eq!(nodes.page_memo.borrow().test_hit_miss(), (0, 0));
}

#[test]
fn sorted_admission_never_hides_corrupted_superseded_node_media() {
    use std::io::{Seek, SeekFrom, Write};
    for resident_budget in [352, 65536] {
        let map = map(10);
        let root = map.root().unwrap();
        let mut file = DurableFile::native(tempfile::tempfile().unwrap());
        let budget =
            LocationIndexMemoryBudget::new(NonZeroU64::new(resident_budget).unwrap()).unwrap();
        let mut admission =
            NodeAdmission::new(&file, RecoveryLimits::process_addressable(), budget).unwrap();
        let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &map.nodes()[&root]).unwrap();
        let payload = frame.encode().unwrap();
        let first =
            crate::engine::durable::append_frame(&mut file, METADATA_MAGIC, &payload).unwrap();
        admission.admit(first.offset, &payload, &frame).unwrap();
        for (id, node) in map.nodes() {
            if *id != root {
                append(&mut file, &mut admission, node);
            }
        }
        let second =
            crate::engine::durable::append_frame(&mut file, METADATA_MAGIC, &payload).unwrap();
        file.seek(SeekFrom::Start(
            first.offset + crate::engine::durable::FRAME_HEADER_LEN,
        ))
        .unwrap();
        file.write_all(&[payload[0] ^ 0x80]).unwrap();
        if admission.admit(second.offset, &payload, &frame).is_err() {
            assert!(admission.finish().is_err());
        } else {
            assert!(
                admission.finish().is_err(),
                "final merge must authenticate a superseded spilled location"
            );
        }
    }
}

#[test]
fn positive_closure_memo_reuses_only_successful_queries_until_run_replacement() {
    let map = map(11);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut admission = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut admission, node);
    }
    let mut nodes = admission.finish().unwrap();
    let id = map.root().unwrap();
    assert!(
        nodes
            .resident_capacity_bytes()
            .strict_add(nodes.complete_memo.borrow().capacity_bytes())
            <= usize::try_from(nodes.budget.bytes().get()).unwrap() / 2
    );
    assert!(!nodes.complete(&id).unwrap());
    assert!(!nodes.complete_memo.borrow().contains(id));
    assert!(super::super::map_closure_complete(Some(id), &mut nodes).unwrap());
    // remember() alone never populates the hot-query memo with every new node.
    assert!(!nodes.complete_memo.borrow().contains(id));
    assert!(nodes.complete(&id).unwrap());
    assert!(nodes.complete_memo.borrow().contains(id));
    *nodes.page_memo.get_mut() = AuthenticatedPageMemo::default();
    assert!(nodes.complete(&id).unwrap());
    assert_eq!(
        nodes.page_memo.borrow().test_hit_miss(),
        (0, 0),
        "a successful repeated closure query needs no random page walk"
    );
    nodes.locations.truncate_test_run();
    assert!(
        nodes.complete(&id).is_err(),
        "a changed run must be authenticated again"
    );
    assert!(nodes.locations.failed());
    assert!(!nodes.complete_memo.borrow().contains(id));
    // Even an independently warm slot must never bypass the failure fence.
    nodes.complete_memo.get_mut().insert(id);
    assert!(
        nodes.complete(&id).is_err(),
        "the failure fence must win over any memo"
    );
}

#[test]
fn positive_closure_memo_reset_and_failure_never_leave_sticky_true() {
    let map = map(12);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut admission = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut admission, node);
    }
    let mut nodes = admission.finish().unwrap();
    let id = map.root().unwrap();
    assert!(super::super::map_closure_complete(Some(id), &mut nodes).unwrap());
    assert!(nodes.complete(&id).unwrap());
    nodes.reset_proofs().unwrap();
    assert!(!nodes.complete_memo.borrow().contains(id));
    assert!(!nodes.complete(&id).unwrap());
    let missing = PhysicalMapNodeId::new([0xf1; 32]);
    assert!(!nodes.complete(&missing).unwrap());
    assert!(!nodes.complete_memo.borrow().contains(missing));
    assert!(super::super::map_closure_complete(Some(id), &mut nodes).unwrap());
    assert!(nodes.complete(&id).unwrap());
    nodes.locations.truncate_test_run();
    assert!(nodes.reset_proofs().is_err());
    assert!(!nodes.complete_memo.borrow().contains(id));
    assert!(nodes.complete(&id).is_err());
}

#[test]
fn positive_closure_memo_is_bounded_and_full_identity_checked() {
    for bytes in [LocationIndexMemoryBudget::MIN_BYTES, 352, 65536, 1_048_576] {
        let budget = LocationIndexMemoryBudget::new(NonZeroU64::new(bytes).unwrap()).unwrap();
        let mut memo = CompleteMemo::new(budget).unwrap();
        let capacity = memo.capacity_bytes();
        assert!(u64::try_from(capacity).unwrap() <= bytes / 4);
        let first = PhysicalMapNodeId::new([1; 32]);
        memo.insert(first);
        if capacity == 0 {
            assert!(!memo.contains(first));
            continue;
        }
        assert!(memo.contains(first));
        let mut colliding = [1; 32];
        colliding[31] = 2; // Same native-word slot, distinct complete identity.
        let colliding = PhysicalMapNodeId::new(colliding);
        assert!(!memo.contains(colliding));
        memo.insert(colliding);
        assert!(memo.contains(colliding));
        assert!(!memo.contains(first));
        for n in 0_u32..10_000 {
            memo.insert(PhysicalMapNodeId::new(
                *blake3::hash(&n.to_be_bytes()).as_bytes(),
            ));
        }
        assert_eq!(memo.capacity_bytes(), capacity);
        memo.sync(1);
        assert!(!memo.contains(colliding));
    }
}
