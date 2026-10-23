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
