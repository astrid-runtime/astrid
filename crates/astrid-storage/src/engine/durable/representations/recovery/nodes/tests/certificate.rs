use super::*;

#[test]
fn closed_graph_certifies_present_full_ids_without_journal_proof_allocations() {
    for bytes in [LocationIndexMemoryBudget::MIN_BYTES, 352, 65536, 1_048_576] {
        let map = map(31);
        let mut file = DurableFile::native(tempfile::tempfile().unwrap());
        let budget = LocationIndexMemoryBudget::new(NonZeroU64::new(bytes).unwrap()).unwrap();
        let mut admission =
            NodeAdmission::new(&file, RecoveryLimits::process_addressable(), budget).unwrap();
        for node in map.nodes().values() {
            append(&mut file, &mut admission, node);
        }
        let mut nodes = admission.finish().unwrap();
        nodes.reset_proofs().unwrap();
        nodes.certify_closures().unwrap();
        assert!(nodes.certificate.is_some());
        for id in map.nodes().keys() {
            assert!(nodes.complete(id).unwrap());
        }
        let mut absent = *map.root().unwrap().as_bytes();
        absent[31] ^= 1;
        assert!(!nodes.complete(&PhysicalMapNodeId::new(absent)).unwrap());
        assert!(super::super::super::map_closure_complete(map.root(), &mut nodes).unwrap());
        assert_eq!(nodes.proofs.borrow().resident_capacity_bytes(), 0);
        nodes.reset_proofs().unwrap();
        assert!(nodes.certificate.is_none());
        assert!(!nodes.complete(&map.root().unwrap()).unwrap());
    }
}

#[test]
fn missing_child_discards_certificate_without_rejecting_a_complete_unrelated_root() {
    let broken = map(32);
    let valid = map(33);
    let missing = broken
        .nodes()
        .iter()
        .find_map(|(id, node)| {
            matches!(
                node,
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. }
            )
            .then_some(*id)
        })
        .unwrap();
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut admission = reader(&file);
    for (id, node) in broken.nodes().iter().chain(valid.nodes()) {
        if *id != missing {
            append(&mut file, &mut admission, node);
        }
    }
    let mut nodes = admission.finish().unwrap();
    nodes.reset_proofs().unwrap();
    nodes.certify_closures().unwrap();
    assert!(nodes.certificate.is_none());
    assert!(!super::super::super::map_closure_complete(broken.root(), &mut nodes).unwrap());
    assert!(super::super::super::map_closure_complete(valid.root(), &mut nodes).unwrap());
}

#[test]
fn certificate_cannot_survive_source_replacement_or_hide_new_run_damage() {
    let map = map(34);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut admission = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut admission, node);
    }
    let mut nodes = admission.finish().unwrap();
    nodes.certify_closures().unwrap();
    assert!(nodes.complete(&map.root().unwrap()).unwrap());
    nodes.locations.clear_proofs().unwrap();
    assert!(!nodes.has_matching_certificate());
    nodes.locations.truncate_test_run_without_epoch();
    assert!(nodes.complete(&map.root().unwrap()).is_err());
    assert!(nodes.node(map.root().unwrap()).is_err());
    assert!(nodes.reset_proofs().is_err());
    assert!(nodes.into_cold(&[&map]).is_err());
}

#[test]
fn certificate_build_freshly_authenticates_bodies_and_fences_failed_handoff() {
    use std::io::{Seek, SeekFrom, Write};
    let map = map(35);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut admission = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut admission, node);
    }
    let mut nodes = admission.finish().unwrap();
    file.seek(SeekFrom::Start(crate::engine::durable::FRAME_HEADER_LEN))
        .unwrap();
    file.write_all(&[0xff]).unwrap();
    assert!(nodes.certify_closures().is_err());
    assert!(nodes.certificate.is_none());
    assert!(nodes.complete(&map.root().unwrap()).is_err());
    assert!(nodes.node(map.root().unwrap()).is_err());
    assert!(nodes.into_cold(&[&map]).is_err());
}

#[test]
fn healthy_source_replacement_requires_a_new_graph_certificate() {
    let map = map(36);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut admission = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut admission, node);
    }
    let mut nodes = admission.finish().unwrap();
    nodes.certify_closures().unwrap();
    assert!(nodes.complete(&map.root().unwrap()).unwrap());
    nodes.locations.clear_proofs().unwrap();
    assert!(!nodes.complete(&map.root().unwrap()).unwrap());
    nodes.certify_closures().unwrap();
    assert!(nodes.complete(&map.root().unwrap()).unwrap());
}

#[test]
fn matching_certificate_cannot_hide_same_epoch_source_damage_before_lookup() {
    let map = map(37);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut admission = reader(&file);
    for node in map.nodes().values() {
        append(&mut file, &mut admission, node);
    }
    let mut nodes = admission.finish().unwrap();
    nodes.certify_closures().unwrap();
    assert!(nodes.has_matching_certificate());
    assert_eq!(nodes.page_memo.borrow().test_hit_miss(), (0, 0));
    nodes.locations.truncate_test_run_without_epoch();
    assert!(nodes.has_matching_certificate());
    assert!(nodes.complete(&map.root().unwrap()).is_err());
    assert!(nodes.complete(&map.root().unwrap()).is_err());
    assert!(nodes.reset_proofs().is_err());
    assert!(nodes.into_cold(&[&map]).is_err());
}
