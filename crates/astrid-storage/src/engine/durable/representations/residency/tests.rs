use super::super::{ArenaLocation, ObjectId, RepresentationStore};
use crate::volume::{AstridVolume, HostedFileVolume};
use std::sync::Arc;

#[test]
fn active_closure_recovery_still_rejects_invalid_identity_and_domain() {
    use crate::storage_model::{
        PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode, PhysicalMapNodeId,
    };
    use std::collections::BTreeMap;

    let id = PhysicalMapNodeId::new([7; 32]);
    let node = PhysicalMapNode::Page {
        domain: PhysicalMapDomain::Profile,
        entries: vec![(PhysicalMapKey::new([8; 32]), vec![9])],
    };
    let valid_id = node.identify(&super::Blake3PhysicalIdentity).unwrap();
    for (domain, stored_id) in [
        (PhysicalMapDomain::Profile, id),
        (PhysicalMapDomain::Placement, valid_id),
    ] {
        let arena = BTreeMap::from([(stored_id, node.clone())]);
        assert!(super::recover_active_map(domain, Some(stored_id), &arena).is_err());
    }
    assert!(
        super::recover_active_map(PhysicalMapDomain::Profile, Some(id), &BTreeMap::new(),).is_err()
    );
}

#[test]
fn published_updates_bound_resident_history_and_recover_every_entry() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("test.volume")).unwrap();
    let limits = super::super::RecoveryLimits::process_addressable();
    let mut store = RepresentationStore::activate_volume(
        &volume,
        limits,
        ObjectId::new([1; 32]),
        [],
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    let mut objects = Vec::new();
    let mut remeasured = false;
    let initial_measurement = store.residency.measured_history;
    let mut prior_persisted = store.persisted_map_nodes.len();
    for sequence in 0_u64..4096 {
        let bytes = sequence.to_le_bytes();
        let object = ObjectId::new(*blake3::hash(&bytes).as_bytes());
        let direct = store
            .describe_direct(
                object,
                &bytes,
                ArenaLocation {
                    offset: sequence * 100,
                    payload_len: 8,
                    checksum: [3; 32],
                },
            )
            .unwrap();
        let update = store.append_direct_update(&[direct]).unwrap().unwrap();
        store.publish_direct_update(update).unwrap();
        if store.residency.measured_history > initial_measurement {
            remeasured = true;
        }
        // Node values are fetched from existing metadata frames; the complete
        // physical-ID index retains only its finite shared staging workspace.
        assert!(store.persisted_map_nodes.staging_capacity_bytes() <= 1_048_576);
        assert!(store.persisted_map_nodes.len() > prior_persisted);
        prior_persisted = store.persisted_map_nodes.len();
        objects.push(object);
    }
    assert!(
        remeasured,
        "exercise active-closure remeasurement and subsequent writes"
    );
    let active = store.active;
    drop(store);
    let mut reopened = RepresentationStore::open_volume(
        &volume,
        limits,
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(reopened.active, active);
    for object in objects {
        assert!(reopened.contains_direct(object).unwrap());
    }
    reopened.checkpoint_volume(&volume, limits).unwrap();
    assert_eq!(reopened.active, active);
}

#[test]
fn dense_history_is_bounded_by_measured_reachable_nodes() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("dense.volume")).unwrap();
    let limits = super::super::RecoveryLimits::process_addressable();
    let mut store = RepresentationStore::activate_volume(
        &volume,
        limits,
        ObjectId::new([1; 32]),
        [],
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    let mut objects = Vec::new();
    for sequence in 0_u64..256 {
        let bytes = sequence.to_le_bytes();
        let object = ObjectId::new(*blake3::hash(&bytes).as_bytes());
        let direct = store
            .describe_direct(
                object,
                &bytes,
                ArenaLocation {
                    offset: sequence * 100,
                    payload_len: 8,
                    checksum: [3; 32],
                },
            )
            .unwrap();
        let update = store.append_direct_update(&[direct]).unwrap().unwrap();
        store.publish_direct_update(update).unwrap();
        let mut active_nodes = 0;
        for map in [
            &store.profiles,
            &store.representations,
            &store.placement_entries,
        ] {
            active_nodes += super::super::node_view::node_count(map).unwrap();
            assert!(store.persisted_map_nodes.staging_capacity_bytes() <= 1_048_576);
        }
        if store.persisted_map_nodes.len() > active_nodes * 2 {
            assert!(
                store.checkpoint_required(),
                "physical ID history must not wait for a binary-tree worst-case bound"
            );
        }
        objects.push(object);
    }
    assert!(store.checkpoint_required());
    let active = store.active;
    let persisted = store.persisted_map_nodes.len();
    store.checkpoint_volume(&volume, limits).unwrap();
    assert!(store.persisted_map_nodes.len() < persisted);
    assert_eq!(store.active, active);
    drop(store);
    let reopened = RepresentationStore::open_volume(
        &volume,
        limits,
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(reopened.active, active);
    for object in objects {
        assert!(reopened.contains_direct(object).unwrap());
    }
}
