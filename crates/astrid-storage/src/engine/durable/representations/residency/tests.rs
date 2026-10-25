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
    super::super::node_view::test_take_count_walks();
    let mut reopened = RepresentationStore::open_volume(
        &volume,
        limits,
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        super::super::node_view::test_take_count_walks(),
        0,
        "real volume recovery must reuse its validated active-closure counts"
    );
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

#[test]
fn residency_remeasurement_reuses_page_authentication_but_not_node_bodies() {
    use super::super::super::locations::test_take_page_auth_count;
    for damage_locator in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let volume: Arc<dyn AstridVolume> =
            HostedFileVolume::open(directory.path().join("memo.volume")).unwrap();
        let budget = super::super::LocationIndexMemoryBudget::new(
            std::num::NonZeroU64::new(super::super::LocationIndexMemoryBudget::MIN_BYTES).unwrap(),
        )
        .unwrap();
        let mut store = RepresentationStore::activate_volume(
            &volume,
            super::super::RecoveryLimits::process_addressable(),
            ObjectId::new([1; 32]),
            [],
            budget,
        )
        .unwrap();
        let direct = (0_u64..256)
            .map(|sequence| {
                let bytes = sequence.to_le_bytes();
                store
                    .describe_direct(
                        ObjectId::new(*blake3::hash(&bytes).as_bytes()),
                        &bytes,
                        ArenaLocation {
                            offset: sequence * 100,
                            payload_len: 8,
                            checksum: [3; 32],
                        },
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let update = store.append_direct_update(&direct).unwrap().unwrap();
        store.publish_direct_update(update).unwrap();
        test_take_page_auth_count();
        let expected = super::MapResidency::new(
            &store.profiles,
            &store.representations,
            &store.placement_entries,
            store.persisted_map_nodes.len(),
        )
        .unwrap();
        let uncached = test_take_page_auth_count();
        // Force only the disposable scheduling hints, leaving authority untouched.
        store.residency = super::MapResidency {
            profiles: 0,
            representations: 0,
            placements: 0,
            measured_history: 0,
        };
        store.reclaim_map_history().unwrap();
        let cached = test_take_page_auth_count();
        assert_eq!(store.residency.profiles, expected.profiles);
        assert_eq!(store.residency.representations, expected.representations);
        assert_eq!(store.residency.placements, expected.placements);
        assert_eq!(store.residency.measured_history, expected.measured_history);
        assert!(cached > 0, "must authenticate actual spilled pages");
        assert!(
            cached < uncached,
            "reuse ancestors during the count: {cached} vs {uncached}"
        );

        if damage_locator {
            store.persisted_map_nodes.truncate_test_run();
        } else {
            store.metadata.set_len(0).unwrap();
        }
        store.residency.measured_history = 0;
        store.residency.profiles = 0;
        store.residency.representations = 0;
        store.residency.placements = 0;
        assert!(store.reclaim_map_history().is_err());
    }
}

#[test]
fn recovered_residency_counts_only_active_nodes_without_another_map_walk() {
    use super::super::node_view::test_take_count_walks;
    use crate::storage_model::{CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapKey};
    use std::collections::BTreeMap;

    for dense in [false, true] {
        let mut arena = BTreeMap::new();
        let mut roots = [None; 3];
        let mut expected = [0; 3];
        for (index, domain) in [
            PhysicalMapDomain::Profile,
            PhysicalMapDomain::Representation,
            PhysicalMapDomain::Placement,
        ]
        .into_iter()
        .enumerate()
        {
            let entries = (0_u64..64)
                .map(|n| {
                    (
                        PhysicalMapKey::new(*blake3::hash(&n.to_le_bytes()).as_bytes()),
                        n.to_le_bytes().to_vec(),
                    )
                })
                .collect();
            let mut map = if dense {
                CanonicalPhysicalMap::build_dense(&super::Blake3PhysicalIdentity, domain, entries)
            } else {
                CanonicalPhysicalMap::build(&super::Blake3PhysicalIdentity, domain, entries)
            }
            .unwrap();
            roots[index] = map.root();
            expected[index] = map.nodes().len();
            // Retain a later root in the same arena: its nodes must not inflate
            // the original active root's residency baseline.
            map.insert(
                &super::Blake3PhysicalIdentity,
                PhysicalMapKey::new([255; 32]),
                vec![7; 4096],
            )
            .unwrap();
            arena.extend(map.nodes().iter().map(|(id, node)| (*id, node.clone())));
        }
        test_take_count_walks();
        let (residency, maps) = super::MapResidency::recover(roots, &arena, arena.len()).unwrap();
        assert_eq!(
            test_take_count_walks(),
            0,
            "canonical recovery already visited these nodes"
        );
        assert_eq!(
            [
                residency.profiles,
                residency.representations,
                residency.placements
            ],
            expected
        );
        assert_eq!(residency.measured_history, arena.len());
        for (map, count) in maps.iter().zip(expected) {
            assert_eq!(map.nodes().len(), count);
            assert_eq!(super::super::node_view::node_count(map).unwrap(), count);
        }
        assert_eq!(
            test_take_count_walks(),
            3,
            "the counter must detect the three intentional comparison walks"
        );
        let (empty, _) = super::MapResidency::recover([None; 3], &arena, arena.len()).unwrap();
        assert_eq!(empty.total(), 0);
    }
}
