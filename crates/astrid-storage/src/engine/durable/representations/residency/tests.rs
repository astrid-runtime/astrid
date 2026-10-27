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
        let mut arena = BTreeMap::from([(stored_id, node.clone())]);
        assert!(super::recover_active_map(domain, Some(stored_id), &mut arena).is_err());
    }
    assert!(
        super::recover_active_map(PhysicalMapDomain::Profile, Some(id), &mut BTreeMap::new(),)
            .is_err()
    );
}

#[test]
fn published_updates_bound_resident_history_and_recover_every_entry() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("test.volume")).unwrap();
    let limits = super::super::RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    let mut objects = Vec::new();
    let mut reclaimed = false;
    let mut prior_nodes = 0;
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
        let resident = store.representations.nodes().len() + store.placement_entries.nodes().len();
        if resident < prior_nodes {
            assert!(store.complete_map_subtrees.is_empty());
            reclaimed = true;
        }
        // Append memos must not retain IDs whose runtime nodes were evicted.
        let all_resident = resident + store.profiles.nodes().len();
        assert!(store.persisted_map_nodes.len() <= all_resident);
        prior_nodes = resident;
        for (map, baseline) in [
            (&store.profiles, store.residency.profiles),
            (&store.representations, store.residency.representations),
            (&store.placement_entries, store.residency.placements),
        ] {
            assert!(map.nodes().len() <= baseline.saturating_mul(2));
        }
        objects.push(object);
    }
    assert!(reclaimed, "exercise proof eviction and subsequent writes");
    let active = store.active;
    drop(store);
    let mut reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.active, active);
    for object in objects {
        assert!(reopened.contains_direct(object));
    }
    reopened.checkpoint_volume(&volume, limits).unwrap();
    assert_eq!(reopened.active, active);
}

#[test]
fn recovery_retains_only_active_physical_id_memos_without_changing_durable_history() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("ids.volume")).unwrap();
    let limits = super::super::RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    for sequence in 0_u64..128 {
        let bytes = sequence.to_le_bytes();
        let direct = store
            .describe_direct(
                ObjectId::new(*blake3::hash(&bytes).as_bytes()),
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
    }
    let active = store.active;
    let metadata_bytes = store.metadata.metadata().unwrap().len();
    drop(store);
    let reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.active, active);
    assert_eq!(reopened.metadata.metadata().unwrap().len(), metadata_bytes);
    let resident = reopened.profiles.nodes().len()
        + reopened.representations.nodes().len()
        + reopened.placement_entries.nodes().len();
    assert_eq!(
        reopened.persisted_map_nodes.len(),
        resident,
        "historical durable IDs must not remain in the live append memo"
    );
    for sequence in 0_u64..128 {
        assert!(reopened.contains_direct(ObjectId::new(
            *blake3::hash(&sequence.to_le_bytes()).as_bytes()
        )));
    }
}

#[test]
fn append_reintroduces_evicted_nodes_and_reopen_authenticates_duplicate_frames() {
    use super::super::super::scan_frames;
    use super::super::format::{METADATA_FILE, METADATA_MAGIC, MetadataFrame, MetadataKind};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("reintroduced.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let limits = super::super::RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    let object = ObjectId::new([7; 32]);
    let direct = store
        .describe_direct(
            object,
            &[42; 8],
            ArenaLocation {
                offset: 100,
                payload_len: 8,
                checksum: [3; 32],
            },
        )
        .unwrap();
    let pending = store
        .append_direct_update(std::slice::from_ref(&direct))
        .unwrap()
        .unwrap();
    store.publish_direct_update(pending).unwrap();
    let id = store.representations.root().unwrap();
    let placement = store.placement_entries.root();
    store.rebase_all_direct(&[]).unwrap();
    assert!(!store.persisted_map_nodes.contains(&id));
    assert!(!store.representations.nodes().contains_key(&id));
    assert!(!store.contains_direct(object));
    let pending = store.append_direct_update(&[direct]).unwrap().unwrap();
    assert_eq!(store.representations.root(), Some(id));
    assert_eq!(store.placement_entries.root(), placement);
    let mut copies = 0;
    scan_frames(
        &mut store.metadata,
        METADATA_FILE,
        METADATA_MAGIC,
        limits,
        |_, payload| {
            let frame = MetadataFrame::decode(payload)?;
            if frame.kind == MetadataKind::MapNode && frame.identity == *id.as_bytes() {
                copies += 1;
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        copies, 2,
        "append must persist the reintroduced canonical node"
    );
    store.publish_direct_update(pending).unwrap();
    let active = store.active;
    drop(store);
    volume.sync().unwrap();
    std::fs::copy(&path, directory.path().join("independent.volume")).unwrap();
    let independent: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("independent.volume")).unwrap();
    let reopened = RepresentationStore::open_volume(&independent, limits)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.active, active);
    assert!(reopened.contains_direct(object));
    assert_eq!(reopened.representations.root(), Some(id));
    assert_eq!(reopened.placement_entries.root(), placement);
}

#[test]
fn unpublished_append_is_not_authority_and_equal_retry_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("unpublished.volume")).unwrap();
    let limits = super::super::RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    let object = ObjectId::new([7; 32]);
    let direct = store
        .describe_direct(
            object,
            &[42; 8],
            ArenaLocation {
                offset: 100,
                payload_len: 8,
                checksum: [3; 32],
            },
        )
        .unwrap();
    let active = store.active;
    let pending = store
        .append_direct_update(std::slice::from_ref(&direct))
        .unwrap()
        .unwrap();
    let root = store.representations.root();
    drop(pending);
    store.flush_metadata().unwrap();
    volume.sync().unwrap();
    assert_eq!(store.active, active);
    assert!(!store.contains_direct(object));
    drop(store);
    let mut reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.active, active);
    assert!(!reopened.contains_direct(object));
    let pending = reopened.append_direct_update(&[direct]).unwrap().unwrap();
    assert_eq!(reopened.representations.root(), root);
    reopened.publish_direct_update(pending).unwrap();
    let published = reopened.active;
    drop(reopened);
    let reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.active, published);
    assert_ne!(published, active);
    assert!(reopened.contains_direct(object));
}

#[test]
fn shared_arena_second_map_does_not_accept_a_stolen_node() {
    use crate::storage_model::{PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode};
    use std::collections::BTreeMap;

    let node = PhysicalMapNode::Page {
        domain: PhysicalMapDomain::Profile,
        entries: vec![(PhysicalMapKey::new([8; 32]), vec![9])],
    };
    let id = node.identify(&super::Blake3PhysicalIdentity).unwrap();
    let mut arena = BTreeMap::from([(id, node)]);
    let recovered =
        super::recover_active_map(PhysicalMapDomain::Profile, Some(id), &mut arena).unwrap();
    assert_eq!(recovered.root(), Some(id));
    assert!(
        arena.is_empty(),
        "first recover must consume the shared node"
    );
    let error = super::recover_active_map(PhysicalMapDomain::Representation, Some(id), &mut arena)
        .unwrap_err();
    match error {
        super::DurableError::InvalidRepresentationState(detail) => {
            assert_eq!(detail, "active physical map closure is incomplete");
        },
        other => panic!("expected incomplete closure, got {other:?}"),
    }
    assert!(
        arena.is_empty(),
        "leftover arena must not become the second map"
    );
}

#[test]
fn later_map_reclaim_failure_clears_complete_proofs_after_earlier_shrink() {
    use crate::storage_model::PhysicalMapNodeId;

    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("partial-reclaim.volume")).unwrap();
    let limits = super::super::RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    for sequence in 0_u64..8 {
        let bytes = sequence.to_le_bytes();
        let direct = store
            .describe_direct(
                ObjectId::new(*blake3::hash(&bytes).as_bytes()),
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
    }
    let before_representations = store.representations.nodes().len();
    assert!(
        before_representations > 1,
        "insert must retain historical representation nodes"
    );
    store
        .complete_map_subtrees
        .insert(PhysicalMapNodeId::new([0x11; 32]));
    store.residency.representations = 0;
    store.residency.placements = 0;
    assert!(
        !store.placement_entries.nodes().is_empty(),
        "later map must have nodes so reclaim runs after the earlier shrink"
    );
    store
        .placement_entries
        .corrupt_root_for_reclaim_fault(PhysicalMapNodeId::new([0x71; 32]));
    assert!(store.reclaim_map_history().is_err());
    assert!(
        store.representations.nodes().len() < before_representations,
        "earlier map must shrink before the later map fails"
    );
    assert!(store.complete_map_subtrees.is_empty());
}
