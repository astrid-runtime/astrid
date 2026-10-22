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
        let resident = store.representations.nodes().len() + store.placement_entries.nodes().len();
        if resident < prior_nodes {
            assert!(store.complete_map_subtrees.is_empty());
            reclaimed = true;
        }
        // New path copies must still be persisted after proof-cache eviction.
        assert!(store.persisted_map_nodes.len() > prior_persisted);
        prior_nodes = resident;
        prior_persisted = store.persisted_map_nodes.len();
        for map in [&store.representations, &store.placement_entries] {
            // Every internal node has at least two children. At most 2n-1
            // nodes are active; the runtime amortizes collection at twice that.
            let maximum = map.entry_count().saturating_mul(2).saturating_sub(1) * 2;
            assert!(u64::try_from(map.nodes().len()).unwrap() <= maximum);
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
