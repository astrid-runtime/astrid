//! Canonical proof emission stays private on faults and encodes each node once.

use std::sync::Arc;

use super::super::{
    ArenaLocation, Blake3PhysicalIdentity, ObjectId, RepresentationStore, generation_name,
};
use super::adoption_tests::{SyncFailOnceVolume, next_generation_files, primed_volume};
use crate::storage_model::physical::{ProfileMap, RepresentationMap};
use crate::storage_model::{
    PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode, RepresentationCatalogueRoot,
    RepresentationState,
};
use crate::volume::{AstridVolume, VolumeRegion};

fn bind_tip(store: &mut RepresentationStore) {
    store.catalogue = RepresentationCatalogueRoot::new(
        store.catalogue.generation().strict_add(1),
        store.profiles.root(),
        store.profiles.entry_count(),
        store.representations.root(),
        store.representations.entry_count(),
    )
    .unwrap();
    store.state = RepresentationState::new(
        store.state.generation().strict_add(1),
        Some(store.active),
        store.catalogue.identify(&Blake3PhysicalIdentity),
        store.placements.identify(&Blake3PhysicalIdentity),
    )
    .unwrap();
    store.active = store.state.identify(&Blake3PhysicalIdentity);
}

#[test]
fn production_checkpoint_encoding_slope_is_one_per_node_and_cold_emit_is_unchanged() {
    let mut measurements = Vec::new();
    for dense in [false, true] {
        let (_directory, volume, mut store, limits) = primed_volume();
        let objects: Vec<_> = (2_u8..34)
            .map(|index| {
                store
                    .describe_direct(
                        ObjectId::new([index; 32]),
                        &[index; 8],
                        ArenaLocation {
                            offset: u64::from(index),
                            payload_len: 8,
                            checksum: [3; 32],
                        },
                    )
                    .unwrap()
            })
            .collect();
        store.rebase_all_direct(&objects).unwrap();
        let entries = super::super::recovery::active_entries(store.representations.as_canonical())
            .unwrap()
            .into_iter()
            .map(|(key, value)| (key, value.to_vec()))
            .collect();
        let (rebuilt, build_encodes) = PhysicalMapNode::count_encodings_during(|| {
            if dense {
                RepresentationMap::build_dense(entries)
            } else {
                RepresentationMap::build(entries)
            }
            .unwrap()
        });
        assert_eq!(
            build_encodes,
            rebuilt.nodes().len(),
            "ordinary creation still encodes once"
        );
        store.representations = rebuilt;
        bind_tip(&mut store);
        // Capture the actual live size before the production checkpoint flushes.
        let nodes = store
            .profiles
            .nodes()
            .len()
            .strict_add(store.representations.nodes().len())
            .strict_add(store.placement_entries.nodes().len());
        let (result, automatic) =
            PhysicalMapNode::count_encodings_during(|| store.checkpoint_volume(&volume, limits));
        result.unwrap();
        let (mut metadata, mut journal) = next_generation_files(&store, &volume);
        let (result, cold) = PhysicalMapNode::count_encodings_during(|| {
            store.emit_sealed_generation(&mut metadata, &mut journal)
        });
        result.unwrap();
        measurements.push((nodes, automatic, cold));
    }
    let [
        (binary_nodes, binary_auto, binary_cold),
        (radix_nodes, radix_auto, radix_cold),
    ] = measurements.as_slice()
    else {
        unreachable!()
    };
    assert!(
        binary_nodes > radix_nodes,
        "equal entries exercise distinct canonical node counts"
    );
    let difference = binary_nodes.strict_sub(*radix_nodes);
    assert_eq!(
        binary_auto.strict_sub(*radix_auto),
        difference,
        "a separate proof and emit pass would encode every extra node twice"
    );
    assert_eq!(
        binary_cold.strict_sub(*radix_cold),
        difference,
        "cold emission still has one node encoding pass"
    );
}

fn install_invalid_second_map(store: &mut RepresentationStore) {
    // A frame larger than the stream buffer forces actual private I/O in the
    // first map before the second map's live walk rejects a wrong-domain node.
    // Typed slots make cross-domain assignment unconstructible, so corrupt an
    // active representation node in place after legitimate birth.
    store.profiles = ProfileMap::build_dense(vec![(
        PhysicalMapKey::new([13; 32]),
        vec![1; super::super::super::format::TRANSFER_BUFFER_BYTES.strict_mul(2)],
    )])
    .unwrap();
    store.representations =
        RepresentationMap::build_dense(vec![(PhysicalMapKey::new([14; 32]), vec![2])]).unwrap();
    let (id, node) = store.representations.nodes().iter().next().unwrap();
    let id = *id;
    let mut forged = node.clone();
    match &mut forged {
        PhysicalMapNode::Leaf { domain, .. }
        | PhysicalMapNode::Branch { domain, .. }
        | PhysicalMapNode::Page { domain, .. }
        | PhysicalMapNode::Radix { domain, .. } => {
            *domain = PhysicalMapDomain::Placement;
        },
    }
    assert!(
        store
            .representations
            .replace_arena_node_for_fault(id, forged),
        "fault injection must replace the active node under test"
    );
    bind_tip(store);
}

#[test]
fn private_proof_failure_or_write_failure_leaves_old_authority_and_retry_cleans_up() {
    for fail_write in [false, true] {
        let (_directory, inner, mut store, limits) = primed_volume();
        let wrapper = Arc::new(SyncFailOnceVolume::new(Arc::clone(&inner)));
        let volume: Arc<dyn AstridVolume> = wrapper.clone();
        let generation = store.journal_generation;
        let active = store.active;
        let old_regions = volume.list_regions("representations/generations/").unwrap();
        let old_lengths: Vec<_> = old_regions
            .iter()
            .map(|region| volume.region_len(region).unwrap())
            .collect();
        let original = (
            store.profiles.clone(),
            store.representations.clone(),
            store.catalogue,
            store.state,
            store.active,
        );
        install_invalid_second_map(&mut store);
        let private_metadata = VolumeRegion::new(format!(
            "representations/generations/{}/metadata.arena",
            generation_name(generation + 1)
        ))
        .unwrap();
        wrapper.watch_metadata(private_metadata.clone(), fail_write);
        let error = store.checkpoint_volume(&volume, limits).unwrap_err();
        let message = format!("{error:?}");
        if fail_write {
            assert!(
                message.contains("injected private metadata write failure"),
                "{message}"
            );
        } else {
            assert!(message.contains("map domain mismatch"), "{message}");
            assert!(
                wrapper.private_written()
                    > u64::try_from(super::super::super::format::TRANSFER_BUFFER_BYTES).unwrap()
            );
        }
        assert_eq!(store.journal_generation, generation);
        let private_journal = VolumeRegion::new(format!(
            "representations/generations/{}/state.journal",
            generation_name(generation + 1)
        ))
        .unwrap();
        assert_eq!(volume.region_len(&private_journal).unwrap(), 0);
        for (region, length) in old_regions.iter().zip(old_lengths) {
            assert_eq!(volume.region_len(region).unwrap(), length);
        }
        let reopened = RepresentationStore::open_volume(&inner, limits)
            .unwrap()
            .unwrap();
        assert_eq!(reopened.journal_generation, generation);
        assert_eq!(reopened.active, active);
        assert_eq!(
            store.metadata.metadata().unwrap().len(),
            reopened.metadata.metadata().unwrap().len()
        );
        assert_eq!(
            store.journal.metadata().unwrap().len(),
            reopened.journal.metadata().unwrap().len()
        );
        drop(reopened);
        (
            store.profiles,
            store.representations,
            store.catalogue,
            store.state,
            store.active,
        ) = original;
        // The production retry removes failed private files, including a large
        // partial frame written while the previous proof was still incomplete.
        store.checkpoint_volume(&volume, limits).unwrap();
        assert_eq!(store.journal_generation, generation + 1);
        assert!(
            volume.region_len(&private_metadata).unwrap()
                < u64::try_from(super::super::super::format::TRANSFER_BUFFER_BYTES).unwrap()
        );
        let reopened = RepresentationStore::open_volume(&inner, limits)
            .unwrap()
            .unwrap();
        assert_eq!(reopened.active, active);
        assert_eq!(reopened.journal_generation, generation + 1);
    }
}

#[test]
fn automatic_checkpoint_skips_map_identify_rebuild_after_typed_birth() {
    use super::super::activation::visit_new_reachable_map_nodes;
    use std::collections::BTreeSet;

    let (_directory, volume, mut store, limits) = primed_volume();
    let mut live_nodes = 0usize;
    for map in [
        store.profiles.as_canonical(),
        store.representations.as_canonical(),
        store.placement_entries.as_canonical(),
    ] {
        live_nodes = live_nodes.strict_add(
            visit_new_reachable_map_nodes(
                map,
                &mut BTreeSet::new(),
                &mut BTreeSet::new(),
                &mut BTreeSet::new(),
                |_| Ok(()),
            )
            .unwrap(),
        );
    }
    assert!(live_nodes > 0);

    // Old prove_root_into / MetadataFrame::map_node seal minted one identify per
    // live node while encoding. encode_live_into must perform zero identifies;
    // cold prove_root still rebuilds/identifies the full tip.
    let (result, identifies) =
        PhysicalMapNode::count_identifies_during(|| store.checkpoint_volume(&volume, limits));
    result.unwrap();
    assert_eq!(
        identifies, 0,
        "automatic seal must not re-identify/rebuild authenticated live maps"
    );

    let (cold, cold_identifies) = PhysicalMapNode::count_identifies_during(|| {
        store
            .profiles
            .prove_root()
            .and_then(|_| store.representations.prove_root())
            .and_then(|_| store.placement_entries.prove_root())
    });
    cold.unwrap();
    assert_eq!(
        cold_identifies, live_nodes,
        "cold/independent proof must still identify every live node"
    );
}
