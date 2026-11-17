//! Observing destination evidence must not introduce another update grammar.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use super::super::{
    DurableFile, ObjectId, RecoveryLimits, RepresentationStore, append_authenticated_map_nodes,
};
use super::*;
use crate::storage_model::physical::AuthenticatedPhysicalMap;
use crate::volume::{AstridVolume, HostedFileVolume};

pub(super) fn empty_store(volume: &Arc<dyn AstridVolume>) -> RepresentationStore {
    RepresentationStore::activate_volume(
        volume,
        RecoveryLimits::process_addressable(),
        ObjectId::new([1; 32]),
        [],
    )
    .unwrap()
}

fn bytes(file: &mut DurableFile) -> Vec<u8> {
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn direct_publication_reuses_authenticated_node_identities() {
    use crate::storage_model::PhysicalMapNode;

    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("direct.volume")).unwrap();
    let mut store = empty_store(&volume);
    let direct = store
        .describe_direct(
            ObjectId::new([42; 32]),
            &[42; 16],
            ArenaLocation {
                offset: 42,
                payload_len: 16,
                checksum: [42; 32],
            },
        )
        .unwrap();
    let ((result, encodings), identifies) = PhysicalMapNode::count_identifies_during(|| {
        PhysicalMapNode::count_encodings_during(|| store.append_direct_update_observed(&[direct]))
    });
    let (update, evidence) = result.unwrap().unwrap();
    assert!(!evidence.appended_map_nodes.is_empty());
    assert!(evidence.appended_map_nodes.iter().all(|id| {
        store.complete_map_subtrees.contains(id) && !store.persisted_map_nodes.contains(id)
    }));
    let mut extra_frames = Vec::new();
    let mut appended = BTreeSet::new();
    for map in [
        &store.representations as &dyn AuthenticatedPhysicalMap,
        &store.placement_entries,
    ] {
        assert_eq!(
            append_authenticated_map_nodes(
                &mut extra_frames,
                map,
                &mut store.persisted_map_nodes,
                &mut appended,
                &mut store.complete_map_subtrees,
            )
            .unwrap(),
            0,
            "a successful append must retain its closed-subtree proof"
        );
    }
    assert!(extra_frames.is_empty());
    assert_eq!(
        encodings,
        identifies + evidence.appended_map_nodes.len(),
        "publication encodes each admitted node without minting its identity again"
    );
    store.publish_direct_update(update).unwrap();
}

#[test]
fn direct_append_retains_tight_payload_allocations() {
    use crate::storage_model::PhysicalMapNode;

    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("payload-capacity.volume")).unwrap();
    let mut store = empty_store(&volume);
    for ordinal in 42_u8..44 {
        let direct = store
            .describe_direct(
                ObjectId::new([ordinal; 32]),
                &[ordinal; 16],
                ArenaLocation {
                    offset: u64::from(ordinal),
                    payload_len: 16,
                    checksum: [ordinal; 32],
                },
            )
            .unwrap();
        let update = store.append_direct_update(&[direct]).unwrap().unwrap();
        store.publish_direct_update(update).unwrap();
    }
    let mut payloads = 0;
    for map in [
        store.representations.as_canonical(),
        store.placement_entries.as_canonical(),
    ] {
        for node in map.nodes().values() {
            if let PhysicalMapNode::Page { entries, .. } = node.as_ref() {
                for (_, value) in entries {
                    assert_eq!(
                        value.capacity(),
                        value.len(),
                        "persistent payloads must not retain encoder growth capacity"
                    );
                    payloads += 1;
                }
            }
        }
    }
    assert_eq!(
        payloads, 4,
        "check both real direct-map payloads per object"
    );
}

#[test]
fn failed_append_does_not_promote_unwritten_closures_and_retry_reopens() {
    // This bounded metadata batch now uses header/name/payload, with no
    // fourth checksum backpatch. Fail every write before proof promotion.
    for successful_writes in [0, 1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let volume: Arc<dyn AstridVolume> =
            HostedFileVolume::open(directory.path().join("retry.volume")).unwrap();
        let mut store = empty_store(&volume);
        let before_nodes = store
            .representations
            .nodes()
            .keys()
            .chain(store.placement_entries.nodes().keys())
            .chain(store.profiles.nodes().keys())
            .copied()
            .collect::<BTreeSet<_>>();
        let before_active = store.active;
        let direct = store
            .describe_direct(
                ObjectId::new([42; 32]),
                &[42; 16],
                ArenaLocation {
                    offset: 42,
                    payload_len: 16,
                    checksum: [42; 32],
                },
            )
            .unwrap();
        let failed = HostedFileVolume::with_append_failure_for_test(successful_writes, || {
            store.append_direct_update_observed(std::slice::from_ref(&direct))
        });
        assert!(failed.is_err(), "fault after {successful_writes} writes");
        assert_eq!(store.active, before_active);
        assert!(store.complete_map_subtrees.is_subset(&before_nodes));
        let (update, evidence) = store
            .append_direct_update_observed(std::slice::from_ref(&direct))
            .unwrap()
            .unwrap();
        assert!(!evidence.appended_map_nodes.is_empty());
        assert!(evidence.appended_map_nodes.iter().all(|id| {
            store.complete_map_subtrees.contains(id) && !store.persisted_map_nodes.contains(id)
        }));
        store.publish_direct_update(update).unwrap();
        store.flush().unwrap();
        drop(store);
        let reopened =
            RepresentationStore::open_volume(&volume, RecoveryLimits::process_addressable())
                .unwrap()
                .unwrap();
        assert!(reopened.contains_direct(direct.object));
    }
}

#[test]
fn observed_and_ordinary_direct_updates_emit_identical_metadata_and_journal() {
    let directory = tempfile::tempdir().unwrap();
    let normal_volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("normal.volume")).unwrap();
    let observed_volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("observed.volume")).unwrap();
    let mut normal = empty_store(&normal_volume);
    let mut observed = empty_store(&observed_volume);
    for tag in [42, 43] {
        let direct = normal
            .describe_direct(
                ObjectId::new([tag; 32]),
                &[tag; 16],
                ArenaLocation {
                    offset: u64::from(tag),
                    payload_len: 16,
                    checksum: [tag; 32],
                },
            )
            .unwrap();
        let before_metadata = observed.metadata.metadata().unwrap().len();
        let before_journal = observed.journal.metadata().unwrap().len();
        let update = normal
            .append_direct_update(std::slice::from_ref(&direct))
            .unwrap()
            .unwrap();
        normal.publish_direct_update(update).unwrap();
        let (update, evidence) = observed
            .append_direct_update_observed(&[direct])
            .unwrap()
            .unwrap();
        assert!(!evidence.appended_map_nodes.is_empty());
        let journal = observed.publish_direct_update_observed(update).unwrap();
        assert_eq!(evidence.metadata.start().get(), before_metadata);
        assert_eq!(
            evidence.metadata.end().get(),
            observed.metadata.metadata().unwrap().len()
        );
        assert_eq!(journal.start().get(), before_journal);
        assert_eq!(
            journal.end().get(),
            observed.journal.metadata().unwrap().len()
        );
        assert_eq!(bytes(&mut normal.metadata), bytes(&mut observed.metadata));
        assert_eq!(bytes(&mut normal.journal), bytes(&mut observed.journal));
        assert_eq!(normal.active, observed.active);
        assert_eq!(normal.reverse, observed.reverse);
        assert_eq!(normal.map_frame_count, observed.map_frame_count);
        assert_eq!(normal.complete_map_subtrees, observed.complete_map_subtrees);
        assert_eq!(normal.persisted_map_nodes, observed.persisted_map_nodes);
    }
}

#[test]
fn observing_an_already_direct_object_emits_no_append_evidence_or_frames() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("duplicate.volume")).unwrap();
    let mut store = empty_store(&volume);
    let direct = store
        .describe_direct(
            ObjectId::new([42; 32]),
            &[7; 16],
            ArenaLocation {
                offset: 17,
                payload_len: 16,
                checksum: [8; 32],
            },
        )
        .unwrap();
    let update = store
        .append_direct_update(std::slice::from_ref(&direct))
        .unwrap()
        .unwrap();
    store.publish_direct_update(update).unwrap();
    let metadata = bytes(&mut store.metadata);
    let journal = bytes(&mut store.journal);
    assert!(
        store
            .append_direct_update_observed(&[direct])
            .unwrap()
            .is_none()
    );
    assert_eq!(bytes(&mut store.metadata), metadata);
    assert_eq!(bytes(&mut store.journal), journal);
}
