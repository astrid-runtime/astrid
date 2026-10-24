use super::super::DurableFile;
use super::*;
use crate::storage_model::{PhysicalMapDomain, PhysicalMapNodes};

#[test]
fn recovery_memo_never_remembers_an_incomplete_closure() {
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        (0_u32..32)
            .map(|ordinal| {
                (
                    PhysicalMapKey::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                    ordinal.to_le_bytes().to_vec(),
                )
            })
            .collect(),
    )
    .unwrap();
    let root = map.root().unwrap();
    assert!(map.nodes().len() > 1);
    let partial = BTreeMap::from([(root, map.nodes()[&root].clone())]);
    let mut complete = BTreeSet::new();
    assert!(!test_map_closure_complete(Some(root), &partial, &mut complete).unwrap());
    assert!(complete.is_empty());
    assert!(!test_map_closure_complete(Some(root), &partial, &mut complete).unwrap());
    assert!(test_map_closure_complete(Some(root), map.nodes(), &mut complete).unwrap());
    assert_eq!(complete.len(), map.nodes().len());
    let verified = complete.clone();
    assert!(test_map_closure_complete(Some(root), map.nodes(), &mut complete).unwrap());
    assert_eq!(complete, verified);
    let absent = PhysicalMapKey::new([255; 32]);
    let other = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(absent, vec![0])],
    )
    .unwrap();
    assert!(!test_map_closure_complete(other.root(), map.nodes(), &mut complete).unwrap());
    assert_eq!(complete, verified);
}

#[test]
fn metadata_recovery_retains_each_map_node_only_once() {
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        (0_u32..32)
            .map(|ordinal| {
                (
                    PhysicalMapKey::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                    vec![u8::try_from(ordinal).unwrap(); 4096],
                )
            })
            .collect(),
    )
    .unwrap();
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    for node in map.nodes().values() {
        let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node).unwrap();
        for _ in 0..2 {
            super::super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap())
                .unwrap();
        }
    }
    let catalogue = RepresentationCatalogueRoot::new(1, None, 0, None, 0).unwrap();
    let frame = MetadataFrame::catalogue(&Blake3PhysicalIdentity, catalogue);
    super::super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    let index = recover_metadata(
        &mut file,
        RecoveryLimits::process_addressable(),
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    assert_eq!(index.nodes.len(), map.nodes().len());
    for (id, node) in map.nodes() {
        assert_eq!(index.nodes.node(*id).unwrap().unwrap().as_ref(), node);
    }
    assert_eq!(index.values.len(), 1, "retain only non-node metadata bytes");
    assert_eq!(
        index
            .value(MetadataKind::Catalogue, &frame.identity)
            .unwrap(),
        frame.value
    );
    let recovered = super::super::residency::recover_active_map(
        PhysicalMapDomain::Placement,
        map.root(),
        &index.nodes,
    )
    .unwrap();
    assert_eq!(recovered.root(), map.root());
    assert_eq!(recovered.entry_count(), map.entry_count());
}

#[test]
fn metadata_node_rejection_preserves_verified_index() {
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        vec![(PhysicalMapKey::new([7; 32]), vec![42])],
    )
    .unwrap();
    let frame = MetadataFrame::map_node(
        &Blake3PhysicalIdentity,
        map.nodes().values().next().unwrap(),
    )
    .unwrap();
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let payload = frame.encode().unwrap();
    let offset = super::super::super::append_frame(&mut file, METADATA_MAGIC, &payload).unwrap();
    let mut index = MetadataAdmission::new(
        &file,
        RecoveryLimits::process_addressable(),
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    index.insert(offset.offset, &payload).unwrap();
    let mut forged = frame.clone();
    forged.identity[0] ^= 1;
    assert!(
        index
            .insert(offset.offset, &forged.encode().unwrap())
            .is_err()
    );
    let mut noncanonical = frame;
    noncanonical.value.push(0);
    assert!(
        index
            .insert(offset.offset, &noncanonical.encode().unwrap())
            .is_err()
    );
    let index = index.finish().unwrap();
    assert_eq!(index.nodes.len(), map.nodes().len());
    for (id, node) in map.nodes() {
        assert_eq!(index.nodes.node(*id).unwrap().unwrap().as_ref(), node);
    }
    assert!(index.values.is_empty());
}

#[test]
fn metadata_recovery_rejects_a_forged_node_after_valid_frames() {
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        vec![(PhysicalMapKey::new([7; 32]), vec![42])],
    )
    .unwrap();
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let mut frame = MetadataFrame::map_node(
        &Blake3PhysicalIdentity,
        map.nodes().values().next().unwrap(),
    )
    .unwrap();
    super::super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    frame.identity[0] ^= 1;
    super::super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    assert!(matches!(
        recover_metadata(
            &mut file,
            RecoveryLimits::process_addressable(),
            super::super::LocationIndexMemoryBudget::default()
        ),
        Err(DurableError::InvalidRepresentationState(
            "metadata identity does not match canonical value"
        ))
    ));
}

#[test]
fn metadata_recovery_pages_payloads_and_revalidates_media_instead_of_caching_bodies() {
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        (0_u32..64)
            .map(|n| {
                (
                    PhysicalMapKey::new(*blake3::hash(&n.to_be_bytes()).as_bytes()),
                    vec![7; 16 * 1024],
                )
            })
            .collect(),
    )
    .unwrap();
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    for node in map.nodes().values() {
        let bytes = MetadataFrame::map_node(&Blake3PhysicalIdentity, node)
            .unwrap()
            .encode()
            .unwrap();
        super::super::super::append_frame(&mut file, METADATA_MAGIC, &bytes).unwrap();
    }
    let budget = super::super::LocationIndexMemoryBudget::new(
        std::num::NonZeroU64::new(super::super::LocationIndexMemoryBudget::MIN_BYTES).unwrap(),
    )
    .unwrap();
    let index = recover_metadata(&mut file, RecoveryLimits::process_addressable(), budget).unwrap();
    assert_eq!(index.nodes.len(), map.nodes().len());
    assert!(
        index.nodes.resident_capacity_bytes() <= usize::try_from(budget.bytes().get()).unwrap()
    );
    let recovered = super::super::residency::recover_active_map(
        PhysicalMapDomain::Placement,
        map.root(),
        &index.nodes,
    )
    .unwrap();
    assert_eq!(recovered, map);
    // The scanner's clone must use positioned reads, and no retained decoded
    // body may conceal a changed/truncated backing frame after admission.
    file.durable_set_len(0).unwrap();
    assert!(index.nodes.node(map.root().unwrap()).is_err());
}

#[test]
fn duplicate_admission_authenticates_the_previous_body_before_locator_replacement() {
    use std::io::{Seek, Write};
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        vec![(PhysicalMapKey::new([17; 32]), vec![23; 1024])],
    )
    .unwrap();
    let node = map.nodes().values().next().unwrap();
    let payload = MetadataFrame::map_node(&Blake3PhysicalIdentity, node)
        .unwrap()
        .encode()
        .unwrap();
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    let first = super::super::super::append_frame(&mut file, METADATA_MAGIC, &payload).unwrap();
    let mut index = MetadataAdmission::new(
        &file,
        RecoveryLimits::process_addressable(),
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    index.insert(first.offset, &payload).unwrap();
    let second = super::super::super::append_frame(&mut file, METADATA_MAGIC, &payload).unwrap();
    file.seek(SeekFrom::Start(
        first.offset.checked_add(FRAME_HEADER_LEN).unwrap(),
    ))
    .unwrap();
    file.write_all(&[payload[0] ^ 0x80]).unwrap();
    assert!(
        index.insert(second.offset, &payload).is_err(),
        "a new duplicate must not hide corrupted prior media"
    );
    assert!(
        index.finish().is_err(),
        "failed admission cannot publish an index"
    );
}

#[test]
fn journal_recovery_does_not_repair_authenticated_locator_read_failures() {
    use std::io::Seek;
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        vec![(PhysicalMapKey::new([31; 32]), vec![19; 1024])],
    )
    .unwrap();
    let catalogue = RepresentationCatalogueRoot::new(1, None, 0, None, 0).unwrap();
    let first_placements = PlacementSet::new(1, None, 0, 0).unwrap();
    let second_placements = PlacementSet::new(2, map.root(), 1, 1).unwrap();
    let first = RepresentationState::new(
        1,
        None,
        catalogue.identify(&Blake3PhysicalIdentity),
        first_placements.identify(&Blake3PhysicalIdentity),
    )
    .unwrap();
    let first_id = first.identify(&Blake3PhysicalIdentity);
    let second = RepresentationState::new(
        2,
        Some(first_id),
        catalogue.identify(&Blake3PhysicalIdentity),
        second_placements.identify(&Blake3PhysicalIdentity),
    )
    .unwrap();
    let second_id = second.identify(&Blake3PhysicalIdentity);
    let mut file = DurableFile::native(tempfile::tempfile().unwrap());
    for node in map.nodes().values() {
        append_test_metadata(
            &mut file,
            &MetadataFrame::map_node(&Blake3PhysicalIdentity, node).unwrap(),
        );
    }
    for frame in [
        MetadataFrame::catalogue(&Blake3PhysicalIdentity, catalogue),
        MetadataFrame::placement(&Blake3PhysicalIdentity, first_placements),
        MetadataFrame::placement(&Blake3PhysicalIdentity, second_placements),
        MetadataFrame::state(&Blake3PhysicalIdentity, first),
        MetadataFrame::state(&Blake3PhysicalIdentity, second),
    ] {
        append_test_metadata(&mut file, &frame);
    }
    append_unreferenced_catalogues(&mut file);
    let mut metadata = recover_metadata(
        &mut file,
        RecoveryLimits::process_addressable(),
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    let mut journal = DurableFile::native(tempfile::tempfile().unwrap());
    let checkpoint = JournalEntry::Checkpoint {
        journal_generation: FIRST_JOURNAL_GENERATION,
        active: None,
        state_generation: 0,
        prior_journal_digest: None,
    };
    super::super::super::append_frame(&mut journal, JOURNAL_MAGIC, &checkpoint.encode()).unwrap();
    let checkpoint_bytes = read_all(&mut journal, "read test checkpoint").unwrap();
    let current = CurrentPointer {
        journal_generation: FIRST_JOURNAL_GENERATION,
        checkpoint_digest: journal_digest(&checkpoint_bytes),
        max_tail_frames: 2,
        max_tail_bytes: 4096,
    };
    for (expected, replacement) in [(None, first_id), (Some(first_id), second_id)] {
        let entry = JournalEntry::StateCas {
            journal_generation: FIRST_JOURNAL_GENERATION,
            expected,
            replacement,
        };
        super::super::super::append_frame(&mut journal, JOURNAL_MAGIC, &entry.encode()).unwrap();
    }
    let limits = RecoveryLimits::process_addressable();
    assert_eq!(
        recover_journal(&mut journal, current, &mut metadata, limits).unwrap(),
        (second_id, second)
    );
    assert_eq!(
        metadata.values.len(),
        5,
        "keep both states and their authority roots"
    );
    let original_len = journal.seek(SeekFrom::End(0)).unwrap();
    // Admission succeeded, but the immutable locator's backing media now fails.
    // This is corruption, not a missing final publication eligible for repair.
    file.durable_set_len(0).unwrap();
    assert!(recover_journal(&mut journal, current, &mut metadata, limits).is_err());
    assert_eq!(journal.seek(SeekFrom::End(0)).unwrap(), original_len);
}

fn append_test_metadata(file: &mut DurableFile, frame: &MetadataFrame) {
    super::super::super::append_frame(file, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
}

fn append_unreferenced_catalogues(file: &mut DurableFile) {
    for generation in 10..74 {
        let unused = RepresentationCatalogueRoot::new(generation, None, 0, None, 0).unwrap();
        append_test_metadata(
            file,
            &MetadataFrame::catalogue(&Blake3PhysicalIdentity, unused),
        );
    }
}

fn test_map_closure_complete(
    root: Option<crate::storage_model::PhysicalMapNodeId>,
    nodes: &BTreeMap<crate::storage_model::PhysicalMapNodeId, PhysicalMapNode>,
    complete: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
) -> Result<bool, DurableError> {
    struct Provider<'a> {
        nodes: &'a BTreeMap<crate::storage_model::PhysicalMapNodeId, PhysicalMapNode>,
        complete: &'a mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
    }
    impl PhysicalMapNodes for Provider<'_> {
        type Error = DurableError;
        fn node(
            &self,
            id: crate::storage_model::PhysicalMapNodeId,
        ) -> Result<Option<std::borrow::Cow<'_, PhysicalMapNode>>, DurableError> {
            Ok(self.nodes.get(&id).map(std::borrow::Cow::Borrowed))
        }
    }
    impl super::super::activation::CompleteNodes for Provider<'_> {
        fn complete(
            &self,
            id: &crate::storage_model::PhysicalMapNodeId,
        ) -> Result<bool, DurableError> {
            Ok(self.complete.contains(id))
        }
        fn remember(
            &mut self,
            id: crate::storage_model::PhysicalMapNodeId,
        ) -> Result<(), DurableError> {
            self.complete.insert(id);
            Ok(())
        }
    }
    map_closure_complete(root, &mut Provider { nodes, complete })
}

#[test]
fn recovery_validates_unreferenced_placements_before_rebuilding_reverse_catalogue() {
    use crate::storage_model::{ObjectId, Replica, ReplicaLocator};
    let (profile, profile_id) =
        super::super::activation::direct_profile(ObjectId::new([1; 32])).unwrap();
    let profiles = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(PhysicalMapKey::from(profile_id), profile.encode().unwrap())],
    )
    .unwrap();
    let representations = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![],
    )
    .unwrap();
    let blob = crate::storage_model::BlobId::new([2; 32]);
    let replica = Replica::new(
        super::super::LOCAL_STORAGE_NODE,
        ReplicaLocator::ArenaFrame {
            arena_generation: 0,
            offset: 0,
            payload_length: 8,
            frame_checksum: [3; 32],
        },
    )
    .unwrap();
    let placement = PlacementEntry::new(blob, profile_id, 8, vec![replica]).unwrap();
    let encoded = placement.encode().unwrap();
    for (key, bytes, succeeds) in [
        (PhysicalMapKey::from(blob), encoded.clone(), true),
        (PhysicalMapKey::new([9; 32]), encoded, false),
        (PhysicalMapKey::from(blob), vec![0], false),
    ] {
        let placements = CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Placement,
            vec![(key, bytes)],
        )
        .unwrap();
        let result = validate_representations(
            &profiles,
            &representations,
            &placements,
            super::super::LocationIndexMemoryBudget::default(),
        );
        if succeeds {
            let (reverse, extents, _) = result.unwrap();
            assert_eq!(extents, 1);
            assert_eq!(reverse.len(), 0);
        } else {
            assert!(result.is_err(), "unused placement must still be validated");
        }
    }
}

#[test]
fn recovery_rejects_unused_placement_profile_and_missing_direct_blob() {
    use crate::storage_model::{ObjectId, Replica, ReplicaLocator};
    let (profile, profile_id) =
        super::super::activation::direct_profile(ObjectId::new([1; 32])).unwrap();
    let profiles = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(PhysicalMapKey::from(profile_id), profile.encode().unwrap())],
    )
    .unwrap();
    let empty_profiles = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![],
    )
    .unwrap();
    let empty_representations = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![],
    )
    .unwrap();
    let blob = crate::storage_model::BlobId::new([2; 32]);
    let replica = Replica::new(
        super::super::LOCAL_STORAGE_NODE,
        ReplicaLocator::ArenaFrame {
            arena_generation: 0,
            offset: 0,
            payload_length: 8,
            frame_checksum: [3; 32],
        },
    )
    .unwrap();
    let placement = PlacementEntry::new(blob, profile_id, 8, vec![replica]).unwrap();
    let placements = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        vec![(PhysicalMapKey::from(blob), placement.encode().unwrap())],
    )
    .unwrap();
    assert!(
        validate_representations(
            &empty_profiles,
            &empty_representations,
            &placements,
            super::super::LocationIndexMemoryBudget::default()
        )
        .is_err()
    );
    let record = RepresentationRecord::new(
        profile_id,
        Coverage::exact(ObjectId::new([4; 32]), 8).unwrap(),
        Recipe::DirectCanonical { blob },
        8,
        8,
        None,
    )
    .unwrap();
    let representations = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        vec![(
            PhysicalMapKey::from(record.identify(&Blake3PhysicalIdentity).unwrap()),
            record.encode().unwrap(),
        )],
    )
    .unwrap();
    let empty_placements = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        vec![],
    )
    .unwrap();
    assert!(
        validate_representations(
            &profiles,
            &representations,
            &empty_placements,
            super::super::LocationIndexMemoryBudget::default()
        )
        .is_err()
    );
}

#[test]
fn reverse_recovery_keeps_multiple_direct_records_and_selects_the_original_first_placement() {
    use crate::storage_model::{BlobId, ObjectId, Replica, ReplicaLocator};
    let object = ObjectId::new([4; 32]);
    let (profile, profile_id) =
        super::super::activation::direct_profile(ObjectId::new([1; 32])).unwrap();
    let profiles = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(PhysicalMapKey::from(profile_id), profile.encode().unwrap())],
    )
    .unwrap();
    let mut records = Vec::new();
    let mut placement_entries = Vec::new();
    let mut locations = BTreeMap::new();
    for n in [9_u8, 2] {
        let blob = BlobId::new([n; 32]);
        let record = RepresentationRecord::new(
            profile_id,
            Coverage::exact(object, 8).unwrap(),
            Recipe::DirectCanonical { blob },
            8,
            8,
            None,
        )
        .unwrap();
        let id = record.identify(&Blake3PhysicalIdentity).unwrap();
        records.push((PhysicalMapKey::from(id), record.encode().unwrap()));
        let location = super::super::ArenaLocation {
            offset: u64::from(n),
            payload_len: 8,
            checksum: [n; 32],
        };
        let replica = Replica::new(
            super::super::LOCAL_STORAGE_NODE,
            ReplicaLocator::ArenaFrame {
                arena_generation: 0,
                offset: location.offset,
                payload_length: location.payload_len,
                frame_checksum: location.checksum,
            },
        )
        .unwrap();
        let placement = PlacementEntry::new(blob, profile_id, 8, vec![replica]).unwrap();
        placement_entries.push((PhysicalMapKey::from(blob), placement.encode().unwrap()));
        locations.insert(id, location);
    }
    let representations = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        records,
    )
    .unwrap();
    let placements = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Placement,
        placement_entries,
    )
    .unwrap();
    let expected = active_entries(&representations)
        .map(|entry| {
            let (_, bytes) = entry.unwrap();
            RepresentationRecord::decode(&bytes)
                .unwrap()
                .identify(&Blake3PhysicalIdentity)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let (reverse, extents, direct) = validate_representations(
        &profiles,
        &representations,
        &placements,
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    assert_eq!(extents, 2);
    assert_eq!(
        reverse.snapshot().unwrap(),
        BTreeMap::from([(object, expected.clone())])
    );
    assert_eq!(reverse.first(object).unwrap(), Some(expected[0]));
    direct
        .validate(&BTreeMap::from([(object, locations[&expected[0]])]))
        .unwrap();
}
