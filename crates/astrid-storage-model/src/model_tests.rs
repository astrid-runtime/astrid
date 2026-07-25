//! Executable-model conformance and adversarial tests.
use alloc::collections::BTreeSet;

use super::*;
use alloc::vec;

fn id(value: u8) -> ObjectId {
    ObjectId::new([value; 32])
}

fn blob(value: u8) -> BlobId {
    BlobId::new([value; 32])
}

fn label(value: &[u8]) -> ReferenceLabel {
    ReferenceLabel::new(value.to_vec())
}

fn data(value: u8) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        vec![value],
        vec![],
        1,
        ObjectClass::Data,
    )
    .unwrap()
}

fn metadata(value: u8, references: Vec<ObjectId>) -> ObjectRecord {
    let references = references
        .into_iter()
        .enumerate()
        .map(|(index, target)| {
            ObjectReference::owns(
                ReferenceLabel::new(vec![u8::try_from(index).unwrap()]),
                target,
            )
        })
        .collect();
    ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        vec![value],
        references,
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

fn metadata_refs(value: u8, references: Vec<ObjectReference>) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        vec![value],
        references,
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

#[derive(Clone, Copy)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        fn mix(mut state: u64, bytes: &[u8]) -> u64 {
            for byte in bytes {
                state ^= u64::from(*byte);
                state = state.wrapping_mul(0x0000_0100_0000_01b3);
            }
            state
        }

        let mut state = mix(0xcbf2_9ce4_8422_2325, &record.kind().code().to_le_bytes());
        state = mix(state, &record.format_version().get().to_le_bytes());
        state = mix(
            state,
            &u64::try_from(record.canonical_bytes().len())
                .unwrap()
                .to_le_bytes(),
        );
        state = mix(state, record.canonical_bytes());
        state = mix(state, &record.logical_bytes().to_le_bytes());
        state = mix(state, &[record.class().code()]);
        for reference in record.references() {
            state = mix(
                state,
                &u64::try_from(reference.label().as_bytes().len())
                    .unwrap()
                    .to_le_bytes(),
            );
            state = mix(state, reference.label().as_bytes());
            state = mix(state, reference.target().as_bytes());
            state = mix(state, &[reference.kind().code()]);
        }

        let mut bytes = [0_u8; 32];
        for (index, chunk) in bytes.chunks_exact_mut(8).enumerate() {
            state = mix(state, &[u8::try_from(index).unwrap()]);
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        ObjectId::new(bytes)
    }
}

struct ProofTree {
    identity: TestIdentity,
    root: (ObjectId, ObjectRecord),
    home: (ObjectId, ObjectRecord),
    first: (ObjectId, ObjectRecord),
    second: (ObjectId, ObjectRecord),
}

fn proof_tree() -> ProofTree {
    let identity = TestIdentity;
    let first_record = data(1);
    let first = identity.identify(&first_record);
    let second_record = data(2);
    let second = identity.identify(&second_record);
    let home_record = metadata_refs(
        3,
        vec![
            ObjectReference::owns(label(b"a"), first),
            ObjectReference::owns(label(b"b"), second),
        ],
    );
    let home = identity.identify(&home_record);
    let root_record = metadata_refs(
        4,
        vec![
            ObjectReference::new(label(b"audit"), id(99), ReferenceKind::Evidence),
            ObjectReference::owns(label(b"home"), home),
        ],
    );
    let root = identity.identify(&root_record);
    ProofTree {
        identity,
        root: (root, root_record),
        home: (home, home_record),
        first: (first, first_record),
        second: (second, second_record),
    }
}

fn ordered_records(mut records: Vec<(ObjectId, ObjectRecord)>) -> Vec<(ObjectId, ObjectRecord)> {
    records.sort_by_key(|(object, _)| *object);
    records
}

fn insert_small_tree(world: &mut World<&'static str>) {
    world.insert_object(id(1), data(1)).unwrap();
    world.insert_object(id(2), data(2)).unwrap();
    world
        .insert_object(id(3), metadata(3, vec![id(1), id(2)]))
        .unwrap();
    world.register_representation(id(1), blob(1)).unwrap();
    world.register_representation(id(2), blob(2)).unwrap();
    world.register_representation(id(3), blob(3)).unwrap();
}

#[test]
fn identifier_collision_is_never_silently_deduplicated() {
    let mut world = World::<&str>::new();
    assert_eq!(
        world.insert_object(id(1), data(1)),
        Ok(InsertOutcome::Inserted)
    );
    assert_eq!(
        world.insert_object(id(1), data(1)),
        Ok(InsertOutcome::AlreadyPresent)
    );
    assert_eq!(
        world.insert_object(id(1), data(2)),
        Err(ModelError::ObjectCollision(id(1)))
    );
}

#[test]
fn format_versions_and_replica_requirements_are_non_zero_by_type() {
    assert_eq!(ObjectFormatVersion::new(0), None);
    assert_eq!(ObjectFormatVersion::new(1), Some(ObjectFormatVersion::V1));
    assert_eq!(ReplicaCount::new(0), None);
    assert_eq!(ReplicaCount::new(3).unwrap().get(), 3);
}

#[test]
fn physical_blob_cannot_alias_different_logical_content() {
    let mut world = World::<&str>::new();
    world.insert_object(id(1), data(1)).unwrap();
    world.insert_object(id(2), data(2)).unwrap();
    assert_eq!(
        world.register_representation(id(1), blob(9)),
        Ok(RepresentationOutcome::Registered)
    );
    assert_eq!(
        world.register_representation(id(1), blob(9)),
        Ok(RepresentationOutcome::AlreadyPresent)
    );
    assert_eq!(
        world.register_representation(id(2), blob(9)),
        Err(ModelError::BlobCollision(blob(9)))
    );
}

#[test]
fn incomplete_root_is_not_visible() {
    let mut world = World::<&str>::new();
    world
        .insert_object(id(3), metadata(3, vec![id(1)]))
        .unwrap();
    assert_eq!(
        world.compare_and_swap_root("alice", None, id(3)),
        Err(ModelError::MissingObject(id(1)))
    );
    assert_eq!(world.root(&"alice"), None);
}

#[test]
fn principal_root_must_name_a_commit_object() {
    let mut world = World::<&str>::new();
    world.insert_object(id(1), data(1)).unwrap();

    assert_eq!(
        world.compare_and_swap_root("alice", None, id(1)),
        Err(ModelError::RootNotCommit {
            object: id(1),
            actual: ObjectKind::Chunk,
        })
    );
    assert_eq!(world.root(&"alice"), None);
}

#[test]
fn non_owning_reference_does_not_expand_principal_closure() {
    let mut world = World::<&str>::new();
    world
        .insert_object(
            id(2),
            metadata_refs(
                2,
                vec![ObjectReference::new(
                    ReferenceLabel::new(vec![0]),
                    id(1),
                    ReferenceKind::Evidence,
                )],
            ),
        )
        .unwrap();

    world.compare_and_swap_root("alice", None, id(2)).unwrap();

    assert_eq!(world.closure(id(2)).unwrap(), BTreeSet::from([id(2)]));
    assert_eq!(
        world.principal_usage(&"alice").unwrap(),
        PrincipalUsage {
            object_count: 1,
            logical_bytes: 0,
            retained_object_bytes: 1,
            metadata_bytes: 1,
        }
    );
}

#[test]
fn evidence_requires_its_own_pin_for_retention() {
    let mut world = World::<&str>::new();
    world.insert_object(id(1), data(1)).unwrap();
    world
        .insert_object(
            id(2),
            metadata_refs(
                2,
                vec![ObjectReference::new(
                    ReferenceLabel::new(vec![0]),
                    id(1),
                    ReferenceKind::Evidence,
                )],
            ),
        )
        .unwrap();
    world.compare_and_swap_root("alice", None, id(2)).unwrap();
    world.pin(PinId::new(7), id(1)).unwrap();

    assert_eq!(world.collect_garbage().unwrap().objects_removed, 0);
    world.unpin(PinId::new(7)).unwrap();
    assert_eq!(
        world.collect_garbage().unwrap(),
        GcReport {
            objects_removed: 1,
            bytes_removed: 1,
        }
    );
    assert_eq!(world.closure(id(2)).unwrap(), BTreeSet::from([id(2)]));
}

#[test]
fn one_label_cannot_have_conflicting_reference_relations() {
    let references = vec![
        ObjectReference::owns(ReferenceLabel::new(vec![0]), id(1)),
        ObjectReference::new(ReferenceLabel::new(vec![0]), id(2), ReferenceKind::Lineage),
    ];

    assert_eq!(
        ObjectRecord::new(
            ObjectKind::Commit,
            ObjectFormatVersion::V1,
            vec![2],
            references,
            0,
            ObjectClass::Metadata,
        ),
        Err(ModelError::NonCanonicalReferences)
    );
}

#[test]
fn different_labels_may_share_one_owned_target() {
    let mut world = World::<&str>::new();
    world.insert_object(id(1), data(1)).unwrap();
    world
        .insert_object(
            id(2),
            metadata_refs(
                2,
                vec![
                    ObjectReference::owns(ReferenceLabel::new(vec![0]), id(1)),
                    ObjectReference::owns(ReferenceLabel::new(vec![1]), id(1)),
                ],
            ),
        )
        .unwrap();
    world.compare_and_swap_root("alice", None, id(2)).unwrap();

    assert_eq!(
        world.closure(id(2)).unwrap(),
        BTreeSet::from([id(1), id(2)])
    );
    assert_eq!(world.principal_usage(&"alice").unwrap().object_count, 2);
}

#[test]
fn borrowed_reference_label_queries_without_allocation() {
    let tree = proof_tree();
    let home = ReferenceLabel::new(b"home".as_slice());

    assert_eq!(
        tree.root.1.reference(&home).map(ObjectReference::target),
        Some(tree.home.0)
    );
}

#[test]
fn selector_rejects_empty_duplicate_and_redundant_paths() {
    assert_eq!(
        StateSelector::new(vec![]),
        Err(ModelError::NonCanonicalSelector)
    );
    let home = ReferencePath::new(vec![label(b"home")]);
    assert_eq!(
        StateSelector::new(vec![home.clone(), home.clone()]),
        Err(ModelError::NonCanonicalSelector)
    );
    let child = ReferencePath::new(vec![label(b"home"), label(b"a")]);
    assert_eq!(
        StateSelector::new(vec![home, child]),
        Err(ModelError::NonCanonicalSelector)
    );
}

#[test]
fn view_proof_discloses_only_selected_owned_closure() {
    let tree = proof_tree();
    let selector =
        StateSelector::new(vec![ReferencePath::new(vec![label(b"home"), label(b"a")])]).unwrap();
    let records = ordered_records(vec![
        tree.root.clone(),
        tree.home.clone(),
        tree.first.clone(),
    ]);
    let proof = StateViewProof::new(tree.root.0, selector, records).unwrap();

    let verified = proof.verify(&tree.identity).unwrap();
    assert_eq!(verified.source(), tree.root.0);
    assert_eq!(verified.selected_roots(), &[tree.first.0]);
    assert_eq!(verified.object_count(), 3);
}

#[test]
fn view_proof_rejects_substitution_excess_and_non_owning_path() {
    let tree = proof_tree();
    let selected_first =
        StateSelector::new(vec![ReferencePath::new(vec![label(b"home"), label(b"a")])]).unwrap();

    let substituted = ordered_records(vec![
        tree.root.clone(),
        tree.home.clone(),
        (tree.first.0, data(9)),
    ]);
    let proof = StateViewProof::new(tree.root.0, selected_first.clone(), substituted).unwrap();
    assert!(matches!(
        proof.verify(&tree.identity),
        Err(ModelError::ObjectIdentityMismatch { .. })
    ));

    let excessive = ordered_records(vec![
        tree.root.clone(),
        tree.home.clone(),
        tree.first.clone(),
        tree.second.clone(),
    ]);
    let proof = StateViewProof::new(tree.root.0, selected_first, excessive).unwrap();
    assert_eq!(
        proof.verify(&tree.identity),
        Err(ModelError::ExtraneousProofObject(tree.second.0))
    );

    let audit_selector =
        StateSelector::new(vec![ReferencePath::new(vec![label(b"audit")])]).unwrap();
    let proof = StateViewProof::new(tree.root.0, audit_selector, vec![tree.root.clone()]).unwrap();
    assert_eq!(
        proof.verify(&tree.identity),
        Err(ModelError::ReferenceNotOwned {
            label: label(b"audit"),
        })
    );
}

#[test]
fn view_proof_requires_complete_selected_closure() {
    let tree = proof_tree();
    let selector = StateSelector::new(vec![ReferencePath::new(vec![label(b"home")])]).unwrap();
    let records = ordered_records(vec![tree.root.clone(), tree.home.clone()]);
    let proof = StateViewProof::new(tree.root.0, selector, records).unwrap();

    assert!(matches!(
        proof.verify(&tree.identity),
        Err(ModelError::MissingObject(missing))
            if missing == tree.first.0 || missing == tree.second.0
    ));
}

#[test]
fn transition_witness_recomputes_labelled_root_replacement() {
    let tree = proof_tree();
    let replacement_record = data(9);
    let replacement = tree.identity.identify(&replacement_record);
    let next_home_record = tree
        .home
        .1
        .replace_owned_target(&label(b"a"), tree.first.0, replacement)
        .unwrap();
    let next_home = tree.identity.identify(&next_home_record);
    let next_root_record = tree
        .root
        .1
        .replace_owned_target(&label(b"home"), tree.home.0, next_home)
        .unwrap();
    let next_root = tree.identity.identify(&next_root_record);
    let patch = OwnedSubtreePatch::new(
        ReferencePath::new(vec![label(b"home"), label(b"a")]),
        tree.first.0,
        replacement,
    );
    let records = ordered_records(vec![tree.root.clone(), tree.home.clone()]);
    let witness = TransitionWitness::new(tree.root.0, next_root, patch, records).unwrap();

    assert_eq!(witness.verify(&tree.identity), Ok(next_root));
    let wrong_after = TransitionWitness::new(
        tree.root.0,
        id(77),
        OwnedSubtreePatch::new(
            ReferencePath::new(vec![label(b"home"), label(b"a")]),
            tree.first.0,
            replacement,
        ),
        ordered_records(vec![tree.root.clone(), tree.home.clone()]),
    )
    .unwrap();
    assert!(matches!(
        wrong_after.verify(&tree.identity),
        Err(ModelError::TransitionRootMismatch { .. })
    ));
}

#[test]
fn transition_witness_rejects_wrong_target_root_and_extra_records() {
    let tree = proof_tree();
    let replacement = tree.identity.identify(&data(9));
    let wrong_target = OwnedSubtreePatch::new(
        ReferencePath::new(vec![label(b"home"), label(b"b")]),
        tree.first.0,
        replacement,
    );
    let records = ordered_records(vec![tree.root.clone(), tree.home.clone()]);
    let witness = TransitionWitness::new(tree.root.0, tree.root.0, wrong_target, records).unwrap();
    assert_eq!(
        witness.verify(&tree.identity),
        Err(ModelError::PatchTargetMismatch {
            expected: tree.first.0,
            actual: tree.second.0,
        })
    );

    let root_patch = OwnedSubtreePatch::new(ReferencePath::new(vec![]), tree.root.0, replacement);
    let witness = TransitionWitness::new(
        tree.root.0,
        replacement,
        root_patch,
        vec![tree.root.clone()],
    )
    .unwrap();
    assert_eq!(
        witness.verify(&tree.identity),
        Err(ModelError::ExtraneousProofObject(tree.root.0))
    );
}

#[test]
fn cyclic_root_is_not_visible() {
    let mut world = World::<&str>::new();
    world
        .insert_object(id(1), metadata(1, vec![id(2)]))
        .unwrap();
    world
        .insert_object(id(2), metadata(2, vec![id(1)]))
        .unwrap();

    assert_eq!(
        world.compare_and_swap_root("alice", None, id(1)),
        Err(ModelError::ObjectCycle(id(1)))
    );
    assert_eq!(world.root(&"alice"), None);
}

#[test]
fn compare_and_swap_prevents_lost_update() {
    let mut world = World::<&str>::new();
    insert_small_tree(&mut world);
    let first = world.compare_and_swap_root("alice", None, id(3)).unwrap();
    world.insert_object(id(4), data(4)).unwrap();

    let stale = RootState {
        generation: RootGeneration::new(99),
        commit: id(3),
    };
    assert!(matches!(
        world.compare_and_swap_root("alice", Some(stale), id(4)),
        Err(ModelError::RootConflict { .. })
    ));
    assert_eq!(world.root(&"alice"), Some(first));
}

#[test]
fn export_import_is_complete_and_idempotent() {
    let mut source = World::<&str>::new();
    insert_small_tree(&mut source);
    let records = source.export_closure(id(3)).unwrap();

    let mut destination = World::<&str>::new();
    assert_eq!(destination.import_closure(&records, id(3)).unwrap(), 3);
    assert_eq!(destination.import_closure(&records, id(3)).unwrap(), 0);
    assert_eq!(destination.export_closure(id(3)).unwrap(), records);
}

#[test]
fn failed_import_is_invisible() {
    let mut source = World::<&str>::new();
    insert_small_tree(&mut source);
    let mut records = source.export_closure(id(3)).unwrap();
    records.retain(|(object, _)| *object != id(1));

    let mut destination = World::<&str>::new();
    assert_eq!(
        destination.import_closure(&records, id(3)),
        Err(ModelError::MissingObject(id(1)))
    );
    assert_eq!(destination.object_count(), 0);
}

#[test]
fn extraneous_import_object_is_rejected_atomically() {
    let mut source = World::<&str>::new();
    insert_small_tree(&mut source);
    source.insert_object(id(9), data(9)).unwrap();
    let mut records = source.export_closure(id(3)).unwrap();
    records.push((id(9), data(9)));

    let mut destination = World::<&str>::new();
    assert_eq!(
        destination.import_closure(&records, id(3)),
        Err(ModelError::ExtraneousImportObject(id(9)))
    );
    assert_eq!(destination.object_count(), 0);
}

#[test]
fn every_incomplete_small_import_is_invisible() {
    let mut source = World::<&str>::new();
    insert_small_tree(&mut source);
    let records = source.export_closure(id(3)).unwrap();

    for keep_first in [false, true] {
        for keep_second in [false, true] {
            for keep_third in [false, true] {
                let choices = [keep_first, keep_second, keep_third];
                let subset: Vec<_> = records
                    .iter()
                    .zip(choices)
                    .filter(|(_, keep)| *keep)
                    .map(|(record, _)| record.clone())
                    .collect();
                let mut destination = World::<&str>::new();
                let result = destination.import_closure(&subset, id(3));
                if keep_first && keep_second && keep_third {
                    assert_eq!(result, Ok(3));
                    assert_eq!(destination.object_count(), 3);
                } else {
                    assert!(matches!(result, Err(ModelError::MissingObject(_))));
                    assert_eq!(destination.object_count(), 0);
                }
            }
        }
    }
}

#[test]
fn collision_rolls_back_other_staged_import_objects() {
    let mut destination = World::<&str>::new();
    destination.insert_object(id(1), data(9)).unwrap();
    let records = vec![(id(2), data(2)), (id(1), data(1))];

    assert_eq!(
        destination.import_closure(&records, id(2)),
        Err(ModelError::ObjectCollision(id(1)))
    );
    assert_eq!(destination.object_count(), 1);
    assert_eq!(
        destination.insert_object(id(2), data(2)),
        Ok(InsertOutcome::Inserted)
    );
}

#[test]
fn garbage_collection_respects_roots_and_pins() {
    let mut world = World::<&str>::new();
    insert_small_tree(&mut world);
    world.insert_object(id(9), data(9)).unwrap();
    world.compare_and_swap_root("alice", None, id(3)).unwrap();
    world.pin(PinId::new(7), id(9)).unwrap();

    assert_eq!(world.collect_garbage().unwrap().objects_removed, 0);
    world.unpin(PinId::new(7)).unwrap();
    assert_eq!(
        world.collect_garbage().unwrap(),
        GcReport {
            objects_removed: 1,
            bytes_removed: 1,
        }
    );
}

#[test]
fn another_principal_does_not_change_enforced_usage() {
    let mut world = World::<&str>::new();
    insert_small_tree(&mut world);
    world.compare_and_swap_root("alice", None, id(3)).unwrap();
    let before = world.principal_usage(&"alice").unwrap();

    world.compare_and_swap_root("bob", None, id(3)).unwrap();
    assert_eq!(world.principal_usage(&"alice").unwrap(), before);
    assert_eq!(
        before,
        PrincipalUsage {
            object_count: 3,
            logical_bytes: 2,
            retained_object_bytes: 3,
            metadata_bytes: 1,
        }
    );
}

#[test]
fn deleting_one_principal_preserves_shared_objects() {
    let mut world = World::<&str>::new();
    world.insert_object(id(1), data(1)).unwrap();
    world.insert_object(id(2), data(2)).unwrap();
    world
        .insert_object(id(3), metadata(3, vec![id(1), id(2)]))
        .unwrap();
    world
        .insert_object(id(4), metadata(4, vec![id(1)]))
        .unwrap();

    let alice = world.compare_and_swap_root("alice", None, id(3)).unwrap();
    world.compare_and_swap_root("bob", None, id(4)).unwrap();
    world.compare_and_remove_root(&"alice", alice).unwrap();

    assert_eq!(
        world.collect_garbage().unwrap(),
        GcReport {
            objects_removed: 2,
            bytes_removed: 2,
        }
    );
    assert_eq!(world.principal_usage(&"bob").unwrap().logical_bytes, 1);
    assert_eq!(world.object_count(), 2);
}

#[test]
fn placement_epoch_changes_no_logical_root() {
    let mut world = World::<&str>::new();
    insert_small_tree(&mut world);
    let root = world.compare_and_swap_root("alice", None, id(3)).unwrap();

    let first = PlacementEpoch::new(1);
    let plan = vec![
        (blob(1), vec![StorageNodeId::new(1), StorageNodeId::new(2)]),
        (blob(2), vec![StorageNodeId::new(1), StorageNodeId::new(2)]),
        (blob(3), vec![StorageNodeId::new(1), StorageNodeId::new(2)]),
    ];
    world
        .publish_placement_epoch(first, &plan, ReplicaCount::new(2).unwrap())
        .unwrap();

    world.register_representation(id(1), blob(11)).unwrap();
    world.register_representation(id(2), blob(12)).unwrap();
    world.register_representation(id(3), blob(13)).unwrap();
    let second = PlacementEpoch::new(2);
    let moved = vec![
        (blob(11), vec![StorageNodeId::new(2), StorageNodeId::new(3)]),
        (blob(12), vec![StorageNodeId::new(2), StorageNodeId::new(3)]),
        (blob(13), vec![StorageNodeId::new(2), StorageNodeId::new(3)]),
    ];
    world
        .publish_placement_epoch(second, &moved, ReplicaCount::new(2).unwrap())
        .unwrap();

    assert_eq!(world.root(&"alice"), Some(root));
    assert!(world.replicas(first, blob(1)).is_some());
    assert!(world.replicas(second, blob(11)).is_some());
    assert_eq!(
        world.retire_placement_epoch(second),
        Err(ModelError::ActivePlacementEpoch(second))
    );
    world.retire_placement_epoch(first).unwrap();
    assert!(world.replicas(first, blob(1)).is_none());
}

#[test]
fn under_replicated_epoch_is_not_published() {
    let mut world = World::<&str>::new();
    insert_small_tree(&mut world);
    world.compare_and_swap_root("alice", None, id(3)).unwrap();
    let epoch = PlacementEpoch::new(1);
    let plan = vec![
        (blob(1), vec![StorageNodeId::new(1)]),
        (blob(2), vec![StorageNodeId::new(1)]),
        (blob(3), vec![StorageNodeId::new(1)]),
    ];

    assert!(matches!(
        world.publish_placement_epoch(epoch, &plan, ReplicaCount::new(2).unwrap()),
        Err(ModelError::InsufficientReplicas { .. })
    ));
    assert_eq!(world.active_placement_epoch(), None);
    assert!(world.replicas(epoch, blob(1)).is_none());
}

#[test]
fn placement_epochs_reject_unknown_blobs_stale_versions_and_missing_retirement() {
    let mut world = World::<&str>::new();
    assert_eq!(
        world.publish_placement_epoch(
            PlacementEpoch::new(1),
            &[(blob(9), vec![StorageNodeId::new(1)])],
            ReplicaCount::new(1).unwrap(),
        ),
        Err(ModelError::UnregisteredBlob(blob(9)))
    );

    insert_small_tree(&mut world);
    world.compare_and_swap_root("alice", None, id(3)).unwrap();
    let first = PlacementEpoch::new(2);
    let plan = vec![
        (blob(1), vec![StorageNodeId::new(1)]),
        (blob(2), vec![StorageNodeId::new(1)]),
        (blob(3), vec![StorageNodeId::new(1)]),
    ];
    world
        .publish_placement_epoch(first, &plan, ReplicaCount::new(1).unwrap())
        .unwrap();

    let stale = PlacementEpoch::new(1);
    assert_eq!(
        world.publish_placement_epoch(stale, &plan, ReplicaCount::new(1).unwrap()),
        Err(ModelError::StalePlacementEpoch {
            proposed: stale,
            active: first,
        })
    );
    assert_eq!(
        world.retire_placement_epoch(PlacementEpoch::new(99)),
        Err(ModelError::PlacementEpochMissing(PlacementEpoch::new(99)))
    );
}
