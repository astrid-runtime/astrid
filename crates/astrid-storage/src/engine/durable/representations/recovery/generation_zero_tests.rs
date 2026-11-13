//! Mount selection uses the canonical first record and every selected replica.
use super::*;
use crate::storage_model::{BlobId, PhysicalMapDomain, Replica, ReplicaLocator, StorageNodeId};

type Fixture = (
    CanonicalPhysicalMap,
    CanonicalPhysicalMap,
    CanonicalPhysicalMap,
    RepresentationProfileId,
);
const OBJECT: ObjectId = ObjectId::new([7; 32]);

fn fixture(first: &[(u64, u64)], second: &[(u64, u64)]) -> Fixture {
    let identity = Blake3PhysicalIdentity;
    let (profile, profile_id) =
        super::super::activation::direct_profile(ObjectId::new([9; 32])).unwrap();
    let mut records: Vec<_> = [BlobId::new([1; 32]), BlobId::new([2; 32])]
        .into_iter()
        .map(|blob| {
            let record = RepresentationRecord::new(
                profile_id,
                Coverage::exact(OBJECT, 8).unwrap(),
                Recipe::DirectCanonical { blob },
                8,
                8,
                None,
            )
            .unwrap();
            (record.identify(&identity).unwrap(), record, blob)
        })
        .collect();
    records.sort_by_key(|(id, _, _)| *id);
    let placements = records
        .iter()
        .zip([first, second])
        .map(|((_, _, blob), locations)| {
            let replicas = locations
                .iter()
                .enumerate()
                .map(|(ordinal, &(generation, offset))| {
                    Replica::new(
                        StorageNodeId::new(u32::try_from(ordinal).unwrap()),
                        ReplicaLocator::ArenaFrame {
                            arena_generation: generation,
                            offset,
                            payload_length: 8,
                            frame_checksum: [0; 32],
                        },
                    )
                    .unwrap()
                })
                .collect();
            let placement = PlacementEntry::new(*blob, profile_id, 8, replicas).unwrap();
            (PhysicalMapKey::from(*blob), placement.encode().unwrap())
        })
        .collect();
    (
        CanonicalPhysicalMap::build_dense(
            &identity,
            PhysicalMapDomain::Profile,
            vec![(PhysicalMapKey::from(profile_id), profile.encode().unwrap())],
        )
        .unwrap(),
        CanonicalPhysicalMap::build_dense(
            &identity,
            PhysicalMapDomain::Representation,
            records
                .into_iter()
                .map(|(id, record, _)| (PhysicalMapKey::from(id), record.encode().unwrap()))
                .collect(),
        )
        .unwrap(),
        CanonicalPhysicalMap::build_dense(&identity, PhysicalMapDomain::Placement, placements)
            .unwrap(),
        profile_id,
    )
}

fn validate<const COLLECT: bool>(fixture: &Fixture) -> ValidatedRepresentations {
    validate_representations::<COLLECT>(&fixture.0, &fixture.1, &fixture.2, fixture.3).unwrap()
}

fn location(offset: u64) -> super::super::ArenaLocation {
    super::super::ArenaLocation {
        offset,
        payload_len: 8,
        checksum: [0; 32],
    }
}

#[test]
fn canonical_first_record_wins_over_later_different_placements() {
    let fixture = fixture(&[(0, 10)], &[(0, 100)]);
    let evidence = validate::<true>(&fixture);
    assert_eq!(evidence.reverse[&OBJECT].len(), 2);
    let index = evidence.generation_zero.into_index().unwrap();
    assert_eq!(
        index.protected_len(),
        10 + super::super::FRAME_HEADER_LEN + 8
    );
    index
        .validate(&BTreeMap::from([(OBJECT, location(10))]))
        .unwrap();
    let index = validate::<true>(&fixture)
        .generation_zero
        .into_index()
        .unwrap();
    assert!(
        index
            .validate(&BTreeMap::from([(OBJECT, location(100))]))
            .is_err()
    );
}

#[test]
fn first_selected_record_without_generation_zero_cannot_fall_through() {
    let fixture = fixture(&[(1, 10)], &[(0, 100)]);
    assert!(matches!(
        validate::<true>(&fixture).generation_zero.into_index(),
        Err(DurableError::InvalidRepresentationState(
            "direct representation has no generation-zero arena placement"
        ))
    ));
    validate::<false>(&fixture);
}

#[test]
fn selected_record_keeps_all_replicas_and_later_overflow() {
    let fixture = fixture(&[(0, 10), (0, 100)], &[(0, 200)]);
    let index = validate::<true>(&fixture)
        .generation_zero
        .into_index()
        .unwrap();
    assert_eq!(
        index.protected_len(),
        100 + super::super::FRAME_HEADER_LEN + 8
    );
    index
        .validate(&BTreeMap::from([(OBJECT, location(100))]))
        .unwrap();
    let index = validate::<true>(&fixture)
        .generation_zero
        .into_index()
        .unwrap();
    assert!(
        index
            .validate(&BTreeMap::from([(ObjectId::new([8; 32]), location(100))]))
            .is_err()
    );
    let overflow = self::fixture(&[(0, 10), (0, u64::MAX)], &[(0, 200)]);
    assert!(matches!(
        validate::<true>(&overflow).generation_zero.into_index(),
        Err(DurableError::EncodingOverflow)
    ));
}

#[test]
fn ordinary_validation_does_not_collect_recovery_evidence() {
    let fixture = fixture(&[(0, 10)], &[(0, 100)]);
    super::super::index_validation::PLACEMENT_COLLECTIONS.with(|count| count.set(0));
    validate::<false>(&fixture);
    super::super::index_validation::PLACEMENT_COLLECTIONS.with(|count| assert_eq!(count.get(), 0));
    validate::<true>(&fixture);
    super::super::index_validation::PLACEMENT_COLLECTIONS.with(|count| assert_eq!(count.get(), 2));
}

#[test]
fn ordinary_open_and_checkpoint_do_not_collect_generation_zero() {
    use super::super::RepresentationStore;
    use crate::volume::{AstridVolume, HostedFileVolume};
    use std::sync::Arc;

    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("test.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([9; 32]), []).unwrap();
    let object = store
        .describe_direct(OBJECT, &[42; 8], location(10))
        .unwrap();
    store.rebase_all_direct(&[object]).unwrap();
    drop(store);
    super::super::index_validation::PLACEMENT_COLLECTIONS.with(|count| count.set(0));
    let mut reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert!(reopened.contains_direct(OBJECT));
    reopened.checkpoint_volume(&volume, limits).unwrap();
    super::super::index_validation::PLACEMENT_COLLECTIONS.with(|count| assert_eq!(count.get(), 0));
}
