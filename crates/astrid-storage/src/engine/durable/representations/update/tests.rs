use super::*;
use crate::engine::durable::locations::test_take_page_auth_count;
use crate::engine::durable::representations::{
    ArenaLocation, LocationIndexMemoryBudget, ObjectId, PhysicalMapKey, RecoveryLimits,
    RepresentationProfile, cold::memoized_closure_handles,
};
use crate::volume::{AstridVolume, HostedFileVolume};
use std::sync::Arc;

fn fixture() -> (
    tempfile::TempDir,
    Arc<dyn AstridVolume>,
    RepresentationStore,
) {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("update.volume")).unwrap();
    let budget = LocationIndexMemoryBudget::new(std::num::NonZeroU64::new(352).unwrap()).unwrap();
    let mut store = RepresentationStore::activate_volume(
        &volume,
        RecoveryLimits::process_addressable(),
        ObjectId::new([1; 32]),
        [],
        budget,
    )
    .unwrap();
    let objects = (0_u64..512)
        .map(|index| direct(&store, index))
        .collect::<Vec<_>>();
    let update = store.append_direct_update(&objects).unwrap().unwrap();
    store.publish_direct_update(update).unwrap();
    (directory, volume, store)
}

fn direct(store: &RepresentationStore, index: u64) -> super::super::DirectArenaObject {
    let bytes = index.to_be_bytes();
    store
        .describe_direct(
            ObjectId::new(*blake3::hash(&bytes).as_bytes()),
            &bytes,
            ArenaLocation {
                offset: index.strict_mul(100),
                payload_len: 8,
                checksum: [3; 32],
            },
        )
        .unwrap()
}

fn additions(store: &RepresentationStore) -> Vec<DirectMapEntry> {
    let profile = RepresentationProfile::decode(
        &store
            .profiles
            .try_get(
                &Blake3PhysicalIdentity,
                PhysicalMapKey::from(store.direct_profile),
            )
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    (512..640)
        .map(|index| {
            store
                .prepare_direct_entry(&direct(store, index), &profile)
                .unwrap()
        })
        .collect()
}

// Ordinary providers remain a correctness control and a causal comparison for
// the operation workspace; both execute the unchanged canonical batch builder.
fn without_memo(
    store: &mut RepresentationStore,
    entries: &[DirectMapEntry],
) -> (Vec<MetadataFrame>, BTreeSet<PhysicalMapNodeId>) {
    store
        .representations
        .insert_entries(
            &Blake3PhysicalIdentity,
            entries
                .iter()
                .map(|entry| entry.representation.clone())
                .collect(),
        )
        .unwrap();
    store
        .placement_entries
        .insert_entries(
            &Blake3PhysicalIdentity,
            entries
                .iter()
                .map(|entry| entry.placement.clone())
                .collect(),
        )
        .unwrap();
    let mut frames = Vec::new();
    let mut appended = BTreeSet::new();
    for map in [&store.representations, &store.placement_entries] {
        let (presence, mut complete) = memoized_closure_handles(&store.persisted_map_nodes);
        append_new_reachable_map_nodes(&mut frames, map, &presence, &mut appended, &mut complete)
            .unwrap();
    }
    (frames, appended)
}

#[test]
fn direct_update_reuses_page_proofs_and_matches_uncached_canonical_output() {
    let (_dir, _volume, mut control) = fixture();
    let (_dir2, _volume2, mut memoized) = fixture();
    let entries = additions(&control);
    test_take_page_auth_count();
    let (expected_frames, expected_appended) = without_memo(&mut control, &entries);
    let ordinary = test_take_page_auth_count();
    let mut frames = Vec::new();
    let mut appended = BTreeSet::new();
    memoized
        .stage_direct_maps(&entries, &mut frames, &mut appended)
        .unwrap();
    let reused = test_take_page_auth_count();
    eprintln!("direct update page authentications: memoized={reused}, ordinary={ordinary}");
    assert!(
        reused > 0 && reused < ordinary,
        "operation page workspace: {reused} authentications vs {ordinary} ordinary"
    );
    assert_eq!(
        memoized.representations.root(),
        control.representations.root()
    );
    assert_eq!(
        memoized.placement_entries.root(),
        control.placement_entries.root()
    );
    assert_eq!(appended, expected_appended);
    let encode = |frames: Vec<MetadataFrame>| {
        frames
            .into_iter()
            .map(|frame| frame.encode().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(encode(frames), encode(expected_frames));
}

#[test]
fn direct_update_rejects_damaged_historical_locator_before_authority_changes() {
    let (_dir, _volume, mut store) = fixture();
    let active = store.active;
    let entries = additions(&store);
    store.persisted_map_nodes.truncate_test_run();
    assert!(
        store
            .stage_direct_maps(&entries, &mut Vec::new(), &mut BTreeSet::new())
            .is_err()
    );
    assert_eq!(store.active, active);
    assert!(store.persisted_map_nodes.failed());
}
