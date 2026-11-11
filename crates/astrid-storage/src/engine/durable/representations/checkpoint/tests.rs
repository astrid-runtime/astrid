use super::super::{ArenaLocation, DurableError, ObjectId, open_store_root};
use super::*;
use crate::volume::{AstridVolume, HostedFileVolume};
use std::sync::Arc;

fn advance(store: &mut RepresentationStore, offset: u64) {
    let object = store
        .describe_direct(
            ObjectId::new([7; 32]),
            &[42; 8],
            ArenaLocation {
                offset,
                payload_len: 8,
                checksum: [3; 32],
            },
        )
        .unwrap();
    store.rebase_all_direct(&[object]).unwrap();
}

#[test]
fn volume_checkpoints_bound_metadata_and_preserve_authority_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("test.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    for cycle in 0..4 {
        for offset in 1..=100 {
            advance(&mut store, cycle * 100 + offset);
        }
        let before = store.metadata.metadata().unwrap().len();
        let active = store.active;
        let reverse = store.reverse.clone();
        store.checkpoint_volume(&volume, limits).unwrap();
        assert_eq!(store.active, active);
        assert_eq!(store.reverse, reverse);
        assert!(store.metadata.metadata().unwrap().len() < before / 10);
        assert!(store.metadata.metadata().unwrap().len() < 4096);
        assert_eq!(
            volume
                .list_regions("representations/generations/")
                .unwrap()
                .len(),
            2
        );
        drop(store);
        // Independent file reopen, not merely replay from the live region map.
        std::fs::copy(&path, directory.path().join("reopen.volume")).unwrap();
        let reopened: Arc<dyn AstridVolume> =
            HostedFileVolume::open(directory.path().join("reopen.volume")).unwrap();
        let recovered = RepresentationStore::open_volume(&reopened, limits)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.active, active);
        assert_eq!(recovered.reverse, reverse);
        store = RepresentationStore::open_volume(&volume, limits)
            .unwrap()
            .unwrap();
    }
}

#[test]
fn native_checkpoints_preserve_updates_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let root = open_store_root(directory.path()).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate(&root, limits, ObjectId::new([1; 32]), []).unwrap();
    for cycle in 0..3 {
        for offset in 1..=50 {
            advance(&mut store, cycle * 50 + offset);
        }
        let active = store.active;
        store.checkpoint_native(&root, limits).unwrap();
        assert!(store.metadata.metadata().unwrap().len() < 4096);
        drop(store);
        store = RepresentationStore::open(&root, limits).unwrap().unwrap();
        assert_eq!(store.active, active);
        assert!(store.contains_direct(ObjectId::new([7; 32])));
        assert_eq!(
            std::fs::read_dir(directory.path().join("representations/generations"))
                .unwrap()
                .count(),
            1
        );
    }
}

#[test]
fn unpublished_volume_checkpoint_cannot_change_authority_and_is_retryable() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("test.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    advance(&mut store, 1);
    let active = store.active;
    let metadata = DurableFile::volume(
        Arc::clone(&volume),
        "representations/generations/0000000000000002/metadata.arena",
        true,
    )
    .unwrap();
    let journal = DurableFile::volume(
        Arc::clone(&volume),
        "representations/generations/0000000000000002/state.journal",
        true,
    )
    .unwrap();
    let (replacement, _) = store.checkpoint_into(metadata, journal, limits).unwrap();
    drop(replacement);
    drop(store);
    let mut recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.journal_generation, 1);
    assert_eq!(recovered.active, active);
    recovered.checkpoint_volume(&volume, limits).unwrap();
    assert_eq!(recovered.journal_generation, 2);
    assert_eq!(recovered.active, active);
}

#[test]
fn published_checkpoint_recovers_before_cleanup_and_does_not_fall_back_on_corruption() {
    use crate::volume::VolumeRegion;
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("test.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    advance(&mut store, 1);
    let active = store.active;
    let metadata = DurableFile::volume(
        Arc::clone(&volume),
        "representations/generations/0000000000000002/metadata.arena",
        true,
    )
    .unwrap();
    let journal = DurableFile::volume(
        Arc::clone(&volume),
        "representations/generations/0000000000000002/state.journal",
        true,
    )
    .unwrap();
    let (replacement, current) = store.checkpoint_into(metadata, journal, limits).unwrap();
    let mut pointer =
        DurableFile::volume(Arc::clone(&volume), "representations/CURRENT.tmp", true).unwrap();
    append_frame(&mut pointer, format::CURRENT_MAGIC, &current.encode()).unwrap();
    pointer.sync_data().unwrap();
    volume
        .replace_region(
            &VolumeRegion::new("representations/CURRENT.tmp").unwrap(),
            &VolumeRegion::new("representations/CURRENT").unwrap(),
        )
        .unwrap();
    volume.sync().unwrap();
    drop(replacement);
    drop(store);
    assert_eq!(
        volume
            .list_regions("representations/generations/")
            .unwrap()
            .len(),
        4
    );
    let mut recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.journal_generation, 2);
    assert_eq!(recovered.active, active);
    recovered.checkpoint_volume(&volume, limits).unwrap();
    assert_eq!(
        volume
            .list_regions("representations/generations/")
            .unwrap()
            .len(),
        2
    );
    drop(recovered);
    // A broken authoritative snapshot must fail; surviving logical data is not
    // permission to invent an older physical placement state.
    volume
        .set_region_len(
            &VolumeRegion::new("representations/generations/0000000000000003/metadata.arena")
                .unwrap(),
            0,
        )
        .unwrap();
    volume.sync().unwrap();
    assert!(RepresentationStore::open_volume(&volume, limits).is_err());
}

#[test]
fn recovered_maps_retain_only_their_active_closures() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("residency.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    for offset in 1..=40 {
        advance(&mut store, offset);
    }
    let active = store.active;
    let reverse = store.reverse.clone();
    let historical_bytes = store.metadata.metadata().unwrap().len();
    let final_placement = store.placement_entries.root();
    drop(store);

    let mut recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.active, active);
    assert_eq!(recovered.reverse, reverse);
    for map in [
        &recovered.profiles,
        &recovered.representations,
        &recovered.placement_entries,
    ] {
        assert_eq!(map.entry_count(), 1);
        assert_eq!(map.nodes().len(), 1, "retain only this root's active page");
    }
    assert_eq!(recovered.persisted_map_nodes.len(), 3);
    assert_eq!(
        recovered.metadata.metadata().unwrap().len(),
        historical_bytes
    );

    // Reintroduce a prior placement whose ID memo was evicted. Its old durable
    // frames remain valid, and re-appending identical canonical nodes is safe.
    advance(&mut recovered, 1);
    assert_ne!(recovered.placement_entries.root(), final_placement);
    assert_eq!(recovered.persisted_map_nodes.len(), 3);
    advance(&mut recovered, 40);
    assert_eq!(recovered.placement_entries.root(), final_placement);
    assert_eq!(recovered.persisted_map_nodes.len(), 3);
    advance(&mut recovered, 41);
    let active = recovered.active;
    drop(recovered);
    let reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.active, active);
    assert_eq!(reopened.reverse, reverse);
    assert_eq!(reopened.placement_entries.nodes().len(), 1);
}

#[test]
fn should_checkpoint_uses_live_frame_count_versus_tip_nodes() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("residue.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    assert!(!store.should_checkpoint_representations_metadata());
    for offset in 1..=40 {
        advance(&mut store, offset);
    }
    assert!(
        store.map_frame_count() > store.resident_map_node_count(),
        "path-copy history should accumulate MapNode frames"
    );
    assert!(
        store.should_checkpoint_representations_metadata(),
        "O >= T must fire with live tip count, not a stale byte budget"
    );
    let before = store.metadata.metadata().unwrap().len();
    assert!(store.maybe_checkpoint_volume(&volume, limits).unwrap());
    assert!(!store.should_checkpoint_representations_metadata());
    assert!(store.map_frame_count() <= store.resident_map_node_count());
    assert!(store.metadata.metadata().unwrap().len() < before / 10);
    // Idempotent when residue is below tip.
    assert!(!store.maybe_checkpoint_volume(&volume, limits).unwrap());
}

#[test]
fn checkpoint_reopen_restores_frame_count_from_scan_including_duplicates() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("frames.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    for offset in 1..=24 {
        advance(&mut store, offset);
    }
    // Force residency reclaim then reintroduce an earlier placement so an identical
    // canonical MapNode is appended again (duplicate frame in the generation).
    for offset in 1..=24 {
        advance(&mut store, offset);
    }
    let frames_before = store.map_frame_count();
    assert!(frames_before >= store.resident_map_node_count());
    store.checkpoint_volume(&volume, limits).unwrap();
    assert!(store.map_frame_count() <= store.resident_map_node_count());
    let tip_frames = store.map_frame_count();
    drop(store);

    let recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.map_frame_count(), tip_frames);
    assert!(recovered.map_frame_count() <= recovered.resident_map_node_count());
}

#[test]
fn prepare_checkpoint_recovery_limit_failure_keeps_old_handles_readable() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("fault-phase.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    for offset in 1..=8 {
        advance(&mut store, offset);
    }
    let active = store.active;
    let frames = store.map_frame_count();
    let generation = store.journal_generation;
    let metadata_len = store.metadata.metadata().unwrap().len();
    // Independent read handles on the published generation must remain usable.
    let observer = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(observer.journal_generation, generation);
    assert_eq!(observer.active, active);
    assert_eq!(observer.metadata.metadata().unwrap().len(), metadata_len);

    // Tiny frame ceiling makes tip verify fail after the replacement files are written.
    let tiny = RecoveryLimits::new(1).unwrap();
    let err = store
        .prepare_checkpoint_volume(&volume, tiny)
        .expect_err("prepare must fail under a one-byte frame ceiling");
    assert!(
        matches!(err, DurableError::FrameTooLarge { .. })
            || err.to_string().contains("frame")
            || err.to_string().contains("limit"),
        "unexpected prepare error: {err:?}"
    );
    assert_eq!(store.journal_generation, generation);
    assert_eq!(store.active, active);
    assert_eq!(store.map_frame_count(), frames);
    assert_eq!(store.metadata.metadata().unwrap().len(), metadata_len);
    assert!(store.contains_direct(ObjectId::new([7; 32])));
    assert_eq!(observer.journal_generation, generation);
    assert_eq!(observer.active, active);
    assert_eq!(observer.metadata.metadata().unwrap().len(), metadata_len);
    assert!(observer.contains_direct(ObjectId::new([7; 32])));

    store.checkpoint_volume(&volume, limits).unwrap();
    assert!(store.journal_generation > generation);
    assert_eq!(store.active, active);
    assert!(store.contains_direct(ObjectId::new([7; 32])));
}
