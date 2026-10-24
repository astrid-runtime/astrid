use super::super::{ArenaLocation, ObjectId, open_store_root};
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
    let mut volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store = RepresentationStore::activate_volume(
        &volume,
        limits,
        ObjectId::new([1; 32]),
        [],
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    for cycle in 0..4 {
        for offset in 1..=100 {
            advance(&mut store, cycle * 100 + offset);
        }
        let before = store.metadata.metadata().unwrap().len();
        let active = store.active;
        let reverse = store.reverse.snapshot().unwrap();
        store.checkpoint_volume(&volume, limits).unwrap();
        assert_eq!(store.active, active);
        assert_eq!(store.reverse.snapshot().unwrap(), reverse);
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
        // Close the owned handle before independent recovery. Windows holds
        // mandatory byte-range locks, so copying a live volume is not portable.
        drop(volume);
        volume = HostedFileVolume::open(&path).unwrap();
        let recovered = RepresentationStore::open_volume(
            &volume,
            limits,
            super::super::LocationIndexMemoryBudget::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(recovered.active, active);
        assert_eq!(recovered.reverse.snapshot().unwrap(), reverse);
        store = recovered;
    }
}

#[test]
fn native_checkpoints_preserve_updates_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let root = open_store_root(directory.path()).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store = RepresentationStore::activate(
        &root,
        limits,
        ObjectId::new([1; 32]),
        [],
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    for cycle in 0..3 {
        for offset in 1..=50 {
            advance(&mut store, cycle * 50 + offset);
        }
        let active = store.active;
        store.checkpoint_native(&root, limits).unwrap();
        assert!(store.metadata.metadata().unwrap().len() < 4096);
        drop(store);
        store = RepresentationStore::open(
            &root,
            limits,
            super::super::LocationIndexMemoryBudget::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(store.active, active);
        assert!(store.contains_direct(ObjectId::new([7; 32])).unwrap());
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
    let mut store = RepresentationStore::activate_volume(
        &volume,
        limits,
        ObjectId::new([1; 32]),
        [],
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
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
    let mut recovered = RepresentationStore::open_volume(
        &volume,
        limits,
        super::super::LocationIndexMemoryBudget::default(),
    )
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
    let mut store = RepresentationStore::activate_volume(
        &volume,
        limits,
        ObjectId::new([1; 32]),
        [],
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
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
    let mut recovered = RepresentationStore::open_volume(
        &volume,
        limits,
        super::super::LocationIndexMemoryBudget::default(),
    )
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
    assert!(
        RepresentationStore::open_volume(
            &volume,
            limits,
            super::super::LocationIndexMemoryBudget::default()
        )
        .is_err()
    );
}

#[test]
fn recovered_maps_retain_only_their_active_closures() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("residency.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store = RepresentationStore::activate_volume(
        &volume,
        limits,
        ObjectId::new([1; 32]),
        [],
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    for offset in 1..=40 {
        advance(&mut store, offset);
    }
    let active = store.active;
    let reverse = store.reverse.snapshot().unwrap();
    let historical_nodes = store.persisted_map_nodes.len();
    assert!(historical_nodes > 3);
    drop(store);

    let mut recovered = RepresentationStore::open_volume(
        &volume,
        limits,
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(recovered.active, active);
    assert_eq!(recovered.reverse.snapshot().unwrap(), reverse);
    for map in [
        &recovered.profiles,
        &recovered.representations,
        &recovered.placement_entries,
    ] {
        assert_eq!(map.entry_count(), 1);
        assert_eq!(
            super::super::node_view::node_count(map).unwrap(),
            1,
            "retain only this root's active page"
        );
    }
    assert_eq!(recovered.persisted_map_nodes.len(), historical_nodes);

    advance(&mut recovered, 41);
    let active = recovered.active;
    drop(recovered);
    let reopened = RepresentationStore::open_volume(
        &volume,
        limits,
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(reopened.active, active);
    assert_eq!(reopened.reverse.snapshot().unwrap(), reverse);
    assert_eq!(
        super::super::node_view::node_count(&reopened.placement_entries).unwrap(),
        1
    );
}

#[test]
fn spilled_checkpoint_preserves_authority_and_rejects_older_run_damage_before_current() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("spilled.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let budget = super::super::LocationIndexMemoryBudget::new(
        std::num::NonZeroU64::new(super::super::LocationIndexMemoryBudget::MIN_BYTES).unwrap(),
    )
    .unwrap();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), [], budget)
            .unwrap();
    for offset in 1..=17 {
        advance(&mut store, offset);
    }
    store.flush().unwrap();
    assert!(store.persisted_map_nodes.test_spilled_run_count() > 1);
    let active = store.active;
    let reverse = store.reverse.snapshot().unwrap();
    store.checkpoint_volume(&volume, limits).unwrap();
    assert_eq!(store.active, active);
    assert_eq!(store.reverse.snapshot().unwrap(), reverse);
    drop(store);
    let mut store = RepresentationStore::open_volume(&volume, limits, budget)
        .unwrap()
        .unwrap();
    assert_eq!(store.active, active);
    assert_eq!(store.reverse.snapshot().unwrap(), reverse);
    for offset in 18..=34 {
        advance(&mut store, offset);
    }
    store.flush().unwrap();
    assert!(store.persisted_map_nodes.test_spilled_run_count() > 1);
    let generation = store.journal_generation;
    let mut before =
        DurableFile::volume(Arc::clone(&volume), "representations/CURRENT", false).unwrap();
    let pointer = read_all(&mut before, "read test pointer").unwrap();
    store.persisted_map_nodes.truncate_oldest_test_run();
    assert!(store.checkpoint_volume(&volume, limits).is_err());
    assert_eq!(store.journal_generation, generation);
    let mut after =
        DurableFile::volume(Arc::clone(&volume), "representations/CURRENT", false).unwrap();
    assert_eq!(
        read_all(&mut after, "read unchanged pointer").unwrap(),
        pointer
    );
    assert!(store.persisted_map_nodes.failed());
}
