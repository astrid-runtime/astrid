//! Closed-tip capture and shared proof regressions, on disposable volumes only.

use std::io::{Seek, SeekFrom};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::super::adoption_tests::primed_volume;
use super::*;
use crate::engine::durable::representations::CheckpointControl;
use crate::engine::durable::representations::{ArenaLocation, ObjectId};

fn append_direct(store: &mut RepresentationStore, tag: u8) {
    let direct = store
        .describe_direct(
            ObjectId::new([tag; 32]),
            &[tag; 8],
            ArenaLocation {
                offset: u64::from(tag),
                payload_len: 8,
                checksum: [tag; 32],
            },
        )
        .unwrap();
    let update = store.append_direct_update(&[direct]).unwrap().unwrap();
    store.publish_direct_update(update).unwrap();
}

#[test]
fn capture_and_preparation_do_not_share_live_cursors_or_publish_current() {
    let (_directory, volume, mut store, limits) = primed_volume();
    store.metadata.seek(SeekFrom::Start(17)).unwrap();
    store.journal.seek(SeekFrom::Start(19)).unwrap();
    let captured_active = store.active;
    let captured_generation = store.journal_generation;
    let capture = CapturedCheckpoint::capture_from_media(
        &mut store,
        CheckpointMedia::Volume(Arc::clone(&volume)),
    )
    .unwrap();
    assert_eq!(store.metadata.stream_position().unwrap(), 17);
    assert_eq!(store.journal.stream_position().unwrap(), 19);
    let prepared = capture.prepare(limits, &AtomicBool::new(false)).unwrap();
    assert_eq!(store.metadata.stream_position().unwrap(), 17);
    assert_eq!(store.journal.stream_position().unwrap(), 19);
    assert_eq!(prepared.replacement.active, captured_active);
    assert_eq!(
        prepared.current.journal_generation,
        captured_generation.strict_add(1)
    );
    let recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.journal_generation, captured_generation);
    assert_eq!(recovered.active, captured_active);
    drop(prepared);
    // Dropping unpublished work reclaims only its private generation.
    assert_eq!(
        volume
            .list_regions("representations/generations/")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn preparation_digest_is_bound_to_capture_before_concurrent_source_append() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let captured_active = store.active;
    let capture = CapturedCheckpoint::capture_from_media(
        &mut store,
        CheckpointMedia::Volume(Arc::clone(&volume)),
    )
    .unwrap();
    append_direct(&mut store, 99);
    let new_active = store.active;
    let mut prepared = capture.prepare(limits, &AtomicBool::new(false)).unwrap();
    assert_eq!(prepared.replacement.active, captured_active);
    assert!(!prepared.tip_matches_live(&store));
    let tail = prepared.capture_tail(&store).unwrap();
    prepared
        .replay_tail(&tail, limits, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(prepared.replacement.active, new_active);
    let retired = prepared
        .finish_publish(&mut store, limits, &AtomicBool::new(false))
        .unwrap();
    retired.reclaim().unwrap();
    drop(store);
    let recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.active, new_active);
    assert!(recovered.contains_direct(ObjectId::new([99; 32])));
}

#[test]
fn closed_tip_uses_unchanged_semantic_reverse_validation() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let active = store.active;
    let mut capture = CapturedCheckpoint::capture_from_media(
        &mut store,
        CheckpointMedia::Volume(Arc::clone(&volume)),
    )
    .unwrap();
    capture.snapshot.reverse.clear();
    assert!(capture.prepare(limits, &AtomicBool::new(false)).is_err());
    let recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.active, active);
    assert_eq!(
        volume
            .list_regions("representations/generations/")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn cancelled_preparation_and_cancelled_publication_leave_current_untouched() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let active = store.active;
    let generation = store.journal_generation;
    let capture = CapturedCheckpoint::capture_from_media(
        &mut store,
        CheckpointMedia::Volume(Arc::clone(&volume)),
    )
    .unwrap();
    let cancel = AtomicBool::new(true);
    assert!(capture.prepare(limits, &cancel).is_err());
    cancel.store(false, Ordering::Release);
    let capture = CapturedCheckpoint::capture_from_media(
        &mut store,
        CheckpointMedia::Volume(Arc::clone(&volume)),
    )
    .unwrap();
    let prepared = capture.prepare(limits, &cancel).unwrap();
    cancel.store(true, Ordering::Release);
    assert!(
        prepared
            .finish_publish(&mut store, limits, &cancel)
            .is_err()
    );
    let recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.active, active);
    assert_eq!(recovered.journal_generation, generation);
    assert_eq!(
        volume
            .list_regions("representations/generations/")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn native_capture_opens_independent_cursors_and_reopens_published_generation() {
    let directory = tempfile::tempdir().unwrap();
    let root = Arc::new(super::super::super::open_store_root(directory.path()).unwrap());
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate(&root, limits, ObjectId::new([1; 32]), []).unwrap();
    append_direct(&mut store, 31);
    store.metadata.seek(SeekFrom::Start(7)).unwrap();
    store.journal.seek(SeekFrom::Start(9)).unwrap();
    let capture = CapturedCheckpoint::capture_from_media(
        &mut store,
        CheckpointMedia::Directory(Arc::clone(&root)),
    )
    .unwrap();
    assert_eq!(store.metadata.stream_position().unwrap(), 7);
    assert_eq!(store.journal.stream_position().unwrap(), 9);
    let prepared = capture.prepare(limits, &AtomicBool::new(false)).unwrap();
    assert_eq!(store.metadata.stream_position().unwrap(), 7);
    assert_eq!(store.journal.stream_position().unwrap(), 9);
    let active = store.active;
    let retired = prepared
        .finish_publish(&mut store, limits, &AtomicBool::new(false))
        .unwrap();
    retired.reclaim().unwrap();
    drop(store);
    let recovered = RepresentationStore::open(&root, limits).unwrap().unwrap();
    assert_eq!(recovered.active, active);
    assert!(recovered.contains_direct(ObjectId::new([31; 32])));
    assert_eq!(
        std::fs::read_dir(directory.path().join("representations/generations"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn draining_close_replays_bulk_residual_without_loosening_ordinary_preflight() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn crate::volume::AstridVolume> =
        crate::volume::HostedFileVolume::open(directory.path().join("drain.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    let control = CheckpointControl::running();
    let capture = CapturedCheckpoint::capture_from_media(
        &mut store,
        CheckpointMedia::Volume(Arc::clone(&volume)),
    )
    .unwrap();
    let mut prepared = capture.prepare(limits, &control).unwrap();
    append_direct(&mut store, 47);
    let expected = store.active;
    // The first insertion requires a bulk rebuild; it cannot run during the
    // ordinary writer's bounded final handover.
    assert!(!prepared.can_finish(&store, limits, &control).unwrap());
    control.request_drain();
    prepared
        .finish_drained(&mut store, limits, &control)
        .unwrap()
        .reclaim()
        .unwrap();
    assert!(control.is_draining());
    drop(store);
    let recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.active, expected);
    assert!(recovered.contains_direct(ObjectId::new([47; 32])));
    assert_eq!(
        volume
            .list_regions("representations/generations/")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn draining_does_not_bypass_initial_semantic_proof() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let expected = store.active;
    let mut capture = CapturedCheckpoint::capture_from_media(
        &mut store,
        CheckpointMedia::Volume(Arc::clone(&volume)),
    )
    .unwrap();
    capture.snapshot.reverse.clear();
    let control = CheckpointControl::running();
    control.request_drain();
    assert!(capture.prepare(limits, &control).is_err());
    let recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.active, expected);
    assert_eq!(
        volume
            .list_regions("representations/generations/")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn drained_publication_barrier_failure_installs_new_custody_and_retains_old_media() {
    use super::super::adoption_tests::SyncFailOnceVolume;
    let (_directory, volume, mut store, limits) = primed_volume();
    let old_generation = store.journal_generation;
    let failing = Arc::new(SyncFailOnceVolume::new(Arc::clone(&volume)));
    let media: Arc<dyn crate::volume::AstridVolume> = failing.clone();
    let control = CheckpointControl::running();
    let capture =
        CapturedCheckpoint::capture_from_media(&mut store, CheckpointMedia::Volume(media)).unwrap();
    let prepared = capture.prepare(limits, &control).unwrap();
    append_direct(&mut store, 49);
    let expected = store.active;
    control.request_drain();
    failing.arm_next_sync_failure();
    assert!(
        prepared
            .finish_drained(&mut store, limits, &control)
            .is_err()
    );
    assert_eq!(store.journal_generation, old_generation.strict_add(1));
    // CURRENT may have crossed the durable namespace boundary. Neither side
    // of that uncertain publication can be reclaimed by an error cleanup.
    assert_eq!(
        volume
            .list_regions("representations/generations/")
            .unwrap()
            .len(),
        4
    );
    drop(store);
    let recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.active, expected);
    assert!(recovered.contains_direct(ObjectId::new([49; 32])));
}
