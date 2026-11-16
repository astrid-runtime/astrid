use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use super::*;
use crate::engine::durable::format::{DurableFrameRange, DurablePrefixEnd};
use crate::storage_model::{ObjectId, RepresentationStateId};
use crate::volume::{AstridVolume, HostedFileVolume};

use super::super::super::{
    ArenaLocation, DurableFile, JOURNAL_MAGIC, JournalEntry, append_frame, open_store_root,
};

struct Fixture {
    _directory: tempfile::TempDir,
    volume: Option<Arc<dyn AstridVolume>>,
    root: cap_std::fs::Dir,
    store: RepresentationStore,
}

impl Fixture {
    fn new(hosted: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = open_store_root(directory.path()).unwrap();
        let volume = hosted.then(|| {
            HostedFileVolume::open(directory.path().join("test.volume")).unwrap()
                as Arc<dyn AstridVolume>
        });
        let limits = RecoveryLimits::process_addressable();
        let store = if let Some(volume) = &volume {
            RepresentationStore::activate_volume(volume, limits, ObjectId::new([1; 32]), [])
                .unwrap()
        } else {
            RepresentationStore::activate(&root, limits, ObjectId::new([1; 32]), []).unwrap()
        };
        Self {
            _directory: directory,
            volume,
            root,
            store,
        }
    }

    fn checkpoint(&mut self) {
        let limits = RecoveryLimits::process_addressable();
        if let Some(volume) = &self.volume {
            self.store.checkpoint_volume(volume, limits).unwrap();
        } else {
            self.store.checkpoint_native(&self.root, limits).unwrap();
        }
    }

    fn reopen(&self) -> RepresentationStore {
        let limits = RecoveryLimits::process_addressable();
        if let Some(volume) = &self.volume {
            RepresentationStore::open_volume(volume, limits)
                .unwrap()
                .unwrap()
        } else {
            RepresentationStore::open(&self.root, limits)
                .unwrap()
                .unwrap()
        }
    }
}

fn ends(store: &RepresentationStore) -> (DurablePrefixEnd, DurablePrefixEnd) {
    (
        DurablePrefixEnd::exclusive(store.metadata.metadata().unwrap().len()),
        DurablePrefixEnd::exclusive(store.journal.metadata().unwrap().len()),
    )
}

fn add(store: &mut RepresentationStore, start: u32, count: u32) {
    let objects: Vec<_> = (start..start.strict_add(count))
        .map(|ordinal| {
            let bytes = ordinal.to_le_bytes().repeat(16);
            store
                .describe_direct(
                    ObjectId::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                    &bytes,
                    ArenaLocation {
                        offset: u64::from(ordinal) * 512,
                        payload_len: 64,
                        checksum: [9; 32],
                    },
                )
                .unwrap()
        })
        .collect();
    let update = store.append_direct_update(&objects).unwrap().unwrap();
    store.publish_direct_update(update).unwrap();
}

fn tail_between(
    source: &RepresentationStore,
    from: (DurablePrefixEnd, DurablePrefixEnd),
    to: (DurablePrefixEnd, DurablePrefixEnd),
    expected_active: RepresentationStateId,
) -> CheckpointTail {
    CheckpointTail {
        metadata: DurableFrameRange::try_new(from.0, to.0).unwrap(),
        journal: DurableFrameRange::try_new(from.1, to.1).unwrap(),
        source_generation: source.journal_generation,
        expected_active,
    }
}

fn replay(
    target: &mut RepresentationStore,
    source: &mut RepresentationStore,
    from: (DurablePrefixEnd, DurablePrefixEnd),
    to: (DurablePrefixEnd, DurablePrefixEnd),
    expected_active: RepresentationStateId,
) -> Result<(), DurableError> {
    let tail = tail_between(source, from, to, expected_active);
    target.replay_checkpoint_tail(
        &mut source.metadata,
        &mut source.journal,
        &tail,
        RecoveryLimits::process_addressable(),
        &AtomicBool::new(false),
    )
}

fn nonbulk(
    target: &RepresentationStore,
    source: &mut RepresentationStore,
    from: (DurablePrefixEnd, DurablePrefixEnd),
    to: (DurablePrefixEnd, DurablePrefixEnd),
    expected_active: RepresentationStateId,
) -> Result<bool, DurableError> {
    let tail = CheckpointTail {
        metadata: DurableFrameRange::try_new(from.0, to.0).unwrap(),
        journal: DurableFrameRange::try_new(from.1, to.1).unwrap(),
        source_generation: source.journal_generation,
        expected_active,
    };
    target.checkpoint_tail_is_nonbulk(
        &mut source.metadata,
        &mut source.journal,
        &tail,
        RecoveryLimits::process_addressable(),
        &AtomicBool::new(false),
    )
}

#[test]
fn direct_tail_replays_in_new_epoch_and_ignores_later_appends() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        let initial_map_frames = source.store.map_frame_count;
        add(&mut source.store, 1, 128);
        add(&mut source.store, 129, 3);
        let to = ends(&source.store);
        let source_map_frames = source.store.map_frame_count - initial_map_frames;
        let expected = source.store.active;
        add(&mut source.store, 132, 7);
        let later = ends(&source.store);
        let generation = source.store.journal_generation;
        assert_ne!(generation, target.store.journal_generation);
        let (result, owned_decodes) = PhysicalMapNode::count_owned_decodes_during(|| {
            replay(&mut target.store, &mut source.store, from, to, expected)
        });
        result.unwrap();
        assert_eq!(owned_decodes, usize::try_from(source_map_frames).unwrap());
        assert_eq!(target.store.active, expected);
        assert_ne!(target.store.active, source.store.active);
        assert_eq!(target.store.reverse.len(), 131);
        assert_eq!(source.store.journal_generation, generation);
        let later_active = source.store.active;
        replay(
            &mut target.store,
            &mut source.store,
            to,
            later,
            later_active,
        )
        .unwrap();
        assert_eq!(target.store.active, source.store.active);
        assert_eq!(target.store.reverse, source.store.reverse);
        assert_eq!(target.store.catalogue, source.store.catalogue);
        assert_eq!(target.store.placements, source.store.placements);
        let reopened = target.reopen();
        assert_eq!(reopened.active, source.store.active);
        assert_eq!(reopened.reverse, source.store.reverse);
        assert_eq!(reopened.journal_generation, generation + 1);
    }
}

#[test]
fn empty_tail_requires_matching_expected_active() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let at = ends(&source.store);
        let active = source.store.active;
        replay(&mut target.store, &mut source.store, at, at, active).unwrap();
        assert!(nonbulk(&target.store, &mut source.store, at, at, active).unwrap());
        assert!(
            replay(
                &mut target.store,
                &mut source.store,
                at,
                at,
                RepresentationStateId::new([0x11; 32]),
            )
            .is_err()
        );
        assert!(
            nonbulk(
                &target.store,
                &mut source.store,
                at,
                at,
                RepresentationStateId::new([0x11; 32]),
            )
            .is_err()
        );
    }
}

#[test]
fn single_residual_is_nonbulk_and_preflight_does_not_mutate_destination() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        // A one-entry insertion into an empty map deliberately chooses the
        // ordinary dense rebuild. Seed both tips to exercise a non-bulk suffix.
        add(&mut source.store, 0, 1);
        add(&mut target.store, 0, 1);
        target.checkpoint();
        let before = target.store.active;
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        // Appends after the captured fence must not enter destination replay.
        add(&mut source.store, 2, 1);
        assert!(nonbulk(&target.store, &mut source.store, from, to, expected).unwrap());
        assert_eq!(target.store.active, before);
        assert_eq!(target.store.reverse.len(), 1);
        replay(&mut target.store, &mut source.store, from, to, expected).unwrap();
        assert_eq!(target.store.active, expected);
        target
            .store
            .verify_checkpoint_tip(&source.store)
            .unwrap_err();
        // Destination caught up to the captured residual tip, not later source.
        assert_eq!(target.store.reverse.len(), 2);
    }
}

#[test]
fn wide_residual_is_rejected_by_nonbulk_preflight() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        add(&mut source.store, 2, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        assert!(!nonbulk(&target.store, &mut source.store, from, to, expected).unwrap());
        assert_eq!(target.store.reverse.len(), 0);
    }
}

#[test]
fn tail_rejects_generation_and_cas_mismatch_without_mutating_source() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 2);
        let to = ends(&source.store);
        let expected = source.store.active;
        let mut bad = tail_between(&source.store, from, to, expected);
        bad.source_generation = source.store.journal_generation + 1;
        assert!(
            target
                .store
                .replay_checkpoint_tail(
                    &mut source.store.metadata,
                    &mut source.store.journal,
                    &bad,
                    RecoveryLimits::process_addressable(),
                    &AtomicBool::new(false),
                )
                .is_err()
        );
        target.store.active = RepresentationStateId::new([0x37; 32]);
        assert!(replay(&mut target.store, &mut source.store, from, to, expected).is_err());
        assert_eq!(ends(&source.store), to);
        assert_eq!(source.reopen().active, source.store.active);
    }
}

#[test]
fn tail_rejects_rebased_placements_instead_of_treating_them_as_additions() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        add(&mut source.store, 1, 2);
        add(&mut target.store, 1, 2);
        target.checkpoint();
        let from = ends(&source.store);
        let object = source
            .store
            .describe_direct(
                ObjectId::new(*blake3::hash(&1_u32.to_le_bytes()).as_bytes()),
                &1_u32.to_le_bytes().repeat(16),
                ArenaLocation {
                    offset: 9000,
                    payload_len: 64,
                    checksum: [5; 32],
                },
            )
            .unwrap();
        source.store.rebase_all_direct(&[object]).unwrap();
        let to = ends(&source.store);
        let expected = source.store.active;
        assert!(replay(&mut target.store, &mut source.store, from, to, expected).is_err());
        assert_eq!(ends(&source.store), to);
        assert_eq!(source.reopen().active, source.store.active);
    }
}

#[test]
fn tail_rejects_whole_journal_frame_drop_and_wrong_expected_active() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        let to = ends(&source.store);
        let expected = source.store.active;

        // Drop the trailing journal frame by truncating the captured end early.
        let truncated = CheckpointTail {
            metadata: DurableFrameRange::try_new(from.0, to.0).unwrap(),
            journal: DurableFrameRange::try_new(from.1, from.1).unwrap(),
            source_generation: source.store.journal_generation,
            expected_active: expected,
        };
        assert!(
            target
                .store
                .replay_checkpoint_tail(
                    &mut source.store.metadata,
                    &mut source.store.journal,
                    &truncated,
                    RecoveryLimits::process_addressable(),
                    &AtomicBool::new(false),
                )
                .is_err()
        );

        // Captured expected_active must match the residual tip, not an older identity.
        assert!(
            replay(
                &mut target.store,
                &mut source.store,
                from,
                to,
                RepresentationStateId::new([0x5a; 32]),
            )
            .is_err()
        );
        assert_eq!(ends(&source.store), to);
    }
}

#[test]
fn cancelled_replay_fails_closed() {
    let mut source = Fixture::new(true);
    let mut target = Fixture::new(true);
    target.checkpoint();
    let from = ends(&source.store);
    add(&mut source.store, 1, 1);
    let to = ends(&source.store);
    let expected = source.store.active;
    let tail = tail_between(&source.store, from, to, expected);
    let cancel = AtomicBool::new(true);
    assert!(
        target
            .store
            .replay_checkpoint_tail(
                &mut source.store.metadata,
                &mut source.store.journal,
                &tail,
                RecoveryLimits::process_addressable(),
                &cancel,
            )
            .is_err()
    );
    assert!(
        target
            .store
            .checkpoint_tail_is_nonbulk(
                &mut source.store.metadata,
                &mut source.store.journal,
                &tail,
                RecoveryLimits::process_addressable(),
                &cancel,
            )
            .is_err()
    );
}

fn flip_last_byte(file: &mut DurableFile) {
    let length = file.metadata().unwrap().len();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xA5;
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_data().unwrap();
    assert_eq!(file.metadata().unwrap().len(), length);
}

#[test]
fn source_metadata_crc_corruption_rejects_without_mutating_destination() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        let before = target.store.active;
        flip_last_byte(&mut source.store.metadata);
        assert!(replay(&mut target.store, &mut source.store, from, to, expected).is_err());
        assert_eq!(target.store.active, before);
        assert_eq!(ends(&source.store), to);
    }
}

#[test]
fn forged_crc_valid_map_identity_rejects_before_destination_mutation() {
    use crate::engine::durable::format::{frame_checksum, frame_header};

    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        let before = (target.store.active, ends(&target.store));
        let range = DurableFrameRange::try_new(from.0, to.0).unwrap();
        let (location, payload) = read_frame_in_range(
            &mut source.store.metadata,
            format::METADATA_FILE,
            METADATA_MAGIC,
            RecoveryLimits::process_addressable(),
            range,
            from.0,
        )
        .unwrap()
        .unwrap();
        let mut frame = MetadataFrame::decode(&payload).unwrap();
        assert_eq!(frame.kind, MetadataKind::MapNode);
        frame.identity[0] ^= 1;
        let forged = frame.encode().unwrap();
        assert_eq!(forged.len(), payload.len());
        let length = u64::try_from(forged.len()).unwrap();
        let header = frame_header(
            METADATA_MAGIC,
            length,
            frame_checksum(METADATA_MAGIC, length, &forged),
        );
        source
            .store
            .metadata
            .seek(SeekFrom::Start(location.offset()))
            .unwrap();
        source.store.metadata.write_all(&header).unwrap();
        source.store.metadata.write_all(&forged).unwrap();
        source.store.metadata.sync_data().unwrap();
        assert!(matches!(
            replay(&mut target.store, &mut source.store, from, to, expected),
            Err(DurableError::InvalidRepresentationState(
                "metadata identity does not match canonical value"
            ))
        ));
        assert_eq!((target.store.active, ends(&target.store)), before);
        assert_eq!(ends(&source.store), to);
    }
}

#[test]
fn source_journal_crc_corruption_rejects_without_mutating_destination() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        let before = target.store.active;
        flip_last_byte(&mut source.store.journal);
        assert!(replay(&mut target.store, &mut source.store, from, to, expected).is_err());
        assert_eq!(target.store.active, before);
        assert_eq!(ends(&source.store), to);
    }
}

#[test]
fn source_whole_metadata_frame_drop_rejects_without_mutating_destination() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        let before = target.store.active;
        // Keep journal intact; drop the trailing metadata frame by truncating early.
        let truncated = CheckpointTail {
            metadata: DurableFrameRange::try_new(from.0, from.0).unwrap(),
            journal: DurableFrameRange::try_new(from.1, to.1).unwrap(),
            source_generation: source.store.journal_generation,
            expected_active: expected,
        };
        assert!(
            target
                .store
                .replay_checkpoint_tail(
                    &mut source.store.metadata,
                    &mut source.store.journal,
                    &truncated,
                    RecoveryLimits::process_addressable(),
                    &AtomicBool::new(false),
                )
                .is_err()
        );
        assert_eq!(target.store.active, before);
        assert_eq!(ends(&source.store), to);
    }
}

#[test]
fn forged_crc_valid_source_cas_rejects_without_mutating_destination() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        let before = target.store.active;
        // Replace the committed CAS with another CRC-valid frame that names a
        // forged replacement identity while preserving generation shape.
        source.store.journal.set_len(from.1.get()).unwrap();
        source
            .store
            .journal
            .seek(SeekFrom::Start(from.1.get()))
            .unwrap();
        let forged = JournalEntry::StateCas {
            journal_generation: source.store.journal_generation,
            expected: Some(before),
            replacement: RepresentationStateId::new([0x44; 32]),
        };
        append_frame(&mut source.store.journal, JOURNAL_MAGIC, &forged.encode()).unwrap();
        source.store.journal.sync_data().unwrap();
        let forged_end =
            DurablePrefixEnd::exclusive(source.store.journal.metadata().unwrap().len());
        let forged_tail = CheckpointTail {
            metadata: DurableFrameRange::try_new(from.0, to.0).unwrap(),
            journal: DurableFrameRange::try_new(from.1, forged_end).unwrap(),
            source_generation: source.store.journal_generation,
            expected_active: expected,
        };
        assert!(
            target
                .store
                .replay_checkpoint_tail(
                    &mut source.store.metadata,
                    &mut source.store.journal,
                    &forged_tail,
                    RecoveryLimits::process_addressable(),
                    &AtomicBool::new(false),
                )
                .is_err()
        );
        assert_eq!(target.store.active, before);
    }
}

#[test]
fn wide_preflight_returns_before_unreadable_metadata() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        add(&mut source.store, 2, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        // Make metadata unreadable inside the residual. Preflight must still
        // return Ok(false) from the second journal CAS without scanning it.
        flip_last_byte(&mut source.store.metadata);
        assert!(!nonbulk(&target.store, &mut source.store, from, to, expected).unwrap());
        assert_eq!(target.store.reverse.len(), 0);
        assert_eq!(ends(&source.store), to);
    }
}

#[test]
fn cancel_before_publish_leaves_destination_and_source_unchanged() {
    let mut source = Fixture::new(true);
    let mut target = Fixture::new(true);
    target.checkpoint();
    let from = ends(&source.store);
    add(&mut source.store, 1, 1);
    let to = ends(&source.store);
    let expected = source.store.active;
    let before_active = target.store.active;
    let before_target = ends(&target.store);
    let before_source = ends(&source.store);
    let tail = tail_between(&source.store, from, to, expected);
    let cancel = AtomicBool::new(true);
    assert!(
        target
            .store
            .replay_checkpoint_tail(
                &mut source.store.metadata,
                &mut source.store.journal,
                &tail,
                RecoveryLimits::process_addressable(),
                &cancel,
            )
            .is_err()
    );
    assert_eq!(target.store.active, before_active);
    assert_eq!(ends(&target.store), before_target);
    assert_eq!(ends(&source.store), before_source);
}

#[test]
fn destination_journal_fresh_readback_rejects_crc_and_forged_cas() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        let prior = target.store.active;
        let journal_generation = target.store.journal_generation;
        let journal_from = ends(&target.store).1;
        replay(&mut target.store, &mut source.store, from, to, expected).unwrap();
        let journal_to = ends(&target.store).1;
        let range = DurableFrameRange::try_new(journal_from, journal_to).unwrap();
        let limits = RecoveryLimits::process_addressable();
        let cancel = AtomicBool::new(false);

        // CRC-valid length-preserving corruption of the destination CAS.
        flip_last_byte(&mut target.store.journal);
        assert!(
            verify_checkpoint_journal_tail(
                &mut target.store.journal,
                range,
                journal_generation,
                prior,
                expected,
                limits,
                &cancel,
            )
            .is_err()
        );

        // Restore length and write a CRC-valid forged CAS instead.
        target.store.journal.set_len(journal_from.get()).unwrap();
        target
            .store
            .journal
            .seek(SeekFrom::Start(journal_from.get()))
            .unwrap();
        let forged = JournalEntry::StateCas {
            journal_generation,
            expected: Some(prior),
            replacement: RepresentationStateId::new([0x3c; 32]),
        };
        append_frame(&mut target.store.journal, JOURNAL_MAGIC, &forged.encode()).unwrap();
        target.store.journal.sync_data().unwrap();
        let forged_range = DurableFrameRange::try_new(
            journal_from,
            DurablePrefixEnd::exclusive(target.store.journal.metadata().unwrap().len()),
        )
        .unwrap();
        assert!(
            verify_checkpoint_journal_tail(
                &mut target.store.journal,
                forged_range,
                journal_generation,
                prior,
                expected,
                limits,
                &cancel,
            )
            .is_err()
        );
    }
}

#[test]
fn destination_metadata_fresh_readback_rejects_crc_corruption() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        let metadata_from = ends(&target.store).0;
        replay(&mut target.store, &mut source.store, from, to, expected).unwrap();
        let metadata_to = ends(&target.store).0;
        let range = DurableFrameRange::try_new(metadata_from, metadata_to).unwrap();
        flip_last_byte(&mut target.store.metadata);
        // Empty expected set is fine: framing/CRC fails before authority finish.
        let expected_nodes = std::collections::BTreeSet::new();
        assert!(
            target
                .store
                .verify_checkpoint_metadata_tail(
                    range,
                    &expected_nodes,
                    RecoveryLimits::process_addressable(),
                    &AtomicBool::new(false),
                )
                .is_err()
        );
    }
}

#[test]
fn single_bulk_residual_requires_off_writer_catchup() {
    for hosted in [false, true] {
        let mut source = Fixture::new(hosted);
        let mut target = Fixture::new(hosted);
        target.checkpoint();
        let before = target.store.active;
        let before_ends = ends(&target.store);
        let from = ends(&source.store);
        add(&mut source.store, 1, 1);
        let to = ends(&source.store);
        let expected = source.store.active;
        assert!(!nonbulk(&target.store, &mut source.store, from, to, expected).unwrap());
        assert_eq!(target.store.active, before);
        assert_eq!(ends(&target.store), before_ends);
        replay(&mut target.store, &mut source.store, from, to, expected).unwrap();
        assert_eq!(target.store.active, expected);
        target.store.verify_checkpoint_tip(&source.store).unwrap();
    }
}
