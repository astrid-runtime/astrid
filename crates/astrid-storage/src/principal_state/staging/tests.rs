use std::io::{Read as _, Seek as _, Write as _};
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;
use uuid::Uuid;

use super::format::{
    LegacyStagingIntent, LegacyStagingOwner, StagingIntent, decode_intent, decode_legacy_intent,
    encode_intent, encode_legacy_intent,
};
use super::journal::{
    JournalRecord, StageKey, append_records, encoded_frame, flush_journal, refresh_frame_checksum,
};
use super::*;
use crate::principal_state::native_io::{atomic_write, sync_directory};

fn uid() -> PrincipalUid {
    let digest = blake3::Hasher::new_derive_key("astrid staging owner test fixture v1")
        .update(b"alice")
        .finalize();
    PrincipalUid::from_bytes(*digest.as_bytes())
}

fn owner() -> StateOwner {
    StateOwner::Principal(uid())
}

#[test]
fn public_staging_handles_remain_unwind_safe() {
    fn assert_unwind_safe<T: std::panic::RefUnwindSafe + std::panic::UnwindSafe>() {}

    assert_unwind_safe::<NativeContentStagingArea>();
    assert_unwind_safe::<StagedContentWriter>();
}

fn open_area(path: &Path) -> NativeContentStagingArea {
    open_area_result(path).unwrap()
}

fn open_area_result(path: &Path) -> StorageResult<NativeContentStagingArea> {
    NativeContentStagingArea::open_with_group_commit_policy(path, GroupCommitPolicy::immediate())
}

fn writer(area: &NativeContentStagingArea, name: &str) -> StagedContentWriter {
    area.begin(
        owner(),
        ContentName::new(name).unwrap(),
        ChunkingProfile::ASTRID_V1,
    )
    .unwrap()
}

#[test]
fn begin_collision_preserves_the_existing_generation() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let id = StagedContentId(Uuid::from_u128(42));
    let path = area.inner.generations.join(open_generation_name(id));
    std::fs::write(&path, b"other writer's bytes").unwrap();

    let error = area
        .begin_with_id(
            owner(),
            ContentName::new("collision.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            id,
        )
        .unwrap_err();

    assert!(error.to_string().contains("create private file"));
    assert_eq!(std::fs::read(path).unwrap(), b"other writer's bytes");
}

fn wait_for_queued_seals(area: &NativeContentStagingArea, expected: usize) {
    let started = Instant::now();
    while area.queued_seal_count() < expected {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for {expected} queued seals"
        );
        std::thread::yield_now();
    }
}

fn read_logical(staged: &ReadyStagedContent) -> Vec<u8> {
    let mut bytes = Vec::new();
    open_private_file(&staged.content_path())
        .unwrap()
        .take(staged.logical_bytes())
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

#[derive(Debug)]
struct FailOnce {
    point: StagingFaultPoint,
    fired: AtomicBool,
}

#[derive(Debug)]
struct BarrierAt {
    point: StagingFaultPoint,
    barrier: Arc<Barrier>,
}

#[derive(Debug)]
struct PauseAt {
    point: StagingFaultPoint,
    reached: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[derive(Debug)]
struct PauseFirstAt {
    point: StagingFaultPoint,
    fired: AtomicBool,
    reached: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl StagingFaultInjector for BarrierAt {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()> {
        if point == self.point {
            self.barrier.wait();
        }
        Ok(())
    }
}

impl StagingFaultInjector for PauseAt {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()> {
        if point == self.point {
            self.reached.wait();
            self.release.wait();
        }
        Ok(())
    }
}

impl StagingFaultInjector for PauseFirstAt {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()> {
        if point == self.point && !self.fired.swap(true, AtomicOrdering::SeqCst) {
            self.reached.wait();
            self.release.wait();
        }
        Ok(())
    }
}

impl StagingFaultInjector for FailOnce {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()> {
        if point == self.point && !self.fired.swap(true, AtomicOrdering::SeqCst) {
            Err(connection(format!("injected staging fault at {point:?}")))
        } else {
            Ok(())
        }
    }
}

fn open_with_fault(path: &Path, point: StagingFaultPoint) -> NativeContentStagingArea {
    NativeContentStagingArea::open_configured(
        path.to_path_buf(),
        GroupCommitPolicy::immediate(),
        Arc::new(FailOnce {
            point,
            fired: AtomicBool::new(false),
        }),
    )
    .unwrap()
}

#[test]
fn intent_round_trips_and_rejects_corruption() {
    let intent = StagingIntent {
        sequence: 7,
        id: StagedContentId(Uuid::parse_str("86c54e54-a944-41d2-8bf1-28be44985973").unwrap()),
        owner: owner(),
        name: ContentName::new("projects/game/assets.bin").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 98_765,
    };
    let bytes = encode_intent(&intent).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        "4153545249442d53544147452d5632000200070000000000000086c54e54a94441d28bf128be44985973210000000000000001003243b2489c6f911b35f55a12ad27bdfc996669c927d65548321c51bf48b6c5180000000000000070726f6a656374732f67616d652f6173736574732e62696e010100010040000000000100000004000000000000000000cd81010000000000b5cd550559ff256d340253488186ad0c240c07eb2e244205e2445356353706e2"
    );
    assert_eq!(decode_intent(&bytes).unwrap(), intent);

    let mut corrupt = bytes;
    corrupt[24] ^= 0x80;
    assert_eq!(
        decode_intent(&corrupt),
        Err("staged intent checksum mismatch")
    );
}

#[test]
fn alias_intent_migration_is_crash_idempotent_and_reaches_the_flat_journal() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let writing = root.join(legacy::WRITING_DIRECTORY);
    let ready = root.join(legacy::READY_DIRECTORY);
    let quarantine = root.join(QUARANTINE_DIRECTORY);
    for path in [&writing, &ready, &quarantine] {
        std::fs::create_dir_all(path).unwrap();
    }
    let malformed_id = StagedContentId(Uuid::new_v4());
    let malformed = writing.join(malformed_id.to_string());
    std::fs::write(&malformed, b"not a legacy staging directory").unwrap();

    let id = StagedContentId(Uuid::new_v4());
    let staging_directory = writing.join(id.to_string());
    std::fs::create_dir(&staging_directory).unwrap();
    std::fs::write(
        staging_directory.join(legacy::CONTENT_FILE),
        b"durable staged bytes",
    )
    .unwrap();
    let legacy_intent = LegacyStagingIntent {
        sequence: 4,
        id,
        owner: LegacyStagingOwner::Principal(PrincipalId::new("alice").unwrap()),
        name: ContentName::new("projects/game/save.bin").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 20,
    };
    atomic_write(
        &staging_directory.join(migration::LEGACY_INTENT_FILE),
        &encode_legacy_intent(&legacy_intent).unwrap(),
    )
    .unwrap();
    let migrated = StagingIntent {
        sequence: legacy_intent.sequence,
        id,
        owner: owner(),
        name: legacy_intent.name,
        profile: legacy_intent.profile,
        logical_bytes: legacy_intent.logical_bytes,
    };
    atomic_write(
        &staging_directory.join(legacy::INTENT_FILE),
        &encode_intent(&migrated).unwrap(),
    )
    .unwrap();

    migrate_alias_owner_intents(root, |alias| {
        assert_eq!(alias.as_str(), "alice");
        Ok(uid())
    })
    .unwrap();
    migrate_alias_owner_intents(root, |_| {
        panic!("an already-migrated intent must not be resolved twice")
    })
    .unwrap();

    assert!(
        !staging_directory
            .join(migration::LEGACY_INTENT_FILE)
            .exists()
    );
    assert_eq!(
        decode_intent(&std::fs::read(staging_directory.join(legacy::INTENT_FILE)).unwrap())
            .unwrap(),
        migrated
    );
    let reopened = open_area(root);
    let entries = reopened.ready().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].owner(), &owner());
    assert_eq!(read_logical(&entries[0]), b"durable staged bytes");
    assert!(!malformed.exists());
    assert!(
        quarantine
            .join(format!("{malformed_id}.legacy-unsealed.0"))
            .exists()
    );
}

#[test]
fn conflicting_alias_intents_fail_before_any_entry_is_migrated() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let writing = root.join(legacy::WRITING_DIRECTORY);
    let ready = root.join(legacy::READY_DIRECTORY);
    std::fs::create_dir_all(&writing).unwrap();
    std::fs::create_dir_all(&ready).unwrap();
    let id = StagedContentId(Uuid::new_v4());
    let sequence = 17;
    let alias = PrincipalId::new("alice").unwrap();
    let entries = [
        (writing.join(id.to_string()), "writing"),
        (ready.join(format!("{sequence:020}-{id}")), "ready"),
    ];
    for (path, name) in &entries {
        std::fs::create_dir(path).unwrap();
        let intent = LegacyStagingIntent {
            sequence,
            id,
            owner: LegacyStagingOwner::Principal(alias.clone()),
            name: ContentName::new(*name).unwrap(),
            profile: ChunkingProfile::ASTRID_V1,
            logical_bytes: 0,
        };
        atomic_write(
            &path.join(migration::LEGACY_INTENT_FILE),
            &encode_legacy_intent(&intent).unwrap(),
        )
        .unwrap();
    }

    let error = migrate_alias_owner_intents(root, |_| Ok(uid())).unwrap_err();
    assert!(error.to_string().contains("disagrees"), "{error}");
    for (path, _) in entries {
        assert!(path.join(migration::LEGACY_INTENT_FILE).exists());
        assert!(!path.join(legacy::INTENT_FILE).exists());
    }
}

#[test]
fn legacy_intent_decoder_does_not_accept_uid_intents() {
    let intent = StagingIntent {
        sequence: 7,
        id: StagedContentId(Uuid::parse_str("86c54e54-a944-41d2-8bf1-28be44985973").unwrap()),
        owner: owner(),
        name: ContentName::new("projects/game/assets.bin").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 98_765,
    };
    assert_eq!(
        decode_legacy_intent(&encode_intent(&intent).unwrap()),
        Err("staged intent checksum mismatch")
    );
}

#[test]
fn sealing_orders_by_close_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut older = writer(&area, "same-name");
    let mut newer = writer(&area, "same-name");
    older.write_all(b"began first").unwrap();
    newer.write_all(b"closed first").unwrap();
    let closed_first = newer.seal().unwrap();
    older.seek(SeekFrom::Start(0)).unwrap();
    older.write_all(b"closed last!").unwrap();
    let closed_last = older.seal().unwrap();

    assert!(closed_first.sequence() < closed_last.sequence());
    drop(area);
    let reopened = open_area(directory.path());
    let ready = reopened.ready().unwrap();
    assert_eq!(ready.len(), 2);
    assert_eq!(ready[0].id(), closed_first.id());
    assert_eq!(ready[1].id(), closed_last.id());
    assert_eq!(ready[1].logical_bytes(), 12);
}

#[test]
fn a_later_close_cannot_publish_while_an_earlier_close_is_still_syncing() {
    let directory = tempfile::tempdir().unwrap();
    let reached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let area = Arc::new(
        NativeContentStagingArea::open_configured(
            directory.path().to_path_buf(),
            GroupCommitPolicy::immediate(),
            Arc::new(PauseFirstAt {
                point: StagingFaultPoint::ContentFlushed,
                fired: AtomicBool::new(false),
                reached: Arc::clone(&reached),
                release: Arc::clone(&release),
            }),
        )
        .unwrap(),
    );
    let mut earlier = writer(&area, "same-name");
    earlier.write_all(b"earlier").unwrap();
    let earlier_worker = std::thread::spawn(move || earlier.seal().unwrap());

    reached.wait();
    let mut later = writer(&area, "same-name");
    later.write_all(b"later").unwrap();
    let later = later.seal().unwrap();
    let error = area.ensure_publication_order(&later).unwrap_err();
    assert!(error.to_string().contains("earlier close"));

    release.wait();
    let earlier = earlier_worker.join().unwrap();
    assert!(earlier.sequence() < later.sequence());
    let ready = area.ready().unwrap();
    assert_eq!(ready, vec![earlier, later]);
}

#[test]
fn publication_order_does_not_validate_unrelated_generation_files() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut unrelated = writer(&area, "unrelated");
    unrelated.write_all(b"unrelated").unwrap();
    let unrelated = unrelated.seal().unwrap();
    let mut candidate = writer(&area, "candidate");
    candidate.write_all(b"candidate").unwrap();
    let candidate = candidate.seal().unwrap();

    std::fs::remove_file(unrelated.content_path()).unwrap();
    area.ensure_publication_order(&candidate).unwrap();
}

#[test]
fn unacknowledged_open_and_orphan_sealed_generations_are_quarantined() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut open = writer(&area, "open");
    open.write_all(b"not acknowledged").unwrap();
    open.preserve_on_drop = true;
    let open_name = open.path.as_ref().unwrap().file_name().unwrap().to_owned();
    drop(open);

    let mut orphan = writer(&area, "orphan");
    orphan.write_all(b"renamed but not journalled").unwrap();
    let open_path = orphan.path.take().unwrap();
    let orphan_path = area
        .inner
        .generations
        .join(sealed_generation_name(9, orphan.id));
    std::fs::rename(&open_path, &orphan_path).unwrap();
    orphan.preserve_on_drop = true;
    drop(orphan);
    drop(area);

    let reopened = open_area(directory.path());
    assert!(reopened.ready().unwrap().is_empty());
    let quarantine = directory.path().join(QUARANTINE_DIRECTORY);
    assert!(
        quarantine
            .join(format!("{}.unsealed.0", open_name.to_string_lossy()))
            .exists()
    );
    assert!(
        quarantine
            .join(format!(
                "{}.orphan.0",
                orphan_path.file_name().unwrap().to_string_lossy()
            ))
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn ready_scan_rejects_a_symlinked_content_source() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged_writer = writer(&area, "redirect");
    staged_writer.write_all(b"safe").unwrap();
    let staged = staged_writer.seal().unwrap();
    std::fs::remove_file(staged.content_path()).unwrap();
    symlink("/etc/passwd", staged.content_path()).unwrap();

    let error = area.ready().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("redirected or not a regular file")
    );
}

#[test]
fn torn_journal_tail_is_truncated_without_losing_the_valid_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut first_writer = writer(&area, "first");
    first_writer.write_all(b"first").unwrap();
    let first = first_writer.seal().unwrap();

    let torn_intent = StagingIntent {
        sequence: first.sequence().checked_add(1).unwrap(),
        id: StagedContentId(Uuid::new_v4()),
        owner: owner(),
        name: ContentName::new("torn").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 4,
    };
    let frame = encoded_frame(&JournalRecord::Sealed(torn_intent)).unwrap();
    let mut journal = area.inner.journal.lock();
    journal.file.seek(SeekFrom::End(0)).unwrap();
    journal.file.write_all(&frame[..frame.len() / 2]).unwrap();
    drop(journal);
    drop(area);

    let reopened = open_area(directory.path());
    assert_eq!(reopened.ready().unwrap(), vec![first]);
}

#[test]
fn torn_physical_header_tail_is_truncated_without_losing_the_valid_prefix() {
    for field in ["version", "reserved"] {
        let directory = tempfile::tempdir().unwrap();
        let area = open_area(directory.path());
        let mut first_writer = writer(&area, "first");
        first_writer.write_all(b"first").unwrap();
        let first = first_writer.seal().unwrap();
        let torn_intent = StagingIntent {
            sequence: first.sequence().checked_add(1).unwrap(),
            id: StagedContentId(Uuid::new_v4()),
            owner: owner(),
            name: ContentName::new("torn-header").unwrap(),
            profile: ChunkingProfile::ASTRID_V1,
            logical_bytes: 0,
        };
        let mut frame = encoded_frame(&JournalRecord::Sealed(torn_intent)).unwrap();
        if field == "version" {
            frame[8..10].copy_from_slice(&0_u16.to_le_bytes());
        } else {
            frame[10] = 1;
        }
        let journal_path = directory.path().join(JOURNAL_FILE);
        let valid_len = std::fs::metadata(&journal_path).unwrap().len();
        {
            let mut journal = area.inner.journal.lock();
            journal.file.seek(SeekFrom::End(0)).unwrap();
            journal.file.write_all(&frame).unwrap();
        }
        drop(area);

        let reopened = open_area(directory.path());
        assert_eq!(reopened.ready().unwrap(), vec![first], "{field}");
        assert_eq!(
            std::fs::metadata(journal_path).unwrap().len(),
            valid_len,
            "{field}"
        );
    }
}

#[test]
fn overflowing_torn_length_tail_is_truncated_without_losing_the_valid_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut first_writer = writer(&area, "first");
    first_writer.write_all(b"first").unwrap();
    let first = first_writer.seal().unwrap();
    let torn_intent = StagingIntent {
        sequence: first.sequence().checked_add(1).unwrap(),
        id: StagedContentId(Uuid::new_v4()),
        owner: owner(),
        name: ContentName::new("overflowing-tail").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 0,
    };
    let mut frame = encoded_frame(&JournalRecord::Sealed(torn_intent)).unwrap();
    frame[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    let journal_path = directory.path().join(JOURNAL_FILE);
    let valid_len = std::fs::metadata(&journal_path).unwrap().len();
    {
        let mut journal = area.inner.journal.lock();
        journal.file.seek(SeekFrom::End(0)).unwrap();
        journal.file.write_all(&frame).unwrap();
    }
    drop(area);

    let reopened = open_area(directory.path());
    assert_eq!(reopened.ready().unwrap(), vec![first]);
    assert_eq!(std::fs::metadata(journal_path).unwrap().len(), valid_len);
}

#[test]
fn self_consistent_future_header_fails_without_truncating_the_journal() {
    for field in ["version", "reserved"] {
        let directory = tempfile::tempdir().unwrap();
        let area = open_area(directory.path());
        let mut staged_writer = writer(&area, "current");
        staged_writer.write_all(b"current").unwrap();
        staged_writer.seal().unwrap();
        let future_intent = StagingIntent {
            sequence: 99,
            id: StagedContentId(Uuid::new_v4()),
            owner: owner(),
            name: ContentName::new("future-header").unwrap(),
            profile: ChunkingProfile::ASTRID_V1,
            logical_bytes: 0,
        };
        let mut frame = encoded_frame(&JournalRecord::Sealed(future_intent)).unwrap();
        if field == "version" {
            frame[8..10].copy_from_slice(&2_u16.to_le_bytes());
        } else {
            frame[10] = 1;
        }
        refresh_frame_checksum(&mut frame).unwrap();
        let journal_path = directory.path().join(JOURNAL_FILE);
        {
            let mut journal = area.inner.journal.lock();
            journal.file.seek(SeekFrom::End(0)).unwrap();
            journal.file.write_all(&frame).unwrap();
            journal.file.sync_all().unwrap();
        }
        drop(area);
        let bytes_before = std::fs::read(&journal_path).unwrap();

        let error = open_area_result(directory.path()).unwrap_err();
        assert!(error.to_string().contains(field), "{field}: {error}");
        assert_eq!(
            std::fs::read(journal_path).unwrap(),
            bytes_before,
            "{field}"
        );
    }
}

#[test]
fn future_envelope_after_a_corrupt_frame_prevents_tail_truncation() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged_writer = writer(&area, "current");
    staged_writer.write_all(b"current").unwrap();
    let current = staged_writer.seal().unwrap();
    let next_sequence = current.sequence().checked_add(1).unwrap();
    let corrupt_intent = StagingIntent {
        sequence: next_sequence,
        id: StagedContentId(Uuid::new_v4()),
        owner: owner(),
        name: ContentName::new("corrupt").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 0,
    };
    let future_intent = StagingIntent {
        sequence: next_sequence.checked_add(1).unwrap(),
        id: StagedContentId(Uuid::new_v4()),
        owner: owner(),
        name: ContentName::new("future").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 0,
    };
    let mut corrupt = encoded_frame(&JournalRecord::Sealed(corrupt_intent)).unwrap();
    corrupt[20] ^= 0x80;
    let mut future = encoded_frame(&JournalRecord::Sealed(future_intent)).unwrap();
    future[8..10].copy_from_slice(&2_u16.to_le_bytes());
    refresh_frame_checksum(&mut future).unwrap();
    let journal_path = directory.path().join(JOURNAL_FILE);
    {
        let mut journal = area.inner.journal.lock();
        journal.file.seek(SeekFrom::End(0)).unwrap();
        journal.file.write_all(&corrupt).unwrap();
        journal.file.write_all(&future).unwrap();
        journal.file.sync_all().unwrap();
    }
    drop(area);
    let bytes_before = std::fs::read(&journal_path).unwrap();

    let error = open_area_result(directory.path()).unwrap_err();
    assert!(error.to_string().contains("corrupt interior"), "{error}");
    assert_eq!(std::fs::read(journal_path).unwrap(), bytes_before);
}

#[test]
fn every_seal_crash_prefix_recovers_only_acknowledgeable_state() {
    let cases = [
        (StagingFaultPoint::ContentFlushed, 0),
        (StagingFaultPoint::GenerationRenamed, 1),
        (StagingFaultPoint::GenerationDirectoryFlushed, 1),
        // An append that reached the page cache may survive even though the
        // caller did not receive acknowledgement. Recovery accepting that
        // complete record is safe because the generation directory was
        // synchronized first.
        (StagingFaultPoint::SealJournalAppended, 1),
        (StagingFaultPoint::SealJournalFlushed, 1),
    ];
    for (point, recovered_count) in cases {
        let directory = tempfile::tempdir().unwrap();
        let area = open_with_fault(directory.path(), point);
        let mut staged_writer = writer(&area, "faulted");
        staged_writer.write_all(b"preserve me").unwrap();
        assert!(staged_writer.seal().is_err(), "{point:?}");
        drop(area);

        let reopened = open_area(directory.path());
        assert_eq!(
            reopened.ready().unwrap().len(),
            recovered_count,
            "{point:?}"
        );
    }
}

#[test]
fn orphan_recovery_flushes_the_generation_name_before_journalling_it() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_with_fault(directory.path(), StagingFaultPoint::GenerationRenamed);
    let mut staged_writer = writer(&area, "recovered");
    staged_writer.write_all(b"recover after rename").unwrap();
    assert!(staged_writer.seal().is_err());
    drop(area);

    let error = NativeContentStagingArea::open_configured(
        directory.path().to_path_buf(),
        GroupCommitPolicy::immediate(),
        Arc::new(FailOnce {
            point: StagingFaultPoint::RecoveryGenerationDirectoryFlushed,
            fired: AtomicBool::new(false),
        }),
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected staging fault"));
    assert_eq!(
        std::fs::metadata(directory.path().join(JOURNAL_FILE))
            .unwrap()
            .len(),
        0
    );

    let reopened = open_area(directory.path());
    let ready = reopened.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(read_logical(&ready[0]), b"recover after rename");
}

#[test]
fn every_publication_cleanup_prefix_reopens_as_completed() {
    for point in [
        StagingFaultPoint::PublicationJournalAppended,
        StagingFaultPoint::PublicationJournalFlushed,
        StagingFaultPoint::GenerationCleaned,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let area = open_with_fault(directory.path(), point);
        let mut staged_writer = writer(&area, "published");
        staged_writer.write_all(b"published bytes").unwrap();
        let staged = staged_writer.seal().unwrap();
        assert!(area.mark_published(&staged).is_err(), "{point:?}");
        drop(area);

        let reopened = open_area(directory.path());
        assert!(reopened.ready().unwrap().is_empty(), "{point:?}");
        assert!(!staged.content_path().exists(), "{point:?}");
    }
}

#[test]
fn concurrent_seals_share_one_journal_group() {
    let directory = tempfile::tempdir().unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let drain_reached = Arc::new(Barrier::new(2));
    let drain_release = Arc::new(Barrier::new(2));
    let area = Arc::new(
        NativeContentStagingArea::open_configured(
            directory.path().to_path_buf(),
            GroupCommitPolicy::immediate(),
            Arc::new(BarrierAt {
                point: StagingFaultPoint::ContentFlushed,
                barrier: Arc::clone(&barrier),
            }),
        )
        .unwrap(),
    );
    area.gate_next_seal_group_drain(Arc::clone(&drain_reached), Arc::clone(&drain_release));
    let mut workers = Vec::new();
    for index in 0..8 {
        let area = Arc::clone(&area);
        workers.push(std::thread::spawn(move || {
            let mut staged_writer = writer(&area, &format!("file-{index}"));
            staged_writer.write_all(b"batched").unwrap();
            staged_writer.seal().unwrap()
        }));
    }
    drain_reached.wait();
    wait_for_queued_seals(&area, 8);
    drain_release.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(area.inner.seal_groups_completed.load(Ordering::SeqCst), 1);
    assert_eq!(area.ready().unwrap().len(), 8);
}

#[test]
fn seal_acknowledgement_waits_for_the_journal_flush_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let reached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let area = Arc::new(
        NativeContentStagingArea::open_configured(
            directory.path().to_path_buf(),
            GroupCommitPolicy::immediate(),
            Arc::new(PauseAt {
                point: StagingFaultPoint::SealJournalFlushed,
                reached: Arc::clone(&reached),
                release: Arc::clone(&release),
            }),
        )
        .unwrap(),
    );
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = {
        let area = Arc::clone(&area);
        std::thread::spawn(move || {
            let mut staged_writer = writer(&area, "durable");
            staged_writer.write_all(b"durable bytes").unwrap();
            sender.send(staged_writer.seal()).unwrap();
        })
    };

    reached.wait();
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    release.wait();
    assert!(receiver.recv().unwrap().is_ok());
    worker.join().unwrap();
}

#[test]
fn corrupt_interior_journal_frame_fails_open() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    for name in ["first", "second"] {
        let mut staged_writer = writer(&area, name);
        staged_writer.write_all(name.as_bytes()).unwrap();
        staged_writer.seal().unwrap();
    }
    drop(area);

    let journal_path = directory.path().join(JOURNAL_FILE);
    let mut bytes = std::fs::read(&journal_path).unwrap();
    bytes[20] ^= 0x80;
    std::fs::write(&journal_path, bytes).unwrap();

    let error = NativeContentStagingArea::open_with_group_commit_policy(
        directory.path(),
        GroupCommitPolicy::immediate(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("corrupt interior"));
}

#[test]
fn overflowing_interior_frame_length_does_not_hide_a_valid_successor() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    for name in ["first", "second"] {
        let mut staged_writer = writer(&area, name);
        staged_writer.write_all(name.as_bytes()).unwrap();
        staged_writer.seal().unwrap();
    }
    drop(area);

    let journal_path = directory.path().join(JOURNAL_FILE);
    let mut bytes = std::fs::read(&journal_path).unwrap();
    let original_len = bytes.len();
    bytes[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    std::fs::write(&journal_path, bytes).unwrap();

    let error = open_area_result(directory.path()).unwrap_err();
    assert!(error.to_string().contains("corrupt interior"), "{error}");
    assert_eq!(
        usize::try_from(std::fs::metadata(journal_path).unwrap().len()).unwrap(),
        original_len
    );
}

#[test]
fn journal_rejects_reused_sequences_and_identifiers() {
    for collision in ["sequence", "identifier"] {
        let directory = tempfile::tempdir().unwrap();
        let area = open_area(directory.path());
        let first = StagingIntent {
            sequence: 7,
            id: StagedContentId(Uuid::new_v4()),
            owner: owner(),
            name: ContentName::new("first").unwrap(),
            profile: ChunkingProfile::ASTRID_V1,
            logical_bytes: 0,
        };
        let second = StagingIntent {
            sequence: if collision == "sequence" { 7 } else { 8 },
            id: if collision == "identifier" {
                first.id
            } else {
                StagedContentId(Uuid::new_v4())
            },
            owner: owner(),
            name: ContentName::new("second").unwrap(),
            profile: ChunkingProfile::ASTRID_V1,
            logical_bytes: 0,
        };
        {
            let mut journal = area.inner.journal.lock();
            append_records(
                &mut journal.file,
                &[JournalRecord::Sealed(first), JournalRecord::Sealed(second)],
            )
            .unwrap();
            flush_journal(&journal.file).unwrap();
        }
        drop(area);

        let error = open_area_result(directory.path()).unwrap_err();
        assert!(error.to_string().contains(collision), "{error}");
    }
}

#[test]
fn corrupt_seal_tail_rebuilds_from_the_generation_footer() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged = Vec::new();
    for name in ["first", "second"] {
        let mut staged_writer = writer(&area, name);
        staged_writer.write_all(name.as_bytes()).unwrap();
        staged.push(staged_writer.seal().unwrap());
    }
    drop(area);

    let journal_path = directory.path().join(JOURNAL_FILE);
    let mut bytes = std::fs::read(&journal_path).unwrap();
    let frames: Vec<_> = bytes
        .windows(8)
        .enumerate()
        .filter_map(|(offset, magic)| (magic == b"ASTRSTG1").then_some(offset))
        .collect();
    assert_eq!(frames.len(), 2);
    bytes[frames[1] + 20] ^= 0x80;
    std::fs::write(&journal_path, bytes).unwrap();

    let reopened = open_area(directory.path());
    assert_eq!(reopened.ready().unwrap(), staged);
}

#[test]
fn corrupt_completion_tail_with_missing_generation_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged_writer = writer(&area, "published");
    staged_writer.write_all(b"published").unwrap();
    let staged = staged_writer.seal().unwrap();
    let key = StageKey {
        sequence: staged.sequence(),
        id: staged.id(),
    };
    {
        let mut journal = area.inner.journal.lock();
        append_records(&mut journal.file, &[JournalRecord::Published(key)]).unwrap();
        flush_journal(&journal.file).unwrap();
    }
    std::fs::remove_file(staged.content_path()).unwrap();
    sync_directory(&area.inner.generations).unwrap();
    drop(area);

    let journal_path = directory.path().join(JOURNAL_FILE);
    let mut bytes = std::fs::read(&journal_path).unwrap();
    let completion = bytes
        .windows(8)
        .enumerate()
        .filter_map(|(offset, magic)| (magic == b"ASTRSTG1").then_some(offset))
        .next_back()
        .unwrap();
    bytes[completion + 20] ^= 0x80;
    std::fs::write(&journal_path, bytes).unwrap();

    assert!(NativeContentStagingArea::open(directory.path()).is_err());
}

#[test]
fn published_record_reaps_every_interrupted_cleanup_state() {
    for remove_before_reopen in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let area = open_area(directory.path());
        let mut staged_writer = writer(&area, "published");
        staged_writer.write_all(b"published bytes").unwrap();
        let staged = staged_writer.seal().unwrap();
        let key = StageKey {
            sequence: staged.sequence(),
            id: staged.id(),
        };
        {
            let mut journal = area.inner.journal.lock();
            append_records(&mut journal.file, &[JournalRecord::Published(key)]).unwrap();
            flush_journal(&journal.file).unwrap();
        }
        if remove_before_reopen {
            std::fs::remove_file(staged.content_path()).unwrap();
        }
        drop(area);

        let reopened = open_area(directory.path());
        assert!(reopened.ready().unwrap().is_empty());
        assert!(!staged.content_path().exists());
        assert_eq!(
            std::fs::metadata(directory.path().join(JOURNAL_FILE))
                .unwrap()
                .len(),
            0
        );
    }
}

#[test]
fn recovery_flushes_a_missing_completed_generation_before_dropping_its_record() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged_writer = writer(&area, "published");
    staged_writer.write_all(b"published bytes").unwrap();
    let staged = staged_writer.seal().unwrap();
    let key = StageKey {
        sequence: staged.sequence(),
        id: staged.id(),
    };
    {
        let mut journal = area.inner.journal.lock();
        append_records(&mut journal.file, &[JournalRecord::Published(key)]).unwrap();
        flush_journal(&journal.file).unwrap();
    }
    std::fs::remove_file(staged.content_path()).unwrap();
    drop(area);

    let error = NativeContentStagingArea::open_configured(
        directory.path().to_path_buf(),
        GroupCommitPolicy::immediate(),
        Arc::new(FailOnce {
            point: StagingFaultPoint::RecoveryCleanupDirectoryFlushed,
            fired: AtomicBool::new(false),
        }),
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected staging fault"));
    assert_ne!(
        std::fs::metadata(directory.path().join(JOURNAL_FILE))
            .unwrap()
            .len(),
        0
    );

    let reopened = open_area(directory.path());
    assert!(reopened.ready().unwrap().is_empty());
    assert_eq!(
        std::fs::metadata(directory.path().join(JOURNAL_FILE))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn legacy_pending_published_and_unsealed_entries_migrate_without_loss() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let writing = root.join(legacy::WRITING_DIRECTORY);
    let ready = root.join(legacy::READY_DIRECTORY);
    let quarantine = root.join(QUARANTINE_DIRECTORY);
    for path in [&writing, &ready, &quarantine] {
        std::fs::create_dir_all(path).unwrap();
    }

    let pending = legacy_entry(&ready, 4, "pending", b"keep me", false);
    let published = legacy_entry(&ready, 5, "published", b"already published", true);
    let published_directory = ready.join(format!("{:020}-{}", published.sequence, published.id));

    let unsealed_id = StagedContentId(Uuid::new_v4());
    let unsealed = writing.join(unsealed_id.to_string());
    std::fs::create_dir(&unsealed).unwrap();
    std::fs::write(unsealed.join(legacy::CONTENT_FILE), b"never acknowledged").unwrap();
    let malformed_id = StagedContentId(Uuid::new_v4());
    std::fs::write(writing.join(malformed_id.to_string()), b"not a directory").unwrap();
    sync_directory(&writing).unwrap();

    let area = open_area(root);
    let ready_entries = area.ready().unwrap();
    assert_eq!(ready_entries.len(), 1);
    assert_eq!(ready_entries[0].id(), pending.id);
    assert_eq!(read_logical(&ready_entries[0]), b"keep me");
    assert!(!published_directory.exists());
    assert!(
        quarantine
            .join(format!("{unsealed_id}.legacy-unsealed.0"))
            .exists()
    );
    assert!(
        quarantine
            .join(format!("{malformed_id}.legacy-unsealed.0"))
            .exists()
    );
}

#[test]
fn legacy_migration_resumes_before_or_after_the_generation_footer() {
    for footer_state in ["missing", "torn", "complete"] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let ready = root.join(legacy::READY_DIRECTORY);
        let generations = root.join(GENERATIONS_DIRECTORY);
        let quarantine = root.join(QUARANTINE_DIRECTORY);
        for path in [&ready, &generations, &quarantine] {
            std::fs::create_dir_all(path).unwrap();
        }
        let intent = legacy_entry(&ready, 11, "resume", b"migration bytes", false);
        let legacy_directory = ready.join(format!("{:020}-{}", intent.sequence, intent.id));
        let target = generations.join(sealed_generation_name(intent.sequence, intent.id));
        std::fs::rename(legacy_directory.join(legacy::CONTENT_FILE), &target).unwrap();
        if footer_state == "complete" {
            let mut generation = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&target)
                .unwrap();
            append_generation_footer(&mut generation, &intent).unwrap();
            generation.sync_all().unwrap();
        } else if footer_state == "torn" {
            let mut generation = std::fs::OpenOptions::new()
                .append(true)
                .open(&target)
                .unwrap();
            generation.write_all(b"ASTRID-STAGE-F1").unwrap();
            generation.sync_all().unwrap();
        }
        sync_directory(&generations).unwrap();

        let area = open_area(root);
        let entries = area.ready().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id(), intent.id);
        assert_eq!(read_logical(&entries[0]), b"migration bytes");
        assert!(!legacy_directory.exists());
    }
}

#[test]
fn legacy_migration_flushes_both_rename_namespaces_before_adding_a_footer() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let ready = root.join(legacy::READY_DIRECTORY);
    std::fs::create_dir_all(&ready).unwrap();
    let intent = legacy_entry(&ready, 21, "namespace-order", b"legacy bytes", false);
    let legacy_directory = ready.join(format!("{:020}-{}", intent.sequence, intent.id));

    let error = NativeContentStagingArea::open_configured(
        root.to_path_buf(),
        GroupCommitPolicy::immediate(),
        Arc::new(FailOnce {
            point: StagingFaultPoint::MigrationNamespaceFlushed,
            fired: AtomicBool::new(false),
        }),
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected staging fault"));
    assert!(!legacy_directory.join(legacy::CONTENT_FILE).exists());
    let target = root
        .join(GENERATIONS_DIRECTORY)
        .join(sealed_generation_name(intent.sequence, intent.id));
    assert_eq!(
        std::fs::metadata(&target).unwrap().len(),
        intent.logical_bytes
    );

    let reopened = open_area(root);
    let entries = reopened.ready().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(read_logical(&entries[0]), b"legacy bytes");
}

#[test]
fn malformed_legacy_keys_fail_before_migration_writes_or_cleanup() {
    for collision in ["sequence", "identifier"] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let ready = root.join(legacy::READY_DIRECTORY);
        let writing = root.join(legacy::WRITING_DIRECTORY);
        std::fs::create_dir_all(&ready).unwrap();
        std::fs::create_dir_all(&writing).unwrap();
        let shared_id = StagedContentId(Uuid::new_v4());
        let (first_sequence, first_id, second_sequence, second_id) = if collision == "sequence" {
            (31, StagedContentId(Uuid::new_v4()), 31, shared_id)
        } else {
            (31, shared_id, 32, shared_id)
        };
        let first =
            legacy_entry_with_id(&ready, first_sequence, first_id, "first", b"first", false);
        let published = legacy_entry_with_id(
            &ready,
            second_sequence,
            second_id,
            "second",
            b"second",
            true,
        );
        let writing_intent = legacy_writing_entry(&writing, 40, "writing", b"writing");
        let writing_directory = writing.join(writing_intent.id.to_string());

        let error = open_area_result(root).unwrap_err();
        assert!(
            error.to_string().contains(collision),
            "{collision}: {error}"
        );
        assert_eq!(
            std::fs::metadata(root.join(JOURNAL_FILE)).unwrap().len(),
            0,
            "{collision}"
        );
        for intent in [first, published] {
            let directory = ready.join(format!("{:020}-{}", intent.sequence, intent.id));
            assert!(directory.join(legacy::CONTENT_FILE).exists(), "{collision}");
            assert_eq!(
                std::fs::metadata(directory.join(legacy::CONTENT_FILE))
                    .unwrap()
                    .len(),
                intent.logical_bytes,
                "{collision}"
            );
        }
        assert!(writing_directory.exists(), "{collision}");
        assert!(
            writing_directory.join(legacy::CONTENT_FILE).exists(),
            "{collision}"
        );
        assert!(
            read_directory(&root.join(GENERATIONS_DIRECTORY))
                .unwrap()
                .next()
                .is_none(),
            "{collision}"
        );
    }
}

#[test]
fn disagreeing_legacy_intents_for_one_key_fail_before_migration_mutates() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let ready = root.join(legacy::READY_DIRECTORY);
    let writing = root.join(legacy::WRITING_DIRECTORY);
    std::fs::create_dir_all(&ready).unwrap();
    std::fs::create_dir_all(&writing).unwrap();
    let id = StagedContentId(Uuid::new_v4());
    let ready_intent = legacy_entry_with_id(&ready, 41, id, "ready", b"ready", false);
    let writing_intent = legacy_writing_entry_with_id(&writing, 41, id, "writing", b"writing");
    let ready_directory = ready.join(format!("{:020}-{}", ready_intent.sequence, ready_intent.id));
    let writing_directory = writing.join(writing_intent.id.to_string());

    let error = open_area_result(root).unwrap_err();
    assert!(error.to_string().contains("disagrees"), "{error}");
    assert_eq!(std::fs::metadata(root.join(JOURNAL_FILE)).unwrap().len(), 0);
    assert!(ready_directory.join(legacy::CONTENT_FILE).exists());
    assert!(writing_directory.join(legacy::CONTENT_FILE).exists());
    assert!(
        read_directory(&root.join(GENERATIONS_DIRECTORY))
            .unwrap()
            .next()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn legacy_ready_symlink_is_rejected_before_published_cleanup() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("staging");
    let ready = root.join(legacy::READY_DIRECTORY);
    let outside = directory.path().join("outside");
    std::fs::create_dir_all(&ready).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let intent = legacy_entry(&outside, 51, "outside", b"must survive", true);
    let name = format!("{:020}-{}", intent.sequence, intent.id);
    let outside_entry = outside.join(&name);
    symlink(&outside_entry, ready.join(&name)).unwrap();

    let error = open_area_result(&root).unwrap_err();
    assert!(error.to_string().contains("redirected"));
    assert_eq!(
        std::fs::read(outside_entry.join(legacy::CONTENT_FILE)).unwrap(),
        b"must survive"
    );
    assert!(outside_entry.join(legacy::INTENT_FILE).exists());
    assert!(outside_entry.join(legacy::PUBLISHED_FILE).exists());
}

#[cfg(unix)]
#[test]
fn dangling_legacy_queue_symlinks_are_not_treated_as_absent() {
    use std::os::unix::fs::symlink;

    for name in [legacy::WRITING_DIRECTORY, legacy::READY_DIRECTORY] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("staging");
        std::fs::create_dir(&root).unwrap();
        let queue = root.join(name);
        symlink(directory.path().join("missing"), &queue).unwrap();

        let error = open_area_result(&root).unwrap_err();
        assert!(error.to_string().contains("redirected"), "{name}: {error}");
        assert!(
            std::fs::symlink_metadata(queue)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}

fn legacy_entry(
    ready: &Path,
    sequence: u64,
    name: &str,
    content: &[u8],
    published: bool,
) -> StagingIntent {
    legacy_entry_with_id(
        ready,
        sequence,
        StagedContentId(Uuid::new_v4()),
        name,
        content,
        published,
    )
}

fn legacy_entry_with_id(
    ready: &Path,
    sequence: u64,
    id: StagedContentId,
    name: &str,
    content: &[u8],
    published: bool,
) -> StagingIntent {
    let directory = ready.join(format!("{sequence:020}-{id}"));
    std::fs::create_dir(&directory).unwrap();
    let content_path = directory.join(legacy::CONTENT_FILE);
    std::fs::write(&content_path, content).unwrap();
    File::open(&content_path).unwrap().sync_all().unwrap();
    let intent = StagingIntent {
        sequence,
        id,
        owner: owner(),
        name: ContentName::new(name).unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: u64::try_from(content.len()).unwrap(),
    };
    atomic_write(
        &directory.join(legacy::INTENT_FILE),
        &encode_intent(&intent).unwrap(),
    )
    .unwrap();
    if published {
        atomic_write(
            &directory.join(legacy::PUBLISHED_FILE),
            legacy::PUBLISHED_MARKER,
        )
        .unwrap();
    }
    sync_directory(ready).unwrap();
    intent
}

fn legacy_writing_entry(
    writing: &Path,
    sequence: u64,
    name: &str,
    content: &[u8],
) -> StagingIntent {
    let id = StagedContentId(Uuid::new_v4());
    legacy_writing_entry_with_id(writing, sequence, id, name, content)
}

fn legacy_writing_entry_with_id(
    writing: &Path,
    sequence: u64,
    id: StagedContentId,
    name: &str,
    content: &[u8],
) -> StagingIntent {
    let directory = writing.join(id.to_string());
    std::fs::create_dir(&directory).unwrap();
    let content_path = directory.join(legacy::CONTENT_FILE);
    std::fs::write(&content_path, content).unwrap();
    File::open(&content_path).unwrap().sync_all().unwrap();
    let intent = StagingIntent {
        sequence,
        id,
        owner: owner(),
        name: ContentName::new(name).unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: u64::try_from(content.len()).unwrap(),
    };
    atomic_write(
        &directory.join(legacy::INTENT_FILE),
        &encode_intent(&intent).unwrap(),
    )
    .unwrap();
    sync_directory(writing).unwrap();
    intent
}

#[cfg(unix)]
#[test]
fn staging_root_cannot_be_a_symlink() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let redirected = directory.path().join("redirected");
    symlink(&target, &redirected).unwrap();

    let error = NativeContentStagingArea::open(&redirected).unwrap_err();
    assert!(error.to_string().contains("redirected or not a directory"));
}

#[cfg(unix)]
#[test]
fn staging_journal_cannot_be_a_symlink() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("outside.log");
    std::fs::write(&target, b"must remain untouched").unwrap();
    let root = directory.path().join("staging");
    std::fs::create_dir(&root).unwrap();
    symlink(&target, root.join(JOURNAL_FILE)).unwrap();

    let error = open_area_result(&root).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("redirected or not a regular file")
    );
    assert_eq!(std::fs::read(target).unwrap(), b"must remain untouched");
}

#[test]
#[ignore = "explicit native seal-group throughput probe"]
fn native_seal_group_scale_probe() {
    const SEALS_PER_WRITER: u16 = 64;
    const SAMPLES: u8 = 3;

    for writers in [1_u8, 2, 4, 8] {
        for sample in 0..SAMPLES {
            let directory = tempfile::tempdir().unwrap();
            let area = Arc::new(NativeContentStagingArea::open(directory.path()).unwrap());
            let barrier = Arc::new(Barrier::new(usize::from(writers)));
            let started = std::time::Instant::now();
            let mut workers = Vec::new();
            for writer_index in 0..writers {
                let area = Arc::clone(&area);
                let barrier = Arc::clone(&barrier);
                workers.push(std::thread::spawn(move || {
                    barrier.wait();
                    let mut latencies = Vec::new();
                    for seal_index in 0..SEALS_PER_WRITER {
                        let mut staged_writer =
                            writer(&area, &format!("probe/{writer_index}/{seal_index}"));
                        staged_writer.write_all(&[0x5a; 4096]).unwrap();
                        let operation = std::time::Instant::now();
                        staged_writer.seal().unwrap();
                        latencies.push(operation.elapsed());
                    }
                    latencies
                }));
            }
            let mut latencies = Vec::new();
            for worker in workers {
                latencies.extend(worker.join().unwrap());
            }
            let elapsed = started.elapsed();
            latencies.sort_unstable();
            let operations = u32::from(writers) * u32::from(SEALS_PER_WRITER);
            let groups = area.inner.seal_groups_completed.load(Ordering::SeqCst);
            let group_flushes = u32::try_from(groups).unwrap().checked_mul(2).unwrap();
            let durability_flushes = operations.checked_add(group_flushes).unwrap();
            let p95_index = latencies.len().saturating_mul(95).div_ceil(100) - 1;
            println!(
                "native_seal_group writers={writers} sample={sample} operations={operations} seal_groups={groups} durability_flushes={durability_flushes} flushes_per_seal={:.3} seals_per_second={:.1} p50_us={} p95_us={} max_us={} wall_ms={}",
                f64::from(durability_flushes) / f64::from(operations),
                f64::from(operations) / elapsed.as_secs_f64(),
                latencies[latencies.len() / 2].as_micros(),
                latencies[p95_index].as_micros(),
                latencies.last().unwrap().as_micros(),
                elapsed.as_millis()
            );
        }
    }
}
