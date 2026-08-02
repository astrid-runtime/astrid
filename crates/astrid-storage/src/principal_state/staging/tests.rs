use std::io::{Read as _, Seek as _, Write as _};
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Duration;

use astrid_core::identity::PrincipalUid;
use uuid::Uuid;

use super::format::{
    LegacyStagingIntent, LegacyStagingOwner, StagingIntent, decode_intent, decode_legacy_intent,
    encode_intent, encode_legacy_intent,
};
use super::journal::{JournalRecord, StageKey, append_records, encoded_frame, flush_journal};
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

fn open_area(path: &Path) -> NativeContentStagingArea {
    NativeContentStagingArea::open_with_group_commit_policy(path, GroupCommitPolicy::immediate())
        .unwrap()
}

fn writer(area: &NativeContentStagingArea, name: &str) -> StagedContentWriter {
    area.begin(
        owner(),
        ContentName::new(name).unwrap(),
        ChunkingProfile::ASTRID_V1,
    )
    .unwrap()
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
struct FailGroupAt {
    align: Arc<Barrier>,
    point: StagingFaultPoint,
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

impl StagingFaultInjector for FailGroupAt {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()> {
        if point == StagingFaultPoint::ContentFlushed {
            self.align.wait();
        }
        if point == self.point {
            return Err(connection(format!("injected staging fault at {point:?}")));
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
fn alias_intent_migration_is_crash_idempotent_and_preserves_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let ready = root.join(READY_DIRECTORY);
    std::fs::create_dir_all(&ready).unwrap();
    let sequence = 0;
    let id = StagedContentId(Uuid::new_v4());
    let staging_directory = ready.join(format!("{sequence:020}-{id}"));
    std::fs::create_dir(&staging_directory).unwrap();
    let content_path = staging_directory.join(legacy::CONTENT_FILE);
    std::fs::write(&content_path, b"durable staged bytes").unwrap();
    File::open(&content_path).unwrap().sync_all().unwrap();
    let legacy = LegacyStagingIntent {
        sequence,
        id,
        owner: LegacyStagingOwner::Principal(PrincipalId::new("alice").unwrap()),
        name: ContentName::new("projects/game/save.bin").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 20,
    };
    atomic_write(
        &staging_directory.join(LEGACY_INTENT_FILE),
        &encode_legacy_intent(&legacy).unwrap(),
    )
    .unwrap();
    let migrated = StagingIntent {
        sequence: legacy.sequence,
        id: legacy.id,
        owner: owner(),
        name: legacy.name.clone(),
        profile: legacy.profile,
        logical_bytes: legacy.logical_bytes,
    };
    atomic_write(
        &staging_directory.join(INTENT_FILE),
        &encode_intent(&migrated).unwrap(),
    )
    .unwrap();
    sync_directory(&staging_directory).unwrap();
    sync_directory(&ready).unwrap();

    migrate_alias_owner_intents(root, |alias| {
        assert_eq!(alias.as_str(), "alice");
        Ok(uid())
    })
    .unwrap();
    migrate_alias_owner_intents(root, |_| {
        panic!("an already-migrated intent must not be resolved twice")
    })
    .unwrap();

    assert!(!staging_directory.join(LEGACY_INTENT_FILE).exists());
    assert_eq!(
        decode_intent(&std::fs::read(staging_directory.join(INTENT_FILE)).unwrap()).unwrap(),
        migrated
    );
    assert_eq!(
        std::fs::read(&content_path).unwrap(),
        b"durable staged bytes"
    );
    let reopened = NativeContentStagingArea::open(root).unwrap();
    let ready = reopened.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].owner(), &owner());
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
    let area = Arc::new(
        NativeContentStagingArea::open_configured(
            directory.path().to_path_buf(),
            GroupCommitPolicy::new(Duration::from_millis(200)),
            Arc::new(BarrierAt {
                point: StagingFaultPoint::ContentFlushed,
                barrier: Arc::clone(&barrier),
            }),
        )
        .unwrap(),
    );
    let mut workers = Vec::new();
    for index in 0..8 {
        let area = Arc::clone(&area);
        workers.push(std::thread::spawn(move || {
            let mut staged_writer = writer(&area, &format!("file-{index}"));
            staged_writer.write_all(b"batched").unwrap();
            staged_writer.seal().unwrap()
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(area.inner.seal_groups_completed.load(Ordering::SeqCst), 1);
    assert_eq!(area.ready().unwrap().len(), 8);
}

#[test]
fn seal_does_not_acknowledge_before_the_journal_flush() {
    let directory = tempfile::tempdir().unwrap();
    let reached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let area = Arc::new(
        NativeContentStagingArea::open_configured(
            directory.path().to_path_buf(),
            GroupCommitPolicy::immediate(),
            Arc::new(PauseAt {
                point: StagingFaultPoint::SealJournalAppended,
                reached: Arc::clone(&reached),
                release: Arc::clone(&release),
            }),
        )
        .unwrap(),
    );
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut staged = writer(&area, "durable");
        staged.write_all(b"durable bytes").unwrap();
        sender.send(staged.seal()).unwrap();
    });

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
fn journal_durability_failure_is_shared_by_the_seal_group() {
    const WRITERS: usize = 8;

    let directory = tempfile::tempdir().unwrap();
    let area = Arc::new(
        NativeContentStagingArea::open_configured(
            directory.path().to_path_buf(),
            GroupCommitPolicy::new(Duration::from_millis(200)),
            Arc::new(FailGroupAt {
                align: Arc::new(Barrier::new(WRITERS)),
                point: StagingFaultPoint::SealJournalAppended,
            }),
        )
        .unwrap(),
    );
    let mut workers = Vec::new();
    for index in 0..WRITERS {
        let area = Arc::clone(&area);
        workers.push(std::thread::spawn(move || {
            let mut staged = writer(&area, &format!("file-{index}"));
            staged.write_all(b"preserve me").unwrap();
            staged.seal()
        }));
    }
    for worker in workers {
        let error = worker.join().unwrap().unwrap_err();
        assert!(error.to_string().contains("reopen staging"));
    }
    assert!(area.ready().is_err());
    drop(area);

    let reopened = open_area(directory.path());
    assert_eq!(reopened.ready().unwrap().len(), WRITERS);
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
}

#[test]
fn malformed_legacy_publication_marker_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let ready = root.join(legacy::READY_DIRECTORY);
    let quarantine = root.join(QUARANTINE_DIRECTORY);
    for path in [&ready, &quarantine] {
        std::fs::create_dir_all(path).unwrap();
    }
    let intent = legacy_entry(&ready, 6, "published", b"keep me", true);
    let entry = ready.join(format!("{:020}-{}", intent.sequence, intent.id));
    std::fs::write(
        entry.join(legacy::PUBLISHED_FILE),
        b"not a publication marker",
    )
    .unwrap();

    let error = NativeContentStagingArea::open_with_group_commit_policy(
        root,
        GroupCommitPolicy::immediate(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("publication marker"));
    assert_eq!(
        std::fs::read(entry.join(legacy::CONTENT_FILE)).unwrap(),
        b"keep me"
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

fn legacy_entry(
    ready: &Path,
    sequence: u64,
    name: &str,
    content: &[u8],
    published: bool,
) -> StagingIntent {
    let id = StagedContentId(Uuid::new_v4());
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
    let root = directory.path().join("staging");
    std::fs::create_dir(&root).unwrap();
    let target = directory.path().join("target");
    std::fs::write(&target, b"must remain intact").unwrap();
    symlink(&target, root.join(JOURNAL_FILE)).unwrap();

    let error = NativeContentStagingArea::open(&root).unwrap_err();
    assert!(error.to_string().contains("redirected"));
    assert_eq!(std::fs::read(target).unwrap(), b"must remain intact");
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
            let p95_index = latencies.len().saturating_mul(95).div_ceil(100) - 1;
            println!(
                "native_seal_group writers={writers} sample={sample} operations={operations} seals_per_second={:.1} p50_us={} p95_us={} max_us={} wall_ms={}",
                f64::from(operations) / elapsed.as_secs_f64(),
                latencies[latencies.len() / 2].as_micros(),
                latencies[p95_index].as_micros(),
                latencies.last().unwrap().as_micros(),
                elapsed.as_millis()
            );
        }
    }
}
