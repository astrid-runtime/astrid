//! Publication and recovery-cleanup regressions for native staging.

use super::*;

#[test]
fn every_publication_cleanup_prefix_reopens_as_completed() {
    for point in [
        StagingFaultPoint::PublicationJournalAppended,
        StagingFaultPoint::PublicationJournalFlushed,
        StagingFaultPoint::GenerationRetired,
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
fn every_batched_publication_cleanup_prefix_reopens_all_as_completed() {
    for point in [
        StagingFaultPoint::PublicationJournalAppended,
        StagingFaultPoint::PublicationJournalFlushed,
        StagingFaultPoint::GenerationRetired,
        StagingFaultPoint::GenerationCleaned,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let area = open_with_fault(directory.path(), point);
        let mut staged = Vec::new();
        for name in ["published-a", "published-b", "published-c"] {
            let mut staged_writer = writer(&area, name);
            staged_writer.write_all(name.as_bytes()).unwrap();
            staged.push(staged_writer.seal().unwrap());
        }

        assert!(area.mark_published_batch(&staged).is_err(), "{point:?}");
        drop(area);

        let reopened = open_area(directory.path());
        assert!(reopened.ready().unwrap().is_empty(), "{point:?}");
        for entry in &staged {
            assert!(!entry.content_path().exists(), "{point:?}");
        }
    }
}

#[test]
fn completed_publication_retry_finishes_cleanup_idempotently() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_with_fault(directory.path(), StagingFaultPoint::GenerationCleaned);
    let mut staged_writer = writer(&area, "published-retry");
    staged_writer.write_all(b"published bytes").unwrap();
    let staged = staged_writer.seal().unwrap();

    assert!(area.mark_published(&staged).is_err());
    assert!(area.mark_published(&staged).is_ok());
    assert!(!staged.content_path().exists());
    assert!(area.ready().unwrap().is_empty());
}

#[test]
fn retired_name_quarantines_reappeared_generation_without_republication() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged_writer = writer(&area, "published-tombstone");
    staged_writer.write_all(b"published bytes").unwrap();
    let staged = staged_writer.seal().unwrap();
    let retired = area
        .inner
        .generations
        .join(retired_generation_name(staged.sequence(), staged.id()));
    std::fs::rename(staged.content_path(), &retired).unwrap();
    std::fs::copy(&retired, staged.content_path()).unwrap();
    drop(area);

    let journal = directory.path().join(JOURNAL_FILE);
    let journal_file = std::fs::OpenOptions::new()
        .write(true)
        .open(&journal)
        .unwrap();
    journal_file.set_len(0).unwrap();
    journal_file.sync_all().unwrap();

    let reopened = open_area(directory.path());
    assert!(reopened.ready().unwrap().is_empty());
    assert!(!staged.content_path().exists());
    assert!(!retired.exists());
    let quarantined = std::fs::read_dir(directory.path().join(QUARANTINE_DIRECTORY))
        .unwrap()
        .map(|entry| entry.unwrap())
        .find(|entry| entry.file_name().to_string_lossy().contains("published"))
        .expect("reappeared published bytes must be quarantined");
    assert!(
        std::fs::read(quarantined.path())
            .unwrap()
            .starts_with(b"published bytes")
    );
    reopened
        .begin_with_id(
            owner(),
            ContentName::new("reusable.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            staged.id(),
        )
        .unwrap();
}

#[test]
fn poisoned_journal_never_reaps_completed_generations() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged_writer = writer(&area, "poisoned-cleanup");
    staged_writer.write_all(b"retain until reopen").unwrap();
    let staged = staged_writer.seal().unwrap();
    let key = StageKey {
        sequence: staged.sequence,
        id: staged.id,
    };
    {
        let mut journal = area.inner.journal.lock();
        append_records(&mut journal.file, &[JournalRecord::Published(key)]).unwrap();
        flush_journal(&journal.file).unwrap();
        journal.pending.remove(&key);
        journal.completed.insert(key);
        journal.poisoned = true;
    }
    let journal_len = std::fs::metadata(directory.path().join(JOURNAL_FILE))
        .unwrap()
        .len();

    let error = area.ready().unwrap_err();
    assert!(error.to_string().contains("requires recovery"), "{error}");
    assert!(staged.content_path().exists());
    assert_eq!(
        std::fs::metadata(directory.path().join(JOURNAL_FILE))
            .unwrap()
            .len(),
        journal_len
    );
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

    let bytes_before = std::fs::read(&journal_path).unwrap();
    let error = open_area_result(directory.path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("could not prove complete coverage"),
        "{error}"
    );
    assert_eq!(std::fs::read(&journal_path).unwrap(), bytes_before);
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
    write_private_file(&unsealed.join(legacy::CONTENT_FILE), b"never acknowledged");
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
            let source_identity = private_file_identity(&generation).unwrap();
            append_generation_footer(&mut generation, &intent, source_identity).unwrap();
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

#[cfg(unix)]
#[test]
fn legacy_migration_stays_below_capabilities_when_root_is_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("staging");
    let displaced = directory.path().join("original-staging");
    let ready = root.join(legacy::READY_DIRECTORY);
    std::fs::create_dir_all(&ready).unwrap();
    let intent = legacy_entry(&ready, 22, "capability-bound", b"legacy bytes", false);

    let area = NativeContentStagingArea::open_configured(
        root.clone(),
        GroupCommitPolicy::immediate(),
        Arc::new(ReplaceRootAt {
            point: StagingFaultPoint::MigrationNamespaceFlushed,
            root: root.clone(),
            displaced: displaced.clone(),
            fired: AtomicBool::new(false),
        }),
    )
    .unwrap();

    let entries = area.ready().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id(), intent.id);
    let generation = displaced
        .join(GENERATIONS_DIRECTORY)
        .join(sealed_generation_name(intent.sequence, intent.id));
    assert!(generation.exists());
    assert!(
        std::fs::read_dir(root.join(GENERATIONS_DIRECTORY))
            .unwrap()
            .next()
            .is_none()
    );
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
fn unsafe_legacy_candidate_fails_before_migration_mutates() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let ready = root.join(legacy::READY_DIRECTORY);
    let writing = root.join(legacy::WRITING_DIRECTORY);
    std::fs::create_dir_all(&ready).unwrap();
    std::fs::create_dir_all(&writing).unwrap();
    let id = StagedContentId(Uuid::new_v4());
    let ready_intent = legacy_entry_with_id(&ready, 42, id, "ready", b"ready", false);
    let writing_intent = legacy_writing_entry_with_id(&writing, 42, id, "writing", b"writing");
    let ready_directory = ready.join(format!("{:020}-{}", ready_intent.sequence, ready_intent.id));
    let writing_directory = writing.join(writing_intent.id.to_string());
    let unsafe_content = writing_directory.join(legacy::CONTENT_FILE);
    std::fs::set_permissions(&unsafe_content, std::fs::Permissions::from_mode(0o644)).unwrap();

    let error = open_area_result(root).unwrap_err();
    assert!(error.to_string().contains("not owner-only"), "{error}");
    assert_eq!(std::fs::metadata(root.join(JOURNAL_FILE)).unwrap().len(), 0);
    assert!(ready_directory.join(legacy::CONTENT_FILE).exists());
    assert!(writing_directory.join(legacy::CONTENT_FILE).exists());
    assert!(
        read_directory(&root.join(GENERATIONS_DIRECTORY))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        read_directory(&root.join(QUARANTINE_DIRECTORY))
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
    write_private_file(&content_path, content);
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
    write_private_file(&content_path, content);
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
