#[test]
fn indexed_object_read_does_not_move_the_append_cursor() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"position-independent read".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (id, _) = engine.persist_standalone_object(&record).unwrap();
    let cursor_before = {
        let mut inner = engine.inner.lock();
        let arena = &mut live_files_mut(&mut inner.files).unwrap().arena;
        arena.seek(SeekFrom::Start(7)).unwrap();
        arena.stream_position().unwrap()
    };

    assert_eq!(engine.object(id).unwrap(), Some(record));

    let cursor_after = {
        let mut inner = engine.inner.lock();
        live_files_mut(&mut inner.files)
            .unwrap()
            .arena
            .stream_position()
            .unwrap()
    };
    assert_eq!(cursor_after, cursor_before);
}

#[test]
fn adjacent_indexed_objects_share_one_positional_read_span() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let first = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"first adjacent object".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let second = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"second adjacent object".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (first_id, _) = engine.persist_standalone_object(&first).unwrap();
    let (second_id, _) = engine.persist_standalone_object(&second).unwrap();
    let missing = ObjectId::new([0x55; 32]);

    assert_eq!(
        engine
            .objects_for(
                &"alice".to_owned(),
                &[second_id, missing, first_id, second_id],
            )
            .unwrap(),
        vec![Some(second.clone()), None, Some(first), Some(second),]
    );
    assert_eq!(last_batch_spans(), 1);
}

#[test]
fn coalesced_positional_reads_respect_the_frame_allocation_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let bounded = RecoveryLimits::new(256).unwrap();
    let engine = DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, bounded).unwrap();
    let mut ids = Vec::new();
    let mut expected = Vec::new();
    for byte in 0_u8..8 {
        let record = ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            vec![byte; 32],
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let (id, _) = engine.persist_standalone_object(&record).unwrap();
        ids.push(id);
        expected.push(Some(record));
    }

    assert_eq!(
        engine.objects_for(&"alice".to_owned(), &ids).unwrap(),
        expected
    );
    assert!(last_batch_spans() > 1);
}

#[test]
fn standalone_bootstrap_object_cannot_own_principal_state() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        Vec::new(),
        vec![ObjectReference::owns(
            label(b"state"),
            ObjectId::new([1; 32]),
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();

    assert!(matches!(
        engine.persist_standalone_object(&record),
        Err(DurableError::BootstrapObjectOwnsState)
    ));
    assert_eq!(engine.object_count().unwrap(), 0);
}

#[test]
fn staged_closure_is_validated_and_flushed_by_root_commit() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (commit, transaction) = transaction("alice", None, b"streamed");
    for (_, record) in transaction.records() {
        assert_eq!(
            engine.stage_object(record).unwrap().1,
            InsertOutcome::Inserted
        );
    }
    assert_eq!(engine.object_count().unwrap(), 2);
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), None);
    assert!(
        transaction
            .records()
            .iter()
            .all(|(id, _)| engine.inner.lock().validated.contains(id))
    );

    let outcome = engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit,
            Vec::new(),
        ))
        .unwrap();
    assert_eq!(outcome.objects_inserted(), 0);
    drop(engine);

    let reopened = open(directory.path());
    assert_eq!(
        reopened.root(&"alice".to_owned()).unwrap(),
        Some(outcome.root())
    );
    assert_eq!(
        reopened
            .snapshot(&"alice".to_owned())
            .unwrap()
            .unwrap()
            .records()
            .len(),
        2
    );
}

#[test]
fn parent_before_child_staging_falls_back_to_publication_validation() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (commit, transaction) = transaction("alice", None, b"out-of-order");
    for (_, record) in transaction.records().iter().rev() {
        engine.stage_object(record).unwrap();
    }
    assert!(!engine.inner.lock().validated.contains(&commit));

    let outcome = engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit,
            Vec::new(),
        ))
        .unwrap();

    assert_eq!(outcome.objects_inserted(), 0);
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(outcome.root()));
}

#[test]
fn incomplete_staging_cannot_publish_a_dangling_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (commit, transaction) = transaction("alice", None, b"incomplete");
    let commit_record = transaction
        .records()
        .iter()
        .find(|(_, record)| record.kind() == ObjectKind::Commit)
        .unwrap()
        .1
        .clone();
    engine.stage_object(&commit_record).unwrap();

    assert!(!engine.inner.lock().validated.contains(&commit));

    assert!(matches!(
        engine.commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit,
            Vec::new(),
        )),
        Err(DurableError::Model(ModelError::MissingObject(_)))
    ));
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), None);
    assert!(engine.object(commit).unwrap().is_some());
}

#[test]
fn staged_batch_is_idempotent_and_publishes_in_one_root_commit() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (commit, transaction) = transaction("alice", None, b"batch");
    let mut records: Vec<_> = transaction
        .records()
        .iter()
        .map(|(_, record)| record.clone())
        .collect();
    records.push(records[0].clone());

    let outcomes = engine.stage_objects(records).unwrap();
    assert_eq!(outcomes.len(), 3);
    assert_eq!(outcomes[0].1, InsertOutcome::Inserted);
    assert_eq!(outcomes[1].1, InsertOutcome::Inserted);
    assert_eq!(outcomes[2].1, InsertOutcome::AlreadyPresent);

    let outcome = engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit,
            Vec::new(),
        ))
        .unwrap();
    assert_eq!(outcome.objects_inserted(), 0);
    assert!(engine.snapshot(&"alice".to_owned()).unwrap().is_some());
}

#[test]
fn equal_dedup_hits_reconstruct_batch_closure_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"dedup evidence");
    let records = transaction
        .records()
        .iter()
        .map(|(_, record)| record.clone())
        .collect::<Vec<_>>();
    engine.stage_objects(records.clone()).unwrap();
    engine.inner.lock().validated.clear();

    let outcomes = engine.stage_objects(records).unwrap();

    assert!(
        outcomes
            .iter()
            .all(|(_, outcome)| *outcome == InsertOutcome::AlreadyPresent)
    );
    let inner = engine.inner.lock();
    assert!(
        transaction
            .records()
            .iter()
            .all(|(id, _)| inner.validated.contains(id))
    );
}

#[test]
fn staged_batch_identity_work_does_not_hold_engine_mutex() {
    let directory = tempfile::tempdir().unwrap();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let engine = Arc::new(
        DurableEngine::<String, BlockingIdentity, Utf8Codec>::open(
            directory.path(),
            BlockingIdentity {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
            Utf8Codec,
            RecoveryLimits::new(8 * 1024 * 1024).unwrap(),
        )
        .unwrap(),
    );
    let record = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        vec![7; 4 * 1024 * 1024],
        Vec::new(),
        4 * 1024 * 1024,
        ObjectClass::Data,
    )
    .unwrap();

    let staging_engine = Arc::clone(&engine);
    let staging = thread::spawn(move || staging_engine.stage_objects(vec![record]));
    entered.wait();

    let (probe_sender, probe_receiver) = std::sync::mpsc::channel();
    let probe_engine = Arc::clone(&engine);
    let probe = thread::spawn(move || {
        probe_sender.send(probe_engine.object_count()).unwrap();
    });
    let probe_before_release = probe_receiver.recv_timeout(Duration::from_secs(1));

    release.wait();
    let outcomes = staging.join().unwrap().unwrap();
    probe.join().unwrap();

    assert_eq!(
        probe_before_release
            .expect("engine mutex was held while computing batch identities")
            .unwrap(),
        0
    );
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].1, InsertOutcome::Inserted);
}

#[test]
fn staged_batch_collision_appends_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let engine = DurableEngine::<String, ConstantIdentity, Utf8Codec>::open(
        directory.path(),
        ConstantIdentity,
        Utf8Codec,
        limits(),
    )
    .unwrap();
    let first = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"first".to_vec(),
        Vec::new(),
        5,
        ObjectClass::Data,
    )
    .unwrap();
    let second = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"second".to_vec(),
        Vec::new(),
        6,
        ObjectClass::Data,
    )
    .unwrap();

    assert!(matches!(
        engine.stage_objects(vec![first, second]),
        Err(DurableError::Model(ModelError::ObjectCollision(_)))
    ));
    assert_eq!(engine.object_count().unwrap(), 0);
    assert_eq!(
        std::fs::metadata(directory.path().join(ARENA_FILE))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn staged_batch_appender_failure_installs_no_authority() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"partial append");
    let records = transaction
        .records()
        .iter()
        .map(|(_, record)| record.clone())
        .collect::<Vec<_>>();
    let ids = records
        .iter()
        .map(|record| engine.identify(record))
        .collect::<Vec<_>>();

    let error = engine
        .stage_objects_with_test_appender(records, |arena, frames| {
            append_prepared_frames(arena, &frames[..1])?;
            Err(DurableError::Io {
                operation: "injected prepared batch append",
                source: std::io::Error::other("injected appender failure"),
            })
        })
        .unwrap_err();

    assert!(matches!(error, DurableError::Io { .. }));
    let inner = engine.inner.lock();
    assert!(inner.poisoned);
    assert!(inner.roots_by_principal.is_empty());
    assert!(ids.iter().all(|id| !inner.index.contains_key(id)));
    assert!(ids.iter().all(|id| !inner.validated.contains(id)));
    assert_eq!(
        engine.lifecycle.load(Ordering::Acquire),
        LIFECYCLE_REQUIRES_RECOVERY
    );
}

#[test]
fn commit_flush_reopen_rebuilds_index_and_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (commit, transaction) = transaction("alice", None, b"durable");

    let outcome = engine.commit(transaction).unwrap();
    assert_eq!(outcome.objects_inserted(), 2);
    assert_eq!(outcome.root().commit, commit);
    engine.flush().unwrap();
    drop(engine);

    let reopened = open(directory.path());
    assert_eq!(
        reopened.root(&"alice".to_owned()).unwrap(),
        Some(outcome.root())
    );
    assert_eq!(reopened.object_count().unwrap(), 2);
    assert_eq!(
        reopened
            .snapshot(&"alice".to_owned())
            .unwrap()
            .unwrap()
            .records()
            .len(),
        2
    );
}

#[test]
fn root_snapshot_preserves_generation_and_accepts_future_cas() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (first_commit, first_transaction) = transaction("alice", None, b"first");
    let first = engine.commit(first_transaction).unwrap().root();
    let (second_commit, second_transaction) = transaction("alice", Some(first), b"second");
    let second = engine.commit(second_transaction).unwrap().root();
    assert_ne!(first_commit, second_commit);
    engine.close().unwrap();

    let payload =
        encode_root_snapshot(TEST_IDENTITY_SCHEME, &[(b"alice".to_vec(), second)]).unwrap();
    let journal_path = directory.path().join(ROOT_FILE);
    let mut journal = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(journal_path)
        .unwrap();
    append_frame(&mut journal, ROOT_MAGIC, &payload).unwrap();
    journal.sync_data().unwrap();
    drop(journal);

    let recovered = open(directory.path());
    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(second));
    let root_only =
        RootTransaction::new("alice".to_owned(), Some(second), second.commit, Vec::new());
    let third = recovered.commit(root_only).unwrap().root();
    assert_eq!(third.generation, second.generation.checked_next().unwrap());
    drop(recovered);

    assert_eq!(
        open(directory.path()).root(&"alice".to_owned()).unwrap(),
        Some(third)
    );
}

#[test]
fn destination_restore_preserves_roots_and_accepts_future_cas() {
    let source_directory = tempfile::tempdir().unwrap();
    let source = open(source_directory.path());
    let (_, first_transaction) = transaction("alice", None, b"first");
    let first = source.commit(first_transaction).unwrap().root();
    let (_, second_transaction) = transaction("alice", Some(first), b"second");
    let second = source.commit(second_transaction).unwrap().root();
    let snapshot = source.snapshot(&"alice".to_owned()).unwrap().unwrap();

    let destination_directory = tempfile::tempdir().unwrap();
    let destination = open(destination_directory.path());
    let bootstrap = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"destination bootstrap".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    destination.persist_standalone_object(&bootstrap).unwrap();
    destination
        .restore_snapshots(vec![("alice".to_owned(), snapshot)])
        .unwrap();
    assert_eq!(destination.root(&"alice".to_owned()).unwrap(), Some(second));
    destination.close().unwrap();

    let restored = open(destination_directory.path());
    assert_eq!(restored.root(&"alice".to_owned()).unwrap(), Some(second));
    assert_eq!(
        restored
            .snapshot(&"alice".to_owned())
            .unwrap()
            .unwrap()
            .records()
            .len(),
        2
    );
    let root_only =
        RootTransaction::new("alice".to_owned(), Some(second), second.commit, Vec::new());
    let third = restored.commit(root_only).unwrap().root();
    assert_eq!(third.generation, second.generation.checked_next().unwrap());
}

#[test]
fn destination_restore_rejects_a_store_with_existing_roots() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"existing");
    engine.commit(transaction).unwrap();
    let snapshot = engine.snapshot(&"alice".to_owned()).unwrap().unwrap();

    assert!(matches!(
        engine.restore_snapshots(vec![("alice".to_owned(), snapshot)]),
        Err(DurableError::InvalidRestore(
            "destination already has principal roots"
        ))
    ));
}

#[test]
fn mapped_root_snapshot_rekeys_principals_without_changing_roots() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, alice_transaction) = transaction("alice", None, b"alice");
    let alice = engine.commit(alice_transaction).unwrap().root();
    let (_, bob_transaction) = transaction("bob", None, b"bob");
    let bob = engine.commit(bob_transaction).unwrap().root();
    let arena_before = std::fs::read(directory.path().join(ARENA_FILE)).unwrap();
    let replacement = directory.path().join("roots.mapped");

    engine
        .write_mapped_root_snapshot(&replacement, &U64Codec, |principal| {
            match principal.as_str() {
                "alice" => Ok(11),
                "bob" => Ok(22),
                _ => Err(DurableError::InvalidRestore("unexpected test principal")),
            }
        })
        .unwrap();
    assert_eq!(
        engine.root(&"alice".to_owned()).unwrap(),
        Some(alice),
        "writing the successor snapshot must not mutate live roots"
    );
    engine.close().unwrap();
    std::fs::rename(
        directory.path().join(ROOT_FILE),
        directory.path().join("roots.previous"),
    )
    .unwrap();
    std::fs::rename(replacement, directory.path().join(ROOT_FILE)).unwrap();

    let migrated = DurableEngine::open(directory.path(), TestIdentity, U64Codec, limits()).unwrap();
    assert_eq!(migrated.root(&11).unwrap(), Some(alice));
    assert_eq!(migrated.root(&22).unwrap(), Some(bob));
    assert_eq!(
        std::fs::read(directory.path().join(ARENA_FILE)).unwrap(),
        arena_before
    );
}

#[test]
fn every_exposed_fault_recovers_old_or_new_complete_root() {
    for point in [
        FaultPoint::AfterObjectAppend,
        FaultPoint::AfterObjectFlush,
        FaultPoint::AfterCommitAppend,
        FaultPoint::AfterCommitFlush,
        FaultPoint::BeforeRootCas,
        FaultPoint::AfterRootCas,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let initial = open(directory.path());
        let (_, first) = transaction("alice", None, b"before");
        let old = initial.commit(first).unwrap().root();
        drop(initial);

        let interrupted = open_with_fault(directory.path(), point);
        let (new_commit, update) = transaction("alice", Some(old), b"after");
        assert!(matches!(
            interrupted.commit(update),
            Err(DurableError::FaultInjected(actual)) if actual == point
        ));
        let visible = interrupted.root(&"alice".to_owned()).unwrap().unwrap();
        if point == FaultPoint::AfterRootCas {
            assert_eq!(
                visible,
                RootState {
                    generation: RootGeneration::new(1),
                    commit: new_commit,
                },
                "point {point:?}"
            );
        } else {
            assert_eq!(visible, old, "point {point:?}");
        }
        assert!(interrupted.snapshot(&"alice".to_owned()).unwrap().is_some());
        assert!(interrupted.object_count().unwrap() > 0);
        assert!(!interrupted.recover_if_required().unwrap());
        assert!(matches!(
            DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
            Err(DurableError::LockHeld(_))
        ));
    }
}

#[test]
fn truncated_arena_tail_is_removed_without_changing_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let root = engine.commit(transaction).unwrap().root();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let valid_len = std::fs::metadata(&arena).unwrap().len();
    append_partial_header(&arena, ARENA_MAGIC);

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(std::fs::metadata(arena).unwrap().len(), valid_len);
}

#[test]
fn truncated_root_payload_is_removed_without_changing_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let root = engine.commit(transaction).unwrap().root();
    drop(engine);
    let journal = directory.path().join(ROOT_FILE);
    let valid_len = std::fs::metadata(&journal).unwrap().len();
    append_torn_payload(&journal, ROOT_MAGIC);

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(std::fs::metadata(journal).unwrap().len(), valid_len);
}

#[test]
fn complete_magic_corruption_at_tail_is_truncated() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let root = engine.commit(transaction).unwrap().root();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let valid_len = append_orphan_object(&arena);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&arena)
        .unwrap();
    file.seek(SeekFrom::Start(valid_len)).unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_data().unwrap();
    drop(file);

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(std::fs::metadata(arena).unwrap().len(), valid_len);
}

#[test]
fn complete_checksum_corruption_at_tail_is_truncated() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let root = engine.commit(transaction).unwrap().root();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let valid_len = append_orphan_object(&arena);
    let tail_len = std::fs::metadata(&arena).unwrap().len();
    flip_byte(&arena, tail_len.saturating_sub(1));

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(std::fs::metadata(arena).unwrap().len(), valid_len);
}

#[test]
fn rooted_checksum_corruption_at_arena_tail_still_fails_closure_validation() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let root = engine.commit(transaction).unwrap().root();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let commit_offset = frame_end(&arena, 0);
    let tail_len = std::fs::metadata(&arena).unwrap().len();
    flip_byte(&arena, tail_len.saturating_sub(1));

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::RecoveryModel {
            file: ROOT_FILE,
            source: ModelError::MissingObject(missing),
            ..
        }) if missing == root.commit
    ));
    assert_eq!(std::fs::metadata(arena).unwrap().len(), commit_offset);
}

#[test]
fn invalid_root_journal_tail_rolls_back_to_the_last_durable_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, first) = transaction("alice", None, b"before");
    let old = engine.commit(first).unwrap().root();
    let (_, second) = transaction("alice", Some(old), b"after");
    engine.commit(second).unwrap();
    drop(engine);
    let journal = directory.path().join(ROOT_FILE);
    let second_offset = frame_end(&journal, 0);
    let tail_len = std::fs::metadata(&journal).unwrap().len();
    flip_byte(&journal, tail_len.saturating_sub(1));

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(old));
    assert_eq!(std::fs::metadata(journal).unwrap().len(), second_offset);
}

#[test]
fn interior_checksum_corruption_is_fatal_not_silently_truncated() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    engine.commit(transaction).unwrap();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(arena)
        .unwrap();
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN + 33)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x80;
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN + 33)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_data().unwrap();
    drop(file);

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::Corrupt {
            file: ARENA_FILE,
            detail: "frame checksum mismatch",
            ..
        })
    ));
}

#[test]
fn interior_magic_corruption_is_fatal_not_silently_truncated() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    engine.commit(transaction).unwrap();
    drop(engine);
    let arena = directory.path().join(ARENA_FILE);
    let original_len = std::fs::metadata(&arena).unwrap().len();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&arena)
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_data().unwrap();
    drop(file);

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::Corrupt {
            file: ARENA_FILE,
            offset: 0,
            detail: "frame magic mismatch",
        })
    ));
    assert_eq!(std::fs::metadata(arena).unwrap().len(), original_len);
}

#[test]
fn live_snapshot_reads_indexed_objects_lazily_from_the_arena() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    engine.commit(transaction).unwrap();

    let arena = directory.path().join(ARENA_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(arena)
        .unwrap();
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN + 33)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x80;
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN + 33)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_data().unwrap();

    assert!(matches!(
        engine.snapshot(&"alice".to_owned()),
        Err(DurableError::Corrupt {
            file: ARENA_FILE,
            detail: "frame checksum mismatch",
            ..
        })
    ));
}

#[test]
fn recovery_reports_root_journal_model_failure_with_offset() {
    let directory = tempfile::tempdir().unwrap();
    drop(open(directory.path()));
    let journal = directory.path().join(ROOT_FILE);
    let payload = encode_root_record(
        TEST_IDENTITY_SCHEME,
        b"alice",
        None,
        RootState {
            generation: RootGeneration::INITIAL,
            commit: ObjectId::new([99; 32]),
        },
    )
    .unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(journal)
        .unwrap();
    append_frame(&mut file, ROOT_MAGIC, &payload).unwrap();
    file.sync_data().unwrap();
    drop(file);

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::RecoveryModel {
            file: ROOT_FILE,
            offset: 0,
            source: ModelError::MissingObject(_),
        })
    ));
}

#[test]
fn recovery_never_accepts_an_identity_collision() {
    let directory = tempfile::tempdir().unwrap();
    drop(open(directory.path()));
    let first = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"first".to_vec(),
        Vec::new(),
        5,
        ObjectClass::Data,
    )
    .unwrap();
    let second = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"second".to_vec(),
        Vec::new(),
        6,
        ObjectClass::Data,
    )
    .unwrap();
    let id = ObjectId::new([42; 32]);
    let arena = directory.path().join(ARENA_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(arena)
        .unwrap();
    append_frame(
        &mut file,
        ARENA_MAGIC,
        &encode_object_frame(TEST_IDENTITY_SCHEME, id, &first).unwrap(),
    )
    .unwrap();
    append_frame(
        &mut file,
        ARENA_MAGIC,
        &encode_object_frame(TEST_IDENTITY_SCHEME, id, &second).unwrap(),
    )
    .unwrap();
    file.sync_data().unwrap();
    drop(file);

    assert!(matches!(
        DurableEngine::open(
            directory.path(),
            ConstantIdentity,
            Utf8Codec,
            limits()
        ),
        Err(DurableError::RecoveryModel {
            file: ARENA_FILE,
            source: ModelError::ObjectCollision(object),
            ..
        }) if object == id
    ));
}

#[test]
fn recovery_rejects_oversized_declaration_before_allocating_payload() {
    let directory = tempfile::tempdir().unwrap();
    drop(open(directory.path()));
    let arena = directory.path().join(ARENA_FILE);
    let mut file = OpenOptions::new().append(true).open(arena).unwrap();
    append_frame(&mut file, ARENA_MAGIC, &[0_u8; 1024]).unwrap();
    file.sync_data().unwrap();
    drop(file);
    let tiny = RecoveryLimits::new(64).unwrap();

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, tiny),
        Err(DurableError::FrameTooLarge {
            file: ARENA_FILE,
            offset: 0,
            declared: 1024,
            limit: 64,
        })
    ));
}

#[test]
fn recovery_repairs_terminal_torn_oversized_declaration() {
    let directory = tempfile::tempdir().unwrap();
    drop(open(directory.path()));
    let arena = directory.path().join(ARENA_FILE);
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    header[..8].copy_from_slice(&ARENA_MAGIC);
    header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&1024_u64.to_le_bytes());
    let mut file = OpenOptions::new().append(true).open(&arena).unwrap();
    file.write_all(&header).unwrap();
    file.sync_data().unwrap();
    drop(file);
    let tiny = RecoveryLimits::new(64).unwrap();

    drop(DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, tiny).unwrap());
    assert_eq!(std::fs::metadata(arena).unwrap().len(), 0);
}

#[test]
fn recovery_rejects_torn_oversized_declaration_before_complete_oversized_frame() {
    let directory = tempfile::tempdir().unwrap();
    drop(open(directory.path()));
    let arena = directory.path().join(ARENA_FILE);
    let declared = 1_u64 << 20;
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    header[..8].copy_from_slice(&ARENA_MAGIC);
    header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&declared.to_le_bytes());
    let mut file = OpenOptions::new().append(true).open(&arena).unwrap();
    file.write_all(&header).unwrap();
    append_frame(&mut file, ARENA_MAGIC, &[0_u8; 1024]).unwrap();
    file.sync_data().unwrap();
    drop(file);
    let tiny = RecoveryLimits::new(64).unwrap();

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, tiny),
        Err(DurableError::FrameTooLarge {
            file: ARENA_FILE,
            offset: 0,
            declared: actual,
            limit: 64,
        }) if actual == declared
    ));
}

#[test]
fn stale_root_conflict_appends_no_bytes_and_does_not_poison() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, first) = transaction("alice", None, b"first");
    let installed = engine.commit(first).unwrap().root();
    let arena = directory.path().join(ARENA_FILE);
    let journal = directory.path().join(ROOT_FILE);
    let before = (
        std::fs::metadata(&arena).unwrap().len(),
        std::fs::metadata(&journal).unwrap().len(),
    );
    let (_, stale) = transaction("alice", None, b"stale");

    assert!(matches!(
        engine.commit(stale),
        Err(DurableError::Model(ModelError::RootConflict { .. }))
    ));
    assert_eq!(
        before,
        (
            std::fs::metadata(arena).unwrap().len(),
            std::fs::metadata(journal).unwrap().len(),
        )
    );
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(installed));
    assert!(engine.snapshot(&"alice".to_owned()).unwrap().is_some());
}

#[test]
fn concurrent_genesis_has_one_durable_winner() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open(directory.path()));
    let barrier = Arc::new(Barrier::new(9));
    let mut handles = Vec::new();
    for value in 0_u8..8 {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let (_, transaction) = transaction("alice", None, &[value]);
            barrier.wait();
            engine.commit(transaction)
        }));
    }
    barrier.wait();

    let mut successes = 0;
    for handle in handles {
        match handle.join().unwrap() {
            Ok(_) => successes += 1,
            Err(DurableError::Model(ModelError::RootConflict { .. })) => {},
            Err(error) => panic!("unexpected commit error: {error}"),
        }
    }
    assert_eq!(successes, 1);
    let root = engine.root(&"alice".to_owned()).unwrap().unwrap();
    drop(engine);

    let recovered = open(directory.path());
    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
}

#[test]
fn second_writer_cannot_open_the_same_store() {
    let directory = tempfile::tempdir().unwrap();
    let first = open(directory.path());

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::LockHeld(_))
    ));

    drop(first);
    assert!(DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()).is_ok());
}

#[test]
fn governed_object_cache_verifies_once_and_charges_each_principal() {
    let directory = tempfile::tempdir().unwrap();
    let total = ObjectCacheCapacity::Bounded(std::num::NonZeroU64::new(2 * 1024 * 1024).unwrap());
    let engine = open_with_cache(directory.path(), ObjectCacheController::new(total));
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"cacheable evidence".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (id, _) = engine.persist_standalone_object(&record).unwrap();
    let alice = "alice".to_owned();
    let bob = "bob".to_owned();

    let alice_first = engine.shared_object_for(&alice, id).unwrap().unwrap();
    let alice_second = engine.shared_object_for(&alice, id).unwrap().unwrap();
    let bob_record = engine.shared_object_for(&bob, id).unwrap().unwrap();
    assert_eq!(alice_first.as_ref(), &record);
    assert!(Arc::ptr_eq(&alice_first, &alice_second));
    assert!(Arc::ptr_eq(&alice_first, &bob_record));

    let stats = engine.object_cache_stats();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 2);
    assert_eq!(stats.insertions, 1);
    assert_eq!(stats.resident_objects, 1);
    assert!(stats.resident_bytes > 0);
    assert_eq!(
        engine.object_cache_principal_charge(&alice),
        stats.resident_record_bytes
    );
    assert_eq!(
        engine.object_cache_principal_charge(&bob),
        stats.resident_record_bytes
    );
    assert_eq!(stats.resident_associations, 2);
    assert!(stats.resident_association_bytes > 0);
    assert_eq!(engine.object_for(&alice, id).unwrap(), Some(record));
}

#[test]
fn explicit_close_releases_files_while_engine_references_remain() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(open(directory.path()));
    let retained = Arc::clone(&engine);

    engine.close().unwrap();
    engine.close().unwrap();
    assert!(matches!(retained.object_count(), Err(DurableError::Closed)));

    let reopened = open(directory.path());
    assert_eq!(reopened.object_count().unwrap(), 0);
}

#[test]
fn explicit_close_releases_cached_records_and_positional_reader() {
    let directory = tempfile::tempdir().unwrap();
    let total = ObjectCacheCapacity::Bounded(std::num::NonZeroU64::new(1024 * 1024).unwrap());
    let engine = open_with_cache(directory.path(), ObjectCacheController::new(total));
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"cached before close".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (id, _) = engine.persist_standalone_object(&record).unwrap();
    let alice = "alice".to_owned();
    assert_eq!(
        engine.shared_object_for(&alice, id).unwrap().as_deref(),
        Some(&record)
    );
    assert_eq!(engine.object_cache_stats().resident_objects, 1);

    engine.close().unwrap();

    assert!(matches!(
        engine.shared_object_for(&alice, id),
        Err(DurableError::Closed)
    ));
    assert!(matches!(
        engine.shared_objects_for(&alice, &[id]),
        Err(DurableError::Closed)
    ));
    assert!(engine.arena_reader.read().is_none());
    assert_eq!(engine.object_cache_stats().resident_objects, 0);
    assert_eq!(engine.object_cache_stats().resident_bytes, 0);
}

#[test]
fn explicit_close_of_a_poisoned_engine_stays_closed() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    {
        let mut inner = engine.inner.lock();
        engine.mark_requires_recovery(&mut inner);
    }

    assert!(matches!(
        engine.close(),
        Err(DurableError::RequiresRecovery)
    ));
    assert!(matches!(engine.object_count(), Err(DurableError::Closed)));
    assert!(matches!(
        engine.recover_if_required(),
        Err(DurableError::Closed)
    ));
    assert!(engine.close().is_ok());
}

#[test]
fn poisoned_engine_recovers_before_serving_cached_reads() {
    let directory = tempfile::tempdir().unwrap();
    let total = ObjectCacheCapacity::Bounded(std::num::NonZeroU64::new(1024 * 1024).unwrap());
    let engine = open_with_cache(directory.path(), ObjectCacheController::new(total));
    let record = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"cached before poison".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (id, _) = engine.persist_standalone_object(&record).unwrap();
    let alice = "alice".to_owned();
    assert!(engine.shared_object_for(&alice, id).unwrap().is_some());
    let before = engine.object_cache_stats();
    {
        let mut inner = engine.inner.lock();
        engine.mark_requires_recovery(&mut inner);
    }

    assert_eq!(engine.object_cache_stats().resident_objects, 1);
    assert_eq!(
        engine.shared_object_for(&alice, id).unwrap().as_deref(),
        Some(&record)
    );
    assert_eq!(engine.object_cache_stats().resident_objects, 1);
    assert_eq!(
        engine.shared_objects_for(&alice, &[id]).unwrap()[0].as_deref(),
        Some(&record)
    );
    let after = engine.object_cache_stats();
    assert_eq!(after.misses, before.misses + 1);
    assert_eq!(after.insertions, before.insertions + 1);
}

#[test]
fn in_process_recovery_retries_transient_io_within_the_configured_budget() {
    let directory = tempfile::tempdir().unwrap();
    let failures = Arc::new(RecoveryIoFailures::new(2));
    let engine = DurableEngine::open_with_options(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        EngineOpenOptions {
            policy: DurableEnginePolicy::new(
                GroupCommitPolicy::immediate(),
                RecoveryRetryPolicy::new(
                    std::num::NonZeroU32::new(3).unwrap(),
                    Duration::from_millis(1),
                ),
                ObjectCacheConfig::disabled(),
            ),
            faults: failures.clone(),
        },
    )
    .unwrap();
    let (_, transaction) = transaction("alice", None, b"durable");
    let root = engine.commit(transaction).unwrap().root();
    {
        let mut inner = engine.inner.lock();
        engine.mark_requires_recovery(&mut inner);
    }

    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(failures.attempts.load(Ordering::Relaxed), 3);
    assert!(!engine.recover_if_required().unwrap());
}

#[test]
fn in_process_recovery_stops_at_the_budget_and_can_retry_later() {
    let directory = tempfile::tempdir().unwrap();
    let failures = Arc::new(RecoveryIoFailures::new(usize::MAX));
    let engine = DurableEngine::open_with_options(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        EngineOpenOptions {
            policy: DurableEnginePolicy::new(
                GroupCommitPolicy::immediate(),
                RecoveryRetryPolicy::new(std::num::NonZeroU32::new(2).unwrap(), Duration::ZERO),
                ObjectCacheConfig::disabled(),
            ),
            faults: failures.clone(),
        },
    )
    .unwrap();
    {
        let mut inner = engine.inner.lock();
        engine.mark_requires_recovery(&mut inner);
    }

    assert!(matches!(
        engine.object_count(),
        Err(DurableError::Io { .. })
    ));
    assert_eq!(failures.attempts.load(Ordering::Relaxed), 2);

    failures.remaining.store(0, Ordering::Relaxed);
    assert_eq!(engine.object_count().unwrap(), 0);
    assert_eq!(failures.attempts.load(Ordering::Relaxed), 3);
}

#[test]
fn in_process_recovery_does_not_retry_structural_failure() {
    let directory = tempfile::tempdir().unwrap();
    let recovery_attempts = Arc::new(RecoveryIoFailures::new(0));
    let engine = DurableEngine::open_with_options(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        EngineOpenOptions {
            policy: DurableEnginePolicy::new(
                GroupCommitPolicy::immediate(),
                RecoveryRetryPolicy::new(std::num::NonZeroU32::new(3).unwrap(), Duration::ZERO),
                ObjectCacheConfig::disabled(),
            ),
            faults: recovery_attempts.clone(),
        },
    )
    .unwrap();
    let (_, transaction) = transaction("alice", None, b"durable");
    let root = engine.commit(transaction).unwrap().root();
    let arena = directory.path().join(ARENA_FILE);
    let tail_len = std::fs::metadata(&arena).unwrap().len();
    flip_byte(&arena, tail_len.saturating_sub(1));
    {
        let mut inner = engine.inner.lock();
        engine.mark_requires_recovery(&mut inner);
    }

    assert!(matches!(
        engine.object_count(),
        Err(DurableError::RecoveryModel {
            file: ROOT_FILE,
            source: ModelError::MissingObject(missing),
            ..
        }) if missing == root.commit
    ));
    assert_eq!(recovery_attempts.attempts.load(Ordering::Relaxed), 1);
}

#[test]
fn in_process_recovery_retries_ordered_stabilization_flushes() {
    for (point, expected) in [
        (
            FaultPoint::BeforeInProcessRecoveryArenaFlush,
            vec![
                FaultPoint::BeforeInProcessRecoveryArenaFlush,
                FaultPoint::BeforeInProcessRecoveryArenaFlush,
                FaultPoint::BeforeInProcessRecoveryRootFlush,
            ],
        ),
        (
            FaultPoint::BeforeInProcessRecoveryRootFlush,
            vec![
                FaultPoint::BeforeInProcessRecoveryArenaFlush,
                FaultPoint::BeforeInProcessRecoveryRootFlush,
                FaultPoint::BeforeInProcessRecoveryArenaFlush,
                FaultPoint::BeforeInProcessRecoveryRootFlush,
            ],
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let failure = Arc::new(RecoveryFlushFailure::once(point));
        let engine = DurableEngine::open_with_options(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            limits(),
            EngineOpenOptions {
                policy: DurableEnginePolicy::new(
                    GroupCommitPolicy::immediate(),
                    RecoveryRetryPolicy::new(std::num::NonZeroU32::new(2).unwrap(), Duration::ZERO),
                    ObjectCacheConfig::disabled(),
                ),
                faults: failure.clone(),
            },
        )
        .unwrap();
        let (_, transaction) = transaction("alice", None, b"durable");
        let root = engine.commit(transaction).unwrap().root();
        {
            let mut inner = engine.inner.lock();
            engine.mark_requires_recovery(&mut inner);
        }

        assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(root));
        assert_eq!(failure.observed(), expected);
    }
}

#[test]
fn one_read_scope_never_enters_recovery_twice() {
    let directory = tempfile::tempdir().unwrap();
    let recovery_attempts = Arc::new(RecoveryIoFailures::new(0));
    let engine = DurableEngine::open_with_options(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        EngineOpenOptions {
            policy: DurableEnginePolicy::new(
                GroupCommitPolicy::immediate(),
                RecoveryRetryPolicy::immediate(),
                ObjectCacheConfig::disabled(),
            ),
            faults: recovery_attempts.clone(),
        },
    )
    .unwrap();
    let mut recovery = RecoveryScope::default();
    {
        let mut inner = engine.inner.lock();
        engine.mark_requires_recovery(&mut inner);
    }
    drop(engine.lock_usable_with(&mut recovery).unwrap());
    {
        let mut inner = engine.inner.lock();
        engine.mark_requires_recovery(&mut inner);
    }

    assert!(matches!(
        engine.lock_usable_with(&mut recovery),
        Err(DurableError::RequiresRecovery)
    ));
    assert_eq!(recovery_attempts.attempts.load(Ordering::Relaxed), 1);
}

#[test]
fn concurrent_callers_share_one_in_process_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let recovery_attempts = Arc::new(RecoveryIoFailures::new(0));
    let engine = Arc::new(
        DurableEngine::open_with_options(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            limits(),
            EngineOpenOptions {
                policy: DurableEnginePolicy::new(
                    GroupCommitPolicy::immediate(),
                    RecoveryRetryPolicy::immediate(),
                    ObjectCacheConfig::disabled(),
                ),
                faults: recovery_attempts.clone(),
            },
        )
        .unwrap(),
    );
    let (_, transaction) = transaction("alice", None, b"durable");
    let root = engine.commit(transaction).unwrap().root();
    {
        let mut inner = engine.inner.lock();
        engine.mark_requires_recovery(&mut inner);
    }

    let barrier = Arc::new(Barrier::new(9));
    let mut callers = Vec::new();
    for _ in 0..8 {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        callers.push(thread::spawn(move || {
            barrier.wait();
            engine.root(&"alice".to_owned())
        }));
    }
    barrier.wait();
    for caller in callers {
        assert_eq!(caller.join().unwrap().unwrap(), Some(root));
    }
    assert_eq!(recovery_attempts.attempts.load(Ordering::Relaxed), 1);
}

#[test]
fn recovery_generation_wrap_invalidates_the_previous_reader() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    {
        let mut inner = engine.inner.lock();
        inner.arena_generation = u64::MAX;
        engine.arena_reader.write().as_mut().unwrap().generation = u64::MAX;
        engine.mark_requires_recovery(&mut inner);
    }

    assert_eq!(engine.object_count().unwrap(), 0);
    assert_eq!(engine.inner.lock().arena_generation, 0);
    assert_eq!(engine.arena_reader.read().as_ref().unwrap().generation, 0);
}

#[test]
fn configured_frame_boundary_rejects_before_writing() {
    let directory = tempfile::tempdir().unwrap();
    let tiny = RecoveryLimits::new(64).unwrap();
    let engine = DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, tiny).unwrap();
    let (_, transaction) = transaction("alice", None, b"too large");

    assert!(matches!(
        engine.commit(transaction),
        Err(DurableError::FrameTooLarge {
            file: ARENA_FILE,
            limit: 64,
            ..
        })
    ));
    assert_eq!(engine.object_count().unwrap(), 0);
    assert!(engine.snapshot(&"alice".to_owned()).unwrap().is_none());
    assert_eq!(
        std::fs::metadata(directory.path().join(ARENA_FILE))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        std::fs::metadata(directory.path().join(ROOT_FILE))
            .unwrap()
            .len(),
        0
    );
}
