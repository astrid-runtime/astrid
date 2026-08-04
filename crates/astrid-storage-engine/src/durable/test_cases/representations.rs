#[test]
fn direct_representation_activation_reopens_and_tracks_later_commits() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"physical format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = engine.persist_standalone_object(&specification).unwrap();
    let (first_commit, first) = transaction("alice", None, b"before activation");
    let first_root = engine.commit(first).unwrap().root();

    let initial_state = engine
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    {
        let inner = engine.inner.lock();
        let representations = inner.representations.as_ref().unwrap();
        assert_eq!(representations.active(), initial_state);
        assert!(representations.contains_direct(first_commit));
        assert!(!representations.contains_direct(specification_id));
    }

    let (second_commit, second) = transaction("alice", Some(first_root), b"after activation");
    engine.commit(second).unwrap();
    let advanced_state = {
        let inner = engine.inner.lock();
        let representations = inner.representations.as_ref().unwrap();
        assert!(representations.contains_direct(second_commit));
        assert_ne!(representations.active(), initial_state);
        representations.active()
    };
    engine.close().unwrap();
    drop(engine);

    let reopened = open(directory.path());
    assert_eq!(
        reopened
            .ensure_direct_representation_catalogue(specification_id, &[specification_id])
            .unwrap(),
        advanced_state
    );
    let inner = reopened.inner.lock();
    let representations = inner.representations.as_ref().unwrap();
    assert!(representations.contains_direct(first_commit));
    assert!(representations.contains_direct(second_commit));
    assert!(!representations.contains_direct(specification_id));
}

#[test]
fn direct_representation_activation_quarantines_an_unpublished_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let representation_root = directory.path().join("representations");
    std::fs::create_dir_all(representation_root.join("generations/0000000000000001")).unwrap();
    std::fs::write(representation_root.join("CURRENT.tmp"), b"torn").unwrap();
    let engine = open(directory.path());
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = engine.persist_standalone_object(&specification).unwrap();

    engine
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();

    assert!(directory.path().join("representations/CURRENT").is_file());
    assert!(
        directory
            .path()
            .join("representations.incomplete.00000000/CURRENT.tmp")
            .is_file()
    );
}

#[test]
fn representation_journal_truncates_an_uncommitted_tail() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = engine.persist_standalone_object(&specification).unwrap();
    let (_, transaction) = transaction("alice", None, b"represented");
    let expected_root = engine.commit(transaction).unwrap().root();
    engine
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    engine.close().unwrap();
    drop(engine);

    let journal = directory
        .path()
        .join("representations/generations/0000000000000001/state.journal");
    let valid_length = std::fs::metadata(&journal).unwrap().len();
    append_partial_header(&journal, *b"ASTREP1\0");
    assert!(std::fs::metadata(&journal).unwrap().len() > valid_length);

    let reopened = open(directory.path());
    assert_eq!(std::fs::metadata(&journal).unwrap().len(), valid_length);
    assert_eq!(
        reopened.root(&"alice".to_owned()).unwrap(),
        Some(expected_root)
    );
}

#[test]
fn valid_representation_cas_without_its_metadata_repairs_from_the_arena() {
    let directory = tempfile::tempdir().unwrap();
    let initial = open(directory.path());
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = initial.persist_standalone_object(&specification).unwrap();
    let (_, first) = transaction("alice", None, b"before repairable physical tail");
    let first_root = initial.commit(first).unwrap().root();
    let initial_state = initial
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    initial.close().unwrap();
    drop(initial);

    let metadata = directory
        .path()
        .join("representations/generations/0000000000000001/metadata.arena");
    let journal = directory
        .path()
        .join("representations/generations/0000000000000001/state.journal");
    let metadata_before = std::fs::metadata(&metadata).unwrap().len();
    let journal_before = std::fs::metadata(&journal).unwrap().len();

    let engine = open(directory.path());
    let (second_commit, second) = transaction(
        "alice",
        Some(first_root),
        b"root durable while physical metadata is torn",
    );
    let second_root = engine.commit(second).unwrap().root();
    engine.close().unwrap();
    drop(engine);
    assert!(std::fs::metadata(&metadata).unwrap().len() > metadata_before);
    assert!(std::fs::metadata(&journal).unwrap().len() > journal_before);

    let metadata_file = OpenOptions::new().write(true).open(&metadata).unwrap();
    metadata_file.set_len(metadata_before).unwrap();
    metadata_file.sync_data().unwrap();
    drop(metadata_file);

    let repaired = open(directory.path());
    assert_eq!(
        repaired.root(&"alice".to_owned()).unwrap(),
        Some(second_root)
    );
    assert_eq!(std::fs::metadata(&journal).unwrap().len(), journal_before);
    {
        let inner = repaired.inner.lock();
        let representations = inner.representations.as_ref().unwrap();
        assert_eq!(representations.active(), initial_state);
        assert!(!representations.contains_direct(second_commit));
    }

    let repaired_state = repaired
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    assert_ne!(repaired_state, initial_state);
    repaired.close().unwrap();
    drop(repaired);

    let reopened = open(directory.path());
    assert_eq!(
        reopened
            .ensure_direct_representation_catalogue(specification_id, &[specification_id])
            .unwrap(),
        repaired_state
    );
    assert_eq!(
        reopened.root(&"alice".to_owned()).unwrap(),
        Some(second_root)
    );
    assert!(
        reopened
            .inner
            .lock()
            .representations
            .as_ref()
            .unwrap()
            .contains_direct(second_commit)
    );
}

#[test]
fn representation_state_is_durable_before_root_publication() {
    let directory = tempfile::tempdir().unwrap();
    let initial = open(directory.path());
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = initial.persist_standalone_object(&specification).unwrap();
    let (_, first) = transaction("alice", None, b"before root fault");
    let old_root = initial.commit(first).unwrap().root();
    initial
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    initial.close().unwrap();
    drop(initial);

    let interrupted = open_with_fault(directory.path(), FaultPoint::BeforeRootCas);
    let (unpublished_commit, update) =
        transaction("alice", Some(old_root), b"represented before root CAS");
    assert!(matches!(
        interrupted.commit(update),
        Err(DurableError::FaultInjected(FaultPoint::BeforeRootCas))
    ));
    assert_eq!(
        interrupted.root(&"alice".to_owned()).unwrap(),
        Some(old_root)
    );
    {
        let inner = interrupted.inner.lock();
        assert!(
            inner
                .representations
                .as_ref()
                .unwrap()
                .contains_direct(unpublished_commit)
        );
    }
    interrupted.close().unwrap();
    drop(interrupted);

    let reopened = open(directory.path());
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(old_root));
    let inner = reopened.inner.lock();
    assert!(
        inner
            .representations
            .as_ref()
            .unwrap()
            .contains_direct(unpublished_commit)
    );
}

#[test]
fn activation_repair_covers_an_arena_flush_without_a_state_cas() {
    let directory = tempfile::tempdir().unwrap();
    let initial = open(directory.path());
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = initial.persist_standalone_object(&specification).unwrap();
    let (_, first) = transaction("alice", None, b"before object flush fault");
    let old_root = initial.commit(first).unwrap().root();
    initial
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    initial.close().unwrap();
    drop(initial);

    let faults = Arc::new(RecoveryFlushFailure::once(FaultPoint::AfterObjectFlush));
    let interrupted = DurableEngine::open_with_faults(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        faults,
    )
    .unwrap();
    let (unpublished_commit, update) = transaction(
        "alice",
        Some(old_root),
        b"flushed without representation CAS",
    );
    assert!(matches!(
        interrupted.commit(update),
        Err(DurableError::FaultInjected(FaultPoint::AfterObjectFlush))
    ));
    assert_eq!(
        interrupted.root(&"alice".to_owned()).unwrap(),
        Some(old_root)
    );

    interrupted
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    assert!(
        interrupted
            .inner
            .lock()
            .representations
            .as_ref()
            .unwrap()
            .contains_direct(unpublished_commit)
    );
    interrupted.close().unwrap();
    drop(interrupted);

    let reopened = open(directory.path());
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(old_root));
    assert!(
        reopened
            .inner
            .lock()
            .representations
            .as_ref()
            .unwrap()
            .contains_direct(unpublished_commit)
    );
}

#[test]
fn retry_represents_a_recovered_orphan_without_reappending_it() {
    let directory = tempfile::tempdir().unwrap();
    let initial = open(directory.path());
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = initial.persist_standalone_object(&specification).unwrap();
    let (_, first) = transaction("alice", None, b"before retry");
    let old_root = initial.commit(first).unwrap().root();
    initial
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    initial.close().unwrap();
    drop(initial);

    let faults = Arc::new(RecoveryFlushFailure::once(FaultPoint::AfterObjectFlush));
    let engine = DurableEngine::open_with_faults(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        limits(),
        faults,
    )
    .unwrap();
    let (commit, first_attempt) = transaction("alice", Some(old_root), b"retry me");
    assert!(matches!(
        engine.commit(first_attempt),
        Err(DurableError::FaultInjected(FaultPoint::AfterObjectFlush))
    ));
    let arena_after_fault = std::fs::metadata(directory.path().join(ARENA_FILE))
        .unwrap()
        .len();
    let (_, retry) = transaction("alice", Some(old_root), b"retry me");
    assert_eq!(engine.commit(retry).unwrap().root().commit, commit);
    assert_eq!(
        std::fs::metadata(directory.path().join(ARENA_FILE))
            .unwrap()
            .len(),
        arena_after_fault
    );
    assert!(
        engine
            .inner
            .lock()
            .representations
            .as_ref()
            .unwrap()
            .contains_direct(commit)
    );
}

#[test]
fn representation_metadata_tail_cannot_remove_active_authority() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = engine.persist_standalone_object(&specification).unwrap();
    let (_, transaction) = transaction("alice", None, b"represented");
    engine.commit(transaction).unwrap();
    engine
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    engine.close().unwrap();
    drop(engine);

    let metadata = directory
        .path()
        .join("representations/generations/0000000000000001/metadata.arena");
    let mut bytes = std::fs::read(&metadata).unwrap();
    *bytes.last_mut().unwrap() ^= 0x80;
    std::fs::write(&metadata, bytes).unwrap();

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::InvalidRepresentationState(_))
    ));
}

#[test]
fn activated_flush_publishes_direct_paths_for_staged_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = engine.persist_standalone_object(&specification).unwrap();
    engine
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    let staged = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"staged before flush".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (staged_id, _) = engine.stage_object(&staged).unwrap();

    engine.flush().unwrap();
    assert!(
        engine
            .inner
            .lock()
            .representations
            .as_ref()
            .unwrap()
            .contains_direct(staged_id)
    );
    engine.close().unwrap();
    drop(engine);

    let reopened = open(directory.path());
    assert!(
        reopened
            .inner
            .lock()
            .representations
            .as_ref()
            .unwrap()
            .contains_direct(staged_id)
    );
}

#[test]
fn standalone_ack_covers_an_earlier_staged_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"format specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = engine.persist_standalone_object(&specification).unwrap();
    engine
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    let earlier = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"earlier staged object".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let later = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"later standalone object".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (earlier_id, _) = engine.stage_object(&earlier).unwrap();
    let (later_id, _) = engine.persist_standalone_object(&later).unwrap();
    engine.close().unwrap();
    drop(engine);

    let reopened = open(directory.path());
    let inner = reopened.inner.lock();
    let representations = inner.representations.as_ref().unwrap();
    assert!(representations.contains_direct(earlier_id));
    assert!(representations.contains_direct(later_id));
}

