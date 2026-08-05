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
fn compatible_format_amendment_reopens_an_existing_direct_profile() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let old_specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"pre-amendment physical specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let new_specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"successor physical specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (old_specification_id, _) = engine
        .persist_standalone_object(&old_specification)
        .unwrap();
    let (new_specification_id, _) = engine
        .persist_standalone_object(&new_specification)
        .unwrap();
    let (first_commit, first) = transaction("alice", None, b"before format amendment");
    let first_root = engine.commit(first).unwrap().root();
    engine
        .ensure_direct_representation_catalogue(
            old_specification_id,
            &[old_specification_id, new_specification_id],
        )
        .unwrap();
    engine.close().unwrap();
    drop(engine);

    let reopened = open(directory.path());
    assert!(
        reopened
            .ensure_direct_representation_catalogue(
                new_specification_id,
                &[old_specification_id, new_specification_id],
            )
            .is_err()
    );
    reopened
        .ensure_direct_representation_catalogue_compatible_with(
            new_specification_id,
            &[old_specification_id],
            &[old_specification_id, new_specification_id],
        )
        .unwrap();
    let (second_commit, second) =
        transaction("alice", Some(first_root), b"after format amendment");
    reopened.commit(second).unwrap();
    reopened.close().unwrap();
    drop(reopened);

    let reopened_again = open(directory.path());
    reopened_again
        .ensure_direct_representation_catalogue_compatible_with(
            new_specification_id,
            &[old_specification_id],
            &[old_specification_id, new_specification_id],
        )
        .unwrap();
    let inner = reopened_again.inner.lock();
    let representations = inner.representations.as_ref().unwrap();
    assert_eq!(
        representations.frozen_specification().unwrap(),
        old_specification_id
    );
    assert!(representations.contains_direct(first_commit));
    assert!(representations.contains_direct(second_commit));
}

#[test]
fn direct_profile_lives_in_the_map_while_legacy_profile_frames_still_reopen() {
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
    let state = engine
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
    engine.close().unwrap();
    drop(engine);

    let metadata_path = directory
        .path()
        .join("representations/generations/0000000000000001/metadata.arena");
    assert_eq!(
        super::representations::profile_frame_count(&metadata_path, limits()).unwrap(),
        0
    );
    super::representations::append_legacy_profile_frame(&metadata_path, specification_id)
        .unwrap();

    let reopened = open(directory.path());
    assert_eq!(
        reopened
            .ensure_direct_representation_catalogue(specification_id, &[specification_id])
            .unwrap(),
        state
    );
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
fn verified_staged_closure_consumes_direct_description_witnesses() {
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
    let (commit, transaction) = transaction("alice", None, b"staged direct witnesses");
    let records = transaction
        .records()
        .iter()
        .map(|(_, record)| record.clone())
        .collect::<Vec<_>>();
    let object_ids = transaction
        .records()
        .iter()
        .map(|(object, _)| *object)
        .collect::<Vec<_>>();

    engine.stage_objects(records).unwrap();
    assert_eq!(engine.inner.lock().pending_direct_objects.len(), 2);
    engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit,
            Vec::new(),
        ))
        .unwrap();

    let inner = engine.inner.lock();
    assert!(inner.pending_direct_objects.is_empty());
    let representations = inner.representations.as_ref().unwrap();
    assert!(
        object_ids
            .into_iter()
            .all(|object| representations.contains_direct(object))
    );
}

#[test]
fn unverified_staged_witness_cannot_hide_arena_tampering() {
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
        b"unreachable staged object".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (staged_id, _) = engine.stage_object(&staged).unwrap();
    let location = engine.inner.lock().index[&staged_id];
    let byte_offset = location
        .offset
        .checked_add(FRAME_HEADER_LEN)
        .and_then(|offset| offset.checked_add(location.payload_len - 1))
        .unwrap();
    let mut arena = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join(ARENA_FILE))
        .unwrap();
    arena.seek(SeekFrom::Start(byte_offset)).unwrap();
    let mut byte = [0_u8; 1];
    arena.read_exact(&mut byte).unwrap();
    arena.seek(SeekFrom::Start(byte_offset)).unwrap();
    arena.write_all(&[byte[0] ^ 0x80]).unwrap();

    assert!(matches!(engine.flush(), Err(DurableError::Corrupt { .. })));
}

#[test]
fn published_direct_tail_corruption_is_not_truncated() {
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
        b"scrubbed when accessed".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (staged_id, _) = engine.stage_object(&staged).unwrap();
    let location = engine.inner.lock().index[&staged_id];
    engine.close().unwrap();
    drop(engine);

    let arena_path = directory.path().join(ARENA_FILE);
    let published_len = std::fs::metadata(&arena_path).unwrap().len();
    let byte_offset = location
        .offset
        .checked_add(FRAME_HEADER_LEN)
        .and_then(|offset| offset.checked_add(location.payload_len - 1))
        .unwrap();
    let mut arena = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&arena_path)
        .unwrap();
    arena.seek(SeekFrom::Start(byte_offset)).unwrap();
    let mut byte = [0_u8; 1];
    arena.read_exact(&mut byte).unwrap();
    arena.seek(SeekFrom::Start(byte_offset)).unwrap();
    arena.write_all(&[byte[0] ^ 0x80]).unwrap();
    arena.sync_data().unwrap();

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::Corrupt { .. })
    ));
    assert_eq!(std::fs::metadata(arena_path).unwrap().len(), published_len);
}

#[test]
fn reopen_defers_unreachable_interior_frame_scrub_until_read() {
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
    let records = [b"scrubbed when accessed one".as_slice(), b"later valid tail"].map(|bytes| {
        ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            bytes.to_vec(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap()
    });
    let ids = engine
        .stage_objects(records.into_iter().collect())
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect::<Vec<_>>();
    engine.flush().unwrap();
    let (corrupt_id, location) = {
        let inner = engine.inner.lock();
        ids.into_iter()
            .map(|id| (id, inner.index[&id]))
            .min_by_key(|(_, location)| location.offset)
            .unwrap()
    };
    engine.close().unwrap();
    drop(engine);

    let byte_offset = location
        .offset
        .checked_add(FRAME_HEADER_LEN)
        .and_then(|offset| offset.checked_add(location.payload_len - 1))
        .unwrap();
    let mut arena = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join(ARENA_FILE))
        .unwrap();
    arena.seek(SeekFrom::Start(byte_offset)).unwrap();
    let mut byte = [0_u8; 1];
    arena.read_exact(&mut byte).unwrap();
    arena.seek(SeekFrom::Start(byte_offset)).unwrap();
    arena.write_all(&[byte[0] ^ 0x80]).unwrap();
    arena.sync_data().unwrap();

    let reopened = open(directory.path());
    assert!(matches!(
        reopened.object(corrupt_id),
        Err(DurableError::Corrupt { .. })
    ));
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

#[test]
fn direct_batch_persists_only_its_final_reachable_map_nodes() {
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
    let metadata_path = directory
        .path()
        .join("representations/generations/0000000000000001/metadata.arena");
    let initial_length = std::fs::metadata(&metadata_path).unwrap().len();
    let records = (0_u32..64)
        .map(|ordinal| {
            ObjectRecord::new(
                ObjectKind::Evidence,
                ObjectFormatVersion::V1,
                ordinal.to_le_bytes().to_vec(),
                Vec::new(),
                0,
                ObjectClass::Metadata,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    engine.stage_objects(records).unwrap();
    engine.flush().unwrap();

    let mut metadata = OpenOptions::new()
        .read(true)
        .write(true)
        .open(metadata_path)
        .unwrap();
    let mut appended_frames = 0_usize;
    scan_frames(
        &mut metadata,
        "representations/metadata.arena",
        *b"ASTRPM1\0",
        limits(),
        |offset, _payload| {
            appended_frames += usize::from(offset >= initial_length);
            Ok(())
        },
    )
    .unwrap();

    // The radix leaves and their branches need 174 reachable frames for
    // these two 64-entry maps. Only the catalogue, placement, and state are
    // additional; historical path-copy nodes must not leak into the batch.
    assert_eq!(appended_frames, 174 + 3);
}
