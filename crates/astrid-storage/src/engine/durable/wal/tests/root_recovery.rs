use super::*;

struct ShortReads<'a> {
    stream: Cursor<&'a [u8]>,
    chunk: usize,
    fail_seek: Option<SeekFrom>,
}

impl Read for ShortReads<'_> {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        let n = self.chunk.min(destination.len());
        self.stream.read(&mut destination[..n])
    }
}

impl Seek for ShortReads<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if self.fail_seek == Some(position) {
            return Err(io::Error::other("injected WAL seek failure"));
        }
        self.stream.seek(position)
    }
}

#[test]
fn short_reads_preserve_every_transaction_descriptor_and_restore_the_payload_cursor() {
    let mut bytes = raw_transaction(1, Some(object_id(1)), b"alice", true);
    bytes.extend_from_slice(&raw_transaction(2, None, b"bob", true));
    let expected = scan_events(bytes.clone()).unwrap();
    for chunk in [
        1,
        7,
        codec::PHYSICAL_HEADER_LEN - 1,
        codec::PHYSICAL_HEADER_LEN + 1,
    ] {
        let input = ShortReads {
            stream: Cursor::new(&bytes),
            chunk,
            fail_seek: None,
        };
        let mut scanner = WalScanner::new(
            input,
            TestIdentity,
            TestCodec,
            RecoveryLimits::process_addressable(),
        )
        .unwrap();
        for expected_event in &expected {
            assert_eq!(scanner.next_event().unwrap().as_ref(), Some(expected_event));
        }
        assert!(scanner.next_event().unwrap().is_none());
        assert_eq!(
            scanner.reader().stream.position(),
            u64::try_from(bytes.len()).unwrap()
        );
    }
}

#[test]
fn length_probe_preserves_the_failed_seek_operation() {
    let bytes = raw_transaction(1, None, b"alice", true);
    let header_end = u64::try_from(codec::PHYSICAL_HEADER_LEN).unwrap();
    for (seek, expected) in [
        (SeekFrom::End(0), "read ASTWAL2 length"),
        (SeekFrom::Start(header_end), "restore ASTWAL2 cursor"),
    ] {
        let reader = ShortReads {
            stream: Cursor::new(&bytes),
            chunk: 7,
            fail_seek: Some(seek),
        };
        let mut scanner = WalScanner::new(
            reader,
            TestIdentity,
            TestCodec,
            RecoveryLimits::process_addressable(),
        )
        .unwrap();
        assert!(
            matches!(scanner.next_event(), Err(WalError::Io {operation, ..}) if operation == expected)
        );
    }
}

#[test]
fn logical_header_reports_unknown_kind_before_feature_errors_at_original_offset() {
    let offset = WalOffset::new(731);
    let mut header = [0_u8; codec::RECORD_HEADER_LEN];
    header[0] = WalRecordKind::Object.tag();
    header[4] = 1;
    for flag in [2, 0x80, 0xff] {
        header[1] = flag;
        assert!(matches!(
            codec::decode_record(&header, offset),
            Err(WalError::Corrupt { offset: found, detail: "WAL record flags or reserved bytes are non-zero" })
                if found == offset
        ));
    }
    header[1] = 0;
    header[2] = 1;
    assert!(matches!(
        codec::decode_record(&header, offset),
        Err(WalError::Corrupt {offset: found, detail: "WAL record flags or reserved bytes are non-zero"})
            if found == offset
    ));
    header[0] = 0xff;
    assert!(matches!(
        codec::decode_record(&header, offset),
        Err(WalError::Corrupt { offset: found, detail: "WAL record kind is unknown" }) if found == offset
    ));
}

#[test]
fn decoder_rejects_malformed_root_fields_at_the_original_offset() {
    let offset = WalOffset::new(731);
    let prior = root(16);
    let next = RootState {
        generation: RootGeneration::new(1),
        commit: object_id(17),
    };
    let canonical = encode_root_record(scheme(), b"x", Some(prior), next).unwrap();
    let read = |bytes: &[u8]| codec::decode_root_body(bytes, scheme(), &TestCodec, offset);
    let corrupt = |bytes: &[u8], detail| matches!(read(bytes), Err(WalError::Corrupt { offset: found, detail: reason }) if found == offset && reason == detail);
    assert!(read(&canonical).is_ok());
    for end in 0..canonical.len() {
        assert!(
            corrupt(&canonical[..end], "WAL root record is truncated"),
            "prefix {end}"
        );
    }
    for (index, byte) in [(18, 0), (20, 2), (70, 31), (70, 33)] {
        let mut malformed = canonical.clone();
        malformed[index] = byte;
        assert!(matches!(
            read(&malformed),
            Err(WalError::IdentitySchemeMismatch)
        ));
    }
    let mut bad = canonical.clone();
    bad[9] = 2;
    assert!(corrupt(&bad, "WAL root expected tag is invalid"));
    let mut exhausted = canonical.clone();
    exhausted[10..18].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(corrupt(
        &exhausted,
        "WAL root generation transition is invalid"
    ));
    let mut trailing = canonical;
    trailing.push(0);
    assert!(corrupt(&trailing, "WAL root record has trailing bytes"));
}

#[test]
fn prepared_payload_must_identify_the_live_transaction_before_append() {
    let mut writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(1), None).unwrap();
    let owner = String::from("alice");
    let replacement = root(71);
    let journal = encode_root_record(scheme(), owner.as_bytes(), None, replacement).unwrap();
    assert!(matches!(
        writer.append_prepared_root(&String::from("other"), None, replacement, &journal),
        Err(WalError::PrincipalMismatch)
    ));
    assert!(matches!(
        writer.append_prepared_root(&owner, None, root(72), &journal),
        Err(WalError::InvalidTransaction(_))
    ));
    let next = RootState {
        generation: RootGeneration::new(1),
        commit: object_id(73),
    };
    let updated = encode_root_record(scheme(), owner.as_bytes(), Some(replacement), next).unwrap();
    assert!(matches!(
        writer.append_prepared_root(&owner, Some(root(72)), next, &updated),
        Err(WalError::InvalidTransaction(_))
    ));
    writer
        .append_prepared_root(&owner, None, replacement, &journal)
        .unwrap();
    let descriptor = writer.finish_commit().unwrap();
    assert_eq!(descriptor.root_count.get(), 1);
    assert_eq!(writer.publish().unwrap(), 1);
}

#[test]
fn replay_exposes_exactly_the_completed_transactions_at_every_byte_cut() {
    let first = raw_transaction(1, Some(object_id(1)), b"alice", true);
    let second = raw_transaction(2, None, b"bob", true);
    let mut image = first.clone();
    image.extend_from_slice(&second);
    for end in 0..=image.len() {
        let mut scanner = WalScanner::new(
            Cursor::new(&image[..end]),
            TestIdentity,
            TestCodec,
            RecoveryLimits::process_addressable(),
        )
        .unwrap();
        for (boundary, owner, object_count) in [
            (first.len(), b"alice".as_slice(), 1),
            (image.len(), b"bob".as_slice(), 0),
        ] {
            if end < boundary {
                break;
            }
            let batch = replay::next_transaction(&mut scanner)
                .unwrap()
                .expect("complete transaction");
            assert_eq!(batch.objects.len(), object_count, "prefix {end}");
            if let Some(object) = batch.objects.first() {
                assert_eq!(object.id(), object_id(1));
            }
            assert_eq!(batch.roots.len(), 1);
            assert_eq!(
                batch.roots[0].transition().principal(),
                owner,
                "prefix {end}"
            );
        }
        assert!(
            replay::next_transaction(&mut scanner).unwrap().is_none(),
            "partial transaction at byte {end}"
        );
    }
}

#[test]
fn commit_errors_identify_the_field_that_disagreed_with_the_stream() {
    let canonical = raw_transaction(1, Some(object_id(1)), b"alice", true);
    let changed = |position| {
        let mut bytes = canonical.clone();
        mutate_record(&mut bytes, 3, |payload| {
            payload[RECORD_HEADER_LEN + position] ^= 2u8;
        });
        scan_events(bytes).unwrap_err()
    };
    assert!(
        matches!(changed(0), WalError::CommitSequenceMismatch { expected, found }
        if expected == sequence(1) && found == sequence(3))
    );
    for (position, label) in [
        (8, "logical records"),
        (16, "objects"),
        (24, "roots"),
        (32, "logical bytes"),
    ] {
        assert!(
            matches!(changed(position), WalError::CommitCountMismatch {field} if field == label)
        );
    }
    assert!(matches!(changed(40), WalError::DigestMismatch));
}

#[test]
fn digest_matches_the_astwal2_transcript_across_record_boundaries() {
    let mut expected = super::super::codec::new_digest();
    let mut actual = super::super::codec::new_digest();
    for (ordinal, (kind, tag, flags, payload)) in [
        (WalRecordKind::Begin, 1, 0, b"begin".as_slice()),
        (WalRecordKind::Object, 2, 1, b"compressed".as_slice()),
        (WalRecordKind::Root, 3, 0, b"root".as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let ordinal = u64::try_from(ordinal).unwrap();
        if flags != 0 {
            expected.update(&[255, tag, flags]);
        } else {
            expected.update(&[tag]);
        }
        expected.update(&513u64.to_le_bytes());
        expected.update(&ordinal.to_le_bytes());
        expected.update(&u64::try_from(payload.len()).unwrap().to_le_bytes());
        expected.update(payload);
        super::super::codec::digest_record_with_flags(
            &mut actual,
            kind,
            flags,
            sequence(513),
            WalOrdinal::new(ordinal),
            payload,
        );
        assert_eq!(actual.finalize(), expected.finalize());
    }
}

#[test]
fn incomplete_and_complete_oversized_candidates_have_different_recovery_boundaries() {
    let limits = RecoveryLimits::new(128).unwrap();
    let size = super::super::codec::wal_physical_limit(limits)
        .length()
        .get()
        + 1;
    let mut later = Vec::from(*b"ASTWAL2\0");
    later.extend_from_slice(&[1, 0, 0, 0]);
    later.extend_from_slice(&size.to_le_bytes());
    // A complete oversized candidate stops truncation without a checksum read.
    later.extend_from_slice(&[0; 32]);
    later.resize(later.len() + usize::try_from(size).unwrap(), 0);
    for gap in [1, 7, 52, 53] {
        let mut image = vec![0; gap];
        image.extend_from_slice(&later);
        let mut full =
            WalScanner::new(Cursor::new(&image), TestIdentity, TestCodec, limits).unwrap();
        assert!(
            matches!(full.next_event(), Err(WalError::InteriorCorruption { offset, .. }) if offset.get() == 0)
        );
        image.pop();
        let mut truncated =
            WalScanner::new(Cursor::new(&image), TestIdentity, TestCodec, limits).unwrap();
        assert!(
            matches!(truncated.next_event().unwrap(), Some(WalEvent::Tail(tail)) if tail.offset.get() == 0)
        );
    }
}

#[test]
fn measured_writer_matches_reference_frame_and_digest_vectors() {
    use super::super::measured_record::{DataKind, Measured, ObjectEncoding};
    // The reference encoder packed the frozen ASTWAL2 fields independently
    // and hashed them with b3sum's two domain-separated derive-key contexts.
    let mut digest = super::super::codec::new_digest();
    let limits = RecoveryLimits::process_addressable();
    let begin = Measured::begin(513, b"begin").ok().unwrap();
    let (bytes, counts) = super::super::codec::write_measured(begin, limits, &mut digest).unwrap();
    assert_eq!(
        hex::encode(bytes),
        "41535457414c3200010000001900000000000000c8ebf8f4785f8dcbe8e3f3f2a7d05d6948603580701fbfabeaed0d1ca7a8e1b30100000001020000000000000000000000000000626567696e"
    );
    let object = Measured::append(counts, DataKind::Object(ObjectEncoding::Lz4), b"compressed")
        .ok()
        .unwrap();
    let (bytes, counts) = super::super::codec::write_measured(object, limits, &mut digest).unwrap();
    assert_eq!(
        hex::encode(bytes),
        "41535457414c3200020000001e00000000000000469ab70d3831d16bddb67d211bea265d9db2aff463ea9fc5edcb481295dc921b0201000001020000000000000100000000000000636f6d70726573736564"
    );
    let root = Measured::append(counts, DataKind::Root, b"root")
        .ok()
        .unwrap();
    let (bytes, counts) = super::super::codec::write_measured(root, limits, &mut digest).unwrap();
    assert_eq!(
        hex::encode(bytes),
        "41535457414c3200010000001800000000000000defd8718428c66690b9822495718565e0f6c5d17cc7e1e9a7c37bcee8fbc4d680300000001020000000000000200000000000000726f6f74"
    );
    assert_eq!(
        (
            counts.sequence,
            counts.logical,
            counts.objects,
            counts.roots,
            counts.bytes
        ),
        (513, 3, 1, 1, 79)
    );
    assert_eq!(
        digest.finalize().to_hex().as_str(),
        "9be4a0c43266399e10756cf2a26b845af308852ad1b0ca292a379cc922cd205d"
    );
    let marker = super::super::commit_wire::Marker {
        counts,
        digest: *digest.finalize().as_bytes(),
    };
    let frame = super::super::codec::write_marker(&marker, limits).unwrap();
    assert_eq!(
        hex::encode(frame),
        "41535457414c3200010000005c00000000000000f1360c7a3ec12c4f8447e1a44a37708ba92dd079a96635b436abcfa69fc8f01c040000000102000000000000030000000000000001020000000000000300000000000000010000000000000001000000000000004f000000000000009be4a0c43266399e10756cf2a26b845af308852ad1b0ca292a379cc922cd205d"
    );
}

#[test]
fn replay_failure_and_retry_preserve_owner_tags_and_the_first_offset() {
    use crate::principal_state::{StateOwner, StateOwnerCodecV2};
    use astrid_core::{FleetUid, identity::PrincipalUid};
    use root_history::Decision;
    use std::collections::BTreeMap;

    let bytes = [7; 32];
    let owner = StateOwner::Principal(PrincipalUid::from_bytes(bytes));
    let fleet = StateOwner::Fleet(FleetUid::from_bytes(bytes));
    let recovered = StateOwnerCodecV2
        .decode(&StateOwnerCodecV2.encode(&owner))
        .unwrap();
    assert_eq!(recovered, owner);
    let mut history = BTreeMap::from([(fleet, (root(4), 19))]);
    let before = history.clone();
    let refused = root_history::fold(
        &mut history,
        recovered,
        None,
        root(0),
        71,
        Into::into,
        |_, _, _| Err::<(), _>("encoding failed"),
    );
    assert!(matches!(refused, Err("encoding failed")));
    assert_eq!(history, before);

    let applied = root_history::fold(
        &mut history,
        recovered,
        None,
        root(0),
        71,
        Into::into,
        |key, expected, replacement| {
            encode_root_record(
                scheme(),
                &StateOwnerCodecV2.encode(key),
                expected,
                replacement,
            )
        },
    );
    assert!(matches!(applied, Ok(Decision::Applied(wire)) if wire ==
        encode_root_record(scheme(), &StateOwnerCodecV2.encode(&owner), None, root(0)).unwrap()));
    let repeat = root_history::fold(
        &mut history,
        recovered,
        None,
        root(0),
        83,
        Into::into,
        |_, _, _| -> Result<(), ()> { panic!("idempotent replay attempted journal encoding") },
    );
    assert!(matches!(repeat, Ok(Decision::AlreadyPublished)));
    assert_eq!(
        history,
        BTreeMap::from([(fleet, (root(4), 19)), (owner, (root(0), 71))])
    );
}

#[test]
fn incremental_closure_checks_the_root_kind_and_follows_only_owning_edges() {
    use crate::engine::durable::{
        DurableError, File,
        validation::{ClosureObjects, validate_incremental_closure},
    };
    use crate::storage_model::{ModelError, ObjectReference, ReferenceKind, ReferenceLabel};
    use std::collections::{BTreeMap, BTreeSet};

    let commit = object_id(1);
    let chunk = object_id(2);
    let absent = object_id(3);
    let mut refs = Vec::new();
    for (label, id, kind) in [
        (0, chunk, ReferenceKind::Owns),
        (1, absent, ReferenceKind::Evidence),
        (2, absent, ReferenceKind::Lineage),
        (3, absent, ReferenceKind::Derived),
    ] {
        refs.push(ObjectReference::new(
            ReferenceLabel::new(vec![label]),
            id,
            kind,
        ));
    }
    let commit_record = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        vec![],
        refs,
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let incoming = BTreeMap::from([(commit, commit_record), (chunk, record(2, 8))]);
    let mut arena = File::Native(tempfile::tempfile().unwrap());
    let mut source = ClosureObjects::<_, String> {
        arena: &mut arena,
        index: &BTreeMap::new(),
        incoming: &incoming,
        pending: None,
        identity: &TestIdentity,
        limits: RecoveryLimits::process_addressable(),
    };
    let seen = validate_incremental_closure(&mut source, &BTreeSet::new(), commit).unwrap();
    assert_eq!(seen, BTreeSet::from([commit, chunk]));
    assert!(
        matches!(validate_incremental_closure(&mut source, &seen, chunk),
        Err(DurableError::Model(ModelError::RootNotCommit {object, ..})) if object == chunk)
    );
    let missing = BTreeMap::from([(commit, incoming[&commit].clone())]);
    let mut source = ClosureObjects {
        incoming: &missing,
        ..source
    };
    assert!(
        matches!(validate_incremental_closure(&mut source,&BTreeSet::new(),commit),
        Err(DurableError::Model(ModelError::MissingObject(id))) if id == chunk)
    );
    assert_eq!(
        validate_incremental_closure(&mut source, &BTreeSet::from([chunk]), commit).unwrap(),
        BTreeSet::from([commit, chunk])
    );

    let cycle_member = ObjectRecord::new(
        ObjectKind::Directory,
        ObjectFormatVersion::V1,
        vec![],
        vec![ObjectReference::owns(ReferenceLabel::new(vec![0]), commit)],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let cyclic = BTreeMap::from([(commit, incoming[&commit].clone()), (chunk, cycle_member)]);
    let mut source = ClosureObjects {
        incoming: &cyclic,
        ..source
    };
    assert!(
        matches!(validate_incremental_closure(&mut source,&BTreeSet::new(),commit),
        Err(DurableError::Model(ModelError::ObjectCycle(id))) if id == commit)
    );
}

#[test]
fn closure_prefers_incoming_then_pending_then_the_indexed_record() {
    use crate::engine::durable::{
        ARENA_MAGIC, DurableError, File,
        format::append_frame,
        validation::{ClosureObjects, validate_incremental_closure},
    };
    use crate::storage_model::ModelError;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        vec![],
        vec![],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let id = TestIdentity.identify(&commit);
    let payload = encode_object_frame(scheme(), id, &commit).unwrap();
    let mut arena = File::Native(tempfile::tempfile().unwrap());
    let location = append_frame(&mut arena, ARENA_MAGIC, &payload).unwrap();
    let index = BTreeMap::from([(id, location)]);
    // Distinct in-memory fixtures make the selected layer observable. The arena
    // contains real frame bytes under the independently computed commit id.
    let mut pending = PendingWalOverlay::<String>::default();
    let chunk = record(2, 8);
    pending
        .insert_prepared(
            id,
            encode_object_frame(scheme(), id, &chunk).unwrap().into(),
            Arc::new(chunk),
        )
        .unwrap();
    let incoming = BTreeMap::from([(id, commit)]);
    let mut source = ClosureObjects {
        arena: &mut arena,
        index: &index,
        incoming: &incoming,
        pending: Some(&pending),
        identity: &TestIdentity,
        limits: RecoveryLimits::process_addressable(),
    };
    let cached = BTreeSet::new();
    assert_eq!(
        validate_incremental_closure(&mut source, &cached, id).unwrap(),
        BTreeSet::from([id])
    );
    let empty = BTreeMap::new();
    let mut source = ClosureObjects {
        incoming: &empty,
        ..source
    };
    assert!(
        matches!(validate_incremental_closure(&mut source,&cached,id),
        Err(DurableError::Model(ModelError::RootNotCommit {object,actual})) if object == id && actual == ObjectKind::Chunk)
    );
    let mut source = ClosureObjects {
        pending: None,
        ..source
    };
    assert_eq!(
        validate_incremental_closure(&mut source, &cached, id).unwrap(),
        BTreeSet::from([id])
    );
}

#[test]
fn indexed_preload_reaches_shared_descendants_and_ignores_nonowning_targets() {
    use crate::engine::durable::{
        ARENA_MAGIC, DurableError, File, format::append_frame, preload_indexed_closures,
    };
    use crate::storage_model::{ModelError, ObjectReference, ReferenceKind, ReferenceLabel};
    use std::collections::BTreeMap;

    let mut arena = File::Native(tempfile::tempfile().unwrap());
    let mut index = BTreeMap::new();
    let mut stored = BTreeMap::new();
    let mut save = |tag: u64, links: &[(ObjectId, ReferenceKind)]| {
        let refs = links
            .iter()
            .enumerate()
            .map(|(i, (id, kind))| {
                ObjectReference::new(
                    ReferenceLabel::new(vec![u8::try_from(i).unwrap()]),
                    *id,
                    *kind,
                )
            })
            .collect();
        let object = ObjectRecord::new(
            ObjectKind::Commit,
            ObjectFormatVersion::V1,
            tag.to_le_bytes().to_vec(),
            refs,
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let id = TestIdentity.identify(&object);
        let payload = encode_object_frame(scheme(), id, &object).unwrap();
        let location = append_frame(&mut arena, ARENA_MAGIC, &payload).unwrap();
        index.insert(id, location);
        stored.insert(id, object);
        id
    };
    let unrelated = save(1, &[]);
    let leaf = save(2, &[]);
    let shared = save(
        3,
        &[
            (leaf, ReferenceKind::Owns),
            (unrelated, ReferenceKind::Evidence),
        ],
    );
    let first = save(4, &[(shared, ReferenceKind::Owns)]);
    let second = save(5, &[(shared, ReferenceKind::Owns)]);
    let limits = RecoveryLimits::process_addressable();
    let history = BTreeMap::from(
        [(1, first), (2, second), (3, first)].map(|(owner, commit)| {
            let root = RootState {
                generation: RootGeneration::new(owner),
                commit,
            };
            (owner, (root, 100 + owner))
        }),
    );
    let projected = crate::engine::durable::journal_closure::project(&history, |owner| *owner);
    assert_eq!(projected.len(), history.len());
    for (owner, (root, _)) in &history {
        assert_eq!(projected.get(owner), Some(root));
    }
    let roots = crate::engine::durable::journal_closure::commits(&history);
    stored.remove(&unrelated);
    assert_eq!(
        preload_indexed_closures(&arena, &index, roots.clone(), &TestIdentity, limits).unwrap(),
        stored
    );
    let admitted = crate::engine::durable::roots::validate_preloaded(&history, &stored).unwrap();
    assert_eq!(admitted, stored.keys().copied().collect());
    index.remove(&leaf);
    assert!(
        matches!(preload_indexed_closures(&arena,&index,roots,&TestIdentity,limits),
        Err(DurableError::Model(ModelError::MissingObject(id))) if id == leaf)
    );
}

#[test]
fn single_and_batched_arena_reads_bind_the_frame_and_canonical_record_to_the_request() {
    use crate::engine::durable::{
        ARENA_FILE, ARENA_MAGIC, DurableError, File,
        format::{append_frame, read_indexed_object, read_indexed_objects},
    };
    let mut arena = File::Native(tempfile::tempfile().unwrap());
    let value = record(1, 8);
    let correct = TestIdentity.identify(&value);
    let other = object_id(2);
    let good = append_frame(
        &mut arena,
        ARENA_MAGIC,
        &encode_object_frame(scheme(), correct, &value).unwrap(),
    )
    .unwrap();
    let mislabeled = append_frame(
        &mut arena,
        ARENA_MAGIC,
        &encode_object_frame(scheme(), other, &value).unwrap(),
    )
    .unwrap();
    let limits = RecoveryLimits::process_addressable();
    assert_eq!(
        read_indexed_object(&arena, correct, good, &TestIdentity, limits).unwrap(),
        value
    );
    assert_eq!(
        read_indexed_objects(&arena, &[(correct, good)], &TestIdentity, limits).unwrap()[&correct],
        value
    );
    for (location, detail) in [
        (good, "indexed object identifier mismatch"),
        (
            mislabeled,
            "indexed object identity does not match its canonical record",
        ),
    ] {
        let single =
            read_indexed_object(&arena, other, location, &TestIdentity, limits).unwrap_err();
        let batch =
            read_indexed_objects(&arena, &[(other, location)], &TestIdentity, limits).unwrap_err();
        for error in [single, batch] {
            assert!(
                matches!(error, DurableError::Corrupt {file:ARENA_FILE,offset, detail: actual}
                if offset == location.offset && actual == detail)
            );
        }
    }
}
