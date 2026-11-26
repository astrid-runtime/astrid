use super::*;

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
    use super::super::measured_record::{DataKind, Measured};
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
    let object = Measured::append(counts, DataKind::Object(1), b"compressed")
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
}
