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
