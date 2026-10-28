//! Suffix searches must preserve interior-corruption checks with bounded I/O.
use super::super::checkpoint_tests::append_legacy_record;
use super::*;

#[test]
fn suffix_search_reads_buffers_instead_of_one_syscall_per_byte() {
    let mut file = tempfile::tempfile().unwrap();
    let bytes = vec![0xa5; RECOVERY_BUFFER_BYTES * 4];
    file.write_all(&bytes).unwrap();
    READ_AT_COUNT.with(|count| count.set(0));
    assert!(!has_physically_valid_record_after(&file, 0, bytes.len() as u64).unwrap());
    let reads = READ_AT_COUNT.with(Cell::get);
    assert!(
        reads <= 6,
        "suffix search issued {reads} reads for four buffers"
    );
}

#[test]
fn suffix_search_detects_valid_records_across_every_magic_boundary() {
    for split in 0..RECORD_MAGIC.len() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let offset = RECOVERY_BUFFER_BYTES - split;
        std::fs::write(temporary.path(), vec![0xa5; offset]).unwrap();
        append_legacy_record(temporary.path(), 1, Operation::Create, b"objects", 0, b"");
        let file = File::open(temporary.path()).unwrap();
        assert!(
            has_physically_valid_record_after(&file, 0, file.metadata().unwrap().len()).unwrap(),
            "split={split}"
        );
    }
}

#[test]
fn suffix_search_ignores_partial_magic_at_end_and_malformed_decoys() {
    let mut file = tempfile::tempfile().unwrap();
    let mut bytes = vec![0xa5; RECOVERY_BUFFER_BYTES * 2];
    bytes[17..25].copy_from_slice(&RECORD_MAGIC);
    bytes.extend_from_slice(&RECORD_MAGIC[..7]);
    file.write_all(&bytes).unwrap();
    assert!(!has_physically_valid_record_after(&file, 0, bytes.len() as u64).unwrap());
    assert!(!has_physically_valid_record_after(&file, 42, 41).unwrap());
}

#[test]
fn suffix_search_does_not_hide_a_corrupt_later_candidate() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let offset = RECOVERY_BUFFER_BYTES - 3;
    std::fs::write(temporary.path(), vec![0xa5; offset]).unwrap();
    append_legacy_record(temporary.path(), 1, Operation::Create, b"objects", 0, b"");
    let mut bytes = std::fs::read(temporary.path()).unwrap();
    bytes[offset + 43] ^= 0x80;
    std::fs::write(temporary.path(), &bytes).unwrap();
    let file = File::open(temporary.path()).unwrap();
    assert!(has_physically_valid_record_after(&file, 0, bytes.len() as u64).is_err());
}
