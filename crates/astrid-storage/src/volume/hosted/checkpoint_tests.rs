use super::*;

const SNAPSHOT_MAGIC: &[u8; 8] = b"ASTMAP1\0";
fn snapshot_count(path: &std::path::Path) -> usize {
    let bytes = std::fs::read(path).unwrap();
    bytes
        .windows(SNAPSHOT_MAGIC.len())
        .filter(|window| *window == SNAPSHOT_MAGIC)
        .count()
}

fn append_legacy_record(
    path: &std::path::Path,
    sequence: u64,
    operation: Operation,
    name: &[u8],
    logical_offset: u64,
    payload: &[u8],
) {
    let name_len = u16::try_from(name.len()).unwrap();
    let payload_len = u64::try_from(payload.len()).unwrap();
    let total = u64::try_from(RECORD_FIXED_BYTES)
        .unwrap()
        .strict_add(u64::from(name_len))
        .strict_add(payload_len);
    let mut hasher = blake3::Hasher::new_derive_key("astrid volume record v1");
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&[operation as u8]);
    hasher.update(&name_len.to_le_bytes());
    hasher.update(&logical_offset.to_le_bytes());
    hasher.update(&payload_len.to_le_bytes());
    hasher.update(name);
    hasher.update(payload);
    let checksum = *hasher.finalize().as_bytes();
    let mut record = Vec::new();
    record.extend_from_slice(&RECORD_MAGIC);
    record.extend_from_slice(&total.to_le_bytes());
    record.extend_from_slice(&sequence.to_le_bytes());
    record.extend_from_slice(&[operation as u8]);
    record.extend_from_slice(&name_len.to_le_bytes());
    record.extend_from_slice(&logical_offset.to_le_bytes());
    record.extend_from_slice(&payload_len.to_le_bytes());
    record.extend_from_slice(&checksum);
    record.extend_from_slice(name);
    record.extend_from_slice(payload);
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&record).unwrap();
    file.sync_all().unwrap();
}

fn footer_fields(path: &std::path::Path) -> (u64, u64, u64) {
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() >= recover::FOOTER_BYTES);
    let start = bytes.len().strict_sub(recover::FOOTER_BYTES);
    let footer = &bytes[start..];
    assert_eq!(&footer[..8], b"ASTFTR1\0");
    (
        u64::from_le_bytes(footer[8..16].try_into().unwrap()),
        u64::from_le_bytes(footer[16..24].try_into().unwrap()),
        u64::from_le_bytes(footer[24..32].try_into().unwrap()),
    )
}

fn record_sequence(path: &std::path::Path, offset: u64) -> u64 {
    let bytes = std::fs::read(path).unwrap();
    let start = usize::try_from(offset).unwrap();
    let seq_start = start.strict_add(16);
    let seq_end = start.strict_add(24);
    u64::from_le_bytes(bytes[seq_start..seq_end].try_into().unwrap())
}

fn open_objects(path: &std::path::Path) -> (Arc<HostedFileVolume>, VolumeRegion) {
    let volume = HostedFileVolume::open(path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    (volume, region)
}

#[test]
fn tiny_overwrite_commits_are_empty_and_recover() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let (volume, region) = open_objects(&path);
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"hello").unwrap();
    volume.sync().unwrap();
    let snapshot_offset = volume.state.lock().last_commit_offset;
    let snapshot_end = volume.state.lock().last_snapshot_end;
    assert_eq!(snapshot_count(&path), 1);

    volume.write_region_at(&region, 0, b"world").unwrap();
    volume.sync().unwrap();
    assert_eq!(volume.state.lock().last_commit_offset, snapshot_offset);
    assert_eq!(volume.state.lock().last_snapshot_end, snapshot_end);
    assert_eq!(snapshot_count(&path), 1);
    let (named, _, sequence) = footer_fields(&path);
    assert_eq!(named, snapshot_offset);
    assert!(sequence > record_sequence(&path, snapshot_offset));
    // Copy before Drop can flush again. Close-triggered durability must not
    // be what makes the empty commit recoverable.
    let copy = temporary.path().join("after-sync.volume");
    std::fs::copy(&path, &copy).unwrap();
    let recovered = HostedFileVolume::open(&copy).unwrap();
    let mut actual = [0_u8; 5];
    recovered.read_region_at(&region, 0, &mut actual).unwrap();
    assert_eq!(&actual, b"world");
    assert_eq!(recovered.state.lock().last_commit_offset, snapshot_offset);
    assert_eq!(recovered.state.lock().last_snapshot_end, snapshot_end);
}

#[test]
fn reopen_keeps_empty_commits_without_extra_snapshots() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let (volume, region) = open_objects(&path);
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, &[1]).unwrap();
    volume.sync().unwrap();
    let snapshot_offset = volume.state.lock().last_commit_offset;
    let copy = temporary.path().join("after-first.volume");
    std::fs::copy(&path, &copy).unwrap();
    let recovered = HostedFileVolume::open(&copy).unwrap();
    assert_eq!(recovered.state.lock().last_commit_offset, snapshot_offset);
    drop(volume);
    let volume = recovered;
    for value in 2_u8..6 {
        volume.write_region_at(&region, 0, &[value]).unwrap();
        volume.sync().unwrap();
        assert_eq!(volume.state.lock().last_commit_offset, snapshot_offset);
    }
    assert_eq!(snapshot_count(&copy), 1);
    let after = temporary.path().join("after-loop.volume");
    std::fs::copy(&copy, &after).unwrap();
    let recovered = HostedFileVolume::open(&after).unwrap();
    let mut actual = [0_u8; 1];
    recovered.read_region_at(&region, 0, &mut actual).unwrap();
    assert_eq!(actual, [5]);
    assert_eq!(snapshot_count(&after), 1);
}

#[test]
fn damaged_footer_after_sparse_commits_scans_and_reinstalls() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let (volume, region) = open_objects(&path);
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"first").unwrap();
    volume.sync().unwrap();
    volume.write_region_at(&region, 0, b"later").unwrap();
    volume.sync().unwrap();
    drop(volume);

    let committed_len = std::fs::metadata(&path).unwrap().len();
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len().checked_sub(1).unwrap();
    bytes[last] ^= 0x80;
    std::fs::write(&path, &bytes).unwrap();

    let volume = HostedFileVolume::open(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), committed_len);
    let mut recovered = [0_u8; 5];
    volume.read_region_at(&region, 0, &mut recovered).unwrap();
    assert_eq!(&recovered, b"later");
    let restored = std::fs::read(&path).unwrap();
    assert_eq!(
        &restored[restored.len() - recover::FOOTER_BYTES..][..8],
        b"ASTFTR1\0"
    );
    assert_ne!(restored[last], bytes[last]);
}

#[test]
fn corrupt_durable_tail_fails_open() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let snapshot_end;
    {
        let (volume, region) = open_objects(&path);
        volume.create_region(&region, true).unwrap();
        volume.write_region_at(&region, 0, b"keep").unwrap();
        volume.sync().unwrap();
        snapshot_end = volume.state.lock().last_snapshot_end;
        volume.write_region_at(&region, 0, b"tail").unwrap();
        volume.sync().unwrap();
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.seek(SeekFrom::Start(snapshot_end)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x80;
    file.seek(SeekFrom::Start(snapshot_end)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let error = HostedFileVolume::open(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn torn_footer_after_sparse_commits_scans_and_reinstalls() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let (volume, region) = open_objects(&path);
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"keep!").unwrap();
    volume.sync().unwrap();
    volume.write_region_at(&region, 0, b"later").unwrap();
    volume.sync().unwrap();
    drop(volume);

    let committed_len = std::fs::metadata(&path).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(committed_len.strict_sub(recover::FOOTER_BYTES as u64 / 2))
        .unwrap();

    let volume = HostedFileVolume::open(&path).unwrap();
    let mut recovered = [0_u8; 5];
    volume.read_region_at(&region, 0, &mut recovered).unwrap();
    assert_eq!(&recovered, b"later");
    let restored = std::fs::read(&path).unwrap();
    assert_eq!(
        &restored[restored.len().strict_sub(recover::FOOTER_BYTES)..][..8],
        b"ASTFTR1\0"
    );
}

#[test]
fn torn_uncommitted_tail_after_sparse_commit_is_retired() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let (volume, region) = open_objects(&path);
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"keep!").unwrap();
    volume.sync().unwrap();
    volume.write_region_at(&region, 0, b"later").unwrap();
    volume.sync().unwrap();
    let snapshot_offset = volume.state.lock().last_commit_offset;
    drop(volume);

    let committed_len = std::fs::metadata(&path).unwrap().len();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"torn-tail")
        .unwrap();

    let volume = HostedFileVolume::open(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), committed_len);
    let mut recovered = [0_u8; 5];
    volume.read_region_at(&region, 0, &mut recovered).unwrap();
    assert_eq!(&recovered, b"later");
    assert_eq!(volume.state.lock().last_commit_offset, snapshot_offset);
}

#[test]
fn legacy_empty_commit_file_upgrades_to_named_snapshot_on_open() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    std::fs::write(&path, VOLUME_MAGIC).unwrap();
    append_legacy_record(&path, 1, Operation::Create, b"objects", 0, &[]);
    append_legacy_record(&path, 2, Operation::Write, b"objects", 0, b"old!");
    append_legacy_record(
        &path,
        3,
        Operation::Commit,
        COMMIT_REGION.as_bytes(),
        0,
        &[],
    );
    assert_eq!(snapshot_count(&path), 0);

    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    let mut recovered = [0_u8; 4];
    volume.read_region_at(&region, 0, &mut recovered).unwrap();
    assert_eq!(&recovered, b"old!");
    assert_eq!(snapshot_count(&path), 1);
    assert_ne!(volume.state.lock().last_snapshot_end, 0);
    volume.write_region_at(&region, 0, b"new!").unwrap();
    volume.sync().unwrap();
    assert_eq!(snapshot_count(&path), 1);
}

#[test]
fn snapshot_rollover_after_format_bound_write() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let (volume, region) = open_objects(&path);
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, &[0x11]).unwrap();
    volume.sync().unwrap();
    assert_eq!(snapshot_count(&path), 1);

    let length = recover::MAX_COMMIT_SNAPSHOT_BYTES;
    volume
        .write_region_from(&region, 0, length, &mut io::repeat(0x5A).take(length))
        .unwrap();
    volume.sync().unwrap();
    assert_eq!(snapshot_count(&path), 2);
    drop(volume);

    let volume = HostedFileVolume::open(&path).unwrap();
    let mut first = [0_u8; 1];
    let mut last = [0_u8; 1];
    volume.read_region_at(&region, 0, &mut first).unwrap();
    volume
        .read_region_at(&region, length.strict_sub(1), &mut last)
        .unwrap();
    assert_eq!(first, [0x5A]);
    assert_eq!(last, [0x5A]);
    assert_eq!(volume.region_len(&region).unwrap(), length);
}

#[test]
fn legacy_reader_rejects_sparse_file_but_open_succeeds() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let (volume, region) = open_objects(&path);
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"old").unwrap();
    volume.sync().unwrap();
    volume.write_region_at(&region, 0, b"new").unwrap();
    volume.sync().unwrap();
    drop(volume);

    let (named, durable_len, sequence) = footer_fields(&path);
    let file = File::open(&path).unwrap();
    assert!(
        !recover::legacy_reader_accepts_terminal_snapshot(&file, named, durable_len, sequence,)
            .unwrap()
    );
    drop(file);

    let volume = HostedFileVolume::open(&path).unwrap();
    let mut recovered = [0_u8; 3];
    volume.read_region_at(&region, 0, &mut recovered).unwrap();
    assert_eq!(&recovered, b"new");
}

#[test]
fn failed_flush_retries_empty_commit_without_appending() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let (volume, region) = open_objects(&path);
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"base").unwrap();
    volume.sync().unwrap();
    volume.write_region_at(&region, 0, b"next").unwrap();
    let mut state = volume.state.lock();
    assert!(
        HostedFileVolume::make_durable_with(&mut state, |_| {
            Err(io::Error::other("injected flush failure"))
        })
        .is_err()
    );
    let sequence = state.sequence;
    let snapshot_offset = state.last_commit_offset;
    drop(state);
    HostedFileVolume::make_durable(&mut volume.state.lock()).unwrap();
    let state = volume.state.lock();
    assert_eq!(state.sequence, sequence);
    assert_eq!(state.last_commit_offset, snapshot_offset);
    assert_eq!(state.flush_state, FlushState::Confirmed);
}

#[test]
fn sparse_tail_rejects_corrupt_write_header_checksum_and_payload() {
    // Preserve valid framing: none of these flips damage the record magic or
    // declared length. The write checksum must authenticate what replay trusts.
    let payload_start = RECORD_FIXED_BYTES as u64 + "objects".len() as u64;
    let payload = vec![0x5A; 64 * 1024 + 17];
    for relative_offset in [27_u64, 43, payload_start, payload_start + 64 * 1024] {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("writer.volume");
        let (volume, region) = open_objects(&path);
        volume.create_region(&region, true).unwrap();
        volume.write_region_at(&region, 0, b"base").unwrap();
        volume.sync().unwrap();
        let tail_start = volume.state.lock().last_snapshot_end;
        volume.write_region_at(&region, 0, &payload).unwrap();
        volume.sync().unwrap();
        let copy = temporary.path().join("corrupt.volume");
        std::fs::copy(&path, &copy).unwrap();
        let mut bytes = std::fs::read(&copy).unwrap();
        let offset = usize::try_from(tail_start + relative_offset).unwrap();
        bytes[offset] ^= 1;
        std::fs::write(&copy, bytes).unwrap();
        let error =
            HostedFileVolume::open(&copy).expect_err("corrupt durable write must not be accepted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("checksum"), "{error}");
    }
}
