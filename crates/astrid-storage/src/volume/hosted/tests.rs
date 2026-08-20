use super::reclaim::set_test_unlock_hook;
use super::*;
use crate::volume::VolumeFile;

fn append_valid_uncommitted_write(path: &std::path::Path, sequence: u64, payload: &[u8]) {
    let name = b"objects";
    let name_len = u16::try_from(name.len()).unwrap();
    let payload_len = u64::try_from(payload.len()).unwrap();
    let total = u64::try_from(RECORD_FIXED_BYTES)
        .unwrap()
        .checked_add(u64::from(name_len))
        .and_then(|value| value.checked_add(payload_len))
        .unwrap();
    let mut hasher = blake3::Hasher::new_derive_key("astrid volume record v2");
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&[Operation::Write as u8]);
    hasher.update(&name_len.to_le_bytes());
    hasher.update(&0_u64.to_le_bytes());
    hasher.update(&payload_len.to_le_bytes());
    hasher.update(name);
    hasher.update(payload);
    let checksum = *hasher.finalize().as_bytes();
    let mut record = Vec::new();
    record.extend_from_slice(&RECORD_MAGIC);
    record.extend_from_slice(&total.to_le_bytes());
    record.extend_from_slice(&sequence.to_le_bytes());
    record.extend_from_slice(&[Operation::Write as u8]);
    record.extend_from_slice(&name_len.to_le_bytes());
    record.extend_from_slice(&0_u64.to_le_bytes());
    record.extend_from_slice(&payload_len.to_le_bytes());
    record.extend_from_slice(&checksum);
    record.extend_from_slice(name);
    record.extend_from_slice(payload);
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&record).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn hosted_volume_recovers_regions_without_host_directory_projection() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("store/objects").unwrap();
    {
        let volume = HostedFileVolume::open(&path).unwrap();
        volume.create_region(&region, true).unwrap();
        volume.write_region_at(&region, 0, b"abcdef").unwrap();
        volume.write_region_at(&region, 2, b"XY").unwrap();
        volume.set_region_len(&region, 8).unwrap();
        volume.sync().unwrap();
    }
    let volume = HostedFileVolume::open(&path).unwrap();
    let mut bytes = [0xff; 8];
    assert_eq!(volume.read_region_at(&region, 0, &mut bytes).unwrap(), 8);
    assert_eq!(&bytes, b"abXYef\0\0");
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 1);
}

#[test]
fn hosted_volume_reclaim_shrinks_and_recovers_swap_artifacts() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    {
        let volume = HostedFileVolume::open(&path).unwrap();
        volume.create_region(&region, true).unwrap();
        volume
            .write_region_at(&region, 0, &vec![0xAA; 256 * 1024])
            .unwrap();
        volume.write_region_at(&region, 0, b"small").unwrap();
        volume.set_region_len(&region, 5).unwrap();
        volume.sync().unwrap();
        let before = std::fs::metadata(&path).unwrap().len();
        volume.reclaim().unwrap();
        let after = std::fs::metadata(&path).unwrap().len();
        assert!(
            after < before,
            "reclaim did not shrink volume: {before} -> {after}"
        );
    }

    let previous = PathBuf::from(format!("{}.previous", path.display()));
    let temporary_path = PathBuf::from(format!("{}.compacting", path.display()));
    std::fs::copy(&path, &previous).unwrap();
    std::fs::remove_file(&path).unwrap();
    let volume = HostedFileVolume::open(&path).unwrap();
    let mut bytes = [0; 5];
    volume.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"small");
    assert!(!previous.exists());
    drop(volume);

    std::fs::write(&temporary_path, b"uncommitted replacement").unwrap();
    let volume = HostedFileVolume::open(&path).unwrap();
    assert!(!temporary_path.exists());
    drop(volume);
}

#[test]
fn reclaim_blocks_concurrent_open_during_unlock_swap_and_preserves_active_path() {
    use std::sync::mpsc;
    use std::time::Duration;

    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    let volume = HostedFileVolume::open(&path).unwrap();
    volume.create_region(&region, true).unwrap();
    volume
        .write_region_at(&region, 0, &vec![0xCD; 256 * 1024])
        .unwrap();
    volume.sync().unwrap();

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    set_test_unlock_hook(
        path.clone(),
        Box::new(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        }),
    );

    let reclaiming = Arc::clone(&volume);
    let reclaim_thread = std::thread::spawn(move || reclaiming.reclaim());
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("reclaim reached the unlock/swap boundary");

    // Opening during the unlock/swap window must not acquire the retired
    // inode or clean up the in-flight compacting artifact. A correct opener
    // may fail fast or wait for the swap; either way, it must not report a
    // successful open before the reclaiming writer is released.
    let (open_tx, open_rx) = mpsc::channel();
    let open_path = path.clone();
    let open_thread = std::thread::spawn(move || {
        let opened = HostedFileVolume::open(&open_path).is_ok();
        open_tx.send(opened).unwrap();
    });
    let opened_during_window = open_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or(false);
    release_tx.send(()).unwrap();
    open_thread.join().unwrap();
    let reclaim_result = reclaim_thread.join().unwrap();
    drop(volume);

    assert!(
        !opened_during_window,
        "concurrent open acquired the retired active inode"
    );
    reclaim_result.expect("reclaim must complete as one single-writer swap");
    let reopened = HostedFileVolume::open(&path).unwrap();
    let mut bytes = vec![0_u8; 256 * 1024];
    reopened
        .read_region_at(&region, 0, &mut bytes)
        .expect("active path remains readable");
    assert!(bytes.iter().all(|byte| *byte == 0xCD));
    assert!(!reclaim::temp_path(&path).exists());
    assert!(!reclaim::previous_path(&path).exists());
}

#[test]
fn volume_file_has_independent_clone_cursors() {
    let temporary = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(temporary.path().join("astrid.volume")).unwrap();
    let region = VolumeRegion::new("roots").unwrap();
    let mut first = VolumeFile::open(Arc::clone(&volume), region, true).unwrap();
    first.write_all(b"roots").unwrap();
    let mut second = first.try_clone().unwrap();
    second.seek(SeekFrom::Start(1)).unwrap();
    let mut bytes = [0; 3];
    second.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"oot");
    assert_eq!(first.stream_position().unwrap(), 5);
}

#[test]
fn torn_tail_is_retired_on_reopen() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    {
        let volume = HostedFileVolume::open(&path).unwrap();
        volume.create_region(&region, true).unwrap();
        volume.write_region_at(&region, 0, b"durable").unwrap();
        volume.sync().unwrap();
    }
    let valid = std::fs::metadata(&path).unwrap().len();
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"torn")
        .unwrap();
    let volume = HostedFileVolume::open(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), valid);
    let mut bytes = [0; 7];
    volume.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"durable");
}

#[test]
fn complete_or_checksum_damaged_uncommitted_record_is_retired() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    {
        let volume = HostedFileVolume::open(&path).unwrap();
        volume.create_region(&region, true).unwrap();
        volume.write_region_at(&region, 0, b"durable").unwrap();
        volume.sync().unwrap();
    }
    let committed_len = std::fs::metadata(&path).unwrap().len();
    append_valid_uncommitted_write(&path, 4, b"pending");

    let volume = HostedFileVolume::open(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), committed_len);
    let mut bytes = [0; 7];
    volume.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"durable");
    drop(volume);

    append_valid_uncommitted_write(&path, 4, b"corrupt!");
    let mut bytes = std::fs::read(&path).unwrap();
    let checksum_offset = usize::try_from(committed_len)
        .unwrap()
        .checked_add(43)
        .unwrap();
    bytes[checksum_offset] ^= 0x80;
    std::fs::write(&path, bytes).unwrap();
    let volume = HostedFileVolume::open(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), committed_len);
    let mut recovered = [0_u8; 7];
    volume.read_region_at(&region, 0, &mut recovered).unwrap();
    assert_eq!(&recovered, b"durable");
}

#[test]
fn concurrent_volume_writes_recover_in_a_single_durable_generation() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("shared").unwrap();
    let volume = HostedFileVolume::open(&path).unwrap();
    volume.create_region(&region, true).unwrap();
    volume.sync().unwrap();

    std::thread::scope(|scope| {
        for index in 0_u8..8 {
            let volume = Arc::clone(&volume);
            let region = region.clone();
            scope.spawn(move || {
                volume
                    .write_region_at(&region, u64::from(index) * 2, &[index, index + 1])
                    .unwrap();
            });
        }
    });
    volume.sync().unwrap();
    drop(volume);

    let volume = HostedFileVolume::open(&path).unwrap();
    let mut bytes = [0_u8; 16];
    assert_eq!(volume.read_region_at(&region, 0, &mut bytes).unwrap(), 16);
    for index in 0_u8..8 {
        assert_eq!(
            &bytes[usize::from(index) * 2..usize::from(index) * 2 + 2],
            &[index, index + 1]
        );
    }
}

#[test]
fn metadata_transaction_recovers_as_one_namespace_commit() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let active = VolumeRegion::new("objects.arena").unwrap();
    let replacement = VolumeRegion::new("objects.arena.compacting").unwrap();
    let prepared = VolumeRegion::new("system/gc-outbox/receipt.prepared").unwrap();
    let ready = VolumeRegion::new("system/gc-outbox/receipt.ready").unwrap();
    {
        let volume = HostedFileVolume::open(&path).unwrap();
        for (region, bytes) in [
            (&active, b"old".as_slice()),
            (&replacement, b"new".as_slice()),
            (&prepared, b"proof".as_slice()),
        ] {
            volume.create_region(region, true).unwrap();
            volume.write_region_at(region, 0, bytes).unwrap();
        }
        volume
            .commit_metadata(&[
                VolumeMetadataMutation::Replace {
                    source: replacement.clone(),
                    destination: active.clone(),
                },
                VolumeMetadataMutation::Rename {
                    source: prepared.clone(),
                    destination: ready.clone(),
                },
            ])
            .unwrap();
        volume.sync().unwrap();
    }
    let volume = HostedFileVolume::open(&path).unwrap();
    assert!(!volume.region_exists(&replacement).unwrap());
    assert!(!volume.region_exists(&prepared).unwrap());
    let mut current = [0; 3];
    volume.read_region_at(&active, 0, &mut current).unwrap();
    assert_eq!(&current, b"new");
    let mut proof = [0; 5];
    volume.read_region_at(&ready, 0, &mut proof).unwrap();
    assert_eq!(&proof, b"proof");
}

#[test]
fn torn_metadata_transaction_exposes_neither_namespace_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let active = VolumeRegion::new("objects.arena").unwrap();
    let replacement = VolumeRegion::new("objects.arena.compacting").unwrap();
    let prepared = VolumeRegion::new("system/gc-outbox/receipt.prepared").unwrap();
    let ready = VolumeRegion::new("system/gc-outbox/receipt.ready").unwrap();
    let committed_len;
    let transaction_len;
    {
        let volume = HostedFileVolume::open(&path).unwrap();
        for (region, bytes) in [
            (&active, b"old".as_slice()),
            (&replacement, b"new".as_slice()),
            (&prepared, b"proof".as_slice()),
        ] {
            volume.create_region(region, true).unwrap();
            volume.write_region_at(region, 0, bytes).unwrap();
        }
        volume.sync().unwrap();
        committed_len = std::fs::metadata(&path).unwrap().len();
        volume
            .commit_metadata(&[
                VolumeMetadataMutation::Replace {
                    source: replacement.clone(),
                    destination: active.clone(),
                },
                VolumeMetadataMutation::Rename {
                    source: prepared.clone(),
                    destination: ready.clone(),
                },
            ])
            .unwrap();
        volume.sync().unwrap();
        transaction_len = std::fs::metadata(&path).unwrap().len() - committed_len;
    }
    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(committed_len + transaction_len / 2)
        .unwrap();

    let volume = HostedFileVolume::open(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), committed_len);
    assert!(volume.region_exists(&replacement).unwrap());
    assert!(volume.region_exists(&prepared).unwrap());
    assert!(!volume.region_exists(&ready).unwrap());
    let mut current = [0; 3];
    volume.read_region_at(&active, 0, &mut current).unwrap();
    assert_eq!(&current, b"old");
}

#[test]
fn corrupt_record_length_cannot_hide_a_valid_successor() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    {
        let volume = HostedFileVolume::open(&path).unwrap();
        volume.create_region(&region, true).unwrap();
        volume.write_region_at(&region, 0, b"first").unwrap();
        volume.write_region_at(&region, 5, b"second").unwrap();
        volume.sync().unwrap();
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.seek(SeekFrom::Start(VOLUME_MAGIC.len() as u64 + 8))
        .unwrap();
    let mut encoded = [0_u8; 8];
    file.read_exact(&mut encoded).unwrap();
    let create_length = u64::from_le_bytes(encoded);
    let first_write = VOLUME_MAGIC.len() as u64 + create_length;
    file.seek(SeekFrom::Start(first_write + 8)).unwrap();
    file.write_all(&u64::MAX.to_le_bytes()).unwrap();
    file.sync_all().unwrap();

    let error = HostedFileVolume::open(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("interior"), "{error}");
}

#[test]
fn corrupt_record_checksum_cannot_hide_a_valid_successor() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    {
        let volume = HostedFileVolume::open(&path).unwrap();
        volume.create_region(&region, true).unwrap();
        volume.write_region_at(&region, 0, b"first").unwrap();
        volume.write_region_at(&region, 5, b"second").unwrap();
        volume.sync().unwrap();
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.seek(SeekFrom::Start(VOLUME_MAGIC.len() as u64 + 8))
        .unwrap();
    let mut encoded = [0_u8; 8];
    file.read_exact(&mut encoded).unwrap();
    let create_length = u64::from_le_bytes(encoded);
    let first_write = (VOLUME_MAGIC.len() as u64)
        .checked_add(create_length)
        .unwrap();
    let checksum = first_write.checked_add(43).unwrap();
    file.seek(SeekFrom::Start(checksum)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x80;
    file.seek(SeekFrom::Start(checksum)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();

    let error = HostedFileVolume::open(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("interior"), "{error}");
    assert!(error.to_string().contains("checksum"), "{error}");
}

#[test]
fn read_region_at_copies_overlapping_extents_only() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    let volume = HostedFileVolume::open(&path).unwrap();
    volume.create_region(&region, true).unwrap();
    for index in 0..256_u64 {
        let byte = [u8::try_from(index % 251).unwrap()];
        volume.write_region_at(&region, index, &byte).unwrap();
    }
    volume.sync().unwrap();
    REGION_STATE_CLONES.with(|count| count.set(0));
    let mut bytes = [0_u8; 4];
    assert_eq!(volume.read_region_at(&region, 10, &mut bytes).unwrap(), 4);
    assert_eq!(&bytes, &[10, 11, 12, 13]);
    assert_eq!(
        REGION_STATE_CLONES.with(std::cell::Cell::get),
        0,
        "read_region_at cloned RegionState"
    );
}
