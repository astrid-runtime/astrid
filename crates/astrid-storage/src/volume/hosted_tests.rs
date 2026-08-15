use super::*;
use crate::volume::VolumeFile;

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
