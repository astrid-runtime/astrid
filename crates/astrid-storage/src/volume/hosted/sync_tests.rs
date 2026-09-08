use super::*;

fn counted_sync(volume: &HostedFileVolume) -> usize {
    let mut calls = 0_usize;
    HostedFileVolume::make_durable_with(&mut volume.state.lock(), |file| {
        calls = calls.strict_add(1);
        file.sync_all()
    })
    .unwrap();
    calls
}

#[test]
fn unchanged_volume_flushes_once_after_each_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let volume = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
    assert_eq!(counted_sync(&volume), 0);
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    assert_eq!(counted_sync(&volume), 1);
    assert_eq!(counted_sync(&volume), 0);
    volume.write_region_at(&region, 0, b"bytes").unwrap();
    assert_eq!(counted_sync(&volume), 1);
    assert_eq!(counted_sync(&volume), 0);
    volume
        .write_region_from(&region, 5, 4, &mut &b"tail"[..])
        .unwrap();
    assert_eq!(counted_sync(&volume), 1);
    assert_eq!(counted_sync(&volume), 0);
    volume.set_region_len(&region, 3).unwrap();
    assert_eq!(counted_sync(&volume), 1);
    let renamed = VolumeRegion::new("renamed").unwrap();
    volume.rename_region(&region, &renamed).unwrap();
    assert_eq!(counted_sync(&volume), 1);
    volume.remove_region(&renamed).unwrap();
    assert_eq!(counted_sync(&volume), 1);
    assert_eq!(counted_sync(&volume), 0);
}

#[test]
fn failed_flush_is_retried_without_appending_another_commit() {
    let directory = tempfile::tempdir().unwrap();
    let volume = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
    volume
        .create_region(&VolumeRegion::new("objects").unwrap(), true)
        .unwrap();
    let mut state = volume.state.lock();
    assert!(
        HostedFileVolume::make_durable_with(&mut state, |_| {
            Err(io::Error::other("injected flush failure"))
        })
        .is_err()
    );
    assert_eq!(state.flush_state, FlushState::Required);
    let sequence = state.sequence;
    drop(state);
    assert_eq!(counted_sync(&volume), 1);
    assert_eq!(volume.state.lock().sequence, sequence);
    assert_eq!(counted_sync(&volume), 0);
}

#[test]
fn failed_stream_invalidates_prior_flush_proof() {
    let directory = tempfile::tempdir().unwrap();
    let volume = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"original").unwrap();
    volume.sync().unwrap();
    assert!(
        volume
            .write_region_from(&region, 0, 8, &mut &b"short"[..])
            .is_err()
    );
    assert_eq!(counted_sync(&volume), 1);
    assert_eq!(counted_sync(&volume), 0);
    let mut actual = [0; 8];
    volume.read_region_at(&region, 0, &mut actual).unwrap();
    assert_eq!(&actual, b"original");
}

#[test]
fn new_write_after_failed_flush_is_durable_before_drop() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"before").unwrap();
    assert!(
        HostedFileVolume::make_durable_with(&mut volume.state.lock(), |_| {
            Err(io::Error::other("injected flush failure"))
        })
        .is_err()
    );
    volume.write_region_at(&region, 0, b"after!").unwrap();
    assert_eq!(counted_sync(&volume), 1);
    assert_eq!(counted_sync(&volume), 0);
    // Copy before Drop can do any additional work. The acknowledged boundary
    // must be sufficient for a fresh recovery, including the later write.
    let copy = directory.path().join("recovered.volume");
    std::fs::copy(&path, &copy).unwrap();
    let recovered = HostedFileVolume::open(copy).unwrap();
    let mut actual = [0; 6];
    assert_eq!(
        recovered.read_region_at(&region, 0, &mut actual).unwrap(),
        6
    );
    assert_eq!(&actual, b"after!");
}

#[test]
fn recovered_footer_is_not_a_process_local_flush_proof() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    volume
        .create_region(&VolumeRegion::new("objects").unwrap(), true)
        .unwrap();
    volume.sync().unwrap();
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(counted_sync(&reopened), 1);
    assert_eq!(counted_sync(&reopened), 0);
}

#[test]
fn reclaim_does_not_reuse_the_old_inode_flush_proof() {
    let directory = tempfile::tempdir().unwrap();
    let volume = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
    volume
        .create_region(&VolumeRegion::new("objects").unwrap(), true)
        .unwrap();
    volume.sync().unwrap();
    reclaim::reclaim(&volume).unwrap();
    assert_eq!(counted_sync(&volume), 1);
    assert_eq!(counted_sync(&volume), 0);
}
