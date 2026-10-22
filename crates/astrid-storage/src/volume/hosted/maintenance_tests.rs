use super::*;

#[test]
fn reclaim_streams_each_region_as_one_extent_without_cloning_namespace() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    // Sparse holes and overwritten bytes must survive coalescing.
    volume.write_region_at(&region, 0, b"first").unwrap();
    volume.write_region_at(&region, 200_000, b"last").unwrap();
    volume.write_region_at(&region, 1, b"!").unwrap();
    volume.sync().unwrap();
    REGION_STATE_CLONES.with(|count| count.set(0));
    volume.reclaim().unwrap();
    assert_eq!(REGION_STATE_CLONES.with(Cell::get), 0);
    assert_eq!(volume.state.lock().regions[&region].extents.len(), 1);
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    let mut bytes = vec![255; 200_004];
    reopened.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes[..5], b"f!rst");
    assert!(bytes[5..200_000].iter().all(|byte| *byte == 0));
    assert_eq!(&bytes[200_000..], b"last");
}

#[test]
fn failed_atomic_publish_preserves_the_original_writable_state() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"before").unwrap();
    volume.sync().unwrap();
    let staged = reclaim::temp_path(&path);
    reclaim::set_test_swap_hook(
        path.clone(),
        Box::new(move || {
            std::fs::remove_file(staged).unwrap();
        }),
    );
    assert!(volume.reclaim().is_err());
    volume.write_region_at(&region, 0, b"after!").unwrap();
    volume.sync().unwrap();
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    let mut bytes = [0; 6];
    reopened.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"after!");
}

#[test]
fn sync_coalesces_a_namespace_exceeding_the_snapshot_format_bound() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"x").unwrap();
    // Construct the same fragmented mapping as repeated one-byte writes,
    // sharing a valid source byte to avoid a large redundant disk fixture.
    let count = recover::MAX_COMMIT_SNAPSHOT_BYTES
        .strict_div(24)
        .strict_add(1);
    {
        let mut state = volume.state.lock();
        let target = state.regions.get_mut(&region).unwrap();
        let physical = target.extents[&0].physical_offset;
        target.extents = (0..count)
            .map(|offset| {
                (
                    offset,
                    Extent {
                        logical_end: offset.strict_add(1),
                        physical_offset: physical,
                    },
                )
            })
            .collect();
        target.length = count;
        assert!(recover::encode_region_snapshot(&state.regions).is_err());
    }
    volume.sync().unwrap();
    assert_eq!(volume.state.lock().regions[&region].extents.len(), 1);
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    let mut bytes = vec![0; usize::try_from(count).unwrap()];
    assert_eq!(
        reopened.read_region_at(&region, 0, &mut bytes).unwrap(),
        bytes.len()
    );
    assert!(bytes.iter().all(|byte| *byte == b'x'));
}

#[test]
fn directory_flush_failure_keeps_publication_pending_until_successful_retry() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"retained").unwrap();
    volume.sync().unwrap();
    reclaim::FAIL_DIRECTORY_SYNC.with(|fail| fail.set(true));
    assert!(volume.reclaim().is_err());
    assert!(volume.state.lock().publication_pending);
    reclaim::FAIL_DIRECTORY_SYNC.with(|fail| fail.set(true));
    assert!(volume.sync().is_err());
    assert!(volume.state.lock().publication_pending);
    volume.sync().unwrap();
    assert!(!volume.state.lock().publication_pending);
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    let mut bytes = [0; 8];
    reopened.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"retained");
}

#[test]
#[ignore = "subprocess crash entry point"]
fn reclaim_crash_before_publication_child() {
    let path = PathBuf::from(std::env::var_os("ASTRID_STORAGE_TEST_RECLAIM_CRASH").unwrap());
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"acknowledged").unwrap();
    volume.sync().unwrap();
    reclaim::set_test_swap_hook(path, Box::new(|| std::process::exit(17)));
    volume.reclaim().unwrap();
    panic!("crash hook must terminate before publication");
}

#[test]
fn process_crash_before_publication_recovers_acknowledged_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "volume::hosted::maintenance_tests::reclaim_crash_before_publication_child",
            "--ignored",
        ])
        .env("ASTRID_STORAGE_TEST_RECLAIM_CRASH", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(17), "{output:?}");
    let staged = reclaim::temp_path(&path);
    assert!(staged.exists());
    // Both sides of the atomic publication point are complete containers.
    let staged_copy = temporary.path().join("staged-copy.volume");
    std::fs::copy(&staged, &staged_copy).unwrap();
    for candidate in [&path, &staged_copy] {
        let volume = HostedFileVolume::open(candidate).unwrap();
        let mut bytes = [0; 12];
        volume
            .read_region_at(&VolumeRegion::new("objects").unwrap(), 0, &mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"acknowledged");
    }
    assert!(!staged.exists());
}

#[cfg(windows)]
#[test]
fn windows_detached_active_name_remains_fenced_by_both_inode_locks() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let captured = path.clone();
    reclaim::AFTER_DETACH.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            assert!(!captured.exists());
            let result = super::open_tests::try_foreign_open(&captured);
            assert!(result.status.success(), "{result:?}");
            assert!(
                !captured.exists(),
                "contender must not create an empty active volume"
            );
            assert!(reclaim::temp_path(&captured).exists());
        }))
    });
    volume.reclaim().unwrap();
    assert!(path.exists());
    assert!(!reclaim::previous_path(&path).exists());
}

#[cfg(windows)]
#[test]
fn windows_failed_restore_blocks_flush_until_old_name_is_durable_again() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"before").unwrap();
    volume.sync().unwrap();
    reclaim::FAIL_PROMOTIONS.with(|fail| *fail.borrow_mut() = [false, true, true, true].into());
    assert!(volume.reclaim().is_err());
    assert!(volume.state.lock().restore_pending);
    // reclaim has returned and dropped the rebuilt descriptor. The still
    // locked previous inode must fence even this unlocked staging artifact.
    let contender = super::open_tests::try_foreign_open(&path);
    assert!(contender.status.success(), "{contender:?}");
    assert!(!path.exists());
    volume.write_region_at(&region, 0, b"after!").unwrap();
    assert!(volume.sync().is_err());
    assert!(volume.state.lock().restore_pending);
    volume.sync().unwrap();
    assert!(!volume.state.lock().restore_pending);
    assert!(path.exists());
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    let mut bytes = [0; 6];
    reopened.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"after!");
}

#[cfg(windows)]
#[test]
fn windows_effective_move_error_adopts_current_inode_and_retries_flush() {
    for failed_move in [0, 1] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("astrid.volume");
        let volume = HostedFileVolume::open(&path).unwrap();
        let region = VolumeRegion::new("objects").unwrap();
        volume.create_region(&region, true).unwrap();
        volume.write_region_at(&region, 0, b"before").unwrap();
        volume.sync().unwrap();
        reclaim::FAIL_AFTER_PROMOTIONS.with(|fail| {
            *fail.borrow_mut() = (0..=failed_move)
                .map(|index| index == failed_move)
                .collect();
        });
        assert!(volume.reclaim().is_err());
        if failed_move == 0 {
            assert!(volume.state.lock().restore_pending);
        } else {
            assert!(volume.state.lock().publication_pending);
            assert!(!volume.state.lock().restore_pending);
            super::open::require_current(&volume.state.lock().file, &path).unwrap();
        }
        let contender = super::open_tests::try_foreign_open(&path);
        assert!(contender.status.success(), "{contender:?}");
        reclaim::FAIL_PUBLICATION_FLUSH.with(|fail| fail.set(true));
        assert!(volume.sync().is_err());
        {
            let state = volume.state.lock();
            assert!(state.restore_pending || state.publication_pending);
        }
        volume.write_region_at(&region, 0, b"after!").unwrap();
        volume.sync().unwrap();
        assert!(!volume.state.lock().restore_pending);
        assert!(!volume.state.lock().publication_pending);
        assert!(!reclaim::temp_path(&path).exists());
        assert!(!reclaim::previous_path(&path).exists());
        drop(volume);
        let reopened = HostedFileVolume::open(&path).unwrap();
        let mut bytes = [0; 6];
        reopened.read_region_at(&region, 0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"after!");
    }
}
