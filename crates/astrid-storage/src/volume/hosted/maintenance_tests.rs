use super::*;
use std::io::Read;

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
fn sync_pages_a_namespace_exceeding_the_legacy_snapshot_bound() {
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
    let before = same_file::Handle::from_path(&path).unwrap();
    volume.sync().unwrap();
    assert_eq!(before, same_file::Handle::from_path(&path).unwrap());
    {
        let state = volume.state.lock();
        assert_eq!(state.checkpoint_format, CheckpointFormat::Paged);
        assert!(state.regions[&region].extents.is_empty());
        assert_eq!(
            state.regions[&region].root.unwrap().extent_count().get(),
            count
        );
    }
    assert!(!volume.state.lock().publication_pending);
    assert!(!reclaim::temp_path(&path).exists());
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    for offset in [0, count / 2, count - 1] {
        let mut byte = [0];
        assert_eq!(
            reopened.read_region_at(&region, offset, &mut byte).unwrap(),
            1
        );
        assert_eq!(byte, *b"x");
    }
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

#[cfg(unix)]
#[test]
#[ignore = "subprocess crash entry point"]
fn reclaim_crash_after_rename_before_directory_flush_child() {
    let path = PathBuf::from(std::env::var_os("ASTRID_STORAGE_TEST_PUBLICATION_CRASH").unwrap());
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"acknowledged").unwrap();
    volume.sync().unwrap();
    reclaim::FAIL_DIRECTORY_SYNC.with(|fail| fail.set(true));
    assert!(volume.reclaim().is_err());
    assert!(volume.state.lock().publication_pending);
    // Bypass Drop: the new inode has a valid footer but its directory flush
    // failed. Reopen must not infer durable publication from that footer.
    std::process::exit(19);
}

#[test]
#[ignore = "subprocess working-directory entry point"]
fn relative_volume_path_after_working_directory_change_child() {
    let root = PathBuf::from(std::env::var_os("ASTRID_STORAGE_TEST_RELATIVE_PATH").unwrap());
    std::env::set_current_dir(&root).unwrap();
    let volume = HostedFileVolume::open("storage/astrid.volume").unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"before").unwrap();
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::env::set_current_dir(&elsewhere).unwrap();
    volume.sync().unwrap();
    volume.reclaim().unwrap();
    volume.write_region_at(&region, 0, b"after!").unwrap();
    volume.sync().unwrap();
    let bare = HostedFileVolume::open("bare.volume").unwrap();
    bare.create_region(&region, true).unwrap();
    bare.write_region_at(&region, 0, b"bare").unwrap();
    bare.sync().unwrap();
}

#[test]
fn relative_volume_keeps_original_path_after_working_directory_changes() {
    let temporary = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "volume::hosted::maintenance_tests::relative_volume_path_after_working_directory_change_child",
            "--ignored",
        ])
        .env("ASTRID_STORAGE_TEST_RELATIVE_PATH", temporary.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let volume = HostedFileVolume::open(temporary.path().join("storage/astrid.volume")).unwrap();
    let mut bytes = [0; 6];
    volume
        .read_region_at(&VolumeRegion::new("objects").unwrap(), 0, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"after!");
    assert!(!temporary.path().join("elsewhere/storage").exists());
    let bare = HostedFileVolume::open(temporary.path().join("elsewhere/bare.volume")).unwrap();
    let mut bytes = [0; 4];
    bare.read_region_at(&VolumeRegion::new("objects").unwrap(), 0, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"bare");
}

#[cfg(unix)]
#[test]
fn reopen_after_interrupted_publication_requires_directory_flush_before_ack() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "volume::hosted::maintenance_tests::reclaim_crash_after_rename_before_directory_flush_child",
            "--ignored",
        ])
        .env("ASTRID_STORAGE_TEST_PUBLICATION_CRASH", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(19), "{output:?}");
    let reopened = HostedFileVolume::open(&path).unwrap();
    reclaim::FAIL_DIRECTORY_SYNC.with(|fail| fail.set(true));
    let error = reopened.sync().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected directory flush failure")
    );
    assert!(reopened.state.lock().publication_pending);
    reopened.sync().unwrap();
    assert!(!reopened.state.lock().publication_pending);
    let mut bytes = [0; 12];
    reopened
        .read_region_at(&VolumeRegion::new("objects").unwrap(), 0, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"acknowledged");
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
        }));
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
    assert_eq!(volume.state.lock().restore, RestoreState::Required);
    // reclaim has returned and dropped the rebuilt descriptor. The still
    // locked previous inode must fence even this unlocked staging artifact.
    let contender = super::open_tests::try_foreign_open(&path);
    assert!(contender.status.success(), "{contender:?}");
    assert!(!path.exists());
    volume.write_region_at(&region, 0, b"after!").unwrap();
    assert!(volume.sync().is_err());
    assert_eq!(volume.state.lock().restore, RestoreState::Required);
    volume.sync().unwrap();
    assert_eq!(volume.state.lock().restore, RestoreState::NotRequired);
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
            assert_eq!(volume.state.lock().restore, RestoreState::Required);
        } else {
            assert!(volume.state.lock().publication_pending);
            assert_eq!(volume.state.lock().restore, RestoreState::NotRequired);
            super::open::require_current(&volume.state.lock().file, &path).unwrap();
        }
        let contender = super::open_tests::try_foreign_open(&path);
        assert!(contender.status.success(), "{contender:?}");
        reclaim::FAIL_PUBLICATION_FLUSH.with(|fail| fail.set(true));
        assert!(volume.sync().is_err());
        {
            let state = volume.state.lock();
            assert!(state.restore == RestoreState::Required || state.publication_pending);
        }
        volume.write_region_at(&region, 0, b"after!").unwrap();
        volume.sync().unwrap();
        assert_eq!(volume.state.lock().restore, RestoreState::NotRequired);
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

fn page_snapshot_bound() -> u64 {
    u64::try_from(extent_index::codec::PAGE_BYTES).expect("PAGE_BYTES fits u64")
}

fn plant_shared_physical_extents(state: &mut ContainerState, region: &VolumeRegion, count: u64) {
    let target = state.regions.get_mut(region).expect("region planted");
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
}

/// Smallest fragmented extent count whose `ASTMAP1` encoding exceeds one index
/// page payload (`PAGE_BYTES`), while remaining under the hard 16 `MiB` commit bound.
fn extent_count_above_one_page_snapshot(
    state: &mut ContainerState,
    region: &VolumeRegion,
) -> (u64, u64) {
    let page = page_snapshot_bound();
    let mut count = 1_u64;
    loop {
        plant_shared_physical_extents(state, region, count);
        let bytes = recover::snapshot_bytes(&state.regions).expect("snapshot size");
        assert!(
            bytes < recover::MAX_COMMIT_SNAPSHOT_BYTES,
            "probe crossed the hard commit bound at count={count} bytes={bytes}"
        );
        if bytes > page {
            return (count, bytes);
        }
        count = count.strict_add(1);
        assert!(
            count < 4096,
            "unable to exceed PAGE_BYTES={page} with fragmented extents"
        );
    }
}

fn read_probe_byte(volume: &HostedFileVolume, region: &VolumeRegion, offset: u64) -> u8 {
    let mut byte = [0];
    assert_eq!(volume.read_region_at(region, offset, &mut byte).unwrap(), 1);
    byte[0]
}

/// Seal the live `Legacy` map with an `ASTMAP1` commit using the unchanged v1
/// encoder plus ordinary `append` / footer / flush. Explicitly a legacy-format
/// fixture built with the current encoder, not an old-`6d` production binary.
/// Skips `commit_payload` so a snapshot above one index page stays on the wire.
fn seal_legacy_astmap1_commit(state: &mut ContainerState) {
    assert_eq!(state.checkpoint_format, CheckpointFormat::Legacy);
    let payload = recover::encode_region_snapshot(&state.regions)
        .expect("legacy ASTMAP1 fixture must remain encodable");
    assert!(
        !payload.is_empty(),
        "legacy fixture commit must carry a nonempty ASTMAP1 payload"
    );
    let commit_region = VolumeRegion::new(COMMIT_REGION).expect("commit region name");
    let commit_start = state.valid_len;
    HostedFileVolume::append(state, Operation::Commit, &commit_region, 0, &payload)
        .expect("append legacy ASTMAP1 commit");
    // Match nonempty-commit durable fields from `make_durable`.
    state.last_commit_offset = commit_start;
    state.last_snapshot_end = state.valid_len;
    state.index_checkpoint = IndexCheckpoint::NotPrepared;
    state.durable_len = state.valid_len;
    state.boundary_pending = true;
    state.physical_tail = PhysicalTail::MayExceed;
    recover::write_footer(
        &mut state.file,
        state.last_commit_offset,
        state.durable_len,
        state.sequence,
    )
    .expect("write legacy fixture footer");
    state.physical_tail = PhysicalTail::Footer;
    state.file.sync_all().expect("flush legacy fixture");
    state.boundary_pending = false;
    state.footer_pending = false;
    state.flush_state = FlushState::Confirmed;
}

fn assert_legacy_fragmented_map(
    volume: &HostedFileVolume,
    region: &VolumeRegion,
    count: u64,
    snapshot_len: Option<u64>,
) {
    let state = volume.state.lock();
    assert_eq!(state.checkpoint_format, CheckpointFormat::Legacy);
    assert_ne!(state.last_snapshot_end, 0);
    assert!(state.regions[region].root.is_none());
    assert_eq!(
        state.regions[region].extents.len(),
        usize::try_from(count).unwrap()
    );
    let live = recover::snapshot_bytes(&state.regions).unwrap();
    assert!(live > page_snapshot_bound());
    if let Some(snapshot_len) = snapshot_len {
        assert_eq!(live, snapshot_len);
    }
}

fn page_after_flush_retry(
    state: &mut ContainerState,
    expected_extents: u64,
    region: &VolumeRegion,
) {
    let error = HostedFileVolume::make_durable_with(state, |_| {
        Err(std::io::Error::other("injected file flush failure"))
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "injected file flush failure");
    assert_eq!(state.flush_state, FlushState::Required);
    let boundary = (state.valid_len, state.sequence, state.last_commit_offset);
    HostedFileVolume::make_durable(state).unwrap();
    assert_eq!(
        (state.valid_len, state.sequence, state.last_commit_offset),
        boundary,
        "flush retry must not append another commit"
    );
    assert_eq!(state.flush_state, FlushState::Confirmed);
    assert_eq!(state.checkpoint_format, CheckpointFormat::Paged);
    assert!(state.regions[region].extents.is_empty());
    assert_eq!(
        state.regions[region].root.unwrap().extent_count().get(),
        expected_extents
    );
}

/// Compatibility: reopen an earlier-committed above-`PAGE_BYTES` `ASTMAP1`
/// volume, keep `Legacy` through the empty-commit short-tail path, then page on
/// the next necessary checkpoint (flush fail/retry + ordinary reopen).
#[test]
fn reopened_legacy_over_page_snapshot_pages_on_next_necessary_checkpoint() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();

    let (count, snapshot_len) = {
        let volume = HostedFileVolume::open(&path).unwrap();
        volume.create_region(&region, true).unwrap();
        volume.write_region_at(&region, 0, b"x").unwrap();
        let mut state = volume.state.lock();
        assert_eq!(state.last_snapshot_end, 0);
        let planted = extent_count_above_one_page_snapshot(&mut state, &region);
        assert!(planted.1 > page_snapshot_bound());
        assert!(planted.1 < recover::MAX_COMMIT_SNAPSHOT_BYTES);
        seal_legacy_astmap1_commit(&mut state);
        assert_eq!(state.checkpoint_format, CheckpointFormat::Legacy);
        // Confirmed flush => Drop's make_durable is a no-op (no conversion).
        planted
    };

    let volume = HostedFileVolume::open(&path).unwrap();
    assert_legacy_fragmented_map(&volume, &region, count, Some(snapshot_len));
    assert_eq!(read_probe_byte(&volume, &region, 0), b'x');

    // Small tail stays on the empty-commit path and must not convert.
    volume.write_region_at(&region, 0, b"y").unwrap();
    volume.sync().unwrap();
    assert_legacy_fragmented_map(&volume, &region, count, None);
    assert_eq!(read_probe_byte(&volume, &region, 0), b'y');

    // Extend past the fragmented map so the physical tail exceeds 16 MiB while
    // the live ASTMAP1 encoding remains above one index page.
    let rollover = recover::MAX_COMMIT_SNAPSHOT_BYTES;
    volume
        .write_region_from(
            &region,
            count,
            rollover,
            &mut std::io::repeat(0x5A).take(rollover),
        )
        .unwrap();
    let expected_len = count.strict_add(rollover);
    assert_eq!(volume.region_len(&region).unwrap(), expected_len);
    let expected_extents = {
        let state = volume.state.lock();
        assert_eq!(state.checkpoint_format, CheckpointFormat::Legacy);
        assert!(recover::snapshot_bytes(&state.regions).unwrap() > page_snapshot_bound());
        let extents = u64::try_from(state.regions[&region].extents.len()).unwrap();
        assert!(
            extents > count,
            "rollover must retain prior fragmented extents"
        );
        extents
    };
    page_after_flush_retry(&mut volume.state.lock(), expected_extents, &region);

    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(
        reopened.state.lock().checkpoint_format,
        CheckpointFormat::Paged
    );
    assert_eq!(reopened.region_len(&region).unwrap(), expected_len);
    assert_eq!(read_probe_byte(&reopened, &region, 0), b'y');
    assert_eq!(read_probe_byte(&reopened, &region, count), 0x5A);
    assert_eq!(
        read_probe_byte(&reopened, &region, expected_len.strict_sub(1)),
        0x5A
    );
}

/// Falsifier for earlier ASTMAP1→ASTMAP2 cutover at `PAGE_BYTES`.
///
/// Plants a moderate map with `PAGE_BYTES < snapshot_bytes < 16MiB`, then runs the
/// **first** necessary checkpoint (writes landed, no prior sync — empty-commit
/// short-tail path does not apply). Old `commit_payload` keeps `Legacy` `ASTMAP1`;
/// the `PAGE_BYTES` predicate must publish `Paged`. Integrates injected file-flush
/// failure/retry and exact reopen through ordinary recovery validation.
#[test]
fn first_necessary_checkpoint_pages_when_astmap1_exceeds_one_index_page() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"x").unwrap();

    let (count, snapshot_len) = {
        let mut state = volume.state.lock();
        assert_eq!(state.last_snapshot_end, 0, "no prior sync/checkpoint");
        assert_eq!(state.checkpoint_format, CheckpointFormat::Legacy);
        let planted = extent_count_above_one_page_snapshot(&mut state, &region);
        assert!(
            planted.1 > page_snapshot_bound(),
            "expected snapshot above PAGE_BYTES, got {}",
            planted.1
        );
        assert!(
            planted.1 < recover::MAX_COMMIT_SNAPSHOT_BYTES,
            "fixture must stay under the hard 16 MiB commit bound"
        );
        // Old predicate still admits ASTMAP1 at this size.
        recover::encode_region_snapshot(&state.regions).expect("ASTMAP1 still encodable");
        planted
    };

    {
        let mut state = volume.state.lock();
        let error = HostedFileVolume::make_durable_with(&mut state, |_| {
            Err(std::io::Error::other("injected file flush failure"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "injected file flush failure");
        assert_eq!(state.flush_state, FlushState::Required);
        let boundary = (state.valid_len, state.sequence, state.last_commit_offset);
        HostedFileVolume::make_durable(&mut state).unwrap();
        assert_eq!(
            (state.valid_len, state.sequence, state.last_commit_offset),
            boundary,
            "flush retry must not append another commit"
        );
        assert_eq!(state.flush_state, FlushState::Confirmed);
        // Falsifier under the current 16 MiB Legacy retention predicate.
        assert_eq!(state.checkpoint_format, CheckpointFormat::Paged);
        assert!(state.regions[&region].extents.is_empty());
        assert_eq!(
            state.regions[&region].root.unwrap().extent_count().get(),
            count
        );
        assert!(
            snapshot_len > page_snapshot_bound(),
            "measured ASTMAP1 length {snapshot_len} must remain the planted bound"
        );
    }

    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(
        reopened.state.lock().checkpoint_format,
        CheckpointFormat::Paged
    );
    for offset in [0, count / 2, count.strict_sub(1)] {
        assert_eq!(read_probe_byte(&reopened, &region, offset), b'x');
    }
    assert_eq!(
        reopened.region_len(&region).unwrap(),
        count,
        "reopen must recover the full logical region through ordinary validation"
    );
}

/// Control: ASTMAP1 that fits in one index page stays Legacy on the first
/// necessary checkpoint (no forced conversion below `PAGE_BYTES`).
#[test]
fn first_necessary_checkpoint_keeps_legacy_when_astmap1_fits_one_index_page() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"y").unwrap();

    let (fit_count, fit_bytes) = {
        let mut state = volume.state.lock();
        let (above_count, _) = extent_count_above_one_page_snapshot(&mut state, &region);
        let fit_count = above_count.strict_sub(1);
        plant_shared_physical_extents(&mut state, &region, fit_count);
        let fit_bytes = recover::snapshot_bytes(&state.regions).unwrap();
        assert!(
            fit_bytes <= page_snapshot_bound(),
            "control snapshot {fit_bytes} must fit in PAGE_BYTES"
        );
        assert!(fit_bytes > 0);
        recover::encode_region_snapshot(&state.regions).unwrap();
        assert_eq!(state.last_snapshot_end, 0);
        (fit_count, fit_bytes)
    };

    volume.sync().unwrap();
    {
        let state = volume.state.lock();
        assert_eq!(state.checkpoint_format, CheckpointFormat::Legacy);
        assert_eq!(
            state.regions[&region].extents.len(),
            usize::try_from(fit_count).unwrap()
        );
        assert!(state.regions[&region].root.is_none());
    }
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(
        reopened.state.lock().checkpoint_format,
        CheckpointFormat::Legacy
    );
    for offset in [0, fit_count / 2, fit_count.strict_sub(1)] {
        assert_eq!(read_probe_byte(&reopened, &region, offset), b'y');
    }
    assert_eq!(reopened.region_len(&region).unwrap(), fit_count);
    assert!(fit_bytes <= page_snapshot_bound());
}
