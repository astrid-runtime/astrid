use super::*;
use std::io;

fn reset_faults() {
    reset_prepare_truncate_count();
    set_fail_prepare_truncate(false);
    set_fail_rollback_truncate(false);
    set_remaining_append_writes(None);
}

fn open_ready_volume(
    directory: &tempfile::TempDir,
) -> (
    std::sync::Arc<HostedFileVolume>,
    VolumeRegion,
    std::path::PathBuf,
) {
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"seed-bytes").unwrap();
    volume.sync().unwrap();
    (volume, region, path)
}

/// Lengths through the owning locked handle. A second path handle is invalid on
/// Windows while the volume holds its mandatory byte-range lock.
fn owned_lengths(volume: &HostedFileVolume) -> (u64, u64) {
    let state = volume.state.lock();
    let physical = state.file.metadata().unwrap().len();
    (state.valid_len, physical)
}

#[test]
fn dirty_plain_and_streamed_appends_truncate_once_after_sync() {
    reset_faults();
    let directory = tempfile::tempdir().unwrap();
    let (volume, region, _) = open_ready_volume(&directory);
    reset_prepare_truncate_count();
    volume.write_region_at(&region, 0, b"plain-one").unwrap();
    assert_eq!(
        prepare_truncate_count(),
        1,
        "first post-sync plain append strips footer"
    );
    volume.write_region_at(&region, 0, b"plain-two").unwrap();
    volume
        .write_region_from(&region, 0, 9, &mut &b"streamed1"[..])
        .unwrap();
    volume
        .write_region_from(&region, 0, 9, &mut &b"streamed2"[..])
        .unwrap();
    assert_eq!(
        prepare_truncate_count(),
        1,
        "later dirty plain/streamed appends must not re-truncate"
    );
    volume.sync().unwrap();
    reset_prepare_truncate_count();
    volume.write_region_at(&region, 0, b"after").unwrap();
    assert_eq!(prepare_truncate_count(), 1);
    volume
        .write_region_from(&region, 0, 5, &mut &b"again"[..])
        .unwrap();
    assert_eq!(prepare_truncate_count(), 1);
}

#[test]
fn failed_prepare_truncate_retries_on_next_append() {
    reset_faults();
    let directory = tempfile::tempdir().unwrap();
    let (volume, region, _) = open_ready_volume(&directory);
    let (valid_before, physical_before) = owned_lengths(&volume);
    assert!(
        physical_before > valid_before,
        "synced fixture must carry a durable footer beyond valid_len"
    );

    set_fail_prepare_truncate(true);
    reset_prepare_truncate_count();
    let error = volume.write_region_at(&region, 0, b"blocked").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected prepare truncate failure")
    );
    assert_eq!(prepare_truncate_count(), 1);
    let (valid_after_fail, physical_after_fail) = owned_lengths(&volume);
    assert_eq!(valid_after_fail, valid_before);
    assert_eq!(
        physical_after_fail, physical_before,
        "failed prepare truncate must not mutate the physical end"
    );

    set_fail_prepare_truncate(false);
    reset_prepare_truncate_count();
    volume.write_region_at(&region, 0, b"retried").unwrap();
    assert_eq!(
        prepare_truncate_count(),
        1,
        "retry after failed prepare truncate must still strip the uncertain/footer tail"
    );
    let (valid_ok, physical_ok) = owned_lengths(&volume);
    assert_eq!(physical_ok, valid_ok);

    volume.sync().unwrap();
    let copy = directory.path().join("prepare-retry.volume");
    super::test_support::copy_container(&volume, &copy);
    let recovered = HostedFileVolume::open(&copy).unwrap();
    let mut actual = [0_u8; 7];
    assert_eq!(
        recovered.read_region_at(&region, 0, &mut actual).unwrap(),
        7
    );
    assert_eq!(&actual, b"retried");
}

#[test]
fn short_stream_restores_footer_and_retry_reopens_clean() {
    reset_faults();
    let directory = tempfile::tempdir().unwrap();
    let (volume, region, _) = open_ready_volume(&directory);
    let (_, before) = owned_lengths(&volume);
    let error = volume
        .write_region_from(&region, 0, 256 * 1024, &mut &b"short"[..])
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    let (_, after) = owned_lengths(&volume);
    assert_eq!(after, before);
    reset_prepare_truncate_count();
    volume.write_region_at(&region, 0, b"ok-retry").unwrap();
    assert_eq!(prepare_truncate_count(), 1);
    volume.sync().unwrap();
    let copy = directory.path().join("reopened.volume");
    super::test_support::copy_container(&volume, &copy);
    let recovered = HostedFileVolume::open(&copy).unwrap();
    let mut actual = [0_u8; 8];
    assert_eq!(
        recovered.read_region_at(&region, 0, &mut actual).unwrap(),
        8
    );
    assert_eq!(&actual, b"ok-retry");
}

#[test]
fn partial_plain_write_failure_stays_uncertain_and_smaller_retry_reopens() {
    reset_faults();
    let directory = tempfile::tempdir().unwrap();
    let (volume, region, _) = open_ready_volume(&directory);
    // Allow the nine fixed/name header writes, then tear the payload prefix.
    set_remaining_append_writes(Some(9));
    let error = volume
        .write_region_at(&region, 0, b"long-payload-bytes")
        .unwrap_err();
    assert!(error.to_string().contains("injected append write failure"));
    set_remaining_append_writes(None);

    let (valid_torn, physical_torn) = owned_lengths(&volume);
    assert!(
        physical_torn > valid_torn,
        "partial plain failure must leave a physical tail"
    );
    let torn = super::test_support::read_container(&volume);
    assert!(
        torn[valid_torn as usize..]
            .windows(8)
            .any(|window| window == b"long-pay"),
        "owned-handle suffix must retain the torn payload prefix before retry"
    );

    reset_prepare_truncate_count();
    volume.write_region_at(&region, 0, b"tiny").unwrap();
    assert_eq!(
        prepare_truncate_count(),
        1,
        "retry after partial plain failure must truncate"
    );
    let (valid_retry, physical_retry) = owned_lengths(&volume);
    assert_eq!(
        physical_retry, valid_retry,
        "successful retry must publish an exact dirty tail before sync"
    );
    // A smaller record would overwrite only a prefix of a left-behind tear;
    // prove the uncertain suffix is gone before sync/footer can hide it.
    let retry_bytes = super::test_support::read_container(&volume);
    assert_eq!(retry_bytes.len() as u64, valid_retry);
    assert!(
        !retry_bytes.windows(8).any(|window| window == b"long-pay"),
        "torn plain prefix must not survive truncate+retry before sync"
    );

    volume.sync().unwrap();
    let copy = directory.path().join("partial-reopen.volume");
    super::test_support::copy_container(&volume, &copy);
    let recovered = HostedFileVolume::open(&copy).unwrap();
    let mut actual = [0_u8; 4];
    assert_eq!(
        recovered.read_region_at(&region, 0, &mut actual).unwrap(),
        4
    );
    assert_eq!(&actual, b"tiny");
}

#[test]
fn rollback_truncate_failure_from_dirty_state_leaves_tail_for_retry() {
    reset_faults();
    let directory = tempfile::tempdir().unwrap();
    let (volume, region, _) = open_ready_volume(&directory);
    // Dirty Exact prestate: one published append after sync, no durable footer yet.
    volume.write_region_at(&region, 0, b"keep-dirty").unwrap();
    let (start_valid, start_physical) = owned_lengths(&volume);
    assert_eq!(
        start_physical, start_valid,
        "dirty prestate must be Exact so a later footer restore cannot mask rollback failure"
    );
    assert!(
        start_valid > volume.state.lock().durable_len,
        "dirty prestate must sit past durable_len"
    );

    set_fail_rollback_truncate(true);
    let error = volume
        .write_region_from(&region, 0, 64, &mut &b"short"[..])
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

    let (valid_uncertain, physical_uncertain) = owned_lengths(&volume);
    assert_eq!(valid_uncertain, start_valid);
    assert!(
        physical_uncertain > valid_uncertain,
        "failed dirty rollback must leave an actual physical tail"
    );
    let uncertain = super::test_support::read_container(&volume);
    assert!(
        uncertain.len() as u64 > valid_uncertain,
        "owned-handle capture must show bytes beyond valid_len before sync"
    );

    reset_prepare_truncate_count();
    volume
        .write_region_at(&region, 0, b"after-uncertain")
        .unwrap();
    assert_eq!(prepare_truncate_count(), 1);
    let (valid_retry, physical_retry) = owned_lengths(&volume);
    assert_eq!(physical_retry, valid_retry);

    volume.sync().unwrap();
    let copy = directory.path().join("uncertain-reopen.volume");
    super::test_support::copy_container(&volume, &copy);
    let recovered = HostedFileVolume::open(&copy).unwrap();
    let mut actual = [0_u8; 15];
    assert_eq!(
        recovered.read_region_at(&region, 0, &mut actual).unwrap(),
        15
    );
    assert_eq!(&actual, b"after-uncertain");
}
