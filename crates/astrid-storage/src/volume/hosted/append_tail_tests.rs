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
fn dirty_plain_and_streamed_appends_overwrite_known_footer_without_truncation() {
    reset_faults();
    let directory = tempfile::tempdir().unwrap();
    let (volume, region, _) = open_ready_volume(&directory);
    let first = VolumeRegion::new("plain-one").unwrap();
    let second = VolumeRegion::new("plain-two").unwrap();
    reset_prepare_truncate_count();
    // Rename carries its destination as a plain append_record payload. The
    // write_region_at convenience method instead delegates to the stream path.
    volume.rename_region(&region, &first).unwrap();
    assert_eq!(
        prepare_truncate_count(),
        0,
        "first plain append overwrites the known footer"
    );
    volume.rename_region(&first, &second).unwrap();
    volume
        .write_region_from(&second, 0, 9, &mut &b"streamed1"[..])
        .unwrap();
    volume
        .write_region_from(&second, 0, 9, &mut &b"streamed2"[..])
        .unwrap();
    assert_eq!(
        prepare_truncate_count(),
        0,
        "later dirty plain/streamed appends must not truncate"
    );
    volume.sync().unwrap();
    let after = VolumeRegion::new("after").unwrap();
    reset_prepare_truncate_count();
    volume.rename_region(&second, &after).unwrap();
    assert_eq!(prepare_truncate_count(), 0);
    volume
        .write_region_from(&after, 0, 5, &mut &b"again"[..])
        .unwrap();
    assert_eq!(prepare_truncate_count(), 0);
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

    // Forget the footer proof to exercise an unknown tail. Such tails still
    // require truncation even when their bytes happen to be a valid footer.
    volume.state.lock().physical_tail = PhysicalTail::MayExceed;
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
fn partial_plain_rename_failure_stays_uncertain_and_smaller_retry_reopens() {
    reset_faults();
    let directory = tempfile::tempdir().unwrap();
    let (volume, region, _) = open_ready_volume(&directory);
    let long = VolumeRegion::new("long-payload-bytes").unwrap();
    let tiny = VolumeRegion::new("tiny").unwrap();
    // Rename reaches append_record directly, without streaming rollback. Allow
    // its nine fixed/name header writes, then tear the destination-name payload.
    set_remaining_append_writes(Some(9));
    let error = volume.rename_region(&region, &long).unwrap_err();
    assert!(error.to_string().contains("injected append write failure"));
    set_remaining_append_writes(None);
    assert!(volume.region_exists(&region).unwrap());
    assert!(!volume.region_exists(&long).unwrap());
    let (valid_torn, physical_torn) = owned_lengths(&volume);
    assert!(
        physical_torn > valid_torn,
        "partial plain failure must leave a physical tail"
    );
    let torn = super::test_support::read_container(&volume);
    assert!(
        torn[usize::try_from(valid_torn).unwrap()..]
            .windows(8)
            .any(|window| window == b"long-pay"),
        "owned-handle suffix must retain the torn payload prefix before retry"
    );
    reset_prepare_truncate_count();
    volume.rename_region(&region, &tiny).unwrap();
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
    // Inspect before any footer rewrite can truncate and hide an uncertain tail.
    let retry_bytes = super::test_support::read_container(&volume);
    assert_eq!(retry_bytes.len() as u64, valid_retry);
    volume.sync().unwrap();
    let copy = directory.path().join("partial-reopen.volume");
    super::test_support::copy_container(&volume, &copy);
    let recovered = HostedFileVolume::open(&copy).unwrap();
    assert!(!recovered.region_exists(&region).unwrap());
    assert!(!recovered.region_exists(&long).unwrap());
    let mut actual = [0_u8; 10];
    assert_eq!(recovered.read_region_at(&tiny, 0, &mut actual).unwrap(), 10);
    assert_eq!(&actual, b"seed-bytes");
}

#[test]
fn preflight_overflow_failed_footer_restore_resyncs_checksummed_footer() {
    reset_faults();
    let directory = tempfile::tempdir().unwrap();
    let (volume, region, _) = open_ready_volume(&directory);
    {
        let mut state = volume.state.lock();
        assert!(
            !state.footer_pending,
            "synced fixture must start with a confirmed durable footer"
        );
        assert_ne!(state.last_commit_offset, 0);
        assert_eq!(state.valid_len, state.durable_len);
        let durable_before = state.durable_len;
        let error = super::stream::append_from_with(
            &mut state,
            Operation::Write,
            &region,
            0,
            u64::MAX,
            &mut &[][..],
            |file, _last_commit_offset, durable_len, _sequence| {
                // Same first effect as recover::write_footer: strip to durable_len,
                // then fail before footer bytes are rewritten.
                file.set_len(durable_len)?;
                Err(io::Error::other("injected footer restore write failure"))
            },
        )
        .expect_err("u64::MAX payload must fail preflight length overflow before prepare");
        assert!(
            error.to_string().contains("volume record length overflow"),
            "unexpected preflight error: {error}"
        );
        assert!(
            state.footer_pending,
            "failed footer restore must mark footer_pending even when prepare never ran"
        );
        assert_eq!(state.physical_tail, PhysicalTail::MayExceed);
        assert_eq!(
            state.file.metadata().unwrap().len(),
            durable_before,
            "failed restore leaves the durable body without footer bytes"
        );
    }

    volume.sync().unwrap();
    let (valid_after, physical_after) = owned_lengths(&volume);
    assert_eq!(
        physical_after,
        valid_after + super::recover::FOOTER_BYTES as u64,
        "sync must rewrite a physical footer before Drop"
    );

    let copy = directory.path().join("preflight-footer-reopen.volume");
    super::test_support::copy_container(&volume, &copy);
    let mut snapshot = std::fs::File::open(&copy).unwrap();
    let recovery = super::recover::recover_container(&mut snapshot).unwrap();
    assert!(
        recovery.footer_present,
        "reopen must accept the checksummed footer path, not only a full-scan fallback"
    );
    let recovered = HostedFileVolume::open(&copy).unwrap();
    let mut actual = [0_u8; 10];
    assert_eq!(
        recovered.read_region_at(&region, 0, &mut actual).unwrap(),
        10
    );
    assert_eq!(&actual, b"seed-bytes");
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

#[test]
fn failed_vectored_write_rolls_back_whole_record_and_preserves_cursor() {
    use crate::volume::VolumeFile;
    use std::io::{IoSlice, Read, Seek, SeekFrom, Write};

    for writes_before_failure in [0, 3, 9, 10] {
        reset_faults();
        let directory = tempfile::tempdir().unwrap();
        let (volume, region, path) = open_ready_volume(&directory);
        let mut file = VolumeFile::open(volume.clone(), region.clone(), false).unwrap();
        let lengths = owned_lengths(&volume);
        set_remaining_append_writes(Some(writes_before_failure));
        assert!(
            file.write_vectored(&[IoSlice::new(b"new-"), IoSlice::new(b"bytes!")])
                .is_err()
        );
        set_remaining_append_writes(None);
        assert_eq!(file.stream_position().unwrap(), 0);
        assert_eq!(owned_lengths(&volume).0, lengths.0);
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, b"seed-bytes");
        file.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(
            file.write_vectored(&[IoSlice::new(b"new-"), IoSlice::new(b"bytes!")])
                .unwrap(),
            10
        );
        file.sync_all().unwrap();
        drop(file);
        drop(volume);
        let reopened = HostedFileVolume::open(&path).unwrap();
        let mut file = VolumeFile::open(reopened, region, false).unwrap();
        actual.clear();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, b"new-bytes!");
    }
    reset_faults();
}
