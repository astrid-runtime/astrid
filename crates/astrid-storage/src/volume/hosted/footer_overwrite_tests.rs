//! In-place footer replacement must preserve the committed-prefix grammar.

use super::*;

#[test]
fn recovered_footer_is_overwritten_without_truncation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("seed").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"old-value").unwrap();
    volume.sync().unwrap();
    let copy = directory.path().join("recovered.volume");
    test_support::copy_container(&volume, &copy);
    let recovered = HostedFileVolume::open(&copy).unwrap();
    assert_eq!(recovered.state.lock().flush_state, FlushState::Required);
    reset_prepare_truncate_count();
    recovered.write_region_at(&region, 0, b"new-value").unwrap();
    assert_eq!(prepare_truncate_count(), 0);
    recovered.sync().unwrap();
    let final_copy = directory.path().join("final.volume");
    test_support::copy_container(&recovered, &final_copy);
    let reopened = HostedFileVolume::open(&final_copy).unwrap();
    assert_region(&reopened, &region, b"new-value");
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    Create,
    Write,
}

fn assert_region(volume: &HostedFileVolume, region: &VolumeRegion, expected: &[u8]) {
    let mut actual = vec![0; expected.len()];
    assert_eq!(
        volume.read_region_at(region, 0, &mut actual).unwrap(),
        expected.len()
    );
    assert_eq!(actual, expected);
}

/// Copy only the completed write prefix onto the old physical image, including
/// its footer. Do not truncate away the bytes the optimization must overwrite.
fn interrupted_image(old: &[u8], new: &[u8], start: usize, prefix: usize) -> Vec<u8> {
    let end = start.strict_add(prefix);
    let mut image = old.to_vec();
    image.resize(image.len().max(end), 0);
    image[start..end].copy_from_slice(&new[start..end]);
    image
}

fn check_every_interrupted_prefix(mutation: Mutation) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let seed = VolumeRegion::new("seed").unwrap();
    let target = VolumeRegion::new("a").unwrap();
    volume.create_region(&seed, true).unwrap();
    volume.write_region_at(&seed, 0, b"unchanged").unwrap();
    if matches!(mutation, Mutation::Write) {
        volume.create_region(&target, true).unwrap();
        volume.write_region_at(&target, 0, b"old-value").unwrap();
    }
    volume.sync().unwrap();
    let old = test_support::read_container(&volume);
    let start = usize::try_from(volume.state.lock().valid_len).unwrap();
    assert_eq!(old.len().strict_sub(start), recover::FOOTER_BYTES);
    match mutation {
        Mutation::Create => volume.create_region(&target, true).unwrap(),
        Mutation::Write => volume.write_region_at(&target, 0, b"new-value").unwrap(),
    }
    volume.sync().unwrap();
    let new = test_support::read_container(&volume);
    let committed_end = usize::try_from(volume.state.lock().durable_len).unwrap();
    assert!(committed_end > start.strict_add(RECORD_FIXED_BYTES));
    let crash_path = directory.path().join("crash.volume");
    for prefix in 0..=new.len().strict_sub(start) {
        let image = interrupted_image(&old, &new, start, prefix);
        std::fs::write(&crash_path, image).unwrap();
        let recovered = HostedFileVolume::open(&crash_path)
            .unwrap_or_else(|error| panic!("{mutation:?} prefix {prefix}: {error}"));
        assert_region(&recovered, &seed, b"unchanged");
        let committed = start.strict_add(prefix) >= committed_end;
        match mutation {
            Mutation::Create => assert_eq!(
                recovered.region_exists(&target).unwrap(),
                committed,
                "{mutation:?} prefix {prefix}"
            ),
            Mutation::Write => assert_region(
                &recovered,
                &target,
                if committed {
                    b"new-value"
                } else {
                    b"old-value"
                },
            ),
        }
        // Close the mandatory Windows lock before replacing the next image.
        drop(recovered);
    }
}

#[test]
fn in_place_create_footer_overwrite_recovers_every_interrupted_prefix() {
    check_every_interrupted_prefix(Mutation::Create);
}

#[test]
fn in_place_write_footer_overwrite_recovers_every_interrupted_prefix() {
    check_every_interrupted_prefix(Mutation::Write);
}

#[test]
fn streamed_write_failures_preserve_the_previous_commit() {
    // Include the final checksum patch, which writes before the current file
    // cursor. The contiguous-prefix matrix alone does not model that order.
    for writes_before_failure in 0..=10 {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.volume");
        let volume = HostedFileVolume::open(&path).unwrap();
        let region = VolumeRegion::new("seed").unwrap();
        volume.create_region(&region, true).unwrap();
        volume.write_region_at(&region, 0, b"old-value").unwrap();
        volume.sync().unwrap();
        set_remaining_append_writes(Some(writes_before_failure));
        let result = volume.write_region_at(&region, 0, b"new-value");
        set_remaining_append_writes(None);
        assert!(result.is_err(), "failure point {writes_before_failure}");
        let copy = directory.path().join("interrupted.volume");
        test_support::copy_container(&volume, &copy);
        let recovered = HostedFileVolume::open(&copy).unwrap();
        assert_region(&recovered, &region, b"old-value");
        volume.write_region_at(&region, 0, b"new-value").unwrap();
        volume.sync().unwrap();
        let retry = directory.path().join("retried.volume");
        test_support::copy_container(&volume, &retry);
        let reopened = HostedFileVolume::open(&retry).unwrap();
        assert_region(&reopened, &region, b"new-value");
    }
}
