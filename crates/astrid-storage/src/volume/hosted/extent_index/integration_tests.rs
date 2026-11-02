use std::io;

use super::super::{CheckpointFormat, FlushState, HostedFileVolume, VolumeRegion};
use super::publication::prepare_checkpoint;
use super::test_support::container_bytes;
use crate::volume::AstridVolume;

fn checkpoint(volume: &HostedFileVolume) {
    let mut state = volume.state.lock();
    prepare_checkpoint(&mut state).unwrap();
    HostedFileVolume::make_durable(&mut state).unwrap();
}

fn read(volume: &HostedFileVolume, region: &VolumeRegion) -> Vec<u8> {
    let mut bytes = vec![255; usize::try_from(volume.region_len(region).unwrap()).unwrap()];
    assert_eq!(
        volume.read_region_at(region, 0, &mut bytes).unwrap(),
        bytes.len()
    );
    bytes
}

#[test]
fn paged_checkpoint_replays_overwrites_truncation_and_regrown_holes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("data/test").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"abc").unwrap();
    volume.write_region_at(&region, 8, b"xyz").unwrap();
    volume.sync().unwrap();
    let inode = same_file::Handle::from_path(&path).unwrap();
    checkpoint(&volume);
    assert_eq!(inode, same_file::Handle::from_path(&path).unwrap());
    assert!(volume.state.lock().regions[&region].extents.is_empty());
    volume.write_region_at(&region, 1, b"!").unwrap();
    volume.set_region_len(&region, 5).unwrap();
    volume.set_region_len(&region, 12).unwrap();
    volume.write_region_at(&region, 10, b"N").unwrap();
    volume.sync().unwrap();
    let expected = b"a!c\0\0\0\0\0\0\0N\0";
    assert_eq!(read(&volume, &region), expected);
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(read(&reopened, &region), expected);
    checkpoint(&reopened);
    assert!(reopened.state.lock().regions[&region].extents.is_empty());
    drop(reopened);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(read(&reopened, &region), expected);
    reopened.reclaim().unwrap();
    assert_eq!(
        reopened.state.lock().checkpoint_format,
        CheckpointFormat::Paged
    );
    assert_eq!(read(&reopened, &region), expected);
    drop(reopened);
    assert_eq!(
        read(&HostedFileVolume::open(&path).unwrap(), &region),
        expected
    );
}

#[test]
fn failed_flush_reuses_the_same_prepared_pages_commit_and_footer() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("data/retry").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"acknowledged").unwrap();
    volume.sync().unwrap();
    let mut state = volume.state.lock();
    prepare_checkpoint(&mut state).unwrap();
    let error = HostedFileVolume::make_durable_with(&mut state, |_| {
        Err(io::Error::other("injected flush failure"))
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "injected flush failure");
    let boundary = (state.valid_len, state.sequence, state.last_commit_offset);
    let bytes = container_bytes(&state.file);
    HostedFileVolume::make_durable(&mut state).unwrap();
    assert_eq!(
        (state.valid_len, state.sequence, state.last_commit_offset),
        boundary
    );
    assert_eq!(container_bytes(&state.file), bytes);
    assert_eq!(state.flush_state, FlushState::Confirmed);
    drop(state);
    drop(volume);
    assert_eq!(
        read(&HostedFileVolume::open(&path).unwrap(), &region),
        b"acknowledged"
    );
}

#[test]
fn paged_roots_follow_namespace_rename_replace_and_durable_removal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let source = VolumeRegion::new("data/source").unwrap();
    let destination = VolumeRegion::new("data/destination").unwrap();
    let alias = VolumeRegion::new("data/renamed").unwrap();
    for (region, bytes) in [
        (&source, b"source".as_slice()),
        (&destination, b"destination".as_slice()),
    ] {
        volume.create_region(region, true).unwrap();
        volume.write_region_at(region, 0, bytes).unwrap();
    }
    checkpoint(&volume);
    volume.rename_region(&source, &alias).unwrap();
    volume.replace_region(&alias, &destination).unwrap();
    volume.sync().unwrap();
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(
        reopened.list_regions("").unwrap(),
        std::slice::from_ref(&destination)
    );
    assert_eq!(read(&reopened, &destination), b"source");
    reopened.remove_region(&destination).unwrap();
    checkpoint(&reopened);
    drop(reopened);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert!(reopened.list_regions("").unwrap().is_empty());
    assert_eq!(
        reopened.state.lock().checkpoint_format,
        CheckpointFormat::Paged
    );
}

#[test]
fn empty_paged_reclaim_preserves_format_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("data/removed").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"retired").unwrap();
    checkpoint(&volume);
    volume.remove_region(&region).unwrap();
    volume.sync().unwrap();
    volume.reclaim().unwrap();
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert!(reopened.list_regions("").unwrap().is_empty());
    assert_eq!(
        reopened.state.lock().checkpoint_format,
        CheckpointFormat::Paged
    );
}

#[test]
fn catalogue_encoding_failure_restores_original_namespace_and_suffix() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("data/rollback").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"acknowledged").unwrap();
    volume.sync().unwrap();
    let mut state = volume.state.lock();
    let original_sequence = state.sequence;
    let original_length = state.valid_len;
    let original_bytes = container_bytes(&state.file);
    // One page can be appended; the catalogue then cannot acquire a sequence.
    state.sequence = u64::MAX.strict_sub(1);
    assert!(prepare_checkpoint(&mut state).is_err());
    assert_eq!(state.sequence, u64::MAX.strict_sub(1));
    assert_eq!(state.valid_len, original_length);
    assert_eq!(state.file.metadata().unwrap().len(), original_length);
    assert_eq!(state.checkpoint_format, CheckpointFormat::Legacy);
    assert!(state.regions[&region].root.is_none());
    assert_eq!(state.regions[&region].extents.len(), 1);
    assert_eq!(
        container_bytes(&state.file),
        original_bytes[..usize::try_from(original_length).unwrap()]
    );
    state.sequence = original_sequence;
    HostedFileVolume::make_durable(&mut state).unwrap();
    drop(state);
    drop(volume);
    assert_eq!(
        read(&HostedFileVolume::open(&path).unwrap(), &region),
        b"acknowledged"
    );
}

#[test]
fn catalogue_failure_before_any_append_preserves_confirmed_footer() {
    use super::super::{MAX_REGION_NAME_BYTES, RegionState, recover::MAX_COMMIT_SNAPSHOT_BYTES};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("data/empty").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.sync().unwrap();
    let mut state = volume.state.lock();
    let before = container_bytes(&state.file);
    let boundary = (state.valid_len, state.sequence);
    assert!(!state.footer_pending);
    assert_eq!(state.flush_state, FlushState::Confirmed);
    // Empty regions append no tree pages. Exercise the real catalogue bound
    // without generating megabytes of unrelated durable Create records.
    let entry_bytes = MAX_REGION_NAME_BYTES.strict_add(2 + 8 + 1);
    let count = usize::try_from(MAX_COMMIT_SNAPSHOT_BYTES)
        .unwrap()
        .strict_div(entry_bytes)
        .strict_add(1);
    let suffix = "x".repeat(MAX_REGION_NAME_BYTES.strict_sub(8));
    let oversized = (0..count)
        .map(|index| {
            (
                VolumeRegion::new(format!("{index:08}{suffix}")).unwrap(),
                RegionState::default(),
            )
        })
        .collect();
    let original = std::mem::replace(&mut state.regions, oversized);
    let error = prepare_checkpoint(&mut state).unwrap_err();
    // Restore the actual durable namespace before Drop, including on a failed
    // assertion: this fixture tests preparation, not publication of fake state.
    state.regions = original;
    assert_eq!(
        error.to_string(),
        "extent-index catalogue exceeds commit record bound"
    );
    assert_eq!((state.valid_len, state.sequence), boundary);
    assert!(!state.footer_pending);
    assert_eq!(state.flush_state, FlushState::Confirmed);
    assert_eq!(container_bytes(&state.file), before);
    drop(state);
    drop(volume);
    assert!(read(&HostedFileVolume::open(&path).unwrap(), &region).is_empty());
}

#[test]
fn independent_python_reader_verifies_actual_multilevel_paged_volume() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("data/test").unwrap();
    volume.create_region(&region, true).unwrap();
    for index in 0..171_u64 {
        volume
            .write_region_at(
                &region,
                index.strict_mul(3),
                &[u8::try_from(index).unwrap()],
            )
            .unwrap();
    }
    checkpoint(&volume);
    assert_eq!(
        volume.state.lock().regions[&region]
            .root
            .unwrap()
            .level()
            .get(),
        1
    );
    // The independent reader opens its own handle, so end the writer's
    // exclusive ownership before checking the committed on-disk grammar.
    drop(volume);
    let before = std::fs::read(&path).unwrap();
    let scripts = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts");
    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg(
            "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); \
             from runatal_v1_volume import recover_volume; \
             expected = bytearray(511); expected[::3] = bytes(range(171)); \
             assert recover_volume(Path(sys.argv[2])) == {'data/test': bytes(expected)}",
        )
        .arg(scripts)
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
