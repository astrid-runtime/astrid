//! Real-API coverage for coalesced stream record I/O.
//!
//! A small streamed write performs four `write_append_bytes` calls: fixed
//! header, name, payload, and checksum patch. A scoped append budget of four
//! therefore succeeds for ordinary tiny payloads.
//!
//! `copy_and_hash` sizes its bounce buffer to `min(payload_len, 64KiB)` so tiny
//! writes do not allocate the full ceiling.

use std::sync::Arc;

use super::super::{
    HostedFileVolume, Operation, RECORD_FIXED_BYTES, RECORD_MAGIC, VolumeRegion, test_support,
};
use super::{STREAM_BUFFER_BYTES, reset_stream_copy_buffer_capacity, stream_copy_buffer_capacity};
use crate::volume::AstridVolume;

fn open_volume(
    directory: &tempfile::TempDir,
) -> (Arc<HostedFileVolume>, VolumeRegion, std::path::PathBuf) {
    let path = directory.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let region = VolumeRegion::new("blob").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.sync().unwrap();
    (volume, region, path)
}

fn expected_stream_record(sequence: u64, name: &[u8], offset: u64, payload: &[u8]) -> Vec<u8> {
    let name_len = u16::try_from(name.len()).unwrap();
    let payload_len = u64::try_from(payload.len()).unwrap();
    let total_len = u64::try_from(RECORD_FIXED_BYTES)
        .unwrap()
        .strict_add(u64::from(name_len))
        .strict_add(payload_len);
    let mut hasher = blake3::Hasher::new_derive_key("astrid volume record v1");
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&[Operation::Write as u8]);
    hasher.update(&name_len.to_le_bytes());
    hasher.update(&offset.to_le_bytes());
    hasher.update(&payload_len.to_le_bytes());
    hasher.update(name);
    hasher.update(payload);
    let checksum = *hasher.finalize().as_bytes();

    let mut record = Vec::new();
    record.extend_from_slice(&RECORD_MAGIC);
    record.extend_from_slice(&total_len.to_le_bytes());
    record.extend_from_slice(&sequence.to_le_bytes());
    record.push(Operation::Write as u8);
    record.extend_from_slice(&name_len.to_le_bytes());
    record.extend_from_slice(&offset.to_le_bytes());
    record.extend_from_slice(&payload_len.to_le_bytes());
    record.extend_from_slice(&checksum);
    record.extend_from_slice(name);
    record.extend_from_slice(payload);
    record
}

#[test]
fn small_stream_write_succeeds_within_four_append_writes() {
    let temporary = tempfile::tempdir().unwrap();
    let (volume, region, path) = open_volume(&temporary);
    let payload = b"tiny-io";
    let (record_start, next_sequence) = {
        let state = volume.state.lock();
        (
            state.valid_len,
            state
                .sequence
                .checked_add(1)
                .expect("fixture sequence must leave room for one write"),
        )
    };
    let before = test_support::read_container(&volume);

    HostedFileVolume::with_append_failure_for_test(4, || {
        volume
            .write_region_from(&region, 0, payload.len() as u64, &mut payload.as_slice())
            .expect("coalesced stream write uses at most four append writes");
    });
    volume.sync().unwrap();

    let mut out = vec![0_u8; payload.len()];
    assert_eq!(
        volume.read_region_at(&region, 0, &mut out).unwrap(),
        payload.len()
    );
    assert_eq!(out, payload);

    let after = test_support::read_container(&volume);
    assert!(after.len() > before.len());
    let start = usize::try_from(record_start).unwrap();
    let expected = expected_stream_record(next_sequence, region.as_str().as_bytes(), 0, payload);
    assert_eq!(
        &after[start..start + expected.len()],
        expected.as_slice(),
        "frozen write record bytes at the pre-write valid_len"
    );
    assert_eq!(&after[start..start + RECORD_MAGIC.len()], &RECORD_MAGIC);

    drop(volume);
    let recovered = HostedFileVolume::open(&path).unwrap();
    let mut out = vec![0_u8; payload.len()];
    assert_eq!(
        recovered.read_region_at(&region, 0, &mut out).unwrap(),
        payload.len()
    );
    assert_eq!(out, payload);
}

#[test]
fn stream_copy_buffer_matches_payload_bound_for_zero_small_and_max_chunks() {
    let temporary = tempfile::tempdir().unwrap();
    let (volume, region, _) = open_volume(&temporary);

    reset_stream_copy_buffer_capacity();
    volume
        .write_region_from(&region, 0, 0, &mut &b""[..])
        .unwrap();
    assert_eq!(
        stream_copy_buffer_capacity(),
        0,
        "zero-length write must not allocate the stream bounce buffer"
    );

    reset_stream_copy_buffer_capacity();
    let small = b"abcd";
    volume
        .write_region_from(&region, 0, small.len() as u64, &mut small.as_slice())
        .unwrap();
    assert_eq!(
        stream_copy_buffer_capacity(),
        small.len(),
        "tiny payload must not allocate the full 64KiB bounce buffer"
    );

    reset_stream_copy_buffer_capacity();
    let exact = vec![0x5A_u8; STREAM_BUFFER_BYTES];
    volume
        .write_region_from(&region, 0, exact.len() as u64, &mut exact.as_slice())
        .unwrap();
    assert_eq!(stream_copy_buffer_capacity(), STREAM_BUFFER_BYTES);

    reset_stream_copy_buffer_capacity();
    let multi = vec![0xA5_u8; STREAM_BUFFER_BYTES + 7];
    volume
        .write_region_from(&region, 0, multi.len() as u64, &mut multi.as_slice())
        .unwrap();
    assert_eq!(
        stream_copy_buffer_capacity(),
        STREAM_BUFFER_BYTES,
        "multi-chunk copy must keep the existing 64KiB ceiling"
    );

    let mut out = vec![0_u8; multi.len()];
    assert_eq!(
        volume.read_region_at(&region, 0, &mut out).unwrap(),
        multi.len()
    );
    assert_eq!(out, multi);
}
