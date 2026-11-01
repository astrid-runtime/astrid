use super::super::reference::{ExtentCount, ExtentRange, PageLevel};
use super::*;

fn commit() -> (RecordOffset, RecordSequence) {
    (
        RecordOffset::new(8192).unwrap(),
        RecordSequence::new(20).unwrap(),
    )
}

fn root() -> PageRef {
    PageRef::new(
        RecordOffset::new(128).unwrap(),
        RecordSequence::new(3).unwrap(),
        [19; 32],
        ExtentRange::new(10, 100).unwrap(),
        ExtentCount::new(4).unwrap(),
        PageLevel::new(1).unwrap(),
    )
    .unwrap()
}

fn catalogue() -> BTreeMap<VolumeRegion, RegionRoot> {
    let (offset, sequence) = commit();
    [
        (
            "data/a",
            RegionRoot::new(150, Some(root()), offset, sequence).unwrap(),
        ),
        (
            "data/b",
            RegionRoot::new(u64::MAX, None, offset, sequence).unwrap(),
        ),
    ]
    .into_iter()
    .map(|(name, region)| (VolumeRegion::new(name).unwrap(), region))
    .collect()
}

#[test]
fn catalogue_round_trips_sparse_and_indexed_regions_canonically() {
    let (offset, sequence) = commit();
    let expected = catalogue();
    let bytes = encode(&expected, offset, sequence).unwrap();
    assert_eq!(&bytes[..8], &CHECKPOINT_MAGIC);
    assert_eq!(&bytes[8..12], &2_u32.to_le_bytes());
    let decoded = decode(&bytes, offset, sequence).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(encode(&decoded, offset, sequence).unwrap(), bytes);
    assert_eq!(decoded.values().next().unwrap().length(), 150);
    assert_eq!(decoded.values().next().unwrap().root(), Some(root()));
    assert_eq!(decoded.values().last().unwrap().length(), u64::MAX);
}

#[test]
fn empty_catalogue_has_exact_framing() {
    let (offset, sequence) = commit();
    let bytes = encode(&BTreeMap::new(), offset, sequence).unwrap();
    assert_eq!(bytes.len(), 12);
    assert!(decode(&bytes, offset, sequence).unwrap().is_empty());
    let mut extended = bytes;
    extended.push(0);
    assert!(decode(&extended, offset, sequence).is_err());
}

#[test]
fn every_truncation_and_extension_is_rejected() {
    let (offset, sequence) = commit();
    let mut bytes = encode(&catalogue(), offset, sequence).unwrap();
    for length in 0..bytes.len() {
        assert!(
            decode(&bytes[..length], offset, sequence).is_err(),
            "length={length}"
        );
    }
    bytes.push(0);
    assert!(decode(&bytes, offset, sequence).is_err());
}

#[test]
fn root_is_bound_to_current_commit_and_region_length() {
    let (offset, sequence) = commit();
    assert!(RegionRoot::new(99, Some(root()), offset, sequence).is_err());
    assert!(RegionRoot::new(100, Some(root()), offset, sequence).is_ok());
    for (bad_offset, bad_sequence) in [(128, 20), (127, 20), (4096, 3), (4096, 2)] {
        let bad_offset = RecordOffset::new(bad_offset).unwrap();
        let bad_sequence = RecordSequence::new(bad_sequence).unwrap();
        assert!(RegionRoot::new(150, Some(root()), bad_offset, bad_sequence).is_err());
        assert!(encode(&catalogue(), bad_offset, bad_sequence).is_err());
        let bytes = encode(&catalogue(), offset, sequence).unwrap();
        assert!(decode(&bytes, bad_offset, bad_sequence).is_err());
    }
}

#[test]
fn decoder_rejects_untrusted_counts_flags_names_and_root_ranges() {
    let (offset, sequence) = commit();
    let valid = encode(&catalogue(), offset, sequence).unwrap();
    // First entry: two-byte name length, six-byte name, eight-byte logical
    // length, one-byte root flag, then its checked page reference.
    for (index, replacement) in [(0, 0), (14, 0xff), (14, b'/'), (28, 2), (28, 255)] {
        let mut corrupt = valid.clone();
        corrupt[index] = replacement;
        assert!(decode(&corrupt, offset, sequence).is_err(), "byte={index}");
    }
    for count in [0, 1, 3, u32::MAX] {
        let mut corrupt = valid.clone();
        corrupt[8..12].copy_from_slice(&count.to_le_bytes());
        assert!(decode(&corrupt, offset, sequence).is_err(), "count={count}");
    }
    let mut corrupt = valid;
    corrupt[20..28].copy_from_slice(&99_u64.to_le_bytes());
    assert!(decode(&corrupt, offset, sequence).is_err());
}

#[test]
fn decoder_rejects_duplicate_and_out_of_order_names() {
    let (offset, sequence) = commit();
    let valid = encode(&catalogue(), offset, sequence).unwrap();
    let second_name = 12 + 2 + 6 + 8 + 1 + PAGE_REFERENCE_BYTES + 2;
    for name in [b"data/a", b"aaaa/a"] {
        let mut corrupt = valid.clone();
        corrupt[second_name..second_name + 6].copy_from_slice(name);
        assert!(decode(&corrupt, offset, sequence).is_err());
    }
}

#[test]
fn existing_commit_record_bound_still_applies() {
    let (offset, sequence) = commit();
    let bytes = vec![0; usize::try_from(MAX_COMMIT_SNAPSHOT_BYTES).unwrap() + 1];
    assert!(decode(&bytes, offset, sequence).is_err());
}
