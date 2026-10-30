use super::super::{
    COMMIT_REGION, Extent, Operation, RECORD_FIXED_BYTES, RecordHeader, apply_record,
    encode_region_snapshot,
};
use super::*;

fn namespace() -> BTreeMap<VolumeRegion, RegionState> {
    ["objects", "profiles"]
        .into_iter()
        .map(|name| {
            (
                VolumeRegion::new(name.to_owned()).unwrap(),
                RegionState {
                    length: 8,
                    extents: BTreeMap::from([(
                        0,
                        Extent {
                            logical_end: 8,
                            physical_offset: 100,
                        },
                    )]),
                },
            )
        })
        .collect()
}

fn apply(
    regions: &mut BTreeMap<VolumeRegion, RegionState>,
    payload: &[u8],
    limit: u64,
) -> io::Result<()> {
    let header_bytes = (RECORD_FIXED_BYTES as u64).strict_add(COMMIT_REGION.len() as u64);
    let header = RecordHeader {
        total_len: header_bytes.strict_add(payload.len() as u64),
        sequence: 1,
        operation: Operation::Commit,
        logical_offset: 0,
        checksum: [0; 32],
        name: VolumeRegion::new(COMMIT_REGION.to_owned()).unwrap(),
        payload_offset: limit.strict_add(header_bytes),
        payload_len: payload.len() as u64,
    };
    apply_record(regions, &header, Some(payload))
}

#[test]
fn identical_valid_commit_reuses_replayed_extent_storage() {
    let mut regions = namespace();
    let payload = encode_region_snapshot(&regions).unwrap();
    let before = std::ptr::from_ref(
        regions
            .first_key_value()
            .unwrap()
            .1
            .extents
            .first_key_value()
            .unwrap()
            .1,
    );
    apply(&mut regions, &payload, 1000).unwrap();
    let after = std::ptr::from_ref(
        regions
            .first_key_value()
            .unwrap()
            .1
            .extents
            .first_key_value()
            .unwrap()
            .1,
    );
    assert_eq!(
        before, after,
        "identical commit rebuilt the replayed extent map"
    );
    assert_eq!(encode_region_snapshot(&regions).unwrap(), payload);
}

#[test]
fn differing_snapshot_wins_over_live_namespace_including_removals() {
    let original = namespace();
    for replacement in [
        BTreeMap::new(),
        BTreeMap::from([original
            .first_key_value()
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap()]),
        {
            let mut changed = namespace();
            changed.first_entry().unwrap().get_mut().length = 16;
            changed
        },
    ] {
        let payload = encode_region_snapshot(&replacement).unwrap();
        let mut regions = namespace();
        apply(&mut regions, &payload, 1000).unwrap();
        assert_eq!(encode_region_snapshot(&regions).unwrap(), payload);
    }
}

#[test]
fn reordered_valid_region_records_remain_accepted() {
    let regions = namespace();
    let payload = encode_region_snapshot(&regions).unwrap();
    let first_bytes = 2 + "objects".len() + 8 + 4 + 24;
    let mut reordered = payload[..12].to_vec();
    reordered.extend_from_slice(&payload[12 + first_bytes..]);
    reordered.extend_from_slice(&payload[12..12 + first_bytes]);
    let mut live = namespace();
    apply(&mut live, &reordered, 1000).unwrap();
    assert_eq!(encode_region_snapshot(&live).unwrap(), payload);
}

fn assert_same_rejection(
    mut live: BTreeMap<VolumeRegion, RegionState>,
    payload: &[u8],
    limit: u64,
) {
    let before = encode_region_snapshot(&live).unwrap();
    let expected = decode_region_snapshot(payload, limit).unwrap_err();
    let actual = apply(&mut live, payload, limit).unwrap_err();
    assert_eq!(actual.kind(), expected.kind());
    assert_eq!(actual.to_string(), expected.to_string());
    assert_eq!(encode_region_snapshot(&live).unwrap(), before);
}

#[test]
fn malformed_snapshots_preserve_decoder_errors_and_live_state() {
    let payload = encode_region_snapshot(&namespace()).unwrap();
    // Empty commit payloads intentionally retain the namespace without a snapshot.
    for end in 1..payload.len() {
        assert_same_rejection(namespace(), &payload[..end], 1000);
    }
    let mut trailing = payload.clone();
    trailing.push(0);
    assert_same_rejection(namespace(), &trailing, 1000);
    let mut bad_magic = payload.clone();
    bad_magic[0] ^= 1;
    assert_same_rejection(namespace(), &bad_magic, 1000);
    let first_bytes = 2 + "objects".len() + 8 + 4 + 24;
    let mut duplicate = payload[..12 + first_bytes].to_vec();
    duplicate.extend_from_slice(&payload[12..12 + first_bytes]);
    assert_same_rejection(namespace(), &duplicate, 1000);
    let mut invalid_name = payload.clone();
    invalid_name[14] = 255;
    assert_same_rejection(namespace(), &invalid_name, 1000);
}

#[test]
fn equal_live_triples_still_require_current_commit_physical_bounds() {
    for offset in [100, u64::MAX - 4] {
        let mut live = namespace();
        for state in live.values_mut() {
            state
                .extents
                .first_entry()
                .unwrap()
                .get_mut()
                .physical_offset = offset;
        }
        let payload = encode_region_snapshot(&live).unwrap();
        assert_same_rejection(live, &payload, 107);
    }
}

#[test]
fn equal_live_triples_still_require_logical_order_and_length_bounds() {
    for mode in 0..4 {
        let mut live = namespace();
        let state = live.first_entry().unwrap().into_mut();
        match mode {
            0 => state.extents.first_entry().unwrap().get_mut().logical_end = 0,
            1 => state.length = 7,
            2 => {
                state.extents.insert(
                    4,
                    Extent {
                        logical_end: 8,
                        physical_offset: 200,
                    },
                );
            },
            _ => {
                state.extents.insert(
                    9,
                    Extent {
                        logical_end: 8,
                        physical_offset: 200,
                    },
                );
            },
        }
        let payload = encode_region_snapshot(&live).unwrap();
        assert_same_rejection(live, &payload, 1000);
    }
}

#[test]
fn empty_commit_payload_preserves_live_namespace() {
    let mut live = namespace();
    let before = encode_region_snapshot(&live).unwrap();
    apply(&mut live, &[], 1000).unwrap();
    assert_eq!(encode_region_snapshot(&live).unwrap(), before);
}
