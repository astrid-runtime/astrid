use crate::error::ClosureError;
use crate::region::{
    ClosureTableRegion, PAGE_SIZE, ReadableRange, is_canonical, prove_pages_readable,
    ranges_overlap,
};
use crate::types::TABLE_LEN;

#[test]
fn zero_or_empty_is_missing() {
    assert_eq!(
        ClosureTableRegion::try_new(0, TABLE_LEN as u64),
        Err(ClosureError::Missing)
    );
    assert_eq!(
        ClosureTableRegion::try_new(0xFFFF_8000_0000_1000, 0),
        Err(ClosureError::Missing)
    );
}

#[test]
fn wrong_length_is_truncated() {
    assert_eq!(
        ClosureTableRegion::try_new(0xFFFF_8000_0000_1000, 1),
        Err(ClosureError::Truncated)
    );
    assert_eq!(
        ClosureTableRegion::try_new(0xFFFF_8000_0000_1000, TABLE_LEN as u64 + 1),
        Err(ClosureError::Truncated)
    );
}

#[test]
fn non_canonical_is_malformed() {
    let non_canonical = 1u64 << 47;
    assert!(!is_canonical(non_canonical));
    assert_eq!(
        ReadableRange::try_new(non_canonical, TABLE_LEN as u64),
        Err(ClosureError::Malformed)
    );
}

#[test]
fn overflowing_end_is_malformed() {
    let start = u64::MAX - 8;
    assert_eq!(
        ReadableRange::try_new(start, TABLE_LEN as u64),
        Err(ClosureError::Malformed)
    );
}

#[test]
fn canonical_kernel_half_accepts() {
    let start = 0xFFFF_8000_0000_1000;
    let region = ClosureTableRegion::try_new(start, TABLE_LEN as u64).expect("canonical");
    assert_eq!(region.start(), start);
    assert_eq!(region.end() - region.start(), TABLE_LEN as u64);
}

#[test]
fn unmapped_page_is_rejected() {
    let start = 0xFFFF_8000_0000_0FF0;
    let region = ReadableRange::try_new(start, TABLE_LEN as u64).expect("straddle");
    let pages: std::vec::Vec<u64> = region.page_bases().collect();
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0], start & !(PAGE_SIZE - 1));
    assert_eq!(pages[1], pages[0] + PAGE_SIZE);
    let err = prove_pages_readable(region, |page| page == pages[0]).expect_err("second page");
    assert_eq!(err, ClosureError::Unmapped);
}

#[test]
fn all_present_pages_pass() {
    let start = 0xFFFF_8000_0000_1000;
    let region = ClosureTableRegion::try_new(start, TABLE_LEN as u64).unwrap();
    prove_pages_readable(region, |_| true).expect("mapped");
}

#[test]
fn generic_range_rejects_canonical_hole_crossing() {
    let start = (1u64 << 47) - 0x10;
    assert_eq!(
        ReadableRange::try_new(start, 0x20),
        Err(ClosureError::Malformed)
    );
}

#[test]
fn overlap_and_checked_arithmetic_are_host_testable() {
    assert!(ranges_overlap(0x1000, 0x100, 0x1000, 0x100).unwrap());
    assert!(ranges_overlap(0x1000, 0x100, 0x1080, 0x100).unwrap());
    assert!(!ranges_overlap(0x1000, 0x100, 0x1100, 0x100).unwrap());
    assert!(ranges_overlap(u64::MAX - 3, 4, 0, 1).is_err());
}
