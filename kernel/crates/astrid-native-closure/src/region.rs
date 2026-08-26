//! Validated loader ranges: canonical bounds plus a page-readable proof.
//!
//! The bytes are untrusted. Copy into kernel-owned memory only after
//! [`ReadableRange::try_new`] and [`prove_pages_readable`] succeed. This module
//! never dereferences a caller-provided address.

use crate::error::ClosureError;
use crate::types::TABLE_LEN;

/// x86-64 4 KiB page size used for the readable-page walk.
pub const PAGE_SIZE: u64 = 4096;

/// Canonical half-open loader range `[start, end)`.
///
/// The range is deliberately address-only: page presence is supplied by the
/// consumer because only the active page-table owner can answer that question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadableRange {
    start: u64,
    end: u64,
}

impl ReadableRange {
    /// Accept only a non-zero canonical span with checked, contiguous bounds.
    pub const fn try_new(start: u64, len: u64) -> Result<Self, ClosureError> {
        if start == 0 || len == 0 {
            return Err(ClosureError::Missing);
        }
        let Some(end) = start.checked_add(len) else {
            return Err(ClosureError::Malformed);
        };
        let last = end - 1;
        if !is_canonical(start) || !is_canonical(last) || crosses_canonical_hole(start, last) {
            return Err(ClosureError::Malformed);
        }
        Ok(Self { start, end })
    }

    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end(self) -> u64 {
        self.end
    }

    /// 4 KiB page bases covering `[start, end)`.
    pub const fn page_bases(self) -> PageBases {
        PageBases {
            next: Some(self.start & !(PAGE_SIZE - 1)),
            end: self.end,
        }
    }
}

/// Canonical half-open region `[start, end)` that covers exactly one table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosureTableRegion(ReadableRange);

impl ClosureTableRegion {
    /// Accept only a non-zero canonical span of exactly [`TABLE_LEN`] bytes.
    pub const fn try_new(start: u64, len: u64) -> Result<Self, ClosureError> {
        if start == 0 || len == 0 {
            return Err(ClosureError::Missing);
        }
        if len != TABLE_LEN as u64 {
            return Err(ClosureError::Truncated);
        }
        match ReadableRange::try_new(start, len) {
            Ok(range) => Ok(Self(range)),
            Err(err) => Err(err),
        }
    }

    pub const fn start(self) -> u64 {
        self.0.start()
    }

    pub const fn end(self) -> u64 {
        self.0.end()
    }

    /// 4 KiB page bases covering `[start, end)`.
    pub const fn page_bases(self) -> PageBases {
        self.0.page_bases()
    }

    const fn readable_range(self) -> ReadableRange {
        self.0
    }

    /// Copy the table into kernel-owned memory.
    ///
    /// # Safety
    /// Every page covering this region must already be present and readable
    /// in the active boot page tables, or in a separately established trusted
    /// loader mapping. Call [`prove_pages_readable`] first.
    pub unsafe fn copy_to(self, dest: &mut [u8; TABLE_LEN]) {
        let src = unsafe { core::slice::from_raw_parts(self.start() as *const u8, TABLE_LEN) };
        dest.copy_from_slice(src);
    }
}

/// Iterator of page-aligned bases covering a region.
#[derive(Clone, Debug)]
pub struct PageBases {
    next: Option<u64>,
    end: u64,
}

impl Iterator for PageBases {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        let page = self.next?;
        if page >= self.end {
            self.next = None;
            return None;
        }
        self.next = page.checked_add(PAGE_SIZE);
        Some(page)
    }
}

/// True iff `addr` is a canonical 48-bit x86-64 virtual address.
pub const fn is_canonical(addr: u64) -> bool {
    let sign_extended = ((addr as i64) << 16) >> 16;
    sign_extended as u64 == addr
}

const fn crosses_canonical_hole(start: u64, last: u64) -> bool {
    const LOW_MAX: u64 = (1 << 47) - 1;
    const HIGH_MIN: u64 = u64::MAX - LOW_MAX;
    start <= LOW_MAX && last >= HIGH_MIN
}

/// Checked overlap test used before copying loader bytes into kernel storage.
pub fn ranges_overlap(
    first_start: u64,
    first_len: u64,
    second_start: u64,
    second_len: u64,
) -> Result<bool, ClosureError> {
    let first_end = first_start
        .checked_add(first_len)
        .ok_or(ClosureError::Malformed)?;
    let second_end = second_start
        .checked_add(second_len)
        .ok_or(ClosureError::Malformed)?;
    Ok(first_start < second_end && second_start < first_end)
}

/// Prove each covering page is present and readable according to `probe`.
///
/// `probe` receives a page base. It must not dereference the table. A false
/// result is [`ClosureError::Unmapped`].
pub fn prove_pages_readable<R, F>(region: R, mut probe: F) -> Result<(), ClosureError>
where
    R: Into<ReadableRange>,
    F: FnMut(u64) -> bool,
{
    for page in region.into().page_bases() {
        if !probe(page) {
            return Err(ClosureError::Unmapped);
        }
    }
    Ok(())
}

impl From<ClosureTableRegion> for ReadableRange {
    fn from(region: ClosureTableRegion) -> Self {
        region.readable_range()
    }
}
