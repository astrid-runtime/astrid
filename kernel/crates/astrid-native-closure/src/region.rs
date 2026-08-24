//! Validated ramdisk region: canonical bounds plus a page-readable proof.
//!
//! The table bytes are untrusted. Copy into kernel-owned memory only after
//! `try_new` and `prove_pages_readable` succeed. This module never dereferences.

use crate::error::ClosureError;
use crate::types::TABLE_LEN;

/// x86-64 4 KiB page size used for the readable-page walk.
pub const PAGE_SIZE: u64 = 4096;

/// Canonical half-open region `[start, end)` that covers exactly one table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosureTableRegion {
    start: u64,
    end: u64,
}

impl ClosureTableRegion {
    /// Accept only a non-zero canonical span of exactly [`TABLE_LEN`] bytes.
    pub const fn try_new(start: u64, len: u64) -> Result<Self, ClosureError> {
        if start == 0 || len == 0 {
            return Err(ClosureError::Missing);
        }
        if len != TABLE_LEN as u64 {
            return Err(ClosureError::Truncated);
        }
        if !is_canonical(start) {
            return Err(ClosureError::Malformed);
        }
        let Some(end) = start.checked_add(len) else {
            return Err(ClosureError::Malformed);
        };
        let last = end - 1;
        if !is_canonical(last) {
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

    /// Copy the table into kernel-owned memory.
    ///
    /// # Safety
    /// Every page covering this region must already be present and readable
    /// in the active boot page tables, or in a separately established trusted
    /// loader mapping. Call [`prove_pages_readable`] first.
    pub unsafe fn copy_to(self, dest: &mut [u8; TABLE_LEN]) {
        let src = unsafe { core::slice::from_raw_parts(self.start as *const u8, TABLE_LEN) };
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

/// Prove each covering page is present and readable according to `probe`.
///
/// `probe` receives a page base. It must not dereference the table. A false
/// result is [`ClosureError::Unmapped`].
pub fn prove_pages_readable<F>(region: ClosureTableRegion, mut probe: F) -> Result<(), ClosureError>
where
    F: FnMut(u64) -> bool,
{
    for page in region.page_bases() {
        if !probe(page) {
            return Err(ClosureError::Unmapped);
        }
    }
    Ok(())
}
