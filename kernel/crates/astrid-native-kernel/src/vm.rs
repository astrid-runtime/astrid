//! Per-domain address spaces. Each domain gets its own PML4 (one frame):
//! every present higher entry of the boot PML4 is copied — with USER cleared,
//! so the kernel side is never reachable from ring 3 — and PML4 slot 0 is built
//! fresh for the user code and stack mappings. The kernel image, boot stack,
//! and the physical-memory window all live at PML4 indices >= 1 under the
//! bootloader's layout (it marks the low identity range used, so no dynamic
//! kernel mapping ever lands in slot 0); copying them keeps the kernel mapped
//! after the CR3 switch, while slot 0 is exclusively the domain's user world.
//!
//! W^X in ring 3 is by construction: code pages are USER|present, read-only and
//! executable (NX clear); stack pages are USER|present|writable|NX.

use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::PhysAddr;

use crate::domain::FrameList;
use crate::memory;

/// User code entry point (fixed).
pub const USER_CODE_VA: u64 = 0x0040_0000;
/// Top of the user stack (exclusive); grows down.
pub const USER_STACK_TOP: u64 = 0x0080_0000;
/// Number of user stack pages mapped below [`USER_STACK_TOP`].
const USER_STACK_PAGES: u64 = 2;

const PAGE_SIZE: u64 = 4096;
const ENTRIES: usize = 512;

/// The result of building a domain address space.
pub struct DomainSpace {
    /// Physical address of the domain's PML4 (its CR3 value).
    pub pml4_phys: u64,
    /// Physical address of the user code frame, for payload copy-in.
    pub code_frame_phys: u64,
}

/// Build a fresh domain address space, recording every allocated frame in
/// `frames` so the kill path can reclaim all of them. Returns `None` on any
/// pool exhaustion (fallible by construction); the caller reclaims whatever was
/// recorded.
pub fn build(frames: &mut FrameList, boot_pml4_phys: u64) -> Option<DomainSpace> {
    let pml4_phys = alloc_zeroed(frames)?;
    copy_higher_kernel(pml4_phys, boot_pml4_phys);

    // User code: USER | present, read-only, executable (NX clear) — W^X.
    let code_frame_phys = alloc_zeroed(frames)?;
    map(
        pml4_phys,
        USER_CODE_VA,
        code_frame_phys,
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        frames,
    )?;

    // User stack: USER | present | writable | NX, growing down.
    for i in 1..=USER_STACK_PAGES {
        let va = USER_STACK_TOP - i * PAGE_SIZE;
        let frame = alloc_zeroed(frames)?;
        map(
            pml4_phys,
            va,
            frame,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::NO_EXECUTE,
            frames,
        )?;
    }

    Some(DomainSpace {
        pml4_phys,
        code_frame_phys,
    })
}

/// Allocate one frame, zero it, and record it in `frames`. Returns its physical
/// address, or `None` if the frame pool or the per-domain frame list is full.
fn alloc_zeroed(frames: &mut FrameList) -> Option<u64> {
    let frame = memory::alloc_frame()?;
    if !frames.push(frame.0) {
        memory::free_frame(frame);
        return None;
    }
    zero_frame(frame.0);
    Some(frame.0)
}

fn zero_frame(phys: u64) {
    // SAFETY: `phys` is a freshly allocated frame within the mapped physical
    // span; nothing else references it. We write exactly one frame.
    unsafe {
        core::ptr::write_bytes(memory::phys_mut(phys), 0, PAGE_SIZE as usize);
    }
}

fn table_mut(phys: u64) -> &'static mut PageTable {
    // SAFETY: `phys` is a page-table frame within the physical-memory window;
    // it is 4 KiB aligned and exclusively owned by the domain being built
    // (single hart, interrupts disabled during construction).
    unsafe { &mut *(memory::phys_mut(phys).cast::<PageTable>()) }
}

/// Copy every present PML4 entry except slot 0 from the boot PML4, clearing
/// USER so no kernel mapping is reachable from ring 3. Slot 0 is left empty for
/// the user mappings.
fn copy_higher_kernel(dst_pml4_phys: u64, src_pml4_phys: u64) {
    let src = table_mut(src_pml4_phys);
    let dst = table_mut(dst_pml4_phys);
    for i in 1..ENTRIES {
        let entry = &src[i];
        if entry.is_unused() {
            continue;
        }
        let flags = entry.flags() & !PageTableFlags::USER_ACCESSIBLE;
        dst[i].set_addr(entry.addr(), flags);
    }
}

/// Map `va` to `frame_phys` with `leaf_flags`, creating intermediate tables as
/// needed (each USER|present|writable so the CPU can walk to the leaf, whose
/// own flags decide the effective rights). Records created tables in `frames`.
fn map(
    pml4_phys: u64,
    va: u64,
    frame_phys: u64,
    leaf_flags: PageTableFlags,
    frames: &mut FrameList,
) -> Option<()> {
    let idx4 = ((va >> 39) & 0x1ff) as usize;
    let idx3 = ((va >> 30) & 0x1ff) as usize;
    let idx2 = ((va >> 21) & 0x1ff) as usize;
    let idx1 = ((va >> 12) & 0x1ff) as usize;

    let l3_phys = ensure(pml4_phys, idx4, frames)?;
    let l2_phys = ensure(l3_phys, idx3, frames)?;
    let l1_phys = ensure(l2_phys, idx2, frames)?;
    table_mut(l1_phys)[idx1].set_addr(PhysAddr::new(frame_phys), leaf_flags);
    Some(())
}

/// Ensure the `idx`-th entry of the table at `table_phys` points at a present
/// sub-table, allocating one if absent. Returns the sub-table's physical
/// address.
fn ensure(table_phys: u64, idx: usize, frames: &mut FrameList) -> Option<u64> {
    let entry_flags = table_mut(table_phys)[idx].flags();
    if entry_flags.contains(PageTableFlags::PRESENT) {
        return Some(table_mut(table_phys)[idx].addr().as_u64());
    }
    let sub_phys = alloc_zeroed(frames)?;
    table_mut(table_phys)[idx].set_addr(
        PhysAddr::new(sub_phys),
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
    );
    Some(sub_phys)
}

/// Copy `len` bytes of a ring-3 payload into the domain's user code frame via
/// the physical-memory window.
///
/// # Safety
/// `src` must be readable for `len` bytes. `len` may run past the payload
/// function's true end into following image bytes; this is accepted for M2
/// (the copied tail is never executed — payloads end by leaving ring 3), and
/// `len <= PAGE_SIZE` keeps the write inside the one code frame.
pub unsafe fn load_payload(code_frame_phys: u64, src: *const u8, len: usize) {
    debug_assert!(len as u64 <= PAGE_SIZE);
    // SAFETY: forwarded `src`/`len` contract; the destination is a freshly
    // allocated, zeroed frame in the physical-memory window, disjoint from src.
    unsafe {
        core::ptr::copy_nonoverlapping(src, memory::phys_mut(code_frame_phys), len);
    }
}
