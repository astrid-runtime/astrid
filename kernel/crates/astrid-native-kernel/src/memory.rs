//! Physical memory: a fixed-pool bitmap frame allocator, a directly-managed
//! fallible heap, and a W^X audit of the live page tables. Every allocation is
//! fallible and every pool is bounded by construction (charter §6).

use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use linked_list_allocator::Heap;
use spin::{Mutex, Once};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::VirtAddr;

/// Frame size (4 KiB).
pub const FRAME_SIZE: u64 = 4096;
/// Physical span the bitmap covers: 256 MiB (the frozen RAM size).
const PHYS_SPAN: u64 = 256 * 1024 * 1024;
/// Number of frames the bitmap tracks.
pub const MAX_FRAMES: usize = (PHYS_SPAN / FRAME_SIZE) as usize; // 65536
/// 64-bit words backing the bitmap.
const BITMAP_WORDS: usize = MAX_FRAMES / 64; // 1024

/// Kernel heap: one static 1 MiB region inside the kernel image (.bss).
pub const HEAP_SIZE: usize = 1024 * 1024;
static mut HEAP_MEM: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// Probe symbols for the W^X audit. `#[used]` keeps them in their sections.
#[used]
static RODATA_PROBE: u8 = 0x42;
#[used]
static mut DATA_PROBE: u64 = 0x5555_5555_5555_5555;

/// Base of the full physical-memory mapping requested from the bootloader.
static PHYS_OFFSET: AtomicU64 = AtomicU64::new(0);

/// A physical frame, identified by its base physical address.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Frame(pub u64);

/// Bitmap frame allocator. `usable` marks frames in usable regions; `allocated`
/// marks handed-out frames. A frame is available iff usable & !allocated.
struct FrameAllocator {
    usable: [u64; BITMAP_WORDS],
    allocated: [u64; BITMAP_WORDS],
    cursor: usize,
}

impl FrameAllocator {
    const fn new() -> Self {
        Self {
            usable: [0; BITMAP_WORDS],
            allocated: [0; BITMAP_WORDS],
            cursor: 0,
        }
    }

    #[inline]
    fn set_usable(&mut self, frame: usize) {
        self.usable[frame / 64] |= 1 << (frame % 64);
    }

    #[inline]
    fn is_available(&self, frame: usize) -> bool {
        let mask = 1u64 << (frame % 64);
        (self.usable[frame / 64] & mask) != 0 && (self.allocated[frame / 64] & mask) == 0
    }

    fn alloc(&mut self) -> Option<Frame> {
        for offset in 0..MAX_FRAMES {
            let frame = (self.cursor + offset) % MAX_FRAMES;
            if self.is_available(frame) {
                self.allocated[frame / 64] |= 1 << (frame % 64);
                self.cursor = (frame + 1) % MAX_FRAMES;
                return Some(Frame(frame as u64 * FRAME_SIZE));
            }
        }
        None
    }

    fn free(&mut self, frame: Frame) {
        let idx = (frame.0 / FRAME_SIZE) as usize;
        if idx < MAX_FRAMES {
            self.allocated[idx / 64] &= !(1u64 << (idx % 64));
            // Rewind the search cursor so a freed frame is reused promptly.
            self.cursor = self.cursor.min(idx);
        }
    }

    fn reset(&mut self) {
        self.allocated = [0; BITMAP_WORDS];
        self.cursor = 0;
    }
}

static FRAMES: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::new());
static HEAP: Once<Mutex<Heap>> = Once::new();

/// Record the physical-memory mapping offset for later page-table walks.
pub fn set_phys_offset(offset: u64) {
    PHYS_OFFSET.store(offset, Ordering::SeqCst);
}

fn phys_offset() -> u64 {
    PHYS_OFFSET.load(Ordering::SeqCst)
}

/// Summarize usable memory for the `mem.map` event.
pub fn summarize(regions: &MemoryRegions) -> (usize, u64) {
    let mut count = 0usize;
    let mut bytes = 0u64;
    for region in regions.iter() {
        if region.kind == MemoryRegionKind::Usable {
            count += 1;
            bytes += region.end - region.start;
        }
    }
    (count, bytes)
}

/// Initialize the frame allocator from usable regions. Frames beyond the
/// bitmap's capacity are ignored and reported once via `mem.truncated`.
pub fn init_frames(regions: &MemoryRegions) {
    let mut ignored: u64 = 0;
    let mut alloc = FRAMES.lock();
    for region in regions.iter() {
        if region.kind != MemoryRegionKind::Usable {
            continue;
        }
        let first = region.start / FRAME_SIZE;
        let last = region.end / FRAME_SIZE; // exclusive
        for frame in first..last {
            if (frame as usize) < MAX_FRAMES {
                alloc.set_usable(frame as usize);
            } else {
                ignored += 1;
            }
        }
    }
    drop(alloc);
    if ignored > 0 {
        crate::serial::ev_mem_truncated(ignored);
    }
}

pub fn alloc_frame() -> Option<Frame> {
    FRAMES.lock().alloc()
}

pub fn free_frame(frame: Frame) {
    FRAMES.lock().free(frame);
}

pub fn reset_frames() {
    FRAMES.lock().reset();
}

/// Real allocator census: the number of frames currently available
/// (`usable & !allocated`), counted from the live bitmap. This is the ground
/// truth the domain reclaim balance check compares against — it is derived by
/// counting free bits, never from side bookkeeping that the same paths mutate.
pub fn free_frame_count() -> usize {
    let alloc = FRAMES.lock();
    let mut count = 0usize;
    for word in 0..BITMAP_WORDS {
        count += (alloc.usable[word] & !alloc.allocated[word]).count_ones() as usize;
    }
    count
}

/// Base of the full physical-memory mapping. Physical frame `p` is readable and
/// writable by the kernel at virtual address `phys_offset_addr() + p`.
pub fn phys_offset_addr() -> u64 {
    phys_offset()
}

/// A kernel-writable pointer to the byte at physical address `phys`, via the
/// physical-memory mapping.
///
/// # Safety
/// `phys` must be a physical address within the mapped physical span; the
/// caller must respect Rust aliasing for the pointee it forms.
pub unsafe fn phys_mut(phys: u64) -> *mut u8 {
    (phys_offset() + phys) as *mut u8
}

/// Initialize the kernel heap over the static region.
pub fn init_heap() {
    HEAP.call_once(|| {
        let mut heap = Heap::empty();
        // SAFETY: HEAP_MEM is a static, resident, exclusively-owned region of
        // exactly HEAP_SIZE bytes; init is called once during boot.
        unsafe {
            heap.init(core::ptr::addr_of_mut!(HEAP_MEM) as *mut u8, HEAP_SIZE);
        }
        Mutex::new(heap)
    });
}

/// Fallible heap allocation (no `#[global_allocator]`; ring 0 only ever mints
/// fallibly).
pub fn heap_alloc(layout: Layout) -> Result<NonNull<u8>, ()> {
    HEAP.get()
        .expect("heap not initialized")
        .lock()
        .allocate_first_fit(layout)
}

/// # Safety
/// `ptr`/`layout` must originate from a matching [`heap_alloc`] call.
pub unsafe fn heap_dealloc(ptr: NonNull<u8>, layout: Layout) {
    // SAFETY: forwarded contract from the caller.
    unsafe {
        HEAP.get()
            .expect("heap not initialized")
            .lock()
            .deallocate(ptr, layout);
    }
}

/// A .text address, used as the executable-section probe for the W^X audit.
#[inline(never)]
extern "C" fn text_probe() {
    // A distinct instruction so the function is never folded away.
    core::hint::black_box(());
}

/// Walk the live page tables and return the leaf entry's flags for `addr`.
/// Intermediate tables are bootloader-created and permissive, so the leaf
/// flags are the effective W^X determinant for the kernel image.
fn leaf_flags(addr: VirtAddr) -> Option<PageTableFlags> {
    let (l4_frame, _) = Cr3::read();
    let mut table_phys = l4_frame.start_address().as_u64();
    let indices = [
        addr.p4_index(),
        addr.p3_index(),
        addr.p2_index(),
        addr.p1_index(),
    ];
    let offset = phys_offset();
    let mut flags = PageTableFlags::empty();
    for index in indices {
        // SAFETY: every physical frame is readable at phys_offset + phys; the
        // table pointer is 4 KiB aligned and valid while paging is live.
        let table = unsafe { &*((offset + table_phys) as *const PageTable) };
        let entry = &table[index];
        flags = entry.flags();
        if !flags.contains(PageTableFlags::PRESENT) {
            return None;
        }
        if flags.contains(PageTableFlags::HUGE_PAGE) {
            return Some(flags);
        }
        table_phys = entry.addr().as_u64();
    }
    Some(flags)
}

/// Audit W^X for the kernel image. Returns violation booleans:
/// `(rodata_nx_w, text_w, data_exec)` — each `true` means a broken invariant.
///
/// * `text_w`      — `.text` page is writable.
/// * `rodata_nx_w` — `.rodata` page is writable OR executable (missing NX).
/// * `data_exec`   — data/heap page is executable (missing NX).
pub fn audit_wx() -> (bool, bool, bool) {
    let text = leaf_flags(VirtAddr::new(text_probe as *const () as u64));
    let rodata = leaf_flags(VirtAddr::new(core::ptr::addr_of!(RODATA_PROBE) as u64));
    let data = leaf_flags(VirtAddr::new(core::ptr::addr_of!(DATA_PROBE) as u64));

    let text_w = text.is_none_or(|f| f.contains(PageTableFlags::WRITABLE));
    let rodata_nx_w = rodata.is_none_or(|f| {
        f.contains(PageTableFlags::WRITABLE) || !f.contains(PageTableFlags::NO_EXECUTE)
    });
    let data_exec = data.is_none_or(|f| !f.contains(PageTableFlags::NO_EXECUTE));

    (rodata_nx_w, text_w, data_exec)
}
