//! Physical memory: a fixed-pool bitmap frame allocator, a directly-managed
//! fallible heap, and a W^X audit of the live page tables. Every allocation is
//! fallible and every pool is bounded by construction (charter §6).
//!
//! `PHYS_SPAN` is 256 MiB and must match the ktest machine contract memory size.

use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use astrid_native_closure::{ClosureError, ReadableRange, prove_pages_readable, ranges_overlap};
use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use linked_list_allocator::Heap;
use spin::{Mutex, Once};
use x86_64::VirtAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTable, PageTableFlags};

pub const FRAME_SIZE: u64 = 4096;
const PHYS_SPAN: u64 = 256 * 1024 * 1024;
pub const MAX_FRAMES: usize = (PHYS_SPAN / FRAME_SIZE) as usize;
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

pub const HEAP_SIZE: usize = 1024 * 1024;
static mut HEAP_MEM: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[used]
static RODATA_PROBE: u8 = 0x42;
#[used]
static mut DATA_PROBE: u64 = 0x5555_5555_5555_5555;

static PHYS_OFFSET: AtomicU64 = AtomicU64::new(0);

/// A physical frame, identified by its base physical address.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    phys: u64,
}

impl Frame {
    pub const fn from_phys(phys: u64) -> Self {
        Self { phys }
    }

    pub const fn phys(self) -> u64 {
        self.phys
    }
}

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
                return Some(Frame::from_phys(frame as u64 * FRAME_SIZE));
            }
        }
        None
    }

    fn free(&mut self, frame: Frame) {
        let idx = (frame.phys() / FRAME_SIZE) as usize;
        if idx < MAX_FRAMES {
            self.allocated[idx / 64] &= !(1u64 << (idx % 64));
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

pub fn set_phys_offset(offset: u64) {
    PHYS_OFFSET.store(offset, Ordering::SeqCst);
}

fn phys_offset() -> u64 {
    PHYS_OFFSET.load(Ordering::SeqCst)
}

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

pub fn init_frames(regions: &MemoryRegions) {
    let mut ignored: u64 = 0;
    let mut alloc = FRAMES.lock();
    for region in regions.iter() {
        if region.kind != MemoryRegionKind::Usable {
            continue;
        }
        let first = region.start / FRAME_SIZE;
        let last = region.end / FRAME_SIZE;
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

pub fn heap_alloc(layout: Layout) -> Result<NonNull<u8>, ()> {
    HEAP.get()
        .expect("heap not initialized")
        .lock()
        .allocate_first_fit(layout)
}

/// # Safety
/// `ptr`/`layout` must originate from a matching [`heap_alloc`] call.
pub unsafe fn heap_dealloc(ptr: NonNull<u8>, layout: Layout) {
    unsafe {
        HEAP.get()
            .expect("heap not initialized")
            .lock()
            .deallocate(ptr, layout);
    }
}

#[inline(never)]
extern "C" fn text_probe() {
    core::hint::black_box(());
}

/// True if `page` is a canonical address whose leaf is present (readable).
fn page_present_readable(page: u64) -> bool {
    let Ok(addr) = VirtAddr::try_new(page) else {
        return false;
    };
    leaf_flags(addr).is_some_and(|f| f.contains(PageTableFlags::PRESENT))
}

/// Validate a loader-mapped virtual range before copying its untrusted bytes.
pub fn prove_readable_range(start: u64, len: u64) -> Result<(), ClosureError> {
    let range = ReadableRange::try_new(start, len)?;
    prove_pages_readable(range, page_present_readable)
}

/// Copy a previously proven loader-mapped range into kernel-owned storage.
///
/// # Safety
/// Call [`prove_readable_range`] for the same range immediately before this
/// operation, and provide a destination of exactly `len` bytes. The source
/// must remain readable for the duration of the copy. The checked overlap
/// guard below is required because the source address is loader input while
/// the destination is a kernel-owned stack buffer.
pub unsafe fn copy_readable_range(start: u64, destination: &mut [u8]) -> Result<(), ClosureError> {
    let len = destination.len() as u64;
    if ranges_overlap(start, len, destination.as_mut_ptr() as u64, len)? {
        return Err(ClosureError::Malformed);
    }
    let source = unsafe { core::slice::from_raw_parts(start as *const u8, destination.len()) };
    destination.copy_from_slice(source);
    Ok(())
}

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
        // SAFETY: every physical frame is readable at phys_offset + phys.
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
