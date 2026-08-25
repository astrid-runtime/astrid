use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use core::{cmp, mem::MaybeUninit};
use x86_64::{
    PhysAddr, align_down, align_up,
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
};

/// A slice of memory that is used by the bootloader and needs to be reserved
/// in the kernel
#[derive(Clone, Copy, Debug)]
pub struct UsedMemorySlice {
    /// the physical start of the slice
    pub start: u64,
    /// The physical end address (exclusive) of the region.
    pub end: u64,
}

impl UsedMemorySlice {
    /// Creates a new slice
    pub fn new_from_len(start: u64, len: u64) -> Self {
        Self {
            start,
            end: start + len,
        }
    }
}

/// Abstraction trait for a memory region returned by the UEFI or BIOS firmware.
pub trait LegacyMemoryRegion: Copy + core::fmt::Debug {
    /// Returns the physical start address of the region.
    fn start(&self) -> PhysAddr;
    /// Returns the size of the region in bytes.
    fn len(&self) -> u64;
    /// Returns whether this region is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Returns the type of the region, e.g. whether it is usable or reserved.
    fn kind(&self) -> MemoryRegionKind;

    /// Some regions become usable when the bootloader jumps to the kernel.
    fn usable_after_bootloader_exit(&self) -> bool;
}

/// A physical frame allocator based on a BIOS or UEFI provided memory map.
pub struct LegacyFrameAllocator<I, D> {
    original: I,
    memory_map: I,
    current_descriptor: Option<D>,
    next_frame: PhysFrame,
    min_frame: PhysFrame,
}

/// Start address of the first frame that is not part of the lower 1MB of frames
const LOWER_MEMORY_END_PAGE: u64 = 0x10_0000;

impl<I, D> LegacyFrameAllocator<I, D>
where
    I: ExactSizeIterator<Item = D> + Clone,
    I::Item: LegacyMemoryRegion,
{
    /// Creates a new frame allocator based on the given legacy memory regions.
    ///
    /// Skips the frame at physical address zero to avoid potential problems. For example
    /// identity-mapping the frame at address zero is not valid in Rust, because Rust's `core`
    /// library assumes that references can never point to virtual address `0`.
    /// Also skips the lower 1MB of frames, there are use cases that require lower conventional memory access (Such as SMP SIPI).
    pub fn new(memory_map: I) -> Self {
        // skip frame 0 because the rust core library does not see 0 as a valid address
        // Also skip at least the lower 1MB of frames, there are use cases that require lower conventional memory access (Such as SMP SIPI).
        let start_frame = PhysFrame::containing_address(PhysAddr::new(LOWER_MEMORY_END_PAGE));
        Self::new_starting_at(start_frame, memory_map)
    }

    /// Creates a new frame allocator based on the given legacy memory regions. Skips any frames
    /// before the given `frame` or `0x10000`(1MB) whichever is higher, there are use cases that require
    /// lower conventional memory access (Such as SMP SIPI).
    pub fn new_starting_at(frame: PhysFrame, memory_map: I) -> Self {
        // skip frame 0 because the rust core library does not see 0 as a valid address
        // Also skip at least the lower 1MB of frames, there are use cases that require lower conventional memory access (Such as SMP SIPI).
        let lower_mem_end = PhysFrame::containing_address(PhysAddr::new(LOWER_MEMORY_END_PAGE));
        let frame = core::cmp::max(frame, lower_mem_end);
        Self {
            original: memory_map.clone(),
            memory_map,
            current_descriptor: None,
            next_frame: frame,
            min_frame: frame,
        }
    }

    fn allocate_frame_from_descriptor(&mut self, descriptor: D) -> Option<PhysFrame> {
        let start_addr = descriptor.start();
        let start_frame = PhysFrame::containing_address(start_addr);
        let end_addr = start_addr + descriptor.len();
        let end_frame = PhysFrame::containing_address(end_addr - 1u64);

        // increase self.next_frame to start_frame if smaller
        if self.next_frame < start_frame {
            self.next_frame = start_frame;
        }

        if self.next_frame <= end_frame {
            let ret = self.next_frame;
            self.next_frame += 1;

            Some(ret)
        } else {
            None
        }
    }

    /// Returns the number of memory regions in the underlying memory map.
    ///
    /// The function always returns the same value, i.e. the length doesn't
    /// change after calls to `allocate_frame`.
    pub fn len(&self) -> usize {
        self.original.len()
    }

    /// Returns whether this memory map is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the largest detected physical memory address.
    ///
    /// Useful for creating a mapping for all physical memory.
    pub fn max_phys_addr(&self) -> PhysAddr {
        let max = self
            .original
            .clone()
            .map(|r| r.start() + r.len())
            .max()
            .unwrap();

        // Always cover at least the first 4 GiB of physical memory. That area
        // contains useful MMIO regions (local APIC, I/O APIC, PCI bars) that
        // we want to make accessible to the kernel even if no DRAM exists >4GiB.
        cmp::max(max, PhysAddr::new(0x1_0000_0000))
    }

    /// Calculate the maximum number of regions produced by [Self::construct_memory_map]
    pub fn memory_map_max_region_count(&self) -> usize {
        // every used region can split an original region into 3 new regions,
        // this means we need to reserve 2 extra spaces for each region.
        // There are 3 used regions: kernel, ramdisk and the bootloader heap
        self.len() + 6
    }

    /// Converts this type to a boot info memory map.
    ///
    /// The memory map is placed in the given `regions` slice. The length of the given slice
    /// must be at least the value returned by [`len`] plus 1.
    ///
    /// The return slice is a subslice of `regions`, shortened to the actual number of regions.
    pub fn construct_memory_map(
        self,
        regions: &mut [MaybeUninit<MemoryRegion>],
        kernel_slice_start: PhysAddr,
        kernel_slice_len: u64,
        ramdisk_slice_start: Option<PhysAddr>,
        ramdisk_slice_len: u64,
    ) -> &mut [MemoryRegion] {
        let used_slices = [
            UsedMemorySlice {
                start: self.min_frame.start_address().as_u64(),
                end: self.next_frame.start_address().as_u64(),
            },
            UsedMemorySlice::new_from_len(kernel_slice_start.as_u64(), kernel_slice_len),
        ]
        .into_iter()
        .chain(
            ramdisk_slice_start
                .map(|start| UsedMemorySlice::new_from_len(start.as_u64(), ramdisk_slice_len)),
        )
        .map(|slice| UsedMemorySlice {
            start: align_down(slice.start, 0x1000),
            end: align_up(slice.end, 0x1000),
        });

        let mut next_index = 0;
        for descriptor in self.original {
            let kind = match descriptor.kind() {
                _ if descriptor.usable_after_bootloader_exit() => {
                    // Region was not usable before, but it will be as soon as
                    // the bootloader passes control to the kernel. We don't
                    // need to check against `next_free` because the
                    // LegacyFrameAllocator only allocates memory from usable
                    // descriptors.
                    MemoryRegionKind::Usable
                }
                other => other,
            };

            let end = descriptor.start() + descriptor.len();
            let region = MemoryRegion {
                start: descriptor.start().as_u64(),
                end: end.as_u64(),
                kind,
            };
            if region.kind == MemoryRegionKind::Usable {
                Self::split_and_add_region(region, regions, &mut next_index, used_slices.clone());
            } else {
                Self::add_region(region, regions, &mut next_index);
            }
        }

        let initialized = &mut regions[..next_index];
        unsafe {
            // inlined variant of: `MaybeUninit::slice_assume_init_mut(initialized)`
            // TODO: undo inlining when `slice_assume_init_mut` becomes stable
            &mut *(initialized as *mut [_] as *mut [_])
        }
    }

    fn split_and_add_region<U>(
        mut region: MemoryRegion,
        regions: &mut [MaybeUninit<MemoryRegion>],
        next_index: &mut usize,
        used_slices: U,
    ) where
        U: Iterator<Item = UsedMemorySlice> + Clone,
    {
        assert!(region.kind == MemoryRegionKind::Usable);
        // Each loop iteration takes a chunk of `region` and adds it to
        // `regions`. Do this until `region` is empty.
        while region.start != region.end {
            // Check if there is overlap between `region` and `used_slices`.
            if let Some((overlap_start, overlap_end)) = used_slices
                .clone()
                .map(|slice| {
                    // Calculate the start and end points of the overlap
                    // between `slice` and `region`. If `slice` and `region`
                    // don't overlap, the range will be ill-formed
                    // (overlap_start > overlap_end).
                    let overlap_start = cmp::max(region.start, slice.start);
                    let overlap_end = cmp::min(region.end, slice.end);
                    (overlap_start, overlap_end)
                })
                .filter(|(overlap_start, overlap_end)| {
                    // Only consider non-empty overlap.
                    overlap_start < overlap_end
                })
                .min_by_key(|&(overlap_start, _)| {
                    // Find the earliest overlap.
                    overlap_start
                })
            {
                // There's no overlapping used slice before `overlap_start`, so
                // we know that memory between `region.start` and
                // `overlap_start` is usable.
                let usable = MemoryRegion {
                    start: region.start,
                    end: overlap_start,
                    kind: MemoryRegionKind::Usable,
                };
                let bootloader = MemoryRegion {
                    start: overlap_start,
                    end: overlap_end,
                    kind: MemoryRegionKind::Bootloader,
                };
                Self::add_region(usable, regions, next_index);
                Self::add_region(bootloader, regions, next_index);
                // Continue after the overlapped region.
                region.start = overlap_end;
            } else {
                // There's no overlap. We can add the whole region.
                Self::add_region(region, regions, next_index);
                break;
            }
        }
    }

    fn add_region(
        region: MemoryRegion,
        regions: &mut [MaybeUninit<MemoryRegion>],
        next_index: &mut usize,
    ) {
        if region.start == region.end {
            // skip zero sized regions
            return;
        }
        unsafe {
            regions
                .get_mut(*next_index)
                .expect("cannot add region: no more free entries in memory map")
                .as_mut_ptr()
                .write(region)
        };
        *next_index += 1;
    }
}

unsafe impl<I, D> FrameAllocator<Size4KiB> for LegacyFrameAllocator<I, D>
where
    I: ExactSizeIterator<Item = D> + Clone,
    I::Item: LegacyMemoryRegion,
{
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        if let Some(current_descriptor) = self.current_descriptor {
            match self.allocate_frame_from_descriptor(current_descriptor) {
                Some(frame) => return Some(frame),
                None => {
                    self.current_descriptor = None;
                }
            }
        }

        // find next suitable descriptor
        while let Some(descriptor) = self.memory_map.next() {
            if descriptor.kind() != MemoryRegionKind::Usable {
                continue;
            }
            if let Some(frame) = self.allocate_frame_from_descriptor(descriptor) {
                self.current_descriptor = Some(descriptor);
                return Some(frame);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Copy, Clone, Debug)]
    struct TestMemoryRegion {
        start: PhysAddr,
        len: u64,
        kind: MemoryRegionKind,
    }

    impl LegacyMemoryRegion for TestMemoryRegion {
        fn start(&self) -> PhysAddr {
            self.start
        }

        fn len(&self) -> u64 {
            assert!(self.len.is_multiple_of(4096));
            self.len
        }

        fn kind(&self) -> MemoryRegionKind {
            self.kind
        }

        fn usable_after_bootloader_exit(&self) -> bool {
            matches!(self.kind, MemoryRegionKind::Usable)
        }
    }

    // we need some kind of max phys memory, 4GB seems reasonable
    const MAX_PHYS_ADDR: u64 = 0x4000_0000;

    fn create_single_test_region() -> Vec<TestMemoryRegion> {
        vec![TestMemoryRegion {
            start: PhysAddr::new(0),
            len: MAX_PHYS_ADDR,
            kind: MemoryRegionKind::Usable,
        }]
    }

    #[test]
    fn test_all_regions_frame_alligned() {
        let regions = create_single_test_region();
        let mut allocator = LegacyFrameAllocator::new(regions.into_iter());
        // allocate at least 1 frame
        allocator.allocate_frame();

        let mut regions = [MaybeUninit::uninit(); 10];
        let kernel_slice_start = PhysAddr::new(0x50000);
        let kernel_slice_len = 0x0500;
        let ramdisk_slice_start = None;
        let ramdisk_slice_len = 0;

        let kernel_regions = allocator.construct_memory_map(
            &mut regions,
            kernel_slice_start,
            kernel_slice_len,
            ramdisk_slice_start,
            ramdisk_slice_len,
        );

        for region in kernel_regions.iter() {
            assert!(region.start % 0x1000 == 0);
            assert!(region.end % 0x1000 == 0);
        }
    }

    #[test]
    fn test_kernel_and_ram_in_same_region() {
        let regions = create_single_test_region();
        let mut allocator = LegacyFrameAllocator::new(regions.into_iter());
        // allocate at least 1 frame
        allocator.allocate_frame();

        let mut regions = [MaybeUninit::uninit(); 10];
        let kernel_slice_start = PhysAddr::new(0x50000);
        let kernel_slice_len = 0x1000;
        let ramdisk_slice_start = Some(PhysAddr::new(0x60000));
        let ramdisk_slice_len = 0x2000;

        let kernel_regions = allocator.construct_memory_map(
            &mut regions,
            kernel_slice_start,
            kernel_slice_len,
            ramdisk_slice_start,
            ramdisk_slice_len,
        );
        let mut kernel_regions = kernel_regions.iter();
        // usable memory before the kernel
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x0000,
                end: 0x50000,
                kind: MemoryRegionKind::Usable
            })
        );
        // kernel
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x50000,
                end: 0x51000,
                kind: MemoryRegionKind::Bootloader
            })
        );
        // usabel memory between kernel and ramdisk
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x51000,
                end: 0x60000,
                kind: MemoryRegionKind::Usable
            })
        );
        // ramdisk
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x60000,
                end: 0x62000,
                kind: MemoryRegionKind::Bootloader
            })
        );
        // usabele memory after ramdisk, up until bootloader allocated memory
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x62000,
                end: 0x10_0000,
                kind: MemoryRegionKind::Usable
            })
        );
        // bootloader allocated memory
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x10_0000,
                end: 0x10_1000,
                kind: MemoryRegionKind::Bootloader
            })
        );
        // rest is free
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x10_1000,
                end: MAX_PHYS_ADDR,
                kind: MemoryRegionKind::Usable
            })
        );
        assert_eq!(kernel_regions.next(), None);
    }

    #[test]
    fn test_multiple_regions() {
        let regions = vec![
            TestMemoryRegion {
                start: PhysAddr::new(0),
                len: 0x10_0000,
                kind: MemoryRegionKind::Usable,
            },
            TestMemoryRegion {
                start: PhysAddr::new(0x10_0000),
                len: 0x5000,
                kind: MemoryRegionKind::UnknownBios(0),
            },
            TestMemoryRegion {
                start: PhysAddr::new(0x10_5000),
                len: MAX_PHYS_ADDR - 0x10_5000,
                kind: MemoryRegionKind::Usable,
            },
        ];
        let mut allocator = LegacyFrameAllocator::new(regions.into_iter());
        // allocate at least 1 frame
        allocator.allocate_frame();

        let mut regions = [MaybeUninit::uninit(); 10];
        let kernel_slice_start = PhysAddr::new(0x50000);
        let kernel_slice_len = 0x1000;
        let ramdisk_slice_start = Some(PhysAddr::new(0x60000));
        let ramdisk_slice_len = 0x2000;

        let kernel_regions = allocator.construct_memory_map(
            &mut regions,
            kernel_slice_start,
            kernel_slice_len,
            ramdisk_slice_start,
            ramdisk_slice_len,
        );
        let mut kernel_regions = kernel_regions.iter();

        // usable memory before the kernel
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x0000,
                end: 0x50000,
                kind: MemoryRegionKind::Usable
            })
        );
        // kernel
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x50000,
                end: 0x51000,
                kind: MemoryRegionKind::Bootloader
            })
        );
        // usabel memory between kernel and ramdisk
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x51000,
                end: 0x60000,
                kind: MemoryRegionKind::Usable
            })
        );
        // ramdisk
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x60000,
                end: 0x62000,
                kind: MemoryRegionKind::Bootloader
            })
        );
        // usabele memory after ramdisk, up until bootloader allocated memory
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x62000,
                end: 0x10_0000,
                kind: MemoryRegionKind::Usable
            })
        );
        // the unknown bios region
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x10_0000,
                end: 0x10_5000,
                kind: MemoryRegionKind::UnknownBios(0)
            })
        );
        // bootloader allocated memory, this gets pushed back by the bios region
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x10_5000,
                end: 0x10_6000,
                kind: MemoryRegionKind::Bootloader
            })
        );
        // rest is free
        assert_eq!(
            kernel_regions.next(),
            Some(&MemoryRegion {
                start: 0x10_6000,
                end: MAX_PHYS_ADDR,
                kind: MemoryRegionKind::Usable
            })
        );
        assert_eq!(kernel_regions.next(), None);
    }
}
