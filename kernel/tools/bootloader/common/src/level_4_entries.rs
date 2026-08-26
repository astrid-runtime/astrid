use crate::{
    BootInfo, RawFrameBufferInfo, entropy,
    load_kernel::{ElfMemoryRequirements, VirtualAddressOffset, calc_elf_memory_requirements},
};
use bootloader_api::{BootloaderConfig, config, info::MemoryRegion};
use core::{alloc::Layout, iter::Step};
use rand::{
    distributions::{Distribution, Uniform},
    seq::IteratorRandom,
};
use rand_hc::Hc128Rng;
use usize_conversions::IntoUsize;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{Page, PageTableIndex, Size4KiB},
};
use xmas_elf::{ElfFile, header, program::ProgramHeader};

/// Keeps track of used entries in a level 4 page table.
///
/// Useful for determining a free virtual memory block, e.g. for mapping additional data.
pub struct UsedLevel4Entries {
    /// Whether an entry is in use by the kernel.
    entry_state: [bool; 512],
    /// A random number generator that should be used to generate random addresses or
    /// `None` if aslr is disabled.
    rng: Option<Hc128Rng>,
}

impl UsedLevel4Entries {
    /// Initializes a new instance.
    ///
    /// Marks the statically configured virtual address ranges from the config as used.
    pub fn new(
        max_phys_addr: PhysAddr,
        regions_len: usize,
        framebuffer: Option<&RawFrameBufferInfo>,
        config: &BootloaderConfig,
        kernel_elf: &ElfFile<'_>,
    ) -> Result<Self, &'static str> {
        let mut used = UsedLevel4Entries {
            entry_state: [false; 512],
            rng: config.mappings.aslr.then(entropy::build_rng),
        };

        // The bootloader maps of the kernel's memory into its own page tables.
        // We need to prevent overlaps, so mark all memory that could already
        // be used by the bootload as inaccessible.

        // All memory in this range is identity mapped.
        used.mark_range_as_used(0, max_phys_addr.as_u64());

        // The bootload needs to access the frame buffer.
        if let Some(frame_buffer) = framebuffer {
            used.mark_range_as_used(
                frame_buffer.addr.as_u64(),
                frame_buffer.info.byte_len as u64,
            );
        }

        // Mark the statically configured ranges from the config as used.

        if let Some(config::Mapping::FixedAddress(physical_memory_offset)) =
            config.mappings.physical_memory
        {
            used.mark_range_as_used(physical_memory_offset, max_phys_addr.as_u64());
        }

        if let Some(config::Mapping::FixedAddress(recursive_address)) =
            config.mappings.page_table_recursive
        {
            let recursive_index = VirtAddr::new(recursive_address).p4_index();
            used.mark_p4_index_as_used(recursive_index);
        }

        if let config::Mapping::FixedAddress(kernel_stack_address) = config.mappings.kernel_stack {
            used.mark_range_as_used(kernel_stack_address, config.kernel_stack_size);
        }

        if let config::Mapping::FixedAddress(kernel_base) = config.mappings.kernel_base {
            let ElfMemoryRequirements { size, align, .. } =
                calc_elf_memory_requirements(kernel_elf);

            if !VirtAddr::new(kernel_base).is_aligned(align) {
                return Err("kernel_code mapping alignment does not match elf file");
            }

            used.mark_range_as_used(kernel_base, size);
        }
        if kernel_elf.header.pt2.type_().as_type() == header::Type::Executable {
            let ElfMemoryRequirements { size, min_addr, .. } =
                calc_elf_memory_requirements(kernel_elf);

            used.mark_range_as_used(min_addr, size);
        }

        if let config::Mapping::FixedAddress(boot_info_address) = config.mappings.boot_info {
            let boot_info_layout = Layout::new::<BootInfo>();
            let regions = regions_len + 1; // one region might be split into used/unused
            let memory_regions_layout = Layout::array::<MemoryRegion>(regions).unwrap();
            let (combined, _) = boot_info_layout.extend(memory_regions_layout).unwrap();

            used.mark_range_as_used(boot_info_address, combined.size() as u64);
        }

        if let config::Mapping::FixedAddress(framebuffer_address) = config.mappings.framebuffer
            && let Some(framebuffer) = framebuffer
        {
            used.mark_range_as_used(framebuffer_address, framebuffer.info.byte_len as u64);
        }

        // Mark everything before the dynamic range as unusable.
        if let Some(dynamic_range_start) = config.mappings.dynamic_range_start {
            let dynamic_range_start = VirtAddr::new(dynamic_range_start);
            let start_page: Page = Page::containing_address(dynamic_range_start);
            if let Some(unusable_page) = Step::backward_checked(start_page, 1) {
                for i in 0..=u16::from(unusable_page.p4_index()) {
                    used.mark_p4_index_as_used(PageTableIndex::new(i));
                }
            }
        }

        // Mark everything after the dynamic range as unusable.
        if let Some(dynamic_range_end) = config.mappings.dynamic_range_end {
            let dynamic_range_end = VirtAddr::new(dynamic_range_end);
            let end_page: Page = Page::containing_address(dynamic_range_end);
            if let Some(unusable_page) = Step::forward_checked(end_page, 1) {
                for i in u16::from(unusable_page.p4_index())..512 {
                    used.mark_p4_index_as_used(PageTableIndex::new(i));
                }
            }
        }

        Ok(used)
    }

    /// Marks all p4 entries in the range `[address..address+size)` as used.
    fn mark_range_as_used(&mut self, address: u64, size: u64) {
        let start = VirtAddr::new(address);
        let end_inclusive = start + (size - 1);
        let start_page = Page::<Size4KiB>::containing_address(start);
        let end_page_inclusive = Page::<Size4KiB>::containing_address(end_inclusive);

        for p4_index in u16::from(start_page.p4_index())..=u16::from(end_page_inclusive.p4_index())
        {
            self.mark_p4_index_as_used(PageTableIndex::new(p4_index));
        }
    }

    fn mark_p4_index_as_used(&mut self, p4_index: PageTableIndex) {
        self.entry_state[usize::from(p4_index)] = true;
    }

    /// Marks the virtual address range of all segments as used.
    pub fn mark_segments<'a>(
        &mut self,
        segments: impl Iterator<Item = ProgramHeader<'a>>,
        virtual_address_offset: VirtualAddressOffset,
    ) {
        for segment in segments.filter(|s| s.mem_size() > 0) {
            self.mark_range_as_used(
                virtual_address_offset + segment.virtual_addr(),
                segment.mem_size(),
            );
        }
    }

    /// Returns the first index of a `num` contiguous unused level 4 entries and marks them as
    /// used. If `CONFIG.aslr` is enabled, this will return random contiguous available entries.
    ///
    /// Since this method marks each returned index as used, it can be used multiple times
    /// to determine multiple unused virtual memory regions.
    pub fn get_free_entries(&mut self, num: u64) -> PageTableIndex {
        // Create an iterator over all available p4 indices with `num` contiguous free entries.
        let mut free_entries = self
            .entry_state
            .windows(num.into_usize())
            .enumerate()
            .filter(|(_, entries)| entries.iter().all(|used| !used))
            .map(|(idx, _)| idx);

        // Choose the free entry index.
        let idx_opt = if let Some(rng) = self.rng.as_mut() {
            // Randomly choose an index.
            free_entries.choose(rng)
        } else {
            // Choose the first index.
            free_entries.next()
        };
        let Some(idx) = idx_opt else {
            panic!("no usable level 4 entries found ({num} entries requested)");
        };

        // Mark the entries as used.
        for i in 0..num.into_usize() {
            self.entry_state[idx + i] = true;
        }

        PageTableIndex::new(idx.try_into().unwrap())
    }

    /// Returns a virtual address in one or more unused level 4 entries and marks them as used.
    ///
    /// This function calls [`get_free_entries`] internally, so all of its docs applies here
    /// too.
    pub fn get_free_address(&mut self, size: u64, alignment: u64) -> VirtAddr {
        assert!(alignment.is_power_of_two());

        const LEVEL_4_SIZE: u64 = 4096 * 512 * 512 * 512;

        let level_4_entries = size.div_ceil(LEVEL_4_SIZE);
        let base = Page::from_page_table_indices_1gib(
            self.get_free_entries(level_4_entries),
            PageTableIndex::new(0),
        )
        .start_address();

        let offset = if let Some(rng) = self.rng.as_mut() {
            // Choose a random offset.
            let max_offset = LEVEL_4_SIZE - (size % LEVEL_4_SIZE);
            let uniform_range = Uniform::from(0..max_offset / alignment);
            uniform_range.sample(rng) * alignment
        } else {
            0
        };

        base + offset
    }
}
