#![cfg_attr(not(test), no_std)]
#![feature(step_trait)]
#![deny(unsafe_op_in_unsafe_fn)]

use crate::legacy_memory_region::{LegacyFrameAllocator, LegacyMemoryRegion};
use bootloader_api::{
    BootInfo, BootloaderConfig,
    config::Mapping,
    info::{FrameBuffer, FrameBufferInfo, MemoryRegion, TlsTemplate},
};
use bootloader_boot_config::{BootConfig, LevelFilter};
use core::{alloc::Layout, arch::asm, mem::MaybeUninit, slice};
use level_4_entries::UsedLevel4Entries;
use usize_conversions::FromUsize;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{
        FrameAllocator, Mapper, OffsetPageTable, Page, PageSize, PageTableFlags, PageTableIndex,
        PhysFrame, Size2MiB, Size4KiB, page_table::PageTableLevel,
    },
};
use xmas_elf::ElfFile;

mod astrid_handoff;
/// Provides a function to gather entropy and build a RNG.
mod entropy;
/// Provides a type that logs output as text to pixel-based framebuffers.
pub mod framebuffer;
mod gdt;
/// Provides a frame allocator based on a BIOS or UEFI memory map.
pub mod legacy_memory_region;
/// Provides a type to keep track of used entries in a level 4 page table.
pub mod level_4_entries;
/// Implements a loader for the kernel ELF binary.
pub mod load_kernel;
/// Provides a logger that logs output as text in various formats.
pub mod logger;
/// Provides a type that logs output as text to a Serial Being port.
pub mod serial;

pub use astrid_handoff::{expected_context, verify_before_mapping};

const PAGE_SIZE: u64 = 4096;

/// Initialize a text-based logger using the given pixel-based framebuffer as output.
pub fn init_logger(
    framebuffer: &'static mut [u8],
    info: FrameBufferInfo,
    log_level: LevelFilter,
    frame_buffer_logger_status: bool,
    serial_logger_status: bool,
) {
    let logger = logger::LOGGER.get_or_init(move || {
        logger::LockedLogger::new(
            framebuffer,
            info,
            frame_buffer_logger_status,
            serial_logger_status,
        )
    });
    log::set_logger(logger).expect("logger already set");
    log::set_max_level(convert_level(log_level));
    log::info!("Framebuffer info: {:?}", info);
}

fn convert_level(level: LevelFilter) -> log::LevelFilter {
    match level {
        LevelFilter::Off => log::LevelFilter::Off,
        LevelFilter::Error => log::LevelFilter::Error,
        LevelFilter::Warn => log::LevelFilter::Warn,
        LevelFilter::Info => log::LevelFilter::Info,
        LevelFilter::Debug => log::LevelFilter::Debug,
        LevelFilter::Trace => log::LevelFilter::Trace,
    }
}

/// Required system information that should be queried from the BIOS or UEFI firmware.
#[derive(Debug, Copy, Clone)]
pub struct SystemInfo {
    /// Information about the (still unmapped) framebuffer.
    pub framebuffer: Option<RawFrameBufferInfo>,
    /// Address of the _Root System Description Pointer_ structure of the ACPI standard.
    pub rsdp_addr: Option<PhysAddr>,
    pub ramdisk_addr: Option<u64>,
    pub ramdisk_len: u64,
    /// Read-only view of the original loader ramdisk, available before
    /// mappings are created for pre-relocation policy verification.
    pub ramdisk_bytes: Option<&'static [u8]>,
}

/// The physical address of the framebuffer and information about the framebuffer.
#[derive(Debug, Copy, Clone)]
pub struct RawFrameBufferInfo {
    /// Start address of the pixel-based framebuffer.
    pub addr: PhysAddr,
    /// Information about the framebuffer, including layout and pixel format.
    pub info: FrameBufferInfo,
}

pub struct Kernel<'a> {
    pub elf: ElfFile<'a>,
    pub config: BootloaderConfig,
    pub start_address: *const u8,
    pub len: usize,
}

impl<'a> Kernel<'a> {
    pub fn parse(kernel_slice: &'a [u8]) -> Self {
        let kernel_elf = ElfFile::new(kernel_slice).unwrap();
        let config = {
            let section = kernel_elf
                .find_section_by_name(".bootloader-config")
                .expect("bootloader config section not found; kernel must be compiled against bootloader_api");
            let raw = section.raw_data(&kernel_elf);
            BootloaderConfig::deserialize(raw)
                .expect("kernel was compiled with incompatible bootloader_api version")
        };
        Kernel {
            elf: kernel_elf,
            config,
            start_address: kernel_slice.as_ptr(),
            len: kernel_slice.len(),
        }
    }
}

/// Loads the kernel ELF executable into memory and switches to it.
///
/// This function is a convenience function that first calls [`set_up_mappings`], then
/// [`create_boot_info`], and finally [`switch_to_kernel`]. The given arguments are passed
/// directly to these functions, so see their docs for more info.
pub fn load_and_switch_to_kernel<I, D>(
    kernel: Kernel,
    boot_config: BootConfig,
    mut frame_allocator: LegacyFrameAllocator<I, D>,
    mut page_tables: PageTables,
    system_info: SystemInfo,
) -> !
where
    I: ExactSizeIterator<Item = D> + Clone,
    D: LegacyMemoryRegion,
{
    // Verify while `kernel.elf.input` and the original ramdisk are still
    // owned by the loader. This must precede any PT_LOAD mapping or
    // relocation, because writable load pages may alias the ELF source.
    let ramdisk = system_info
        .ramdisk_bytes
        .unwrap_or_else(|| panic!("Astrid policy handoff ramdisk missing"));
    let loader_receipt = verify_before_mapping(kernel.elf.input, ramdisk)
        .unwrap_or_else(|reason| panic!("Astrid policy handoff rejected: {reason}"));
    let config = kernel.config;
    let mut mappings = set_up_mappings(
        kernel,
        &mut frame_allocator,
        &mut page_tables,
        system_info.framebuffer.as_ref(),
        &config,
        &system_info,
    );
    let boot_info = create_boot_info(
        &config,
        &boot_config,
        frame_allocator,
        &mut page_tables,
        &mut mappings,
        system_info,
        loader_receipt,
    );
    switch_to_kernel(page_tables, mappings, boot_info);
}

/// Sets up mappings for a kernel stack and the framebuffer.
///
/// The `kernel_bytes` slice should contain the raw bytes of the kernel ELF executable. The
/// `frame_allocator` argument should be created from the memory map. The `page_tables`
/// argument should point to the bootloader and kernel page tables. The function tries to parse
/// the ELF file and create all specified mappings in the kernel-level page table.
///
/// The `framebuffer_addr` and `framebuffer_size` fields should be set to the start address and
/// byte length the pixel-based framebuffer. These arguments are required because the functions
/// maps this framebuffer in the kernel-level page table, unless the `map_framebuffer` config
/// option is disabled.
///
/// This function reacts to unexpected situations (e.g. invalid kernel ELF file) with a panic, so
/// errors are not recoverable.
pub fn set_up_mappings<I, D>(
    kernel: Kernel,
    frame_allocator: &mut LegacyFrameAllocator<I, D>,
    page_tables: &mut PageTables,
    framebuffer: Option<&RawFrameBufferInfo>,
    config: &BootloaderConfig,
    system_info: &SystemInfo,
) -> Mappings
where
    I: ExactSizeIterator<Item = D> + Clone,
    D: LegacyMemoryRegion,
{
    let kernel_page_table = &mut page_tables.kernel;

    let mut used_entries = UsedLevel4Entries::new(
        frame_allocator.max_phys_addr(),
        frame_allocator.len(),
        framebuffer,
        config,
        &kernel.elf,
    )
    .expect("Failed to mark level 4 entries as used");

    // Enable support for the no-execute bit in page tables.
    enable_nxe_bit();
    // Make the kernel respect the write-protection bits even when in ring 0 by default
    enable_write_protect_bit();

    let config = kernel.config;
    let kernel_slice_start = PhysAddr::new(kernel.start_address as _);
    let kernel_slice_len = u64::try_from(kernel.len).unwrap();

    let (kernel_image_offset, entry_point, tls_template) = load_kernel::load_kernel(
        kernel,
        kernel_page_table,
        frame_allocator,
        &mut used_entries,
    )
    .expect("no entry point");
    log::info!("Entry point at: {:#x}", entry_point.as_u64());
    // create a stack
    let stack_start = {
        // we need page-alignment because we want a guard page directly below the stack
        let guard_page = mapping_addr_page_aligned(
            config.mappings.kernel_stack,
            // allocate an additional page as a guard page
            Size4KiB::SIZE + config.kernel_stack_size,
            &mut used_entries,
            "kernel stack start",
        );
        guard_page + 1
    };
    let stack_end_addr = stack_start.start_address() + config.kernel_stack_size;

    let stack_end = Page::containing_address(stack_end_addr - 1u64);
    for page in Page::range_inclusive(stack_start, stack_end) {
        let frame = frame_allocator
            .allocate_frame()
            .expect("frame allocation failed when mapping a kernel stack");
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        match unsafe { kernel_page_table.map_to(page, frame, flags, frame_allocator) } {
            Ok(tlb) => tlb.flush(),
            Err(err) => panic!("failed to map page {:?}: {:?}", page, err),
        }
    }

    // identity-map context switch function, so that we don't get an immediate pagefault
    // after switching the active page table
    let context_switch_function = PhysAddr::new(context_switch as *const () as u64);
    let context_switch_function_start_frame: PhysFrame =
        PhysFrame::containing_address(context_switch_function);
    for frame in PhysFrame::range_inclusive(
        context_switch_function_start_frame,
        context_switch_function_start_frame + 1,
    ) {
        let page = Page::containing_address(VirtAddr::new(frame.start_address().as_u64()));
        match unsafe {
            // The parent table flags need to be both readable and writable to
            // support recursive page tables.
            // See https://github.com/rust-osdev/bootloader/issues/443#issuecomment-2130010621
            kernel_page_table.map_to_with_table_flags(
                page,
                frame,
                PageTableFlags::PRESENT,
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                frame_allocator,
            )
        } {
            Ok(tlb) => tlb.flush(),
            Err(err) => panic!("failed to identity map frame {:?}: {:?}", frame, err),
        }
    }

    // create, load, and identity-map GDT (required for working `iretq`)
    let gdt_frame = frame_allocator
        .allocate_frame()
        .expect("failed to allocate GDT frame");
    gdt::create_and_load(gdt_frame);
    let gdt_page = Page::containing_address(VirtAddr::new(gdt_frame.start_address().as_u64()));
    match unsafe {
        // The parent table flags need to be both readable and writable to
        // support recursive page tables.
        kernel_page_table.map_to_with_table_flags(
            gdt_page,
            gdt_frame,
            PageTableFlags::PRESENT,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            frame_allocator,
        )
    } {
        Ok(tlb) => tlb.flush(),
        Err(err) => panic!("failed to identity map frame {:?}: {:?}", gdt_frame, err),
    }

    // map framebuffer
    let framebuffer_virt_addr = if let Some(framebuffer) = framebuffer {
        log::info!("Map framebuffer");

        let framebuffer_start_frame: PhysFrame = PhysFrame::containing_address(framebuffer.addr);
        let framebuffer_end_frame = PhysFrame::containing_address(
            framebuffer.addr + framebuffer.info.byte_len as u64 - 1u64,
        );
        let start_page = mapping_addr_page_aligned(
            config.mappings.framebuffer,
            u64::from_usize(framebuffer.info.byte_len),
            &mut used_entries,
            "framebuffer",
        );
        for (i, frame) in
            PhysFrame::range_inclusive(framebuffer_start_frame, framebuffer_end_frame).enumerate()
        {
            let page = start_page + u64::from_usize(i);
            let flags =
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
            match unsafe { kernel_page_table.map_to(page, frame, flags, frame_allocator) } {
                Ok(tlb) => tlb.flush(),
                Err(err) => panic!(
                    "failed to map page {:?} to frame {:?}: {:?}",
                    page, frame, err
                ),
            }
        }
        let framebuffer_virt_addr = start_page.start_address();
        Some(framebuffer_virt_addr)
    } else {
        None
    };
    let ramdisk_slice_len = system_info.ramdisk_len;
    let ramdisk_slice_phys_start = system_info.ramdisk_addr.map(PhysAddr::new);
    let ramdisk_slice_start = if let Some(physical_address) = ramdisk_slice_phys_start {
        let start_page = mapping_addr_page_aligned(
            config.mappings.ramdisk_memory,
            system_info.ramdisk_len,
            &mut used_entries,
            "ramdisk start",
        );
        let ramdisk_physical_start_page: PhysFrame<Size4KiB> =
            PhysFrame::containing_address(physical_address);
        let ramdisk_page_count = (system_info.ramdisk_len - 1) / Size4KiB::SIZE;
        let ramdisk_physical_end_page = ramdisk_physical_start_page + ramdisk_page_count;

        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        for (i, frame) in
            PhysFrame::range_inclusive(ramdisk_physical_start_page, ramdisk_physical_end_page)
                .enumerate()
        {
            let page = start_page + i as u64;
            match unsafe { kernel_page_table.map_to(page, frame, flags, frame_allocator) } {
                Ok(tlb) => tlb.ignore(),
                Err(err) => panic!(
                    "Failed to map page {:?} to frame {:?}: {:?}",
                    page, frame, err
                ),
            };
        }
        Some(start_page.start_address())
    } else {
        None
    };

    let physical_memory_offset = if let Some(mapping) = config.mappings.physical_memory {
        log::info!("Map physical memory");

        let start_frame = PhysFrame::containing_address(PhysAddr::new(0));
        let max_phys = frame_allocator.max_phys_addr();
        let end_frame: PhysFrame<Size2MiB> = PhysFrame::containing_address(max_phys - 1u64);

        let size = max_phys.as_u64();
        let alignment = Size2MiB::SIZE;
        let offset = mapping_addr(mapping, size, alignment, &mut used_entries)
            .expect("start address for physical memory mapping must be 2MiB-page-aligned");

        for frame in PhysFrame::range_inclusive(start_frame, end_frame) {
            let page = Page::containing_address(offset + frame.start_address().as_u64());
            let flags =
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
            match unsafe { kernel_page_table.map_to(page, frame, flags, frame_allocator) } {
                Ok(tlb) => tlb.ignore(),
                Err(err) => panic!(
                    "failed to map page {:?} to frame {:?}: {:?}",
                    page, frame, err
                ),
            };
        }

        Some(offset)
    } else {
        None
    };

    let recursive_index = if let Some(mapping) = config.mappings.page_table_recursive {
        log::info!("Map page table recursively");
        let index = match mapping {
            Mapping::Dynamic => used_entries.get_free_entries(1),
            Mapping::FixedAddress(offset) => {
                let offset = VirtAddr::new(offset);
                let table_level = PageTableLevel::Four;
                if !offset.is_aligned(table_level.entry_address_space_alignment()) {
                    panic!(
                        "Offset for recursive mapping must be properly aligned (must be \
                        a multiple of {:#x})",
                        table_level.entry_address_space_alignment()
                    );
                }

                offset.p4_index()
            }
        };

        let entry = &mut kernel_page_table.level_4_table_mut()[index];
        if !entry.is_unused() {
            panic!(
                "Could not set up recursive mapping: index {} already in use",
                u16::from(index)
            );
        }
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        entry.set_frame(page_tables.kernel_level_4_frame, flags);

        Some(index)
    } else {
        None
    };

    Mappings {
        framebuffer: framebuffer_virt_addr,
        entry_point,
        stack_bottom: stack_start.start_address(),
        // Use the configured stack size, even if it's not page-aligned. However, we
        // need to align it down to the next 16-byte boundary because the System V
        // ABI requires a 16-byte stack alignment.
        stack_top: stack_end_addr.align_down(16u8),
        used_entries,
        physical_memory_offset,
        recursive_index,
        tls_template,

        kernel_slice_start,
        kernel_slice_len,
        kernel_image_offset,

        ramdisk_slice_phys_start,
        ramdisk_slice_start,
        ramdisk_slice_len,
    }
}

/// Contains the addresses of all memory mappings set up by [`set_up_mappings`].
pub struct Mappings {
    /// The entry point address of the kernel.
    pub entry_point: VirtAddr,
    pub stack_bottom: VirtAddr,
    /// The (exclusive) end address of the kernel stack.
    pub stack_top: VirtAddr,
    /// Keeps track of used entries in the level 4 page table, useful for finding a free
    /// virtual memory when needed.
    pub used_entries: UsedLevel4Entries,
    /// The start address of the framebuffer, if any.
    pub framebuffer: Option<VirtAddr>,
    /// The start address of the physical memory mapping, if enabled.
    pub physical_memory_offset: Option<VirtAddr>,
    /// The level 4 page table index of the recursive mapping, if enabled.
    pub recursive_index: Option<PageTableIndex>,
    /// The thread local storage template of the kernel executable, if it contains one.
    pub tls_template: Option<TlsTemplate>,

    /// Start address of the kernel slice allocation in memory.
    pub kernel_slice_start: PhysAddr,
    /// Size of the kernel slice allocation in memory.
    pub kernel_slice_len: u64,
    /// Relocation offset of the kernel image in virtual memory.
    pub kernel_image_offset: VirtAddr,
    pub ramdisk_slice_phys_start: Option<PhysAddr>,
    pub ramdisk_slice_start: Option<VirtAddr>,
    pub ramdisk_slice_len: u64,
}

/// Allocates and initializes the boot info struct and the memory map.
///
/// The boot info and memory map are mapped to both the kernel and bootloader
/// address space at the same address. This makes it possible to return a Rust
/// reference that is valid in both address spaces. The necessary physical frames
/// are taken from the given `frame_allocator`.
pub fn create_boot_info<I, D>(
    config: &BootloaderConfig,
    boot_config: &BootConfig,
    mut frame_allocator: LegacyFrameAllocator<I, D>,
    page_tables: &mut PageTables,
    mappings: &mut Mappings,
    system_info: SystemInfo,
    loader_receipt: bootloader_api::info::LoaderHandoffVerification,
) -> &'static mut BootInfo
where
    I: ExactSizeIterator<Item = D> + Clone,
    D: LegacyMemoryRegion,
{
    log::info!("Allocate bootinfo");

    // allocate and map space for the boot info
    let (boot_info, memory_regions) = {
        let boot_info_layout = Layout::new::<BootInfo>();
        let regions = frame_allocator.memory_map_max_region_count();
        let memory_regions_layout = Layout::array::<MemoryRegion>(regions).unwrap();
        let (combined, memory_regions_offset) =
            boot_info_layout.extend(memory_regions_layout).unwrap();

        let boot_info_addr = mapping_addr(
            config.mappings.boot_info,
            u64::from_usize(combined.size()),
            u64::from_usize(combined.align()),
            &mut mappings.used_entries,
        )
        .expect("boot info addr is not properly aligned");

        let memory_map_regions_addr = boot_info_addr + memory_regions_offset as u64;
        let memory_map_regions_end = boot_info_addr + combined.size() as u64;

        let start_page = Page::containing_address(boot_info_addr);
        let end_page = Page::containing_address(memory_map_regions_end - 1u64);
        for page in Page::range_inclusive(start_page, end_page) {
            let flags =
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
            let frame = frame_allocator
                .allocate_frame()
                .expect("frame allocation for boot info failed");
            match unsafe {
                page_tables
                    .kernel
                    .map_to(page, frame, flags, &mut frame_allocator)
            } {
                Ok(tlb) => tlb.flush(),
                Err(err) => panic!("failed to map page {:?}: {:?}", page, err),
            }
            // we need to be able to access it too
            match unsafe {
                page_tables
                    .bootloader
                    .map_to(page, frame, flags, &mut frame_allocator)
            } {
                Ok(tlb) => tlb.flush(),
                Err(err) => panic!("failed to map page {:?}: {:?}", page, err),
            }
        }

        let boot_info: &'static mut MaybeUninit<BootInfo> =
            unsafe { &mut *boot_info_addr.as_mut_ptr() };
        let memory_regions: &'static mut [MaybeUninit<MemoryRegion>] =
            unsafe { slice::from_raw_parts_mut(memory_map_regions_addr.as_mut_ptr(), regions) };
        (boot_info, memory_regions)
    };

    log::info!("Create Memory Map");

    // build memory map
    let memory_regions = frame_allocator.construct_memory_map(
        memory_regions,
        mappings.kernel_slice_start,
        mappings.kernel_slice_len,
        mappings.ramdisk_slice_phys_start,
        mappings.ramdisk_slice_len,
    );

    log::info!("Create bootinfo");

    // create boot info
    boot_info.write({
        let mut info = BootInfo::new(memory_regions.into());
        info.framebuffer = mappings
            .framebuffer
            .map(|addr| unsafe {
                FrameBuffer::new(
                    addr.as_u64(),
                    system_info
                        .framebuffer
                        .expect(
                            "there shouldn't be a mapping for the framebuffer if there is \
                            no framebuffer",
                        )
                        .info,
                )
            })
            .into();
        info.physical_memory_offset = mappings.physical_memory_offset.map(VirtAddr::as_u64).into();
        info.recursive_index = mappings.recursive_index.map(Into::into).into();
        info.rsdp_addr = system_info.rsdp_addr.map(|addr| addr.as_u64()).into();
        info.tls_template = mappings.tls_template.into();
        info.ramdisk_addr = mappings
            .ramdisk_slice_start
            .map(|addr| addr.as_u64())
            .into();
        info.ramdisk_len = mappings.ramdisk_slice_len;
        info.kernel_addr = mappings.kernel_slice_start.as_u64();
        info.kernel_len = mappings.kernel_slice_len as _;
        info.kernel_image_offset = mappings.kernel_image_offset.as_u64();
        info.kernel_stack_bottom = mappings.stack_bottom.as_u64();
        info.kernel_stack_len = config.kernel_stack_size;
        info._test_sentinel = boot_config._test_sentinel;
        info.loader_handoff = Some(loader_receipt).into();
        info
    })
}

/// Switches to the kernel address space and jumps to the kernel entry point.
pub fn switch_to_kernel(
    page_tables: PageTables,
    mappings: Mappings,
    boot_info: &'static mut BootInfo,
) -> ! {
    let PageTables {
        kernel_level_4_frame,
        ..
    } = page_tables;
    let addresses = Addresses {
        page_table: kernel_level_4_frame,
        stack_top: mappings.stack_top,
        entry_point: mappings.entry_point,
        boot_info,
    };

    log::info!(
        "Jumping to kernel entry point at {:?}",
        addresses.entry_point
    );

    unsafe {
        context_switch(addresses);
    }
}

/// Provides access to the page tables of the bootloader and kernel address space.
pub struct PageTables {
    /// Provides access to the page tables of the bootloader address space.
    pub bootloader: OffsetPageTable<'static>,
    /// Provides access to the page tables of the kernel address space (not active).
    pub kernel: OffsetPageTable<'static>,
    /// The physical frame where the level 4 page table of the kernel address space is stored.
    ///
    /// Must be the page table that the `kernel` field of this struct refers to.
    ///
    /// This frame is loaded into the `CR3` register on the final context switch to the kernel.
    pub kernel_level_4_frame: PhysFrame,
}

/// Performs the actual context switch.
unsafe fn context_switch(addresses: Addresses) -> ! {
    unsafe {
        asm!(
            r#"
            xor rbp, rbp
            mov cr3, {}
            mov rsp, {}
            push 0
            jmp {}
            "#,
            in(reg) addresses.page_table.start_address().as_u64(),
            in(reg) addresses.stack_top.as_u64(),
            in(reg) addresses.entry_point.as_u64(),
            in("rdi") addresses.boot_info as *const _ as usize,
        );
    }
    unreachable!();
}

/// Memory addresses required for the context switch.
struct Addresses {
    page_table: PhysFrame,
    stack_top: VirtAddr,
    entry_point: VirtAddr,
    boot_info: &'static mut BootInfo,
}

fn mapping_addr_page_aligned(
    mapping: Mapping,
    size: u64,
    used_entries: &mut UsedLevel4Entries,
    kind: &str,
) -> Page {
    match mapping_addr(mapping, size, Size4KiB::SIZE, used_entries) {
        Ok(addr) => Page::from_start_address(addr).unwrap(),
        Err(addr) => panic!("{kind} address must be page-aligned (is `{addr:?})`"),
    }
}

fn mapping_addr(
    mapping: Mapping,
    size: u64,
    alignment: u64,
    used_entries: &mut UsedLevel4Entries,
) -> Result<VirtAddr, VirtAddr> {
    let addr = match mapping {
        Mapping::FixedAddress(addr) => VirtAddr::new(addr),
        Mapping::Dynamic => used_entries.get_free_address(size, alignment),
    };
    if addr.is_aligned(alignment) {
        Ok(addr)
    } else {
        Err(addr)
    }
}

fn enable_nxe_bit() {
    use x86_64::registers::control::{Efer, EferFlags};
    unsafe { Efer::update(|efer| *efer |= EferFlags::NO_EXECUTE_ENABLE) }
}

fn enable_write_protect_bit() {
    use x86_64::registers::control::{Cr0, Cr0Flags};
    unsafe { Cr0::update(|cr0| *cr0 |= Cr0Flags::WRITE_PROTECT) };
}
