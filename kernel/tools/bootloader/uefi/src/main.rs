#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use crate::memory_descriptor::UefiMemoryDescriptor;
use bootloader_api::info::FrameBufferInfo;
use bootloader_boot_config::BootConfig;
use bootloader_x86_64_common::{
    Kernel, RawFrameBufferInfo, SystemInfo, legacy_memory_region::LegacyFrameAllocator,
};
use core::net::Ipv4Addr;
use core::{ptr, slice};
use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use uefi::table::cfg::ConfigTableEntry;
use uefi::{
    CStr8, CStr16, boot,
    boot::{AllocateType, MemoryType},
    cstr8, cstr16,
    prelude::{Status, entry},
    proto::{
        ProtocolPointer,
        console::gop::{GraphicsOutput, PixelFormat},
        device_path::DevicePath,
        loaded_image::LoadedImage,
        media::file::{File, FileAttribute, FileInfo, FileMode},
        network::pxe::{BaseCode, DhcpV4Packet},
    },
};
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB},
};

mod memory_descriptor;

struct BootFile {
    disk: &'static CStr16,
    tftp: &'static CStr8,
}

const KERNEL_FILE: BootFile = BootFile {
    disk: cstr16!("kernel-x86_64"),
    tftp: cstr8!("kernel-x86_64"),
};
const CONFIG_FILE: BootFile = BootFile {
    disk: cstr16!("boot.json"),
    tftp: cstr8!("boot.json"),
};
const RAMDISK_FILE: BootFile = BootFile {
    disk: cstr16!("ramdisk"),
    tftp: cstr8!("ramdisk"),
};

#[entry]
fn main() -> Status {
    let mut boot_mode = BootMode::Disk;

    let mut kernel = load_kernel(boot_mode);
    if kernel.is_none() {
        // Try TFTP boot
        boot_mode = BootMode::Tftp;
        kernel = load_kernel(boot_mode);
    }
    let kernel = kernel.expect("Failed to load kernel");

    let config_file = load_config_file(boot_mode);
    let mut error_loading_config: Option<serde_json_core::de::Error> = None;
    let mut config: BootConfig = match config_file
        .as_deref()
        .map(serde_json_core::from_slice)
        .transpose()
    {
        Ok(data) => data.unwrap_or_default().0,
        Err(err) => {
            error_loading_config = Some(err);
            Default::default()
        }
    };

    #[allow(deprecated)]
    if config.frame_buffer.minimum_framebuffer_height.is_none() {
        config.frame_buffer.minimum_framebuffer_height =
            kernel.config.frame_buffer.minimum_framebuffer_height;
    }
    #[allow(deprecated)]
    if config.frame_buffer.minimum_framebuffer_width.is_none() {
        config.frame_buffer.minimum_framebuffer_width =
            kernel.config.frame_buffer.minimum_framebuffer_width;
    }
    let framebuffer = init_logger(&config);

    log::info!("UEFI bootloader started");

    if let Some(framebuffer) = framebuffer {
        log::info!("Using framebuffer at {:#x}", framebuffer.addr);
    }

    if let Some(err) = error_loading_config {
        log::warn!("Failed to deserialize the config file {:?}", err);
    } else {
        log::info!("Reading configuration from disk was successful");
    }

    log::info!("Trying to load ramdisk via {:?}", boot_mode);
    // Ramdisk must load from same source, or not at all.
    let ramdisk = load_ramdisk(boot_mode);

    log::info!(
        "{}",
        match ramdisk {
            Some(_) => "Loaded ramdisk",
            None => "Ramdisk not found.",
        }
    );

    log::trace!("exiting boot services");
    let mut memory_map = unsafe { boot::exit_boot_services(None) };

    memory_map.sort();

    let mut frame_allocator =
        LegacyFrameAllocator::new(memory_map.entries().copied().map(UefiMemoryDescriptor));

    let max_phys_addr = frame_allocator.max_phys_addr();
    let page_tables = create_page_tables(&mut frame_allocator, max_phys_addr, framebuffer.as_ref());
    let ramdisk_bytes = ramdisk.map(|rd| {
        // `load_ramdisk` returns loader-owned static storage. Reborrow it as
        // immutable bytes before handing the original backing to the common
        // loader; this keeps the pre-relocation verification view stable.
        let rd: &'static mut [u8] = rd;
        &*rd
    });
    let ramdisk_len = ramdisk_bytes.map_or(0, |rd| rd.len() as u64);
    let ramdisk_addr = ramdisk_bytes.map(|rd| rd.as_ptr() as usize as u64);
    let system_info = SystemInfo {
        framebuffer,
        rsdp_addr: {
            uefi::system::with_config_table(|config_entries| {
                // look for an ACPI2 RSDP first
                let acpi2_rsdp = config_entries
                    .iter()
                    .find(|entry| matches!(entry.guid, ConfigTableEntry::ACPI2_GUID));
                // if no ACPI2 RSDP is found, look for a ACPI1 RSDP
                let rsdp = acpi2_rsdp.or_else(|| {
                    config_entries
                        .iter()
                        .find(|entry| matches!(entry.guid, ConfigTableEntry::ACPI_GUID))
                });
                rsdp.map(|entry| PhysAddr::new(entry.address as u64))
            })
        },
        ramdisk_addr,
        ramdisk_len,
        ramdisk_bytes,
    };

    bootloader_x86_64_common::load_and_switch_to_kernel(
        kernel,
        config,
        frame_allocator,
        page_tables,
        system_info,
    );
}

#[derive(Clone, Copy, Debug)]
pub enum BootMode {
    Disk,
    Tftp,
}

fn load_ramdisk(boot_mode: BootMode) -> Option<&'static mut [u8]> {
    load_file_from_boot_method(&RAMDISK_FILE, boot_mode)
}

fn load_config_file(boot_mode: BootMode) -> Option<&'static mut [u8]> {
    load_file_from_boot_method(&CONFIG_FILE, boot_mode)
}

fn load_kernel(boot_mode: BootMode) -> Option<Kernel<'static>> {
    let kernel_slice = load_file_from_boot_method(&KERNEL_FILE, boot_mode)?;
    Some(Kernel::parse(kernel_slice))
}

fn load_file_from_boot_method(
    filename: &BootFile,
    boot_mode: BootMode,
) -> Option<&'static mut [u8]> {
    match boot_mode {
        BootMode::Disk => load_file_from_disk(filename.disk),
        BootMode::Tftp => load_file_from_tftp_boot_server(filename.tftp),
    }
}

fn load_file_from_disk(name: &CStr16) -> Option<&'static mut [u8]> {
    let mut file_system = boot::get_image_file_system(boot::image_handle()).ok()?;

    let mut root = file_system.open_volume().unwrap();
    let file_handle_result = root.open(name, FileMode::Read, FileAttribute::empty());
    let file_handle = file_handle_result.ok()?;

    let mut file = match file_handle.into_type().unwrap() {
        uefi::proto::media::file::FileType::Regular(f) => f,
        uefi::proto::media::file::FileType::Dir(_) => panic!(),
    };

    let mut buf = [0; 500];
    let file_info: &mut FileInfo = file.get_info(&mut buf).unwrap();
    let file_size = usize::try_from(file_info.file_size()).unwrap();

    let file_slice = allocate_loader_data(file_size);
    file.read(file_slice).unwrap();

    Some(file_slice)
}

/// Try to load a kernel from a TFTP boot server.
fn load_file_from_tftp_boot_server(name: &CStr8) -> Option<&'static mut [u8]> {
    let mut base_code = open_pxe_base_code()?;

    // Find the TFTP boot server.
    let mode = base_code.mode();
    let dhcpv4: &DhcpV4Packet = mode.dhcp_ack().as_ref();
    let server_ip = Ipv4Addr::from_octets(dhcpv4.bootp_si_addr);

    // Determine the kernel file size.
    let file_size = base_code.tftp_get_file_size(&server_ip.into(), name).ok()?;
    let kernel_size = usize::try_from(file_size).expect("The file size should fit into usize");

    // Allocate some memory for the kernel file.
    let slice = allocate_loader_data(kernel_size);

    // Load the kernel file.
    base_code
        .tftp_read_file(&server_ip.into(), name, Some(slice))
        .expect("Failed to read kernel file from the TFTP boot server");

    Some(slice)
}

fn allocate_loader_data(size: usize) -> &'static mut [u8] {
    let mut ptr = boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        ((size - 1) / 4096) + 1,
    )
    .expect("Failed to allocate memory for the file");
    unsafe { ptr::write_bytes(ptr.as_ptr(), 0, size) };
    unsafe { slice::from_raw_parts_mut(ptr.as_ptr(), size) }
}

/// Opens PXE Base Code for the device path that loaded this image.
///
/// Firmware may expose multiple PXE handles. Resolving through the loaded
/// image's device path keeps TFTP reads tied to the booting network device.
fn open_pxe_base_code() -> Option<boot::ScopedProtocol<BaseCode>> {
    let base_code = locate_and_open_protocol_from_image_device_path::<BaseCode>()?;
    base_code.mode().dhcp_ack_received().then_some(base_code)
}

fn locate_and_open_protocol_from_image_device_path<P: ProtocolPointer + ?Sized>()
-> Option<boot::ScopedProtocol<P>> {
    let image_handle = boot::image_handle();
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(image_handle).ok()?;
    let device_handle = loaded_image.device()?;
    let device_path = boot::open_protocol_exclusive::<DevicePath>(device_handle).ok()?;
    let handle = boot::locate_device_path::<P>(&mut &*device_path).ok()?;
    boot::open_protocol_exclusive::<P>(handle).ok()
}

/// Creates page table abstraction types for both the bootloader and kernel page tables.
fn create_page_tables(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    max_phys_addr: PhysAddr,
    frame_buffer: Option<&RawFrameBufferInfo>,
) -> bootloader_x86_64_common::PageTables {
    // UEFI identity-maps all memory, so the offset between physical and virtual addresses is 0
    let phys_offset = VirtAddr::new(0);

    // copy the currently active level 4 page table, because it might be read-only
    log::trace!("switching to new level 4 table");
    let bootloader_page_table = {
        let old_table = {
            let frame = x86_64::registers::control::Cr3::read().0;
            let ptr: *const PageTable = (phys_offset + frame.start_address().as_u64()).as_ptr();
            unsafe { &*ptr }
        };
        let new_frame = frame_allocator
            .allocate_frame()
            .expect("Failed to allocate frame for new level 4 table");
        let new_table: &mut PageTable = {
            let ptr: *mut PageTable =
                (phys_offset + new_frame.start_address().as_u64()).as_mut_ptr();
            // create a new, empty page table
            unsafe {
                ptr.write(PageTable::new());
                &mut *ptr
            }
        };

        // copy the pml4 entries for all identity mapped memory.
        let end_addr = VirtAddr::new(max_phys_addr.as_u64() - 1);
        for p4 in 0..=usize::from(end_addr.p4_index()) {
            new_table[p4] = old_table[p4].clone();
        }

        // copy the pml4 entry for the frame buffer (the frame buffer is not
        // necessarily part of the identity mapping).
        if let Some(frame_buffer) = frame_buffer {
            let start_addr = VirtAddr::new(frame_buffer.addr.as_u64());
            let end_addr = start_addr + frame_buffer.info.byte_len as u64;
            for p4 in usize::from(start_addr.p4_index())..=usize::from(end_addr.p4_index()) {
                new_table[p4] = old_table[p4].clone();
            }
        }

        // the first level 4 table entry is now identical, so we can just load the new one
        unsafe {
            x86_64::registers::control::Cr3::write(
                new_frame,
                x86_64::registers::control::Cr3Flags::empty(),
            );
            OffsetPageTable::new(&mut *new_table, phys_offset)
        }
    };

    // create a new page table hierarchy for the kernel
    let (kernel_page_table, kernel_level_4_frame) = {
        // get an unused frame for new level 4 page table
        let frame: PhysFrame = frame_allocator.allocate_frame().expect("no unused frames");
        log::info!("New page table at: {:#?}", &frame);
        // get the corresponding virtual address
        let addr = phys_offset + frame.start_address().as_u64();
        // initialize a new page table
        let ptr = addr.as_mut_ptr();
        unsafe { *ptr = PageTable::new() };
        let level_4_table = unsafe { &mut *ptr };
        (
            unsafe { OffsetPageTable::new(level_4_table, phys_offset) },
            frame,
        )
    };

    bootloader_x86_64_common::PageTables {
        bootloader: bootloader_page_table,
        kernel: kernel_page_table,
        kernel_level_4_frame,
    }
}

fn init_logger(config: &BootConfig) -> Option<RawFrameBufferInfo> {
    let gop_handle = boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
    let mut gop = boot::open_protocol_exclusive::<GraphicsOutput>(gop_handle).ok()?;

    let mode = {
        let modes = gop.modes();
        match (
            config
                .frame_buffer
                .minimum_framebuffer_height
                .map(|v| usize::try_from(v).unwrap()),
            config
                .frame_buffer
                .minimum_framebuffer_width
                .map(|v| usize::try_from(v).unwrap()),
        ) {
            (Some(height), Some(width)) => modes
                .filter(|m| {
                    let res = m.info().resolution();
                    res.1 >= height && res.0 >= width
                })
                .last(),
            (Some(height), None) => modes.filter(|m| m.info().resolution().1 >= height).last(),
            (None, Some(width)) => modes.filter(|m| m.info().resolution().0 >= width).last(),
            _ => None,
        }
    };
    if let Some(mode) = mode {
        gop.set_mode(&mode)
            .expect("Failed to apply the desired display mode");
    }

    let mode_info = gop.current_mode_info();
    let mut framebuffer = gop.frame_buffer();
    let slice = unsafe { slice::from_raw_parts_mut(framebuffer.as_mut_ptr(), framebuffer.size()) };
    let info = FrameBufferInfo {
        byte_len: framebuffer.size(),
        width: mode_info.resolution().0,
        height: mode_info.resolution().1,
        pixel_format: match mode_info.pixel_format() {
            PixelFormat::Rgb => bootloader_api::info::PixelFormat::Rgb,
            PixelFormat::Bgr => bootloader_api::info::PixelFormat::Bgr,
            PixelFormat::Bitmask | PixelFormat::BltOnly => {
                panic!("Bitmask and BltOnly framebuffers are not supported")
            }
        },
        bytes_per_pixel: 4,
        stride: mode_info.stride(),
    };

    bootloader_x86_64_common::init_logger(
        slice,
        info,
        config.log_level,
        config.frame_buffer_logging,
        config.serial_logging,
    );

    Some(RawFrameBufferInfo {
        addr: PhysAddr::new(framebuffer.as_mut_ptr() as u64),
        info,
    })
}

#[cfg(target_os = "uefi")]
fn uefi_stdout_available() -> bool {
    uefi::table::system_table_raw()
        .map(|st| {
            // SAFETY: The UEFI entry macro sets this pointer before calling
            // `main`, and `system_table_raw` only returns a non-null pointer.
            let st = unsafe { st.as_ref() };
            !st.boot_services.is_null() && !st.stdout.is_null()
        })
        .unwrap_or(false)
}

#[cfg(target_os = "uefi")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::arch::asm;
    use core::fmt::Write;

    if uefi_stdout_available() {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.clear();
            let _ = writeln!(stdout, "{}", info);
        });
    }

    unsafe {
        bootloader_x86_64_common::logger::LOGGER
            .get()
            .map(|l| l.force_unlock())
    };
    log::error!("{}", info);

    loop {
        unsafe { asm!("cli; hlt") };
    }
}
