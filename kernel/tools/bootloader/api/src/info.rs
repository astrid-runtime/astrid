use core::{ops, slice};

use crate::config::ApiVersion;

/// This structure represents the information that the bootloader passes to the kernel.
///
/// The information is passed as an argument to the entry point. The entry point function must
/// have the following signature:
///
/// ```
/// # use bootloader_api::BootInfo;
/// # type _SIGNATURE =
/// extern "C" fn(boot_info: &'static mut BootInfo) -> !;
/// ```
///
/// Note that no type checking occurs for the entry point function, so be careful to
/// use the correct argument types. To ensure that the entry point function has the correct
/// signature, use the [`entry_point`] macro.
#[derive(Debug)]
#[repr(C)]
#[non_exhaustive]
pub struct BootInfo {
    /// The version of the `bootloader_api` crate. Must match the `bootloader` version.
    pub api_version: ApiVersion,
    /// A map of the physical memory regions of the underlying machine.
    ///
    /// The bootloader queries this information from the BIOS/UEFI firmware and translates this
    /// information to Rust types. It also marks any memory regions that the bootloader uses in
    /// the memory map before passing it to the kernel. Regions marked as usable can be freely
    /// used by the kernel.
    pub memory_regions: MemoryRegions,
    /// Information about the framebuffer for screen output if available.
    pub framebuffer: Optional<FrameBuffer>,
    /// The virtual address at which the mapping of the physical memory starts.
    ///
    /// Physical addresses can be converted to virtual addresses by adding this offset to them.
    ///
    /// The mapping of the physical memory allows to access arbitrary physical frames. Accessing
    /// frames that are also mapped at other virtual addresses can easily break memory safety and
    /// cause undefined behavior. Only frames reported as `USABLE` by the memory map in the `BootInfo`
    /// can be safely accessed.
    ///
    /// Only available if the `map-physical-memory` config option is enabled.
    pub physical_memory_offset: Optional<u64>,
    /// The virtual address of the recursively mapped level 4 page table.
    ///
    /// Only available if the `map-page-table-recursively` config option is enabled.
    pub recursive_index: Optional<u16>,
    /// The address of the `RSDP` data structure, which can be use to find the ACPI tables.
    ///
    /// This field is `None` if no `RSDP` was found (for BIOS) or reported (for UEFI).
    pub rsdp_addr: Optional<u64>,
    /// The thread local storage (TLS) template of the kernel executable, if present.
    pub tls_template: Optional<TlsTemplate>,
    /// Ramdisk address, if loaded
    pub ramdisk_addr: Optional<u64>,
    /// Ramdisk image size, set to 0 if addr is None
    pub ramdisk_len: u64,
    /// Physical address of the kernel ELF in memory.
    pub kernel_addr: u64,
    /// Size of the kernel ELF in memory.
    pub kernel_len: u64,
    /// Virtual address of the loaded kernel image.
    pub kernel_image_offset: u64,
    /// Virtual address of the kernel stack bottom.
    pub kernel_stack_bottom: u64,
    /// Size of the kernel stack
    pub kernel_stack_len: u64,

    #[doc(hidden)]
    pub _test_sentinel: u64,
    /// Astrid's fixture-only pre-relocation policy-handoff evidence.
    ///
    /// This receipt is evidence, not a standalone authority. A kernel must
    /// still verify the signed handoff and closure table against its external
    /// root verifier before accepting it.
    #[doc(hidden)]
    pub loader_handoff: Optional<LoaderHandoffVerification>,
}

impl BootInfo {
    /// Create a new boot info structure with the given memory map.
    ///
    /// The other fields are initialized with default values.
    pub fn new(memory_regions: MemoryRegions) -> Self {
        Self {
            api_version: ApiVersion::new_default(),
            memory_regions,
            framebuffer: Optional::None,
            physical_memory_offset: Optional::None,
            recursive_index: Optional::None,
            rsdp_addr: Optional::None,
            tls_template: Optional::None,
            ramdisk_addr: Optional::None,
            ramdisk_len: 0,
            kernel_addr: 0,
            kernel_len: 0,
            kernel_image_offset: 0,
            kernel_stack_bottom: 0,
            kernel_stack_len: 0,
            _test_sentinel: 0,
            loader_handoff: Optional::None,
        }
    }
}

/// Fixed-size evidence that the UEFI fixture verified a policy handoff before
/// mapping writable PT_LOAD pages or applying relocations.
///
/// The fields are copied into [`BootInfo`] by the local Astrid bootloader
/// vendor. They contain no private keys and do not replace signature checking;
/// the kernel must bind the receipt to the copied signed envelope and table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LoaderHandoffVerification {
    /// Domain-separated receipt marker (`ASTRIDLV`).
    pub magic: [u8; 8],
    /// Receipt encoding version.
    pub version: u8,
    /// `1` means the pre-relocation check completed successfully.
    pub status: u8,
    /// Reserved bytes; must be zero for this version.
    pub reserved: [u8; 6],
    /// Digest of the exact signed ASTRIDPH envelope.
    pub envelope_digest: [u8; 32],
    /// Digest of the raw kernel ELF bytes before loader mapping.
    pub kernel_image: [u8; 32],
    /// Digest of the exact ASTRIDDC table bytes.
    pub closure_table: [u8; 32],
    /// Signed loader-measurement binding.
    pub loader_measurement: [u8; 32],
    /// Signed loader-identity binding.
    pub loader_identity: [u8; 32],
    /// Signed boot-context binding.
    pub boot_context: [u8; 32],
    /// Informational root verification key copied from the envelope.
    pub root_verify: [u8; 32],
    /// Root-authorized kernel verification key.
    pub kernel_verify: [u8; 32],
    /// Root-authorized System Generation verification key.
    pub sysgen_verify: [u8; 32],
    /// Root-authorized policy generation.
    pub policy_generation: u64,
    /// Independent kernel rollback floor.
    pub kernel_floor: u64,
    /// Independent System Generation rollback floor.
    pub sysgen_floor: u64,
}

/// FFI-safe slice of [`MemoryRegion`] structs, semantically equivalent to
/// `&'static mut [MemoryRegion]`.
///
/// This type implements the [`Deref`][core::ops::Deref] and [`DerefMut`][core::ops::DerefMut]
/// traits, so it can be used like a `&mut [MemoryRegion]` slice. It also implements [`From`]
/// and [`Into`] for easy conversions from and to `&'static mut [MemoryRegion]`.
#[derive(Debug)]
#[repr(C)]
pub struct MemoryRegions {
    pub(crate) ptr: *mut MemoryRegion,
    pub(crate) len: usize,
}

impl ops::Deref for MemoryRegions {
    type Target = [MemoryRegion];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl ops::DerefMut for MemoryRegions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl From<&'static mut [MemoryRegion]> for MemoryRegions {
    fn from(regions: &'static mut [MemoryRegion]) -> Self {
        MemoryRegions {
            ptr: regions.as_mut_ptr(),
            len: regions.len(),
        }
    }
}

impl From<MemoryRegions> for &'static mut [MemoryRegion] {
    fn from(regions: MemoryRegions) -> &'static mut [MemoryRegion] {
        unsafe { slice::from_raw_parts_mut(regions.ptr, regions.len) }
    }
}

unsafe impl Send for MemoryRegions {}
unsafe impl Sync for MemoryRegions {}

/// Represent a physical memory region.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryRegion {
    /// The physical start address of the region.
    pub start: u64,
    /// The physical end address (exclusive) of the region.
    pub end: u64,
    /// The memory type of the memory region.
    ///
    /// Only [`Usable`][MemoryRegionKind::Usable] regions can be freely used.
    pub kind: MemoryRegionKind,
}

impl MemoryRegion {
    /// Creates a new empty memory region (with length 0).
    pub const fn empty() -> Self {
        MemoryRegion {
            start: 0,
            end: 0,
            kind: MemoryRegionKind::Bootloader,
        }
    }
}

/// Represents the different types of memory.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
#[repr(C)]
pub enum MemoryRegionKind {
    /// Unused conventional memory, can be used by the kernel.
    Usable,
    /// Memory mappings created by the bootloader, including the page table and boot info mappings.
    ///
    /// This memory should _not_ be used by the kernel.
    Bootloader,
    /// An unknown memory region reported by the UEFI firmware.
    ///
    /// Contains the UEFI memory type tag.
    UnknownUefi(u32),
    /// An unknown memory region reported by the BIOS firmware.
    ///
    /// Contains the E820 memory type.
    UnknownBios(u32),
}

/// A pixel-based framebuffer that controls the screen output.
#[derive(Debug)]
#[repr(C)]
pub struct FrameBuffer {
    pub(crate) buffer_start: u64,
    pub(crate) info: FrameBufferInfo,
}

impl FrameBuffer {
    /// Creates a new framebuffer instance.
    ///
    /// ## Safety
    ///
    /// The given start address and info must describe a valid, accessible, and unaliased
    /// framebuffer.
    pub unsafe fn new(buffer_start: u64, info: FrameBufferInfo) -> Self {
        Self { buffer_start, info }
    }

    /// Returns the raw bytes of the framebuffer as slice.
    pub fn buffer(&self) -> &[u8] {
        unsafe { self.create_buffer() }
    }

    /// Returns the raw bytes of the framebuffer as mutable slice.
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        unsafe { self.create_buffer_mut() }
    }

    /// Converts the frame buffer to a raw byte slice.
    ///
    /// The same as `buffer_mut()` but takes the ownership and returns the
    /// mutable buffer with a `'static` lifetime.
    pub fn into_buffer(self) -> &'static mut [u8] {
        unsafe { self.create_buffer_mut() }
    }

    unsafe fn create_buffer<'a>(&self) -> &'a [u8] {
        unsafe { slice::from_raw_parts(self.buffer_start as *const u8, self.info.byte_len) }
    }

    unsafe fn create_buffer_mut<'a>(&self) -> &'a mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.buffer_start as *mut u8, self.info.byte_len) }
    }

    /// Returns layout and pixel format information of the framebuffer.
    pub fn info(&self) -> FrameBufferInfo {
        self.info
    }
}

/// Describes the layout and pixel format of a framebuffer.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FrameBufferInfo {
    /// The total size in bytes.
    pub byte_len: usize,
    /// The width in pixels.
    pub width: usize,
    /// The height in pixels.
    pub height: usize,
    /// The color format of each pixel.
    pub pixel_format: PixelFormat,
    /// The number of bytes per pixel.
    pub bytes_per_pixel: usize,
    /// Number of pixels between the start of a line and the start of the next.
    ///
    /// Some framebuffers use additional padding at the end of a line, so this
    /// value might be larger than `horizontal_resolution`. It is
    /// therefore recommended to use this field for calculating the start address of a line.
    pub stride: usize,
}

/// Color format of pixels in the framebuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(C)]
pub enum PixelFormat {
    /// One byte red, then one byte green, then one byte blue.
    ///
    /// Length might be larger than 3, check [`bytes_per_pixel`][FrameBufferInfo::bytes_per_pixel]
    /// for this.
    Rgb,
    /// One byte blue, then one byte green, then one byte red.
    ///
    /// Length might be larger than 3, check [`bytes_per_pixel`][FrameBufferInfo::bytes_per_pixel]
    /// for this.
    Bgr,
    /// A single byte, representing the grayscale value.
    ///
    /// Length might be larger than 1, check [`bytes_per_pixel`][FrameBufferInfo::bytes_per_pixel]
    /// for this.
    U8,
    /// Unknown pixel format.
    Unknown {
        /// Bit offset of the red value.
        red_position: u8,
        /// Bit offset of the green value.
        green_position: u8,
        /// Bit offset of the blue value.
        blue_position: u8,
    },
}

/// Information about the thread local storage (TLS) template.
///
/// This template can be used to set up thread local storage for threads. For
/// each thread, a new memory location of size `mem_size` must be initialized.
/// Then the first `file_size` bytes of this template needs to be copied to the
/// location. The additional `mem_size - file_size` bytes must be initialized with
/// zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TlsTemplate {
    /// The virtual start address of the thread local storage template.
    pub start_addr: u64,
    /// The number of data bytes in the template.
    ///
    /// Corresponds to the length of the `.tdata` section.
    pub file_size: u64,
    /// The total number of bytes that the TLS segment should have in memory.
    ///
    /// Corresponds to the combined length of the `.tdata` and `.tbss` sections.
    pub mem_size: u64,
}

/// FFI-safe variant of [`Option`].
///
/// Implements the [`From`] and [`Into`] traits for easy conversion to and from [`Option`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub enum Optional<T> {
    /// Some value `T`
    Some(T),
    /// No value
    None,
}

impl<T> Optional<T> {
    /// Converts the `Optional` to an [`Option`].
    pub fn into_option(self) -> Option<T> {
        self.into()
    }

    /// Converts from `&Optional<T>` to `Option<&T>`.
    ///
    /// For convenience, this method directly performs the conversion to the standard
    /// [`Option`] type.
    pub const fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Some(x) => Some(x),
            Self::None => None,
        }
    }

    /// Converts from `&mut Optional<T>` to `Option<&mut T>`.
    ///
    /// For convenience, this method directly performs the conversion to the standard
    /// [`Option`] type.
    pub fn as_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Some(x) => Some(x),
            Self::None => None,
        }
    }

    /// Takes the value out of the `Optional`, leaving a `None` in its place.
    pub fn take(&mut self) -> Option<T> {
        core::mem::replace(self, Optional::None).into_option()
    }
}

impl<T> From<Option<T>> for Optional<T> {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(v) => Optional::Some(v),
            None => Optional::None,
        }
    }
}

impl<T> From<Optional<T>> for Option<T> {
    fn from(optional: Optional<T>) -> Option<T> {
        match optional {
            Optional::Some(v) => Some(v),
            Optional::None => None,
        }
    }
}

/// Check that bootinfo is FFI-safe
extern "C" fn _assert_ffi(_boot_info: BootInfo) {}
