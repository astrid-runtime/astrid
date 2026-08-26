use crate::{PAGE_SIZE, level_4_entries::UsedLevel4Entries};
use bootloader_api::{config::Mapping, info::TlsTemplate};
use core::{cmp, iter::Step, mem::size_of, ops::Add};

use x86_64::{
    PhysAddr, VirtAddr, align_up,
    structures::paging::{
        FrameAllocator, Page, PageSize, PageTableFlags as Flags, PhysFrame, Size4KiB, Translate,
        mapper::{MappedFrame, MapperAllSizes, TranslateResult},
    },
};
use xmas_elf::{
    ElfFile, dynamic, header,
    program::{self, ProgramHeader, SegmentData, Type},
    sections::Rela,
};

use super::Kernel;

/// Used by [`Inner::make_mut`] and [`Inner::clean_copied_flag`].
const COPIED: Flags = Flags::BIT_9;

struct Loader<'a, M, F> {
    elf_file: ElfFile<'a>,
    inner: Inner<'a, M, F>,
}

struct Inner<'a, M, F> {
    kernel_offset: PhysAddr,
    virtual_address_offset: VirtualAddressOffset,
    page_table: &'a mut M,
    frame_allocator: &'a mut F,
}

impl<'a, M, F> Loader<'a, M, F>
where
    M: MapperAllSizes + Translate,
    F: FrameAllocator<Size4KiB>,
{
    fn new(
        kernel: Kernel<'a>,
        page_table: &'a mut M,
        frame_allocator: &'a mut F,
        used_entries: &mut UsedLevel4Entries,
    ) -> Result<Self, &'static str> {
        log::info!("Elf file loaded at {:#p}", kernel.elf.input);
        let kernel_offset = PhysAddr::new(&kernel.elf.input[0] as *const u8 as u64);
        if !kernel_offset.is_aligned(PAGE_SIZE) {
            return Err("Loaded kernel ELF file is not sufficiently aligned");
        }

        let elf_file = kernel.elf;
        for program_header in elf_file.program_iter() {
            program::sanity_check(program_header, &elf_file)?;
        }

        let virtual_address_offset = match elf_file.header.pt2.type_().as_type() {
            header::Type::None => unimplemented!(),
            header::Type::Relocatable => unimplemented!(),
            header::Type::Executable => match kernel.config.mappings.kernel_base {
                Mapping::Dynamic => VirtualAddressOffset::zero(),
                _ => {
                    return Err(concat!(
                        "Invalid kernel_code mapping. ",
                        "Executable can only be mapped at virtual_address_offset 0."
                    ));
                }
            },
            header::Type::SharedObject => {
                let ElfMemoryRequirements {
                    size,
                    align,
                    min_addr,
                } = calc_elf_memory_requirements(&elf_file);
                match kernel.config.mappings.kernel_base {
                    Mapping::Dynamic => {
                        let offset = used_entries.get_free_address(size, align).as_u64();
                        VirtualAddressOffset::new(i128::from(offset) - i128::from(min_addr))
                    }
                    Mapping::FixedAddress(address) => {
                        VirtualAddressOffset::new(i128::from(address))
                    }
                }
            }
            header::Type::Core => unimplemented!(),
            header::Type::ProcessorSpecific(_) => unimplemented!(),
        };
        log::info!(
            "virtual_address_offset: {:#x}",
            virtual_address_offset.virtual_address_offset()
        );

        used_entries.mark_segments(elf_file.program_iter(), virtual_address_offset);

        header::sanity_check(&elf_file)?;
        let loader = Loader {
            elf_file,
            inner: Inner {
                kernel_offset,
                virtual_address_offset,
                page_table,
                frame_allocator,
            },
        };

        Ok(loader)
    }

    fn load_segments(&mut self) -> Result<Option<TlsTemplate>, &'static str> {
        // Load the segments into virtual memory.
        let mut tls_template = None;
        for program_header in self.elf_file.program_iter() {
            match program_header.get_type()? {
                Type::Load => self.inner.handle_load_segment(program_header)?,
                Type::Tls => {
                    if tls_template.is_none() {
                        tls_template = Some(self.inner.handle_tls_segment(program_header)?);
                    } else {
                        return Err("multiple TLS segments not supported");
                    }
                }
                Type::Null
                | Type::Dynamic
                | Type::Interp
                | Type::Note
                | Type::ShLib
                | Type::Phdr
                | Type::GnuRelro
                | Type::OsSpecific(_)
                | Type::ProcessorSpecific(_) => {}
            }
        }

        // Apply relocations in virtual memory.
        for program_header in self.elf_file.program_iter() {
            if let Type::Dynamic = program_header.get_type()? {
                self.inner
                    .handle_dynamic_segment(program_header, &self.elf_file)?
            }
        }

        // Mark some memory regions as read-only after relocations have been
        // applied.
        for program_header in self.elf_file.program_iter() {
            if let Type::GnuRelro = program_header.get_type()? {
                self.inner.handle_relro_segment(program_header);
            }
        }

        self.inner.remove_copied_flags(&self.elf_file).unwrap();

        Ok(tls_template)
    }

    fn entry_point(&self) -> VirtAddr {
        VirtAddr::new(self.inner.virtual_address_offset + self.elf_file.header.pt2.entry_point())
    }
}

impl<'a, M, F> Inner<'a, M, F>
where
    M: MapperAllSizes + Translate,
    F: FrameAllocator<Size4KiB>,
{
    fn handle_load_segment(&mut self, segment: ProgramHeader) -> Result<(), &'static str> {
        log::info!("Handling Segment: {:x?}", segment);

        let phys_start_addr = self.kernel_offset + segment.offset();
        let start_frame: PhysFrame = PhysFrame::containing_address(phys_start_addr);
        let end_frame: PhysFrame =
            PhysFrame::containing_address(phys_start_addr + segment.file_size() - 1u64);

        let virt_start_addr = VirtAddr::new(self.virtual_address_offset + segment.virtual_addr());
        let start_page: Page = Page::containing_address(virt_start_addr);

        let mut segment_flags = Flags::PRESENT;
        if !segment.flags().is_execute() {
            segment_flags |= Flags::NO_EXECUTE;
        }
        if segment.flags().is_write() {
            segment_flags |= Flags::WRITABLE;
        }

        // map all frames of the segment at the desired virtual address
        for frame in PhysFrame::range_inclusive(start_frame, end_frame) {
            let offset = frame - start_frame;
            let page = start_page + offset;
            let flusher = unsafe {
                // The parent table flags need to be both readable and writable to
                // support recursive page tables.
                // See https://github.com/rust-osdev/bootloader/issues/443#issuecomment-2130010621
                self.page_table
                    .map_to_with_table_flags(
                        page,
                        frame,
                        segment_flags,
                        Flags::PRESENT | Flags::WRITABLE,
                        self.frame_allocator,
                    )
                    .map_err(|_err| "map_to failed")?
            };
            // we operate on an inactive page table, so there's no need to flush anything
            flusher.ignore();
        }

        // Handle .bss section (mem_size > file_size)
        if segment.mem_size() > segment.file_size() {
            // .bss section (or similar), which needs to be mapped and zeroed
            self.handle_bss_section(&segment, segment_flags)?;
        }

        Ok(())
    }

    fn handle_bss_section(
        &mut self,
        segment: &ProgramHeader,
        segment_flags: Flags,
    ) -> Result<(), &'static str> {
        log::info!("Mapping bss section");

        let virt_start_addr = VirtAddr::new(self.virtual_address_offset + segment.virtual_addr());
        let mem_size = segment.mem_size();
        let file_size = segment.file_size();

        // calculate virtual memory region that must be zeroed
        let zero_start = virt_start_addr + file_size;
        let zero_end = virt_start_addr + mem_size;

        // a type alias that helps in efficiently clearing a page
        type PageArray = [u64; Size4KiB::SIZE as usize / 8];
        const ZERO_ARRAY: PageArray = [0; Size4KiB::SIZE as usize / 8];

        // In some cases, `zero_start` might not be page-aligned. This requires some
        // special treatment because we can't safely zero a frame of the original file.
        let data_bytes_before_zero = zero_start.as_u64() & 0xfff;
        if data_bytes_before_zero != 0 {
            // The last non-bss frame of the segment consists partly of data and partly of bss
            // memory, which must be zeroed. Unfortunately, the file representation might have
            // reused the part of the frame that should be zeroed to store the next segment. This
            // means that we can't simply overwrite that part with zeroes, as we might overwrite
            // other data this way.
            //
            // Example:
            //
            //   XXXXXXXXXXXXXXX000000YYYYYYY000ZZZZZZZZZZZ     virtual memory (XYZ are data)
            //   |·············|     /·····/   /·········/
            //   |·············| ___/·····/   /·········/
            //   |·············|/·····/‾‾‾   /·········/
            //   |·············||·····|/·̅·̅·̅·̅·̅·····/‾‾‾‾
            //   XXXXXXXXXXXXXXXYYYYYYYZZZZZZZZZZZ              file memory (zeros are not saved)
            //   '       '       '       '        '
            //   The areas filled with dots (`·`) indicate a mapping between virtual and file
            //   memory. We see that the data regions `X`, `Y`, `Z` have a valid mapping, while
            //   the regions that are initialized with 0 have not.
            //
            //   The ticks (`'`) below the file memory line indicate the start of a new frame. We
            //   see that the last frames of the `X` and `Y` regions in the file are followed
            //   by the bytes of the next region. So we can't zero these parts of the frame
            //   because they are needed by other memory regions.
            //
            // To solve this problem, we need to allocate a new frame for the last segment page
            // and copy all data content of the original frame over. Afterwards, we can zero
            // the remaining part of the frame since the frame is no longer shared with other
            // segments now.

            let last_page = Page::containing_address(virt_start_addr + file_size - 1u64);
            let new_frame = unsafe { self.make_mut(last_page) };
            let new_bytes_ptr = new_frame.start_address().as_u64() as *mut u8;
            unsafe {
                core::ptr::write_bytes(
                    new_bytes_ptr.add(data_bytes_before_zero as usize),
                    0,
                    (Size4KiB::SIZE - data_bytes_before_zero) as usize,
                );
            }
        }

        // map additional frames for `.bss` memory that is not present in source file
        let start_page: Page =
            Page::containing_address(VirtAddr::new(align_up(zero_start.as_u64(), Size4KiB::SIZE)));
        let end_page = Page::containing_address(zero_end - 1u64);
        for page in Page::range_inclusive(start_page, end_page) {
            // allocate a new unused frame
            let frame = self.frame_allocator.allocate_frame().unwrap();

            // zero frame, utilizing identity-mapping
            let frame_ptr = frame.start_address().as_u64() as *mut PageArray;
            unsafe { frame_ptr.write(ZERO_ARRAY) };

            // map frame
            let flusher = unsafe {
                // The parent table flags need to be both readable and writable to
                // support recursive page tables.
                // See https://github.com/rust-osdev/bootloader/issues/443#issuecomment-2130010621
                self.page_table
                    .map_to_with_table_flags(
                        page,
                        frame,
                        segment_flags,
                        Flags::PRESENT | Flags::WRITABLE,
                        self.frame_allocator,
                    )
                    .map_err(|_err| "Failed to map new frame for bss memory")?
            };
            // we operate on an inactive page table, so we don't need to flush our changes
            flusher.ignore();
        }

        Ok(())
    }

    /// Copy from the kernel address space.
    ///
    /// ## Panics
    ///
    /// Panics if a page is not mapped in `self.page_table`.
    fn copy_from(&self, addr: VirtAddr, buf: &mut [u8]) {
        // We can't know for sure that contiguous virtual address are contiguous
        // in physical memory, so we iterate of the pages spanning the
        // addresses, translate them to frames and copy the data.

        let end_inclusive_addr = Step::forward_checked(addr, buf.len() - 1)
            .expect("end address outside of the virtual address space");
        let start_page = Page::<Size4KiB>::containing_address(addr);
        let end_inclusive_page = Page::<Size4KiB>::containing_address(end_inclusive_addr);

        for page in start_page..=end_inclusive_page {
            // Translate the virtual page to the physical frame.
            let phys_addr = self
                .page_table
                .translate_page(page)
                .expect("address is not mapped to the kernel's memory space");

            // Figure out which address range we want to copy from the frame.

            // This page covers these addresses.
            let page_start = page.start_address();
            let page_end_inclusive = page.start_address() + 4095u64;

            // We want to copy from the following address in this frame.
            let start_copy_address = cmp::max(addr, page_start);
            let end_inclusive_copy_address = cmp::min(end_inclusive_addr, page_end_inclusive);

            // These are the offsets into the frame we want to copy from.
            let start_offset_in_frame = start_copy_address - page_start;
            let end_inclusive_offset_in_frame = end_inclusive_copy_address - page_start;

            // Calculate how many bytes we want to copy from this frame.
            let copy_len = end_inclusive_offset_in_frame - start_offset_in_frame + 1;

            // Calculate the physical addresses.
            let start_phys_addr = phys_addr.start_address() + start_offset_in_frame;

            // These are the offsets from the start address. These correspond
            // to the destination indices in `buf`.
            let start_offset_in_buf = Step::steps_between(&addr, &start_copy_address).1.unwrap();

            // Calculate the source slice.
            // Utilize that frames are identity mapped.
            let src_ptr = start_phys_addr.as_u64() as *const u8;
            let src = unsafe {
                // SAFETY: We know that this memory is valid because we got it
                // as a result from a translation. There are not other
                // references to it.
                &*core::ptr::slice_from_raw_parts(src_ptr, copy_len as usize)
            };

            // Calculate the destination pointer.
            let dest = &mut buf[start_offset_in_buf..][..copy_len as usize];

            // Do the actual copy.
            dest.copy_from_slice(src);
        }
    }

    /// Write to the kernel address space.
    ///
    /// ## Safety
    /// - `addr` should refer to a page mapped by a Load segment.
    ///
    /// ## Panics
    ///
    /// Panics if a page is not mapped in `self.page_table`.
    unsafe fn copy_to(&mut self, addr: VirtAddr, buf: &[u8]) {
        // We can't know for sure that contiguous virtual address are contiguous
        // in physical memory, so we iterate of the pages spanning the
        // addresses, translate them to frames and copy the data.

        let end_inclusive_addr = Step::forward_checked(addr, buf.len() - 1)
            .expect("the end address should be in the virtual address space");
        let start_page = Page::<Size4KiB>::containing_address(addr);
        let end_inclusive_page = Page::<Size4KiB>::containing_address(end_inclusive_addr);

        for page in start_page..=end_inclusive_page {
            // Translate the virtual page to the physical frame.
            let phys_addr = unsafe {
                // SAFETY: The caller asserts that the pages are mapped by a Load segment.
                self.make_mut(page)
            };

            // Figure out which address range we want to copy from the frame.

            // This page covers these addresses.
            let page_start = page.start_address();
            let page_end_inclusive = page.start_address() + 4095u64;

            // We want to copy from the following address in this frame.
            let start_copy_address = cmp::max(addr, page_start);
            let end_inclusive_copy_address = cmp::min(end_inclusive_addr, page_end_inclusive);

            // These are the offsets into the frame we want to copy from.
            let start_offset_in_frame = start_copy_address - page_start;
            let end_inclusive_offset_in_frame = end_inclusive_copy_address - page_start;

            // Calculate how many bytes we want to copy from this frame.
            let copy_len = end_inclusive_offset_in_frame - start_offset_in_frame + 1;

            // Calculate the physical addresses.
            let start_phys_addr = phys_addr.start_address() + start_offset_in_frame;

            // These are the offsets from the start address. These correspond
            // to the destination indices in `buf`.
            let start_offset_in_buf = Step::steps_between(&addr, &start_copy_address).1.unwrap();

            // Calculate the source slice.
            // Utilize that frames are identity mapped.
            let dest_ptr = start_phys_addr.as_u64() as *mut u8;
            let dest = unsafe {
                // SAFETY: We know that this memory is valid because we got it
                // as a result from a translation. There are not other
                // references to it.
                &mut *core::ptr::slice_from_raw_parts_mut(dest_ptr, copy_len as usize)
            };

            // Calculate the destination pointer.
            let src = &buf[start_offset_in_buf..][..copy_len as usize];

            // Do the actual copy.
            dest.copy_from_slice(src);
        }
    }

    /// This method is intended for making the memory loaded by a Load segment mutable.
    ///
    /// All memory from a Load segment starts out by mapped to the same frames that
    /// contain the elf file. Thus writing to memory in that state will cause aliasing issues.
    /// To avoid that, we allocate a new frame, copy all bytes from the old frame to the new frame,
    /// and remap the page to the new frame. At this point the page no longer aliases the elf file
    /// and we can write to it.
    ///
    /// When we map the new frame we also set [`COPIED`] flag in the page table flags, so that
    /// we can detect if the frame has already been copied when we try to modify the page again.
    ///
    /// ## Safety
    /// - `page` should be a page mapped by a Load segment.
    ///
    /// ## Panics
    /// Panics if the page is not mapped in `self.page_table`.
    unsafe fn make_mut(&mut self, page: Page) -> PhysFrame {
        let (frame, flags) = match self.page_table.translate(page.start_address()) {
            TranslateResult::Mapped {
                frame,
                offset: _,
                flags,
            } => (frame, flags),
            TranslateResult::NotMapped => panic!("{:?} is not mapped", page),
            TranslateResult::InvalidFrameAddress(_) => unreachable!(),
        };
        let frame = if let MappedFrame::Size4KiB(frame) = frame {
            frame
        } else {
            // We only map 4k pages.
            unreachable!()
        };

        if flags.contains(COPIED) {
            // The frame was already copied, we are free to modify it.
            return frame;
        }

        // Allocate a new frame and copy the memory, utilizing that both frames are identity mapped.
        let new_frame = self.frame_allocator.allocate_frame().unwrap();
        let frame_ptr = frame.start_address().as_u64() as *const u8;
        let new_frame_ptr = new_frame.start_address().as_u64() as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(frame_ptr, new_frame_ptr, Size4KiB::SIZE as usize);
        }

        // Replace the underlying frame and update the flags.
        self.page_table.unmap(page).unwrap().1.ignore();
        let new_flags = flags | COPIED;
        unsafe {
            self.page_table
                .map_to(page, new_frame, new_flags, self.frame_allocator)
                .unwrap()
                .ignore();
        }

        new_frame
    }

    /// Cleans up the custom flags set by [`Inner::make_mut`].
    fn remove_copied_flags(&mut self, elf_file: &ElfFile) -> Result<(), &'static str> {
        for program_header in elf_file.program_iter() {
            if let Type::Load = program_header.get_type()? {
                if program_header.mem_size() == 0 {
                    continue;
                }
                let start = self.virtual_address_offset + program_header.virtual_addr();
                let end = start + (program_header.mem_size() - 1);
                let start = VirtAddr::new(start);
                let end = VirtAddr::new(end);
                let start_page = Page::containing_address(start);
                let end_page = Page::containing_address(end);
                for page in Page::<Size4KiB>::range_inclusive(start_page, end_page) {
                    // Translate the page and get the flags.
                    let res = self.page_table.translate(page.start_address());
                    let flags = match res {
                        TranslateResult::Mapped {
                            frame: _,
                            offset: _,
                            flags,
                        } => flags,
                        TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => {
                            unreachable!("has the elf file not been mapped correctly?")
                        }
                    };

                    if flags.contains(COPIED) {
                        // Remove the flag.
                        unsafe {
                            self.page_table
                                .update_flags(page, flags & !COPIED)
                                .unwrap()
                                .ignore();
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_tls_segment(&mut self, segment: ProgramHeader) -> Result<TlsTemplate, &'static str> {
        Ok(TlsTemplate {
            start_addr: self.virtual_address_offset + segment.virtual_addr(),
            mem_size: segment.mem_size(),
            file_size: segment.file_size(),
        })
    }

    fn handle_dynamic_segment(
        &mut self,
        segment: ProgramHeader,
        elf_file: &ElfFile,
    ) -> Result<(), &'static str> {
        let data = segment.get_data(elf_file)?;
        let data = if let SegmentData::Dynamic64(data) = data {
            data
        } else {
            panic!("expected Dynamic64 segment")
        };

        // Find the `Rela`, `RelaSize` and `RelaEnt` entries.
        let mut rela = None;
        let mut rela_size = None;
        let mut rela_ent = None;
        for rel in data {
            let tag = rel.get_tag()?;
            match tag {
                dynamic::Tag::Rela => {
                    let ptr = rel.get_ptr()?;
                    let prev = rela.replace(ptr);
                    if prev.is_some() {
                        return Err("Dynamic section contains more than one Rela entry");
                    }
                }
                dynamic::Tag::RelaSize => {
                    let val = rel.get_val()?;
                    let prev = rela_size.replace(val);
                    if prev.is_some() {
                        return Err("Dynamic section contains more than one RelaSize entry");
                    }
                }
                dynamic::Tag::RelaEnt => {
                    let val = rel.get_val()?;
                    let prev = rela_ent.replace(val);
                    if prev.is_some() {
                        return Err("Dynamic section contains more than one RelaEnt entry");
                    }
                }
                _ => {}
            }
        }
        let offset = if let Some(rela) = rela {
            rela
        } else {
            // The section doesn't contain any relocations.

            if rela_size.is_some() || rela_ent.is_some() {
                return Err("Rela entry is missing but RelaSize or RelaEnt have been provided");
            }

            return Ok(());
        };
        let total_size = rela_size.ok_or("RelaSize entry is missing")?;
        let entry_size = rela_ent.ok_or("RelaEnt entry is missing")?;

        // Make sure that the reported size matches our `Rela<u64>`.
        assert_eq!(
            entry_size,
            size_of::<Rela<u64>>() as u64,
            "unsupported entry size: {entry_size}"
        );

        // Apply the relocations.
        let num_entries = total_size / entry_size;
        for idx in 0..num_entries {
            let rela = self.read_relocation(offset, idx);
            self.apply_relocation(rela, elf_file)?;
        }

        Ok(())
    }

    /// Reads a relocation from a relocation table.
    fn read_relocation(&self, relocation_table: u64, idx: u64) -> Rela<u64> {
        // Calculate the address of the entry in the relocation table.
        let offset = relocation_table + size_of::<Rela<u64>>() as u64 * idx;
        let value = self.virtual_address_offset + offset;
        let addr = VirtAddr::try_new(value).expect("relocation table is outside the address space");

        // Read the Rela from the kernel address space.
        let mut buf = [0; 24];
        self.copy_from(addr, &mut buf);

        // Convert the bytes we read into a `Rela<u64>`.
        unsafe {
            // SAFETY: Any bitpattern is valid for `Rela<u64>` and buf is
            // valid for reads.
            core::ptr::read_unaligned(&buf as *const u8 as *const Rela<u64>)
        }
    }

    fn apply_relocation(
        &mut self,
        rela: Rela<u64>,
        elf_file: &ElfFile,
    ) -> Result<(), &'static str> {
        let symbol_idx = rela.get_symbol_table_index();
        assert_eq!(
            symbol_idx, 0,
            "relocations using the symbol table are not supported"
        );

        match rela.get_type() {
            // R_AMD64_RELATIVE
            8 => {
                // Make sure that the relocation happens in memory mapped
                // by a Load segment.
                check_is_in_load(elf_file, rela.get_offset())?;

                // Calculate the destination of the relocation.
                let addr = self.virtual_address_offset + rela.get_offset();
                let addr = VirtAddr::new(addr);

                // Calculate the relocated value.
                let value = self.virtual_address_offset + rela.get_addend();

                // Write the relocated value to memory.
                unsafe {
                    // SAFETY: We just verified that the address is in a Load segment.
                    self.copy_to(addr, &value.to_ne_bytes());
                }
            }
            ty => unimplemented!("relocation type {:x} not supported", ty),
        }

        Ok(())
    }

    /// Mark a region of memory indicated by a GNU_RELRO segment as read-only.
    ///
    /// This is a security mitigation used to protect memory regions that
    /// need to be writable while applying relocations, but should never be
    /// written to after relocations have been applied.
    fn handle_relro_segment(&mut self, program_header: ProgramHeader) {
        let start = self.virtual_address_offset + program_header.virtual_addr();
        let end = start + program_header.mem_size();
        let start = VirtAddr::new(start);
        let end = VirtAddr::new(end);
        let start_page = Page::containing_address(start);
        let end_page = Page::containing_address(end - 1u64);
        for page in Page::<Size4KiB>::range_inclusive(start_page, end_page) {
            // Translate the page and get the flags.
            let res = self.page_table.translate(page.start_address());
            let flags = match res {
                TranslateResult::Mapped {
                    frame: _,
                    offset: _,
                    flags,
                } => flags,
                TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => {
                    unreachable!("has the elf file not been mapped correctly?")
                }
            };

            if flags.contains(Flags::WRITABLE) {
                // Remove the WRITABLE flag.
                unsafe {
                    self.page_table
                        .update_flags(page, flags & !Flags::WRITABLE)
                        .unwrap()
                        .ignore();
                }
            }
        }
    }
}

/// Check that the virtual offset belongs to a load segment.
fn check_is_in_load(elf_file: &ElfFile, virt_offset: u64) -> Result<(), &'static str> {
    for program_header in elf_file.program_iter() {
        if let Type::Load = program_header.get_type()?
            && program_header.virtual_addr() <= virt_offset
        {
            let offset_in_segment = virt_offset - program_header.virtual_addr();
            if offset_in_segment < program_header.mem_size() {
                return Ok(());
            }
        }
    }
    Err("offset is not in load segment")
}

/// Loads the kernel ELF file given in `bytes` in the given `page_table`.
///
/// Returns the kernel entry point address, it's thread local storage template (if any),
/// and a structure describing which level 4 page table entries are in use.
pub fn load_kernel(
    kernel: Kernel<'_>,
    page_table: &mut (impl MapperAllSizes + Translate),
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    used_entries: &mut UsedLevel4Entries,
) -> Result<(VirtAddr, VirtAddr, Option<TlsTemplate>), &'static str> {
    let mut loader = Loader::new(kernel, page_table, frame_allocator, used_entries)?;
    let tls_template = loader.load_segments()?;

    Ok((
        VirtAddr::new(loader.inner.virtual_address_offset.virtual_address_offset() as u64),
        loader.entry_point(),
        tls_template,
    ))
}

/// Basic information about the memory segments of an elf file.
pub struct ElfMemoryRequirements {
    /// total size needed for all segments
    pub size: u64,
    /// memory alignment for the elf file
    pub align: u64,
    /// the smallest virtual address used by the elf file
    pub min_addr: u64,
}

/// Calculates basic requirements needed to allocate memory for an elf file.
pub fn calc_elf_memory_requirements(elf_file: &ElfFile) -> ElfMemoryRequirements {
    // Find the highest virtual memory address and the biggest alignment.
    let load_program_headers = elf_file
        .program_iter()
        .filter(|h| matches!(h.get_type(), Ok(Type::Load)));
    let max_addr = load_program_headers
        .clone()
        .map(|h| h.virtual_addr() + h.mem_size())
        .max()
        .unwrap_or(0);
    let min_addr = load_program_headers
        .clone()
        .map(|h| h.virtual_addr())
        .min()
        .unwrap_or(0);
    let size = max_addr - min_addr;
    let align = load_program_headers.map(|h| h.align()).max().unwrap_or(1);
    ElfMemoryRequirements {
        size,
        align,
        min_addr,
    }
}

/// A helper type used to offset virtual addresses for position independent
/// executables.
#[derive(Clone, Copy)]
pub struct VirtualAddressOffset {
    virtual_address_offset: i128,
}

impl VirtualAddressOffset {
    pub fn zero() -> Self {
        Self::new(0)
    }

    pub fn new(virtual_address_offset: i128) -> Self {
        Self {
            virtual_address_offset,
        }
    }

    pub fn virtual_address_offset(&self) -> i128 {
        self.virtual_address_offset
    }
}

impl Add<u64> for VirtualAddressOffset {
    type Output = u64;

    fn add(self, offset: u64) -> Self::Output {
        u64::try_from(
            self.virtual_address_offset
                .checked_add(i128::from(offset))
                .unwrap(),
        )
        .unwrap()
    }
}
