//! Private domain page tables, their construction audit, and bounded teardown.

use x86_64::PhysAddr;
use x86_64::VirtAddr;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB};

use super::types::{
    CODE_BASE, ComponentImage, DomainGeneration, DomainId, DomainPagingError, SLOT_CAPACITY,
    expected_owned_frames, peer_probe, stack_base,
};
use crate::memory::{self, FRAME_SIZE, Frame};
use crate::serial;

const ENTRY_COUNT: usize = 512;
const MAX_KERNEL_COPY_FRAMES: usize = 32;
const APIC_PHYS_BASE: u64 = 0xFEE0_0000;
const CODE_EXECUTABLE: PageTableFlags =
    PageTableFlags::PRESENT.union(PageTableFlags::USER_ACCESSIBLE);
const DATA_LEAF: PageTableFlags = PageTableFlags::PRESENT
    .union(PageTableFlags::WRITABLE)
    .union(PageTableFlags::USER_ACCESSIBLE)
    .union(PageTableFlags::NO_EXECUTE);
// NX propagates from every parent level, so leaf flags alone must decide
// executability. User access still cannot reach supervisor-only subtrees.
const PARENT: PageTableFlags = PageTableFlags::PRESENT
    .union(PageTableFlags::WRITABLE)
    .union(PageTableFlags::USER_ACCESSIBLE);
// NX must not be set here: it applies to the entire subtree. Leaf flags
// remain the authority for executable-versus-writable kernel mappings.
const KERNEL_PARENT: PageTableFlags = PageTableFlags::PRESENT.union(PageTableFlags::WRITABLE);
const KERNEL_DATA_LEAF: PageTableFlags = PageTableFlags::PRESENT
    .union(PageTableFlags::WRITABLE)
    .union(PageTableFlags::NO_EXECUTE);

#[derive(Clone, Copy)]
pub(super) struct OwnedFrames {
    frames: [Option<Frame>; super::types::RESOURCE_CAPACITY],
    len: usize,
}

impl OwnedFrames {
    fn new() -> Self {
        Self {
            frames: [None; super::types::RESOURCE_CAPACITY],
            len: 0,
        }
    }

    fn push(&mut self, frame: Frame) -> Result<usize, DomainPagingError> {
        if self.len == self.frames.len() {
            return Err(DomainPagingError::FrameCapacity);
        }
        self.frames[self.len] = Some(frame);
        self.len += 1;
        Ok(self.len - 1)
    }

    fn alloc_zeroed(&mut self) -> Result<Frame, DomainPagingError> {
        if self.len == self.frames.len() {
            return Err(DomainPagingError::FrameCapacity);
        }
        let frame = memory::alloc_frame().ok_or(DomainPagingError::FrameExhausted)?;
        // SAFETY: the frame is exclusively owned here and is not yet linked.
        unsafe { memory::zero_frame(frame) };
        self.push(frame)?;
        Ok(frame)
    }

    fn count(&self) -> usize {
        self.len
    }
}

pub(super) struct AddressSpace {
    image: ComponentImage,
    owned: OwnedFrames,
    source_cr3: PhysFrame<Size4KiB>,
    source_cr3_flags: Cr3Flags,
    root: Frame,
    probe: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseStatus {
    Released(u64, u64),
    RestoreFailed,
    ReclaimBlocked(u64, u64),
}

impl AddressSpace {
    pub(super) fn new(image: ComponentImage, probe: u64) -> Result<Self, DomainPagingError> {
        let expected = expected_owned_frames(image.code_len(), image.stack_pages());
        if expected != image.owned_frames() {
            return Err(DomainPagingError::AccountingMismatch);
        }
        let (source_cr3, source_cr3_flags) = Cr3::read();
        let mut owned = OwnedFrames::new();
        let root = owned.alloc_zeroed()?;
        let mut space = Self {
            image,
            owned,
            source_cr3,
            source_cr3_flags,
            root,
            probe,
        };
        if let Err(error) = space.build(expected) {
            space.discard();
            return Err(error);
        }
        Ok(space)
    }

    fn build(&mut self, expected: usize) -> Result<(), DomainPagingError> {
        let kernel_frames = self.copy_kernel_space()?;
        if kernel_frames > MAX_KERNEL_COPY_FRAMES {
            return Err(DomainPagingError::FrameCapacity);
        }
        self.map_code()?;
        self.map_stack()?;
        self.map_probe()?;
        self.map_kernel_stack()?;
        self.map_apic()?;
        let total = expected + kernel_frames;
        if self.owned.count() != total {
            serial::ev_domain_accounting(total as u64, self.owned.count() as u64);
            return Err(DomainPagingError::AccountingMismatch);
        }
        let (wx_ok, kernel_excluded) = self.audit_tree();
        let alias_excluded = !self.is_mapped(memory::phys_offset());
        let peer_excluded = !self.peer_probes().any(|probe| self.is_mapped(probe));
        serial::ev_domain_exclusion(alias_excluded, kernel_excluded, peer_excluded);
        serial::ev_domain_audit(
            self.owned.count() as u64,
            wx_ok,
            kernel_excluded && alias_excluded,
            peer_excluded,
        );
        if !(wx_ok && kernel_excluded && alias_excluded && peer_excluded) {
            serial::ev_domain_policy(false, true, true);
            return Err(DomainPagingError::PolicyViolation);
        }
        Ok(())
    }

    pub(super) const fn root_phys(&self) -> u64 {
        self.root.phys()
    }

    pub(super) const fn source_root(&self) -> (PhysFrame<Size4KiB>, Cr3Flags) {
        (self.source_cr3, self.source_cr3_flags)
    }

    pub(super) const fn probe(&self) -> u64 {
        self.probe
    }

    pub(super) fn stack_is_zeroed(&self) -> bool {
        (0..self.image.stack_pages())
            .all(|page| self.zeroed_at(stack_base() + page as u64 * FRAME_SIZE))
    }

    pub(super) fn probe_is_zeroed(&self) -> bool {
        self.zeroed_at(self.probe)
    }

    pub(super) fn user_stack_top(&self) -> u64 {
        super::types::stack_base() + self.image.stack_pages() as u64 * FRAME_SIZE
    }

    pub(super) fn required_frames(&self) -> u64 {
        self.owned.count() as u64
    }

    /// Copy only supervisor subtrees needed by ring zero while a child CR3 is
    /// active. Leaves retain their kernel backing but lose user access; newly
    /// copied table frames are privately owned and reclaimed during teardown.
    fn copy_kernel_space(&mut self) -> Result<usize, DomainPagingError> {
        let source = table_ptr(self.source_cr3.start_address().as_u64());
        let mut copied = 0;
        for p4 in self.kernel_p4_indices() {
            let source_entry = unsafe { (&*source)[p4].clone() };
            if !source_entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            if source_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err(DomainPagingError::PolicyViolation);
            }
            let table = self.owned.alloc_zeroed()?;
            // SAFETY: the exclusively owned root is not yet active.
            unsafe {
                (&mut *table_ptr(self.root.phys()))[p4]
                    .set_addr(PhysAddr::new(table.phys()), KERNEL_PARENT);
            }
            copied += self.copy_kernel_table(source_entry.addr().as_u64(), table.phys(), 3)?;
            if copied > MAX_KERNEL_COPY_FRAMES {
                return Err(DomainPagingError::FrameCapacity);
            }
        }
        Ok(copied)
    }

    fn kernel_p4_indices(&self) -> [usize; 2] {
        let code_anchor = VirtAddr::new(current_rip());
        let stack_anchor = VirtAddr::new(current_stack_pointer());
        [
            usize::from(code_anchor.p4_index()),
            usize::from(stack_anchor.p4_index()),
        ]
    }

    fn copy_kernel_table(
        &mut self,
        source_phys: u64,
        target_phys: u64,
        depth: u8,
    ) -> Result<usize, DomainPagingError> {
        let mut copied = 1;
        for index in 0..ENTRY_COUNT {
            let source_entry = unsafe { (&*table_ptr(source_phys))[index].clone() };
            if !source_entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            let mut leaf_flags = source_entry.flags();
            leaf_flags.remove(PageTableFlags::USER_ACCESSIBLE);
            if depth == 1 || source_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                // SAFETY: target is a private table not yet exposed to user.
                unsafe {
                    (&mut *table_ptr(target_phys))[index].set_addr(source_entry.addr(), leaf_flags);
                }
                continue;
            }
            let table = self.owned.alloc_zeroed()?;
            // SAFETY: target is a private table not yet exposed to user.
            unsafe {
                (&mut *table_ptr(target_phys))[index]
                    .set_addr(PhysAddr::new(table.phys()), KERNEL_PARENT);
            }
            copied +=
                self.copy_kernel_table(source_entry.addr().as_u64(), table.phys(), depth - 1)?;
            if copied > MAX_KERNEL_COPY_FRAMES {
                return Err(DomainPagingError::FrameCapacity);
            }
        }
        Ok(copied)
    }

    fn map_apic(&mut self) -> Result<(), DomainPagingError> {
        let address = memory::phys_offset() + APIC_PHYS_BASE;
        self.map_leaf_at(address, APIC_PHYS_BASE, KERNEL_DATA_LEAF)?;
        Ok(())
    }

    fn ensure_table(&mut self, parent: u64, index: usize) -> Result<u64, DomainPagingError> {
        // SAFETY: both page-table frames are exclusively owned and distinct.
        let entry = unsafe { &mut (&mut *table_ptr(parent))[index] };
        if entry.flags().contains(PageTableFlags::PRESENT) {
            return Ok(entry.addr().as_u64());
        }
        if !entry.is_unused() {
            return Err(DomainPagingError::PolicyViolation);
        }
        let frame = self.owned.alloc_zeroed()?;
        entry.set_addr(PhysAddr::new(frame.phys()), PARENT);
        Ok(frame.phys())
    }

    fn map_leaf(
        &mut self,
        virtual_address: u64,
        flags: PageTableFlags,
    ) -> Result<u64, DomainPagingError> {
        let leaf = self.owned.alloc_zeroed()?;
        self.map_leaf_at(virtual_address, leaf.phys(), flags)?;
        Ok(leaf.phys())
    }

    fn map_leaf_at(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        flags: PageTableFlags,
    ) -> Result<u64, DomainPagingError> {
        if !check_wx(flags)
            || flags.contains(PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE)
                && !flags.contains(PageTableFlags::NO_EXECUTE)
        {
            return Err(DomainPagingError::PolicyViolation);
        }
        let address = x86_64::VirtAddr::new(virtual_address);
        let indices = [
            usize::from(address.p4_index()),
            usize::from(address.p3_index()),
            usize::from(address.p2_index()),
        ];
        let mut table = self.root.phys();
        for index in indices {
            table = self.ensure_table(table, index)?;
        }
        // SAFETY: the leaf is exclusively owned after being linked below.
        let entry = unsafe { &mut (&mut *table_ptr(table))[usize::from(address.p1_index())] };
        if !entry.is_unused() {
            return Err(DomainPagingError::AliasRejected);
        }
        entry.set_addr(PhysAddr::new(physical_address), flags);
        Ok(physical_address)
    }

    fn map_code(&mut self) -> Result<(), DomainPagingError> {
        let leaf = self.map_leaf(CODE_BASE, CODE_EXECUTABLE)?;
        let source = self.image.code();
        if source.len() > FRAME_SIZE as usize {
            return Err(DomainPagingError::PolicyViolation);
        }
        // SAFETY: the code leaf is exclusively owned by this domain and is
        // executable only through CODE_BASE in its private address space.
        unsafe {
            core::ptr::copy_nonoverlapping(
                source.as_ptr(),
                (memory::phys_offset() + leaf) as *mut u8,
                source.len(),
            );
        }
        Ok(())
    }

    fn map_stack(&mut self) -> Result<(), DomainPagingError> {
        for page in 0..self.image.stack_pages() {
            self.map_leaf(stack_base() + page as u64 * FRAME_SIZE, DATA_LEAF)?;
        }
        Ok(())
    }

    fn map_probe(&mut self) -> Result<(), DomainPagingError> {
        self.map_leaf(self.probe, DATA_LEAF)?;
        Ok(())
    }

    fn map_kernel_stack(&mut self) -> Result<(), DomainPagingError> {
        self.map_leaf(super::types::KERNEL_STACK, KERNEL_DATA_LEAF)?;
        Ok(())
    }

    fn leaf_frame(&self, virtual_address: u64) -> Option<Frame> {
        let address = VirtAddr::new(virtual_address);
        let indices = [
            usize::from(address.p4_index()),
            usize::from(address.p3_index()),
            usize::from(address.p2_index()),
            usize::from(address.p1_index()),
        ];
        let mut table = self.root.phys();
        for (level, index) in indices.into_iter().enumerate() {
            // SAFETY: ring zero owns the inactive private table and reads it
            // through the fixed physical-memory mapping.
            let entry = unsafe { &(&*table_ptr(table))[index] };
            if !entry.flags().contains(PageTableFlags::PRESENT)
                || entry.flags().contains(PageTableFlags::HUGE_PAGE)
            {
                return None;
            }
            if level == 3 {
                return Some(Frame::from_phys(entry.addr().as_u64()));
            }
            table = entry.addr().as_u64();
        }
        None
    }

    fn zeroed_at(&self, virtual_address: u64) -> bool {
        let Some(frame) = self.leaf_frame(virtual_address) else {
            return false;
        };
        // SAFETY: the mapped leaf remains exclusively owned by this inactive
        // domain before admission.
        unsafe { memory::frame_is_zeroed(frame) }
    }

    pub(super) fn audit(&self) -> bool {
        let (wx_ok, kernel_excluded) = self.audit_tree();
        kernel_excluded && !self.peer_probes().any(|probe| self.is_mapped(probe)) && wx_ok
    }

    fn peer_probes(&self) -> impl Iterator<Item = u64> {
        (0..SLOT_CAPACITY)
            .map(peer_probe)
            .filter(|probe| *probe != self.probe)
    }

    fn is_mapped(&self, address: u64) -> bool {
        let Ok(address) = x86_64::VirtAddr::try_new(address) else {
            return true;
        };
        let indices = [
            usize::from(address.p4_index()),
            usize::from(address.p3_index()),
            usize::from(address.p2_index()),
            usize::from(address.p1_index()),
        ];
        let mut table = self.root.phys();
        for (level, index) in indices.into_iter().enumerate() {
            // SAFETY: the root is not active here, but ring zero owns it and
            // reads through the fixed physical-memory alias.
            let entry = unsafe { &(&*table_ptr(table))[index] };
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                return false;
            }
            if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return true;
            }
            if level < 3 {
                table = entry.addr().as_u64();
            }
        }
        true
    }

    fn audit_tree(&self) -> (bool, bool) {
        let mut wx_ok = true;
        let alias_excluded = !self.is_mapped(memory::phys_offset());
        let mut excluded = alias_excluded;
        let root = table_ptr(self.root.phys());
        // SAFETY: this private read-only audit aliases no mutable traversal.
        let root_table = unsafe { &*root };
        for (p4, entry) in root_table.iter().enumerate() {
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                excluded = false;
            }
            let p3 = entry.addr().as_u64();
            // SAFETY: distinct table frames are read through the physical map.
            let p3_table = unsafe { &*table_ptr(p3) };
            for (p3i, entry) in p3_table.iter().enumerate() {
                if !entry.flags().contains(PageTableFlags::PRESENT) {
                    continue;
                }
                if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                    wx_ok &= check_wx(entry.flags());
                    if entry.flags().contains(PageTableFlags::USER_ACCESSIBLE) {
                        excluded = false;
                    }
                    continue;
                }
                let p2 = entry.addr().as_u64();
                // SAFETY: distinct table frames are read through the physical map.
                let p2_table = unsafe { &*table_ptr(p2) };
                for (p2i, entry) in p2_table.iter().enumerate() {
                    if !entry.flags().contains(PageTableFlags::PRESENT) {
                        continue;
                    }
                    if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                        wx_ok &= check_wx(entry.flags());
                        if entry.flags().contains(PageTableFlags::USER_ACCESSIBLE) {
                            excluded = false;
                        }
                        continue;
                    }
                    let p1 = entry.addr().as_u64();
                    // SAFETY: distinct table frames are read through the physical map.
                    let p1_table = unsafe { &*table_ptr(p1) };
                    for (p1i, entry) in p1_table.iter().enumerate() {
                        if !entry.flags().contains(PageTableFlags::PRESENT) {
                            continue;
                        }
                        if !check_wx(entry.flags()) {
                            wx_ok = false;
                        }
                        let user_leaf = entry.flags().contains(PageTableFlags::USER_ACCESSIBLE);
                        if user_leaf {
                            let address = leaf_address(p4, p3i, p2i, p1i);
                            excluded &=
                                self.is_expected_leaf(address) && !self.is_peer_probe(address);
                        }
                    }
                }
            }
        }
        (wx_ok, excluded)
    }

    fn is_expected_leaf(&self, address: u64) -> bool {
        if address == self.probe {
            return true;
        }
        let stack = stack_base();
        let stack_end = stack + self.image.stack_pages() as u64 * FRAME_SIZE;
        if (stack..stack_end).contains(&address) {
            return true;
        }
        let code_end = CODE_BASE + self.image.code_len() as u64;
        (CODE_BASE..code_end).contains(&address)
    }

    fn is_peer_probe(&self, address: u64) -> bool {
        self.peer_probes().any(|probe| probe == address)
    }

    pub(super) fn release(&mut self, id: DomainId, generation: DomainGeneration) -> ReleaseStatus {
        self.release_inner(Some((id, generation)))
    }

    /// Release an address space that was never admitted under a domain
    /// identity. It has no lifecycle event of its own, but its frames must
    /// still be returned before prepare reports the admission failure.
    pub(super) fn discard(&mut self) -> ReleaseStatus {
        self.reclaim_owned()
    }

    fn release_inner(&mut self, identity: Option<(DomainId, DomainGeneration)>) -> ReleaseStatus {
        // SAFETY: no further domain access can occur; restore the supervisor
        // root captured before this child root became active.
        unsafe { Cr3::write(self.source_cr3, self.source_cr3_flags) };
        let observed = Cr3::read();
        if observed != self.source_root() {
            if let Some((id, generation)) = identity {
                serial::ev_domain_restore(
                    id.0 + 1,
                    generation.0,
                    false,
                    observed.0.start_address().as_u64(),
                    observed.1.bits(),
                );
            }
            return ReleaseStatus::RestoreFailed;
        }
        if let Some((id, generation)) = identity {
            serial::ev_domain_restore(
                id.0 + 1,
                generation.0,
                true,
                self.source_cr3.start_address().as_u64(),
                self.source_cr3_flags.bits(),
            );
        }
        self.reclaim_owned()
    }

    fn reclaim_owned(&mut self) -> ReleaseStatus {
        let expected = self.owned.count() as u64;
        let mut freed = 0u64;
        while self.owned.len > 0 {
            let Some(frame) = self.owned.frames[self.owned.len - 1] else {
                break;
            };
            if memory::reclaim_frame(frame) {
                freed += 1;
            }
            self.owned.frames[self.owned.len - 1] = None;
            self.owned.len -= 1;
        }
        if expected == freed {
            ReleaseStatus::Released(expected, freed)
        } else {
            ReleaseStatus::ReclaimBlocked(expected, freed)
        }
    }
}

fn current_rip() -> u64 {
    let pointer;
    // SAFETY: obtains the address of the next instruction without control
    // transfer and leaves memory and flags unchanged.
    unsafe {
        core::arch::asm!("lea {}, [rip]", out(reg) pointer, options(nomem, preserves_flags));
    }
    pointer
}

fn current_stack_pointer() -> u64 {
    let pointer;
    // SAFETY: reads the current stack pointer and leaves it unchanged.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) pointer, options(nomem, preserves_flags));
    }
    pointer
}

fn table_ptr(physical: u64) -> *mut PageTable {
    (memory::phys_offset() + physical) as *mut PageTable
}

fn check_wx(flags: PageTableFlags) -> bool {
    !flags.contains(PageTableFlags::WRITABLE) || flags.contains(PageTableFlags::NO_EXECUTE)
}

const fn leaf_address(p4: usize, p3: usize, p2: usize, p1: usize) -> u64 {
    ((p4 as u64) << 39) | ((p3 as u64) << 30) | ((p2 as u64) << 21) | ((p1 as u64) << 12)
}
