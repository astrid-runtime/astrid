//! GDT + TSS. The double-fault handler runs on a dedicated IST stack; ring-3
//! domains enter through the user code/data descriptors, and the CPU takes
//! `TSS.rsp0` when an interrupt or exception fires while CPL=3.
//!
//! Descriptor order is fixed by the `sysret` convention (charter mechanism):
//! kernel code, kernel data, user data, user code, TSS. `sysretq` derives
//! user CS from `STAR[63:48]+16` and user SS from `+8`, so user data must sit
//! immediately below user code.

use spin::Once;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::PrivilegeLevel;
use x86_64::VirtAddr;

/// IST slot used by the double-fault handler.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

const IST_STACK_SIZE: usize = 16 * 1024;

/// Dedicated double-fault stack. `static mut` is sound here: it is only ever
/// read (as an address) once, during single-threaded early boot.
static mut DOUBLE_FAULT_STACK: [u8; IST_STACK_SIZE] = [0; IST_STACK_SIZE];

/// The single TSS. Its `privilege_stack_table[0]` (rsp0) is rewritten before
/// every ring-3 entry via [`set_kernel_stack`]. Accessed only through raw
/// pointers: the GDT descriptor is built once from its address and no shared
/// reference is ever held while rsp0 is mutated (single hart, interrupts
/// disabled at the mutation site).
static mut TSS: TaskStateSegment = TaskStateSegment::new();

static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

/// Selectors installed in the GDT, in append order.
#[derive(Clone, Copy)]
struct Selectors {
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    user_code: SegmentSelector,
    user_data: SegmentSelector,
    tss: SegmentSelector,
}

/// User code selector carrying its required ring-3 RPL, for `iretq`/`STAR`.
pub fn user_code_selector() -> SegmentSelector {
    SegmentSelector::new(selectors().user_code.index(), PrivilegeLevel::Ring3)
}

/// User data selector carrying its required ring-3 RPL, for `iretq`/`STAR`.
pub fn user_data_selector() -> SegmentSelector {
    SegmentSelector::new(selectors().user_data.index(), PrivilegeLevel::Ring3)
}

/// Kernel code selector, for `STAR`'s syscall base.
pub fn kernel_code_selector() -> SegmentSelector {
    selectors().kernel_code
}

/// Kernel data selector, for `STAR`'s syscall stack segment.
pub fn kernel_data_selector() -> SegmentSelector {
    selectors().kernel_data
}

fn selectors() -> Selectors {
    GDT.get().expect("gdt not initialized").1
}

/// Build and load the GDT and TSS. Must run before the IDT is loaded so the
/// double-fault entry's IST index resolves to a valid stack.
pub fn init() {
    let df_base = VirtAddr::from_ptr(core::ptr::addr_of!(DOUBLE_FAULT_STACK));
    // SAFETY: exclusive early-boot initialization of the IST entry; no other
    // access to TSS exists yet.
    unsafe {
        (*core::ptr::addr_of_mut!(TSS)).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            df_base + IST_STACK_SIZE as u64;
    }
    // SAFETY: forms one shared reference to TSS to build its descriptor; after
    // this point TSS is touched only through raw pointers in `set_kernel_stack`.
    let tss_ref: &'static TaskStateSegment = unsafe { &*core::ptr::addr_of!(TSS) };

    let (gdt, selectors) = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());
        let user_data = gdt.append(Descriptor::user_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());
        let tss = gdt.append(Descriptor::tss_segment(tss_ref));
        (
            gdt,
            Selectors {
                kernel_code,
                kernel_data,
                user_code,
                user_data,
                tss,
            },
        )
    });
    gdt.load();
    // SAFETY: `selectors` reference GDT entries just installed. Reload CS with
    // the kernel code selector and set data/stack registers to the kernel data
    // selector; the bootloader's selectors are out of range in our GDT and an
    // `iretq` reloading a now-invalid SS would #GP.
    unsafe {
        CS::set_reg(selectors.kernel_code);
        SS::set_reg(selectors.kernel_data);
        DS::set_reg(selectors.kernel_data);
        ES::set_reg(selectors.kernel_data);
        load_tss(selectors.tss);
    }
}

/// Set `TSS.rsp0` — the stack the CPU switches to when an interrupt or
/// exception is taken while CPL=3. Called before every ring-3 entry with the
/// running domain's kernel-stack top, interrupts disabled.
pub fn set_kernel_stack(top: VirtAddr) {
    // SAFETY: single hart, interrupts disabled at the call site; writes only
    // the rsp0 field through a raw pointer and holds no reference to TSS.
    unsafe {
        core::ptr::addr_of_mut!((*core::ptr::addr_of_mut!(TSS)).privilege_stack_table[0])
            .write(top);
    }
}
