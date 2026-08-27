//! GDT + TSS. The double-fault handler runs on a dedicated IST stack; the
//! privilege-stack entry is armed only while a native domain is running.

use spin::Once;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, DS, ES, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

const IST_STACK_SIZE: usize = 16 * 1024;

static mut DOUBLE_FAULT_STACK: [u8; IST_STACK_SIZE] = [0; IST_STACK_SIZE];
static mut TSS: TaskStateSegment = TaskStateSegment::new();
static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

#[derive(Clone, Copy)]
struct Selectors {
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    user_code: SegmentSelector,
    user_data: SegmentSelector,
    tss: SegmentSelector,
}

/// Build and load the GDT and TSS. Must run before the IDT is loaded so the
/// double-fault entry's IST index resolves to a valid stack.
pub fn init() {
    let df_base = VirtAddr::from_ptr(core::ptr::addr_of!(DOUBLE_FAULT_STACK));
    // SAFETY: exclusive early-boot initialization of the IST entry.
    unsafe {
        (*core::ptr::addr_of_mut!(TSS)).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            df_base + IST_STACK_SIZE as u64;
    }
    // SAFETY: one shared reference to TSS to build its descriptor.
    let tss_ref: &'static TaskStateSegment = unsafe { &*core::ptr::addr_of!(TSS) };

    let (gdt, selectors) = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());
        let user_data = gdt.append(Descriptor::user_data_segment());
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
    // SAFETY: selectors reference GDT entries just installed.
    unsafe {
        CS::set_reg(selectors.kernel_code);
        SS::set_reg(selectors.kernel_data);
        DS::set_reg(selectors.kernel_data);
        ES::set_reg(selectors.kernel_data);
        load_tss(selectors.tss);
    }
}

/// Arm the guarded kernel transition stack for one lower-privilege execution.
pub fn set_privilege_stack(end: VirtAddr) {
    // SAFETY: TSS is exclusively owned by boot and the single-domain manager.
    unsafe {
        (*core::ptr::addr_of_mut!(TSS)).privilege_stack_table[0] = end;
    }
}

pub fn user_selectors() -> (SegmentSelector, SegmentSelector) {
    let (_, selectors) = GDT.get().expect("GDT not initialized");
    (selectors.user_code, selectors.user_data)
}

pub fn kernel_selectors() -> (SegmentSelector, SegmentSelector) {
    let (_, selectors) = GDT.get().expect("GDT not initialized");
    (selectors.kernel_code, selectors.kernel_data)
}
