//! Minimal GDT + TSS so the double-fault handler runs on a dedicated IST stack.

use spin::Once;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// IST slot used by the double-fault handler.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

const IST_STACK_SIZE: usize = 16 * 1024;

/// Dedicated double-fault stack. `static mut` is sound here: it is only ever
/// read (as an address) once, during single-threaded early boot.
static mut DOUBLE_FAULT_STACK: [u8; IST_STACK_SIZE] = [0; IST_STACK_SIZE];

static TSS: Once<TaskStateSegment> = Once::new();
static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

struct Selectors {
    code: SegmentSelector,
    tss: SegmentSelector,
}

fn build_tss() -> &'static TaskStateSegment {
    TSS.call_once(|| {
        let mut tss = TaskStateSegment::new();
        // Stacks grow down: hand the CPU the top of the IST region.
        let base = VirtAddr::from_ptr(core::ptr::addr_of!(DOUBLE_FAULT_STACK));
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = base + IST_STACK_SIZE as u64;
        tss
    })
}

/// Build and load the GDT and TSS. Must run before the IDT is loaded so the
/// double-fault entry's IST index resolves to a valid stack.
pub fn init() {
    let tss = build_tss();
    let (gdt, selectors) = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let code = gdt.append(Descriptor::kernel_code_segment());
        let tss_sel = gdt.append(Descriptor::tss_segment(tss));
        (gdt, Selectors { code, tss: tss_sel })
    });
    gdt.load();
    // SAFETY: `selectors` reference GDT entries just installed. We also reset
    // the data/stack segment registers to the null selector: the bootloader's
    // selectors are out of range in our 3-entry GDT, and `iretq` reloading a
    // now-invalid SS would #GP. Null data/stack selectors are valid in ring-0
    // long mode.
    unsafe {
        CS::set_reg(selectors.code);
        SS::set_reg(SegmentSelector::NULL);
        DS::set_reg(SegmentSelector::NULL);
        ES::set_reg(SegmentSelector::NULL);
        load_tss(selectors.tss);
    }
}
