//! IDT construction. Each architectural exception vector, plus the APIC timer
//! (32) and spurious (255) vectors, points at its naked-function stub via the
//! stable `Entry::set_handler_addr` path.

use core::sync::atomic::Ordering;

use spin::Once;
use x86_64::PrivilegeLevel;
use x86_64::VirtAddr;
use x86_64::structures::idt::InterruptDescriptorTable;

use crate::gdt::DOUBLE_FAULT_IST_INDEX;
use crate::trap;

/// Number of architectural exception vectors covered (0..=31).
pub const EXCEPTION_VECTORS: u32 = 32;

static IDT: Once<InterruptDescriptorTable> = Once::new();

fn addr(f: extern "C" fn()) -> VirtAddr {
    VirtAddr::new(f as usize as u64)
}

/// Build and load the IDT.
pub fn init_idt() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        // SAFETY: every stub is a valid, resident naked-function entry that
        // conforms to the interrupt stack layout the common tail expects.
        unsafe {
            idt.divide_error.set_handler_addr(addr(trap::isr_0));
            idt.debug.set_handler_addr(addr(trap::isr_1));
            idt.non_maskable_interrupt
                .set_handler_addr(addr(trap::isr_2));
            // Domain fixtures return to ring 0 through breakpoint, so the
            // software exception gate must be callable from CPL 3.
            idt.breakpoint
                .set_handler_addr(addr(trap::isr_3))
                .set_privilege_level(PrivilegeLevel::Ring3);
            idt.overflow.set_handler_addr(addr(trap::isr_4));
            idt.bound_range_exceeded.set_handler_addr(addr(trap::isr_5));
            idt.invalid_opcode.set_handler_addr(addr(trap::isr_6));
            idt.device_not_available.set_handler_addr(addr(trap::isr_7));
            idt.double_fault
                .set_handler_addr(addr(trap::isr_8))
                .set_stack_index(DOUBLE_FAULT_IST_INDEX);
            idt.invalid_tss.set_handler_addr(addr(trap::isr_10));
            idt.segment_not_present.set_handler_addr(addr(trap::isr_11));
            idt.stack_segment_fault.set_handler_addr(addr(trap::isr_12));
            idt.general_protection_fault
                .set_handler_addr(addr(trap::isr_13));
            idt.page_fault.set_handler_addr(addr(trap::isr_14));
            idt.x87_floating_point.set_handler_addr(addr(trap::isr_16));
            idt.alignment_check.set_handler_addr(addr(trap::isr_17));
            idt.machine_check.set_handler_addr(addr(trap::isr_18));
            idt.simd_floating_point.set_handler_addr(addr(trap::isr_19));
            idt.virtualization.set_handler_addr(addr(trap::isr_20));
            idt.cp_protection_exception
                .set_handler_addr(addr(trap::isr_21));
            idt.hv_injection_exception
                .set_handler_addr(addr(trap::isr_28));
            idt.vmm_communication_exception
                .set_handler_addr(addr(trap::isr_29));
            idt.security_exception.set_handler_addr(addr(trap::isr_30));
            idt[trap::VECTOR_TIMER].set_handler_addr(addr(trap::isr_32));
            idt[trap::VECTOR_SPURIOUS].set_handler_addr(addr(trap::isr_255));
        }
        idt
    });
    idt.load();
}

pub fn tick_count() -> u32 {
    trap::TICK.load(Ordering::SeqCst)
}
