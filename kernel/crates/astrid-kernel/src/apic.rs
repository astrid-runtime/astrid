//! Legacy PIC masking and local xAPIC timer bring-up (MMIO via the physical
//! memory mapping). No calibration and no timing claims: the timer exists only
//! to prove interrupt delivery under the frozen machine contract.

use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::Msr;

/// Architectural default physical base of the local APIC MMIO window.
const LAPIC_PHYS_BASE: u64 = 0xFEE0_0000;

// Local APIC register offsets.
const REG_SVR: u64 = 0x0F0; // spurious interrupt vector
const REG_EOI: u64 = 0x0B0;
const REG_LVT_TIMER: u64 = 0x320;
const REG_TIMER_INITIAL: u64 = 0x380;
const REG_TIMER_DIVIDE: u64 = 0x3E0;

const IA32_APIC_BASE: u32 = 0x1B;

/// Interrupt vectors we drive.
pub const TIMER_VECTOR: u8 = 32;
pub const SPURIOUS_VECTOR: u8 = 255;

const LVT_MASKED: u32 = 1 << 16;
const LVT_PERIODIC: u32 = 1 << 17;

/// Virtual base of the LAPIC MMIO window (physical base + phys offset).
static LAPIC_VIRT_BASE: AtomicU64 = AtomicU64::new(0);

#[inline]
fn lapic_ptr(reg: u64) -> *mut u32 {
    (LAPIC_VIRT_BASE.load(Ordering::Relaxed) + reg) as *mut u32
}

#[inline]
fn read_reg(reg: u64) -> u32 {
    // SAFETY: LAPIC MMIO window is identity-offset mapped and 4-byte aligned.
    unsafe { core::ptr::read_volatile(lapic_ptr(reg)) }
}

#[inline]
fn write_reg(reg: u64, val: u32) {
    // SAFETY: LAPIC MMIO window is identity-offset mapped and 4-byte aligned.
    unsafe { core::ptr::write_volatile(lapic_ptr(reg), val) }
}

/// Remap the 8259 PICs off the exception vector range and mask every line, so
/// only the local APIC delivers interrupts.
fn disable_legacy_pic() {
    let mut cmd1: Port<u8> = Port::new(0x20);
    let mut data1: Port<u8> = Port::new(0x21);
    let mut cmd2: Port<u8> = Port::new(0xA0);
    let mut data2: Port<u8> = Port::new(0xA1);
    // SAFETY: standard ICW1-ICW4 init sequence, then mask all IRQ lines.
    unsafe {
        cmd1.write(0x11); // ICW1: init + ICW4 present
        cmd2.write(0x11);
        data1.write(0x20); // ICW2: PIC1 vectors 0x20..
        data2.write(0x28); // ICW2: PIC2 vectors 0x28..
        data1.write(0x04); // ICW3: slave on IRQ2
        data2.write(0x02);
        data1.write(0x01); // ICW4: 8086 mode
        data2.write(0x01);
        data1.write(0xFF); // mask all
        data2.write(0xFF);
    }
}

/// Enable the local APIC and start its timer in periodic mode. `phys_offset`
/// is the base of the full physical-memory mapping.
pub fn init(phys_offset: u64) {
    LAPIC_VIRT_BASE.store(phys_offset + LAPIC_PHYS_BASE, Ordering::Relaxed);

    disable_legacy_pic();

    // Ensure the LAPIC is globally enabled (xAPIC / MMIO mode) via the MSR.
    let mut base_msr = Msr::new(IA32_APIC_BASE);
    // SAFETY: reading and setting the global-enable bit of IA32_APIC_BASE.
    unsafe {
        let v = base_msr.read();
        base_msr.write(v | (1 << 11));
    }

    // Software-enable the APIC and set the spurious vector.
    write_reg(REG_SVR, 0x100 | SPURIOUS_VECTOR as u32);

    // Periodic timer: divide by 16, an initial count that yields visible ticks
    // under TCG. The value is arbitrary — no timing claim is made.
    write_reg(REG_TIMER_DIVIDE, 0b0011);
    write_reg(REG_LVT_TIMER, TIMER_VECTOR as u32 | LVT_PERIODIC);
    write_reg(REG_TIMER_INITIAL, 0x0010_0000);
}

/// Mask the LVT timer so no further ticks are delivered.
pub fn mask_timer() {
    let cur = read_reg(REG_LVT_TIMER);
    write_reg(REG_LVT_TIMER, cur | LVT_MASKED);
}

/// Signal end-of-interrupt to the local APIC.
pub fn eoi() {
    write_reg(REG_EOI, 0);
}
