//! Legacy PIC masking and local xAPIC timer bring-up (MMIO via the physical
//! memory mapping). No calibration and no timing claims: the timer exists only
//! to prove interrupt delivery under the experimental TCG machine contract.

use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::Msr;

/// Architectural default physical base of the local APIC MMIO window.
const LAPIC_PHYS_BASE: u64 = 0xFEE0_0000;

const REG_SVR: u64 = 0x0F0;
const REG_EOI: u64 = 0x0B0;
const REG_LVT_TIMER: u64 = 0x320;
const REG_TIMER_INITIAL: u64 = 0x380;
const REG_TIMER_DIVIDE: u64 = 0x3E0;

const IA32_APIC_BASE: u32 = 0x1B;

pub const TIMER_VECTOR: u8 = 32;
pub const SPURIOUS_VECTOR: u8 = 255;

const LVT_PERIODIC: u32 = 1 << 17;
const LVT_MASKED: u32 = 1 << 16;

static LAPIC_VIRT_BASE: AtomicU64 = AtomicU64::new(0);

#[inline]
fn lapic_ptr(reg: u64) -> *mut u32 {
    (LAPIC_VIRT_BASE.load(Ordering::Relaxed) + reg) as *mut u32
}

#[inline]
fn write_reg(reg: u64, val: u32) {
    // SAFETY: LAPIC MMIO window is identity-offset mapped and 4-byte aligned.
    unsafe { core::ptr::write_volatile(lapic_ptr(reg), val) }
}

fn disable_legacy_pic() {
    let mut cmd1: Port<u8> = Port::new(0x20);
    let mut data1: Port<u8> = Port::new(0x21);
    let mut cmd2: Port<u8> = Port::new(0xA0);
    let mut data2: Port<u8> = Port::new(0xA1);
    // SAFETY: standard ICW1-ICW4 init sequence, then mask all IRQ lines.
    unsafe {
        cmd1.write(0x11);
        cmd2.write(0x11);
        data1.write(0x20);
        data2.write(0x28);
        data1.write(0x04);
        data2.write(0x02);
        data1.write(0x01);
        data2.write(0x01);
        data1.write(0xFF);
        data2.write(0xFF);
    }
}

/// Enable the local APIC and start its timer in periodic mode.
pub fn init(phys_offset: u64) {
    LAPIC_VIRT_BASE.store(phys_offset + LAPIC_PHYS_BASE, Ordering::Relaxed);
    disable_legacy_pic();

    let mut base_msr = Msr::new(IA32_APIC_BASE);
    // SAFETY: reading and setting the global-enable bit of IA32_APIC_BASE.
    unsafe {
        let v = base_msr.read();
        base_msr.write(v | (1 << 11));
    }

    write_reg(REG_SVR, 0x100 | u32::from(SPURIOUS_VECTOR));
    // Divide by 16; initial count is arbitrary. No timing claim.
    write_reg(REG_TIMER_DIVIDE, 0b0011);
    write_reg(REG_LVT_TIMER, u32::from(TIMER_VECTOR) | LVT_PERIODIC);
    write_reg(REG_TIMER_INITIAL, 0x0010_0000);
}

pub fn mask_timer() {
    write_reg(
        REG_LVT_TIMER,
        u32::from(TIMER_VECTOR) | LVT_PERIODIC | LVT_MASKED,
    );
}

pub fn unmask_timer() {
    write_reg(REG_LVT_TIMER, u32::from(TIMER_VECTOR) | LVT_PERIODIC);
    write_reg(REG_TIMER_INITIAL, 0x0010_0000);
}

pub fn eoi() {
    write_reg(REG_EOI, 0);
}
