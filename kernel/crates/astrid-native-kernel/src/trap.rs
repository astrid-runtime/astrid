//! Trap entry: naked-function ISR stubs and the single Rust trap handler.
//!
//! The pinned stable toolchain does not offer the nightly `extern
//! "x86-interrupt"` ABI, so each vector's entry is a naked-function stub
//! that normalizes the stack into a [`TrapFrame`] and calls one C-ABI handler.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::{apic, serial};

/// Set by a self-test immediately before it provokes an expected page fault.
pub static EXPECT_FAULT: AtomicBool = AtomicBool::new(false);
/// Instruction pointer the page-fault handler restores for an expected fault.
pub static RECOVERY_RIP: AtomicU64 = AtomicU64::new(0);
/// Count of APIC timer ticks observed so far.
pub static TICK: AtomicU32 = AtomicU32::new(0);

/// Registers saved by the common stub plus the CPU-pushed interrupt frame.
#[repr(C)]
pub struct TrapFrame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const VECTOR_BREAKPOINT: u8 = 3;
const VECTOR_PAGE_FAULT: u8 = 14;
pub const VECTOR_TIMER: u8 = 32;
pub const VECTOR_SPURIOUS: u8 = 255;

/// The one Rust trap handler. Mutations to `frame.rip` take effect on `iretq`.
///
/// # Safety
/// Called only from the naked common stub with a valid `TrapFrame` pointer.
#[unsafe(no_mangle)]
unsafe extern "C" fn rust_trap_handler(frame: *mut TrapFrame) {
    // SAFETY: the common stub passes a pointer to a fully-populated TrapFrame
    // that lives on the current stack for the duration of this call.
    let f = unsafe { &mut *frame };
    let vector = f.vector as u8;
    match vector {
        VECTOR_TIMER => handle_timer(),
        VECTOR_SPURIOUS => {},
        VECTOR_BREAKPOINT => serial::ev_fault(VECTOR_BREAKPOINT, f.error_code, f.rip),
        VECTOR_PAGE_FAULT => handle_page_fault(f),
        _ => {
            serial::ev_fault(vector, f.error_code, f.rip);
            serial::ev_halt(false);
            serial::exit_qemu(false);
        },
    }
}

fn handle_timer() {
    let n = TICK.fetch_add(1, Ordering::SeqCst) + 1;
    if n <= 8 {
        serial::ev_apic_timer_tick(n);
    }
    if n >= 8 {
        apic::mask_timer();
    }
    apic::eoi();
}

fn handle_page_fault(f: &mut TrapFrame) {
    serial::ev_fault(VECTOR_PAGE_FAULT, f.error_code, f.rip);
    if EXPECT_FAULT.swap(false, Ordering::SeqCst) {
        f.rip = RECOVERY_RIP.load(Ordering::SeqCst);
        return;
    }
    serial::ev_halt(false);
    serial::exit_qemu(false);
}

#[unsafe(naked)]
extern "C" fn isr_common() {
    core::arch::naked_asm!(
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rbp",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",
        "mov rdi, rsp",
        "mov rbp, rsp",
        "and rsp, -16",
        "call {handler}",
        "mov rsp, rbp",
        "pop rax",
        "pop rbx",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop rbp",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",
        "add rsp, 16",
        "iretq",
        handler = sym rust_trap_handler,
    );
}

macro_rules! isr_noerr {
    ($name:ident, $vec:literal) => {
        #[unsafe(naked)]
        pub extern "C" fn $name() {
            core::arch::naked_asm!(
                "push 0",
                concat!("push ", stringify!($vec)),
                "jmp {common}",
                common = sym isr_common,
            );
        }
    };
}

macro_rules! isr_err {
    ($name:ident, $vec:literal) => {
        #[unsafe(naked)]
        pub extern "C" fn $name() {
            core::arch::naked_asm!(
                concat!("push ", stringify!($vec)),
                "jmp {common}",
                common = sym isr_common,
            );
        }
    };
}

isr_noerr!(isr_0, 0);
isr_noerr!(isr_1, 1);
isr_noerr!(isr_2, 2);
isr_noerr!(isr_3, 3);
isr_noerr!(isr_4, 4);
isr_noerr!(isr_5, 5);
isr_noerr!(isr_6, 6);
isr_noerr!(isr_7, 7);
isr_err!(isr_8, 8);
isr_err!(isr_10, 10);
isr_err!(isr_11, 11);
isr_err!(isr_12, 12);
isr_err!(isr_13, 13);
isr_err!(isr_14, 14);
isr_noerr!(isr_16, 16);
isr_err!(isr_17, 17);
isr_noerr!(isr_18, 18);
isr_noerr!(isr_19, 19);
isr_noerr!(isr_20, 20);
isr_err!(isr_21, 21);
isr_noerr!(isr_28, 28);
isr_err!(isr_29, 29);
isr_err!(isr_30, 30);
isr_noerr!(isr_32, 32);
isr_noerr!(isr_255, 255);
