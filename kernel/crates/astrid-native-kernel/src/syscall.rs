//! Ring-3 entry/exit mechanism: `syscall`/`sysret` bring-up, the naked syscall
//! entry stub, the xv6-style scheduler continuation (`context_enter` /
//! `context_switch_back`), and the Rust syscall dispatcher.
//!
//! No `swapgs` and no per-CPU GS base: kernel statics are globals. The syscall
//! stub loads the running domain's kernel stack from [`CURRENT_KSTACK_TOP`].
//! `context_enter` saves the scheduler's callee-saved registers and stack into
//! the domain's continuation slot and `iretq`s into ring 3; any path that
//! terminates or suspends the domain calls [`context_switch_back`], which
//! restores that continuation so `context_enter` *returns* to its caller with a
//! [`crate::domain::RunOutcome`] tag. Interrupt/fault kill paths never `iretq`
//! back to user — they restore the continuation.

use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::registers::control::Cr3;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::VirtAddr;

use crate::gdt;

/// Ring-3 selectors, fixed by the GDT append order (asserted in [`init`]).
const USER_CS: u64 = 0x23;
const USER_SS: u64 = 0x1b;
/// User RFLAGS at entry: reserved bit 1 set, IF (bit 9) set so the timer can
/// preempt ring 3.
const USER_RFLAGS: u64 = 0x202;

/// Continuation outcome tags passed through [`context_switch_back`].
pub const OUT_EXITED: u64 = 0;
pub const OUT_KILLED_PF: u64 = 1;
pub const OUT_KILLED_GP: u64 = 2;
pub const OUT_QUOTA: u64 = 3;
/// M3: the domain suspended itself at a `recv` boundary (blocking IPC). It saved
/// its user continuation into the domain slot and is now `Blocked`; the
/// scheduler must not finish/reclaim it — it resumes on a later delivery.
pub const OUT_BLOCKED: u64 = 4;

/// Kernel-stack top for the running domain; loaded by the syscall stub.
pub static CURRENT_KSTACK_TOP: AtomicU64 = AtomicU64::new(0);
/// Address of the running domain's continuation save slot (`*mut u64`).
pub static CURRENT_SAVE_SLOT: AtomicU64 = AtomicU64::new(0);
/// Exit code stashed by `sys_exit` for the scheduler to read on return.
pub static LAST_EXIT_CODE: AtomicU64 = AtomicU64::new(0);
/// Boot PML4 physical address, restored on every switch back to the scheduler.
static BOOT_CR3: AtomicU64 = AtomicU64::new(0);
/// Scratch for the user `rsp` across the syscall stack switch (single hart,
/// interrupts off in the syscall path — no re-entrancy).
static USER_RSP_SCRATCH: AtomicU64 = AtomicU64::new(0);

/// Enable `syscall`/`sysret` and program STAR/LSTAR/SFMASK. Must run after the
/// GDT is loaded.
pub fn init() {
    let (frame, _) = Cr3::read();
    BOOT_CR3.store(frame.start_address().as_u64(), Ordering::SeqCst);

    // The naked entry constants assume this GDT layout.
    assert!(
        gdt::user_code_selector().0 == USER_CS as u16,
        "user code selector must be 0x23"
    );
    assert!(
        gdt::user_data_selector().0 == USER_SS as u16,
        "user data selector must be 0x1b"
    );

    // SAFETY: enabling SCE and NXE via a read-modify-write that preserves LME/
    // LMA and all other EFER bits; both are required for ring-3 syscalls + NX.
    unsafe {
        Efer::update(|f| {
            f.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
            f.insert(EferFlags::NO_EXECUTE_ENABLE);
        });
    }

    Star::write(
        gdt::user_code_selector(),
        gdt::user_data_selector(),
        gdt::kernel_code_selector(),
        gdt::kernel_data_selector(),
    )
    .expect("STAR selector layout");
    LStar::write(VirtAddr::new(syscall_entry as *const () as u64));
    // Clear IF on syscall entry: the kernel syscall path runs with interrupts
    // off until it chooses otherwise.
    SFMask::write(RFlags::INTERRUPT_FLAG);
}

/// Arm the per-run globals the entry stub and continuation read. Called by the
/// scheduler with interrupts disabled before entering ring 3.
pub fn arm(kstack_top: u64, save_slot: u64) {
    CURRENT_KSTACK_TOP.store(kstack_top, Ordering::SeqCst);
    CURRENT_SAVE_SLOT.store(save_slot, Ordering::SeqCst);
    gdt::set_kernel_stack(VirtAddr::new(kstack_top));
}

/// Save the scheduler continuation into `*save_slot`, switch to `cr3`, and
/// `iretq` into ring 3 at `user_rip` with stack `user_rsp`, entering with
/// `rax=entry_rax` and `rdx=entry_rdx` and every OTHER GP register zeroed. Does
/// not return normally: it returns (with the outcome tag in `rax`) only when a
/// later [`context_switch_back`] restores the continuation.
///
/// First run of a domain passes `entry_rax=0, entry_rdx=0` (identical to the
/// M2 all-zero entry). Resuming a `Blocked` domain passes the delivered
/// `(status, data)` in `(entry_rax, entry_rdx)` so a blocked `recv` returns its
/// result. The M2 infoleak defense is preserved: every register other than the
/// two entry values is still zeroed before `iretq`.
///
/// # Safety
/// `save_slot` must point at a live `u64`; `cr3` must be a valid PML4 that maps
/// the kernel; `user_rip`/`user_rsp` must be valid user mappings in that space.
#[unsafe(naked)]
pub unsafe extern "C" fn context_enter(
    save_slot: *mut u64,
    user_rip: u64,
    user_rsp: u64,
    cr3: u64,
    entry_rax: u64,
    entry_rdx: u64,
) -> u64 {
    // Args (SysV): rdi=save_slot, rsi=user_rip, rdx=user_rsp, rcx=cr3,
    // r8=entry_rax, r9=entry_rdx.
    naked_asm!(
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",   // save scheduler rsp into the continuation slot
        "mov cr3, rcx",     // switch to the domain page table
        "push {uss}",       // SS
        "push rdx",         // RSP (user)
        "push {urfl}",      // RFLAGS
        "push {ucs}",       // CS
        "push rsi",         // RIP (user)
        // Zero every GP register (no kernel value leaks into ring 3), except
        // r8/r9 which still carry the two entry values.
        "xor eax, eax",
        "xor ebx, ebx",
        "xor ecx, ecx",
        "xor edx, edx",
        "xor esi, esi",
        "xor edi, edi",
        "xor ebp, ebp",
        "xor r10d, r10d",
        "xor r11d, r11d",
        "xor r12d, r12d",
        "xor r13d, r13d",
        "xor r14d, r14d",
        "xor r15d, r15d",
        // Place the entry values, then zero their source registers.
        "mov rax, r8",      // rax = entry_rax (status on resume, 0 on first run)
        "mov rdx, r9",      // rdx = entry_rdx (data on resume, 0 on first run)
        "xor r8d, r8d",
        "xor r9d, r9d",
        "iretq",
        uss = const USER_SS,
        urfl = const USER_RFLAGS,
        ucs = const USER_CS,
    );
}

/// Restore the scheduler continuation saved by [`context_enter`], returning
/// `outcome` from that `context_enter` call. Switches back to the boot page
/// table first. Never returns to its own caller.
///
/// # Safety
/// `save_slot` must be the same slot a live [`context_enter`] saved into.
#[unsafe(naked)]
pub unsafe extern "C" fn context_switch_back(save_slot: *mut u64, outcome: u64) -> ! {
    naked_asm!(
        "mov rax, qword ptr [rip + {boot_cr3}]",
        "mov cr3, rax",
        "mov rsp, [rdi]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "mov rax, rsi",   // return the outcome tag from context_enter
        "ret",
        boot_cr3 = sym BOOT_CR3,
    );
}

/// Naked `syscall` entry. Switches to the domain kernel stack, builds a
/// [`SyscallFrame`], calls [`syscall_dispatch`], and `sysretq`s back with the
/// status/value the dispatcher returned. Terminating syscalls never reach the
/// `sysretq` — the dispatcher diverts through [`context_switch_back`].
#[unsafe(naked)]
extern "C" fn syscall_entry() {
    naked_asm!(
        "mov qword ptr [rip + {scratch}], rsp",
        "mov rsp, qword ptr [rip + {kstack}]",
        "push qword ptr [rip + {scratch}]", // user rsp   (frame + 56)
        "push r11",                          // user rflags (frame + 48)
        "push rcx",                          // user rip    (frame + 40)
        "push r10",                          // arg4        (frame + 32)
        "push rdx",                          // arg3        (frame + 24)
        "push rsi",                          // arg2        (frame + 16)
        "push rdi",                          // arg1        (frame + 8)
        "push rax",                          // number      (frame + 0)
        "mov rdi, rsp",
        "call {dispatch}",
        "mov rcx, [rsp + 40]",  // user rip -> rcx for sysretq
        "mov r11, [rsp + 48]",  // user rflags -> r11 for sysretq
        "mov rsp, [rsp + 56]",  // restore user rsp
        "sysretq",
        scratch = sym USER_RSP_SCRATCH,
        kstack = sym CURRENT_KSTACK_TOP,
        dispatch = sym syscall_dispatch,
    );
}

/// The on-stack frame the entry stub builds; field order matches push order.
#[repr(C)]
struct SyscallFrame {
    number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    user_rip: u64,
    user_rflags: u64,
    user_rsp: u64,
}

/// Syscall return: status in `rax`, value in `rdx` (SysV two-word struct).
#[repr(C)]
struct SyscallRet {
    status: i64,
    value: u64,
}

/// The Rust syscall dispatcher. `sys_exit` diverges through the continuation
/// and never returns here.
///
/// # Safety
/// Called only from [`syscall_entry`] with a valid `SyscallFrame` pointer.
#[no_mangle]
unsafe extern "C" fn syscall_dispatch(frame: *mut SyscallFrame) -> SyscallRet {
    // SAFETY: the entry stub passes a pointer to a fully-populated frame on the
    // current kernel stack, live for this call.
    let f = unsafe { &*frame };
    match f.number {
        0 => crate::domain::sys_exit(f.arg1),
        1 => SyscallRet {
            status: 0,
            value: 0,
        },
        2 => {
            crate::domain::sys_note(f.arg1);
            SyscallRet {
                status: 0,
                value: 0,
            }
        },
        3 => {
            let (status, value) = crate::domain::sys_cap_rights(f.arg1);
            SyscallRet { status, value }
        },
        4 => {
            let (status, value) = crate::domain::sys_ep_create();
            SyscallRet { status, value }
        },
        5 => {
            let (status, value) = crate::domain::sys_send(f.arg1, f.arg2, f.arg3, f.arg4);
            SyscallRet { status, value }
        },
        6 => {
            // A blocking `recv` on an empty endpoint diverges through
            // `context_switch_back(OUT_BLOCKED)` and never returns here; the
            // ready path returns `(OK, data)` normally.
            let (status, value) = crate::domain::sys_recv(f.arg1, f.arg2, f.user_rip, f.user_rsp);
            SyscallRet { status, value }
        },
        7 => {
            let (status, value) = crate::domain::sys_revoke_tree(f.arg1);
            SyscallRet { status, value }
        },
        // M4 legibility ABI v0.
        8 => {
            let (status, value) = crate::domain::sys_legible_schema(f.arg1, f.arg2);
            SyscallRet { status, value }
        },
        9 => {
            let (status, value) = crate::domain::sys_legible_enumerate(f.arg1, f.arg2);
            SyscallRet { status, value }
        },
        10 => {
            let (status, value) = crate::domain::sys_legible_subscribe(f.arg1);
            SyscallRet { status, value }
        },
        11 => {
            let (status, value) = crate::domain::sys_legible_get(f.arg1, f.arg2, f.arg3, f.arg4);
            SyscallRet { status, value }
        },
        12 => {
            let (status, value) = crate::domain::sys_cap_object(f.arg1);
            SyscallRet { status, value }
        },
        // M5 audit chain (ADR-K7): the read/enumerate surface. Ring 0 orders and
        // roots; user space verifies. All are capability-gated (Audit class).
        13 => {
            let (status, value) = crate::domain::sys_audit_len(f.arg1);
            SyscallRet { status, value }
        },
        14 => {
            let (status, value) = crate::domain::sys_audit_root(f.arg1);
            SyscallRet { status, value }
        },
        15 => {
            let (status, value) = crate::domain::sys_audit_get(f.arg1, f.arg2, f.arg3);
            SyscallRet { status, value }
        },
        16 => {
            let (status, value) = crate::domain::sys_audit_enumerate(f.arg1);
            SyscallRet { status, value }
        },
        _ => SyscallRet {
            status: -1,
            value: 0,
        },
    }
}
