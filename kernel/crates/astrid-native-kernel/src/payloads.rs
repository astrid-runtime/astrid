//! Ring-3 scenario payloads. Each is a position-independent naked function
//! compiled into the kernel image and copied byte-for-byte into a domain's
//! fresh user code frame at [`crate::vm::USER_CODE_VA`]. Payloads use only the
//! `syscall` ABI and rip-relative / absolute-immediate operands — no reference
//! to any data outside their own bytes — so running them from a different
//! virtual address is sound.
//!
//! Syscall ABI: `rax` = number (0 exit, 1 yield, 2 note, 3 cap_rights); args in
//! `rdi`; returns status in `rax` (0 OK, negative error) and value in `rdx`.
//! Callee-saved registers (`rbx`, `r12`) survive syscalls, so payloads stash
//! intermediate results there. Every payload ends in an infinite loop as a
//! safety net; control never falls off the end into the copied tail.

use core::arch::naked_asm;

/// `sys_note(42)`, `sys_yield()`, `sys_exit(7)`.
#[unsafe(naked)]
pub extern "C" fn ring3_happy() {
    naked_asm!(
        "mov rax, 2",
        "mov rdi, 42",
        "syscall",
        "mov rax, 1",
        "syscall",
        "mov rax, 0",
        "mov rdi, 7",
        "syscall",
        "2:",
        "jmp 2b",
    );
}

/// Read a kernel higher-half address from ring 3 -> user page fault.
#[unsafe(naked)]
pub extern "C" fn ring3_kernel_read() {
    naked_asm!(
        "movabs rcx, 0xffff800000000000",
        "mov rax, [rcx]",
        "2:",
        "jmp 2b",
    );
}

/// Execute a privileged instruction (`hlt`) from ring 3 -> #GP.
#[unsafe(naked)]
pub extern "C" fn ring3_priv_insn() {
    naked_asm!("hlt", "2:", "jmp 2b",);
}

/// `sys_cap_rights(63)` (empty slot) and `sys_cap_rights(9999)` (out of range),
/// both expected to return BadCap (-2). Exit 0 iff both did, else exit 1.
#[unsafe(naked)]
pub extern "C" fn ring3_bad_cap() {
    naked_asm!(
        "mov rax, 3",
        "mov rdi, 63",
        "syscall",
        "cmp rax, -2",
        "jne 3f",
        "mov rax, 3",
        "mov rdi, 9999",
        "syscall",
        "cmp rax, -2",
        "jne 3f",
        "mov rax, 0",
        "mov rdi, 0",
        "syscall",
        "3:",
        "mov rax, 0",
        "mov rdi, 1",
        "syscall",
        "2:",
        "jmp 2b",
    );
}

/// `sys_cap_rights(5)` expecting OK/0b111, `sys_note(0xCAFE)` checkpoint (the
/// kernel revokes the object on this note), then `sys_cap_rights(5)` again
/// expecting StaleCap (-3). Exit 0 iff first was OK with rights 0b111 and second
/// was StaleCap, else exit 1.
#[unsafe(naked)]
pub extern "C" fn ring3_stale_cap() {
    naked_asm!(
        "mov rax, 3",
        "mov rdi, 5",
        "syscall",
        "mov rbx, rax",
        "mov r12, rdx",
        "mov rax, 2",
        "mov rdi, 0xCAFE",
        "syscall",
        "mov rax, 3",
        "mov rdi, 5",
        "syscall",
        "cmp rbx, 0",
        "jne 3f",
        "cmp r12, 7",
        "jne 3f",
        "cmp rax, -3",
        "jne 3f",
        "mov rax, 0",
        "mov rdi, 0",
        "syscall",
        "3:",
        "mov rax, 0",
        "mov rdi, 1",
        "syscall",
        "2:",
        "jmp 2b",
    );
}

/// Infinite loop with interrupts enabled in ring 3 -> timer preemption -> quota
/// kill. Proof that a hostile domain cannot hold the CPU.
#[unsafe(naked)]
pub extern "C" fn ring3_runaway() {
    naked_asm!("2:", "jmp 2b",);
}

/// Clean run in a reused slot: `sys_note(7)`, `sys_yield()`, `sys_exit(0)`.
#[unsafe(naked)]
pub extern "C" fn ring3_reuse() {
    naked_asm!(
        "mov rax, 2",
        "mov rdi, 7",
        "syscall",
        "mov rax, 1",
        "syscall",
        "mov rax, 0",
        "mov rdi, 0",
        "syscall",
        "2:",
        "jmp 2b",
    );
}
