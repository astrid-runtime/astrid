//! Ring-3 scenario payloads. Each is a position-independent naked function
//! compiled into the kernel image and copied byte-for-byte into a domain's
//! fresh user code frame at [`crate::vm::USER_CODE_VA`]. Payloads use only the
//! `syscall` ABI and rip-relative / absolute-immediate operands — no reference
//! to any data outside their own bytes — so running them from a different
//! virtual address is sound.
//!
//! Syscall ABI: `rax` = number (0 exit, 1 yield, 2 note, 3 cap_rights,
//! 4 ep_create, 5 send, 6 recv, 7 revoke_tree, 8 legible_schema,
//! 9 legible_enumerate, 10 legible_subscribe, 11 legible_get, 12 cap_object);
//! args in `rdi, rsi, rdx, r10`;
//! returns status in `rax` (0 OK, negative error) and value in `rdx`.
//! Callee-saved registers (`rbx`, `r12`) survive NON-blocking syscalls, so
//! payloads stash intermediate results there. Every payload ends in an infinite
//! loop as a safety net; control never falls off the end into the copied tail.
//!
//! **M3 blocking-ABI rule:** a **blocking** syscall (`recv`, number 6) may
//! clobber EVERY general register except its return `rax` (status) and `rdx`
//! (data). This is because a `recv` that blocks is resumed by a fresh
//! `context_enter` that only restores `(rax, rdx)` and zeroes the rest — the
//! full user register file is not saved at block time. Payloads must therefore
//! NOT hold live values in registers across a `recv`; they reload constants
//! afterward. Non-blocking syscalls preserve callee-saved registers as before.
//!
//! Slot sentinel: a `0xFFFF_FFFF` slot argument to `send` (transfer slot) or
//! `recv` (accept slot) means "none" — emitted as `mov e{dx,si}, -1`.

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

// ---- M3 IPC payloads -------------------------------------------------------

/// Scenario `ipc_rendezvous` receiver: `recv(ep=0, accept=none)`; exit 0 iff the
/// delivered data word is `0xBEEF`, else exit 1. The `recv` blocks until the
/// sender delivers; only `rax`/`rdx` are valid afterward (blocking-ABI rule).
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_r_rendezvous() {
    naked_asm!(
        "mov rax, 6",
        "mov rdi, 0",
        "mov esi, -1", // accept slot = none
        "syscall",
        "cmp rdx, 0xBEEF",
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

/// Scenario `ipc_rendezvous` sender: `send(ep=0, data=0xBEEF, xfer=none)`,
/// `exit(0)`.
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_s_rendezvous() {
    naked_asm!(
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 0xBEEF",
        "mov edx, -1", // transfer slot = none
        "xor r10, r10",
        "syscall",
        "mov rax, 0",
        "mov rdi, 0",
        "syscall",
        "2:",
        "jmp 2b",
    );
}

/// Scenario `ipc_cap_transfer` sender: transfer the slot-10 cap with a shrink
/// mask of `0b011`, then `exit(0)`.
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_s_xfer3() {
    naked_asm!(
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 0xD1",
        "mov rdx, 10", // transfer cap slot 10
        "mov r10, 3",  // grant mask 0b011
        "syscall",
        "mov rax, 0",
        "mov rdi, 0",
        "syscall",
        "2:",
        "jmp 2b",
    );
}

/// Scenario `ipc_cap_transfer` receiver: `recv(ep=0, accept=20)`, then
/// `cap_rights(20)`; exit 0 iff the recv status is OK and the observed rights
/// equal `0b011` (the intersection `0b111 ∩ 0b011`), else exit 1.
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_r_xfer_check3() {
    naked_asm!(
        "mov rax, 6",
        "mov rdi, 0",
        "mov rsi, 20", // accept transferred cap into slot 20
        "syscall",
        "mov rax, 3",
        "mov rdi, 20",
        "syscall",
        "cmp rax, 0",
        "jne 3f",
        "cmp rdx, 3",
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

/// Scenario `ipc_no_widen` sender: hold `0b001` in slot 10, transfer with mask
/// `0b111`; the kernel must NOT widen. `exit(0)`.
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_s_xfer7() {
    naked_asm!(
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 0xD2",
        "mov rdx, 10", // transfer cap slot 10
        "mov r10, 7",  // grant mask 0b111 (must not widen source 0b001)
        "syscall",
        "mov rax, 0",
        "mov rdi, 0",
        "syscall",
        "2:",
        "jmp 2b",
    );
}

/// Scenario `ipc_no_widen` receiver: `recv(ep=0, accept=20)`, then
/// `cap_rights(20)`; exit 0 iff observed rights equal `0b001` (never widened).
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_r_xfer_check1() {
    naked_asm!(
        "mov rax, 6",
        "mov rdi, 0",
        "mov rsi, 20",
        "syscall",
        "mov rax, 3",
        "mov rdi, 20",
        "syscall",
        "cmp rax, 0",
        "jne 3f",
        "cmp rdx, 1", // rights must be exactly 0b001
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

/// Scenario `ipc_scoped_revoke` sender: transfer slot-10 cap (mask `0b011`),
/// then a second cap-less `send(data=2)` (a queued checkpoint), then `exit(0)`.
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_s_revoke() {
    naked_asm!(
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 1",
        "mov rdx, 10",
        "mov r10, 3",
        "syscall",
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 2",
        "mov edx, -1",
        "xor r10, r10",
        "syscall",
        "mov rax, 0",
        "mov rdi, 0",
        "syscall",
        "2:",
        "jmp 2b",
    );
}

/// Scenario `ipc_scoped_revoke` receiver: `recv(ep=0, accept=20)`, validate the
/// cap (`cap_rights(20)` → OK/`0b011`, stashed in callee-saved `rbx`/`r12`),
/// `note(0x5EED)` (the kernel note-hook fires the scoped revoke on the source
/// subtree), then `cap_rights(20)` again which must now be `Revoked (-6)`. Exit
/// 0 iff the first was OK with rights `0b011` and the second was `-6`.
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_r_revoke() {
    naked_asm!(
        "mov rax, 6",
        "mov rdi, 0",
        "mov rsi, 20",
        "syscall",
        // First validation (non-blocking from here: rbx/r12 survive).
        "mov rax, 3",
        "mov rdi, 20",
        "syscall",
        "mov rbx, rax", // status1
        "mov r12, rdx", // rights1
        // Checkpoint note that arms the kernel-side scoped revoke.
        "mov rax, 2",
        "mov rdi, 0x5EED",
        "syscall",
        // Second validation: must observe Revoked.
        "mov rax, 3",
        "mov rdi, 20",
        "syscall",
        "cmp rbx, 0",
        "jne 3f",
        "cmp r12, 3",
        "jne 3f",
        "cmp rax, -6",
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

/// Scenario `ipc_authority` receiver: holds only `EP_RECV`. First attempt a
/// `send` (must be `Denied (-4)` for lack of `EP_SEND`); if not denied, exit 1.
/// Then a legitimate blocking `recv`, then `exit(0)` when woken.
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_r_auth() {
    naked_asm!(
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 0",
        "mov edx, -1",
        "xor r10, r10",
        "syscall",
        "cmp rax, -4", // Denied
        "jne 3f",
        "mov rax, 6",
        "mov rdi, 0",
        "mov esi, -1",
        "syscall",
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

/// Scenario `ipc_authority` sender: attempt to transfer an EMPTY slot 41 (must
/// be `BadCap (-2)`); if not, exit 1. Then a legitimate `send(data=9)` that
/// wakes the receiver, then `exit(0)`.
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_s_auth() {
    naked_asm!(
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 1",
        "mov rdx, 41", // empty cap slot
        "mov r10, 1",
        "syscall",
        "cmp rax, -2", // BadCap
        "jne 3f",
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 9",
        "mov edx, -1",
        "xor r10, r10",
        "syscall",
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

/// Scenario `ipc_ep_full`: create a self-endpoint via `ep_create` (cap lands in
/// the first free slot = 0), send `EP_QUEUE_DEPTH` (4) messages that must all be
/// OK, then a 5th that must be `Full (-5)`. Exit 0 iff so. `rbx` is the loop
/// counter (survives the non-blocking `send`s).
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_d_full() {
    naked_asm!(
        "mov rax, 4", // ep_create -> cap in slot 0
        "syscall",
        "mov rbx, 4", // send four messages
        "4:",
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 0x11",
        "mov edx, -1",
        "xor r10, r10",
        "syscall",
        "cmp rax, 0",
        "jne 3f",
        "dec rbx",
        "jnz 4b",
        // Fifth send: the queue is full.
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 0x11",
        "mov edx, -1",
        "xor r10, r10",
        "syscall",
        "cmp rax, -5", // Full
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

/// Scenario `ipc_deadlock_guard`: a lone receiver blocks on `recv` with no
/// sender scheduled. The scheduler must detect all-blocked and kill it; this
/// payload's `exit` is never reached.
#[unsafe(naked)]
pub extern "C" fn ring3_ipc_r_deadlock() {
    naked_asm!(
        "mov rax, 6",
        "mov rdi, 0",
        "mov esi, -1",
        "syscall",
        "mov rax, 0",
        "mov rdi, 0",
        "syscall",
        "2:",
        "jmp 2b",
    );
}

// ---- M4 legibility reasoner payloads ---------------------------------------

/// Scenario `legible_reasoner` reasoner: a ring-3 tenant that derives a fact
/// about system authority purely from the kernel's emitted relations. It holds
/// an EP_RECV cap (slot 0), a `Legible` cap (slot 1), and will receive a
/// transferred `TestArtifact` cap (into slot 20) plus a second kernel-minted
/// reference to the same object (slot 21). It computes, from relation rows
/// ALONE: "how many capabilities in the system reference MY object O?".
///
/// Steps: `recv` the transfer (blocks; resumes with only `rax`/`rdx` valid);
/// `cap_object(20)` → O (stashed in callee-saved `r12`); `legible_enumerate`
/// REL_CAPABILITY → row count (`r13`); loop `row_index` 0..count reading
/// `COL_OBJECT_ID` via `legible_get`, incrementing `rbx` on a match with O;
/// `note(rbx)`; `exit(0)`. `legible_get` is non-blocking so the callee-saved
/// registers survive the loop.
#[unsafe(naked)]
pub extern "C" fn ring3_reasoner() {
    naked_asm!(
        // Blocking recv of the transferred cap into slot 20.
        "mov rax, 6",
        "mov rdi, 0",
        "mov rsi, 20",
        "syscall",
        // O = cap_object(20).
        "mov rax, 12",
        "mov rdi, 20",
        "syscall",
        "mov r12, rdx", // r12 = O
        // count = legible_enumerate(cap=1, REL_CAPABILITY=2).
        "mov rax, 9",
        "mov rdi, 1",
        "mov rsi, 2",
        "syscall",
        "mov r13, rdx", // r13 = row count
        "xor r14, r14", // r14 = row_index
        "xor rbx, rbx", // rbx = match counter
        "4:",
        "cmp r14, r13",
        "jae 5f",
        // val = legible_get(cap=1, REL_CAPABILITY=2, row=r14, col=COL_OBJECT_ID=2).
        "mov rax, 11",
        "mov rdi, 1",
        "mov rsi, 2",
        "mov rdx, r14",
        "mov r10, 2",
        "syscall",
        "cmp rdx, r12",
        "jne 6f",
        "inc rbx",
        "6:",
        "inc r14",
        "jmp 4b",
        "5:",
        // note(match count).
        "mov rax, 2",
        "mov rdi, rbx",
        "syscall",
        // exit(0).
        "mov rax, 0",
        "mov rdi, 0",
        "syscall",
        "2:",
        "jmp 2b",
    );
}

/// Scenario `legible_reasoner` source: holds a `TestArtifact` cap in slot 10 and
/// transfers it (full mask `0b111`) to the reasoner over the endpoint, creating
/// the real derivation edge + capability row the reasoner will find, then
/// `exit(0)`.
#[unsafe(naked)]
pub extern "C" fn ring3_reasoner_source() {
    naked_asm!(
        "mov rax, 5",
        "mov rdi, 0",
        "mov rsi, 0xC0",
        "mov rdx, 10",
        "mov r10, 7",
        "syscall",
        "mov rax, 0",
        "mov rdi, 0",
        "syscall",
        "2:",
        "jmp 2b",
    );
}
