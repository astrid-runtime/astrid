//! Negative-first self-tests. Each emits `test.pass`/`test.fail`. The negative
//! tests are the point: a W^X or NX regression makes them fail rather than pass
//! silently. `frame_unique` is a positive control so the negative tests are not
//! vacuous.

use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use crate::memory::{self, Frame};
use crate::{serial, trap};

/// Read-only target for the W^X write test (lands in `.rodata`).
#[used]
static RO_TARGET: u8 = 0x42;
/// A `ret` sled in writable, non-executable data for the NX execute test.
#[used]
static NX_EXEC_BUF: [u8; 16] = [0xC3; 16];

/// Run every self-test in order. Returns `true` iff all passed.
pub fn run_all(data_exec_violation: bool) -> bool {
    let mut all = true;
    all &= report("int3_handled", int3_handled());
    all &= report("wx_rodata_write", wx_rodata_write());
    all &= report("nx_data_exec", nx_data_exec(data_exec_violation));
    all &= report("heap_exhaustion", heap_exhaustion());
    all &= report("frame_unique", frame_unique());
    all &= report("frame_exhaustion", frame_exhaustion());
    all
}

fn report(name: &'static str, pass: bool) -> bool {
    serial::ev_test(name, pass);
    pass
}

/// `int3` must be caught by the breakpoint handler, which returns to the
/// instruction after the trap.
fn int3_handled() -> bool {
    // SAFETY: the breakpoint handler emits a fault event and resumes.
    unsafe { core::arch::asm!("int3", options(nomem, nostack)) };
    true
}

/// Writing to a `.rodata` page must page-fault; the handler recovers to the
/// instruction after the store.
fn wx_rodata_write() -> bool {
    trap::EXPECT_FAULT.store(true, Ordering::SeqCst);
    let target = core::ptr::addr_of!(RO_TARGET) as u64;
    // SAFETY: an expected fault is armed. `lea` records the resume point into
    // RECOVERY_RIP; the store to a non-writable page faults; the page-fault
    // handler restores RIP to label 2 and clears the flag. All scratch regs
    // are preserved across the fault by the ISR common tail.
    unsafe {
        core::arch::asm!(
            "lea {tmp}, [rip + 2f]",
            "mov qword ptr [{slot}], {tmp}",
            "mov byte ptr [{target}], 0x55",
            "2:",
            tmp = out(reg) _,
            slot = in(reg) trap::RECOVERY_RIP.as_ptr(),
            target = in(reg) target,
            options(nostack),
        );
    }
    // Pass iff the handler consumed the armed fault (cleared the flag).
    !trap::EXPECT_FAULT.load(Ordering::SeqCst)
}

/// Executing from a non-executable data page must page-fault (NX). If the audit
/// already found data executable, do not jump (it would run the `ret` sled) —
/// fail honestly instead.
fn nx_data_exec(data_exec_violation: bool) -> bool {
    if data_exec_violation {
        return false;
    }
    trap::EXPECT_FAULT.store(true, Ordering::SeqCst);
    let target = core::ptr::addr_of!(NX_EXEC_BUF) as u64;
    // SAFETY: an expected fault is armed. The indirect jump to a non-executable
    // page faults on instruction fetch; the handler restores RIP to label 3.
    unsafe {
        core::arch::asm!(
            "lea {tmp}, [rip + 3f]",
            "mov qword ptr [{slot}], {tmp}",
            "jmp {target}",
            "3:",
            tmp = out(reg) _,
            slot = in(reg) trap::RECOVERY_RIP.as_ptr(),
            target = in(reg) target,
            options(nostack),
        );
    }
    !trap::EXPECT_FAULT.load(Ordering::SeqCst)
}

/// Fallible heap allocation must return `Err` on exhaustion, never fault.
fn heap_exhaustion() -> bool {
    let layout = match Layout::from_size_align(4096, 8) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let mut ptrs: [Option<NonNull<u8>>; 512] = [None; 512];
    let mut count = 0usize;
    let mut got_err = false;
    for slot in ptrs.iter_mut() {
        match memory::heap_alloc(layout) {
            Ok(p) => {
                *slot = Some(p);
                count += 1;
            },
            Err(()) => {
                got_err = true;
                break;
            },
        }
    }
    for p in ptrs.iter().flatten() {
        // SAFETY: each pointer came from heap_alloc with this exact layout.
        unsafe { memory::heap_dealloc(*p, layout) };
    }
    got_err && count > 0
}

/// The frame allocator must return `None` on exhaustion, never fault.
fn frame_exhaustion() -> bool {
    let mut count: u64 = 0;
    let mut got_none = false;
    let ceiling = memory::MAX_FRAMES as u64 + 16;
    loop {
        match memory::alloc_frame() {
            Some(_) => {
                count += 1;
                if count > ceiling {
                    break; // allocator bug: never exhausts
                }
            },
            None => {
                got_none = true;
                break;
            },
        }
    }
    memory::reset_frames();
    got_none && count > 0
}

/// Positive control: 64 distinct frames, freed and re-allocated with reuse.
fn frame_unique() -> bool {
    let mut first = [0u64; 64];
    for slot in first.iter_mut() {
        match memory::alloc_frame() {
            Some(f) => *slot = f.0,
            None => return false,
        }
    }
    for i in 0..64 {
        for j in (i + 1)..64 {
            if first[i] == first[j] {
                return false;
            }
        }
    }
    for &addr in first.iter() {
        memory::free_frame(Frame(addr));
    }
    let mut second = [0u64; 64];
    for slot in second.iter_mut() {
        match memory::alloc_frame() {
            Some(f) => *slot = f.0,
            None => return false,
        }
    }
    let reused = second.iter().any(|b| first.contains(b));
    for &addr in second.iter() {
        memory::free_frame(Frame(addr));
    }
    reused
}
