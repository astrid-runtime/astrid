use core::sync::atomic::Ordering;

use x86_64::registers::control::Cr3;

use super::super::types::{CODE_BASE, DomainHandle, Outcome, Scenario};
use super::{
    CURRENT, IPC_APPEND_OFFSET, IPC_CANCEL_GUEST_APPEND_OFFSET, MANAGER, TERMINAL_CONTEXT,
    TrapContext, fail_terminal, resume_stack_end, scheduler_resume,
};
use crate::trap::TrapFrame;
use crate::{apic, gdt, ipc, serial};

const READINESS_TRAP_GATE: &str = "readiness_reserved_cpl3_trap_accepted";
const READINESS_BOUND_GATE: &str = "readiness_receipt_bound_to_admission";
const READINESS_OBSERVED_GATE: &str = "readiness_receipt_observed_live";
const READINESS_REPEAT_GATE: &str = "readiness_repeated_trap_rejected";

fn guest_entry_state_ok(frame: &TrapFrame, scenario: u64) -> bool {
    let (fs, gs) = guest_segment_selectors();
    frame.rdi == scenario
        && [
            frame.rax, frame.rbx, frame.rcx, frame.rdx, frame.rsi, frame.rbp, frame.r8, frame.r9,
            frame.r10, frame.r11, frame.r12, frame.r13, frame.r14, frame.r15,
        ]
        .into_iter()
        .all(|value| value == 0)
        && fs == 0
        && gs == 0
}

fn guest_segment_selectors() -> (u64, u64) {
    let fs: u16;
    let gs: u16;
    // SAFETY: reads the FS/GS selectors without changing state.
    unsafe {
        core::arch::asm!(
            "mov {fs:x}, fs",
            "mov {gs:x}, gs",
            fs = out(reg) fs,
            gs = out(reg) gs,
            options(nomem, preserves_flags)
        );
    }
    (fs as u64, gs as u64)
}

fn trap_context_matches() -> bool {
    let expected_root = CURRENT.root.load(Ordering::SeqCst);
    let expected_flags = CURRENT.root_flags.load(Ordering::SeqCst);
    let (current_root, current_flags) = Cr3::read();
    current_root.start_address().as_u64() == expected_root && current_flags.bits() == expected_flags
}

fn reject_cr3() -> ! {
    serial::ev_domain_trap_reject("cr3_mismatch");
    serial::ev_domain_harness(false);
    serial::ev_halt(false);
    serial::exit_qemu(false);
}

fn record_guest_entry(frame: &TrapFrame) {
    let (context_root, context_flags) = Cr3::read();
    let (fs, gs) = guest_segment_selectors();
    let entry_state_ok = guest_entry_state_ok(frame, CURRENT.scenario.load(Ordering::SeqCst));
    serial::ev_domain_entered(
        CURRENT.slot.load(Ordering::SeqCst) + 1,
        CURRENT.generation.load(Ordering::SeqCst),
        frame.cs & 3,
    );
    serial::ev_domain_context(
        CURRENT.slot.load(Ordering::SeqCst) + 1,
        CURRENT.generation.load(Ordering::SeqCst),
        context_root.start_address().as_u64(),
        context_flags.bits(),
        frame.cs & 3,
        fs,
        gs,
    );
    super::super::harness::record_entry(frame.cs & 3, entry_state_ok);
}

fn handle_ipc_syscall(frame: &mut TrapFrame) -> Option<bool> {
    if frame.vector as u8 != ipc::VECTOR {
        return None;
    }
    let handle = super::super::wait::current_handle();
    let Some(domain_token) = super::super::wait::ipc_domain_token(handle) else {
        fail_terminal("invalid_ipc_domain");
    };
    match ipc::handle_call(frame, domain_token) {
        ipc::SyscallOutcome::Done(status, aux) => {
            frame.rax = status;
            frame.rdx = aux;
            Some(true)
        },
        ipc::SyscallOutcome::Block(reason) => {
            let status = match reason {
                ipc::BlockReason::SendReady => super::super::wait::BlockStatus::Sent,
                ipc::BlockReason::RecvEmpty => super::super::wait::BlockStatus::Received,
            };
            super::super::wait::park_current(frame, status)
        },
    }
}

fn ipc_cancel_guest_resume(frame: &mut TrapFrame) -> Option<()> {
    let scenario = CURRENT.scenario.load(Ordering::SeqCst);
    if frame.vector == 6
        && scenario == Scenario::IpcCancelGuest.value()
        && frame.rip == CODE_BASE + 95
    {
        // Scenario 10 deliberately reaches the unchanged shared invalid
        // fall-through; only this new scenario resumes into appended bytes.
        frame.rip = CODE_BASE + IPC_CANCEL_GUEST_APPEND_OFFSET;
        return Some(());
    }
    None
}

fn terminal_outcome(frame: &TrapFrame, scenario: u64, vector: u8) -> Option<Outcome> {
    let ipc_scenario = scenario >= Scenario::IpcServer.value();
    if vector == 3 && ipc_scenario {
        return Some(Outcome::CleanExit);
    }
    if vector == 14 && ipc_scenario {
        return Some(Outcome::PageFault);
    }
    if frame.rdi != scenario {
        return Some(Outcome::UnexpectedFault);
    }
    match vector {
        3 => Some(Outcome::CleanExit),
        6 if frame.cs & 3 == 3 => Some(Outcome::InvalidInstruction),
        14 => Some(Outcome::PageFault),
        32 => {
            let quota = CURRENT.quota.load(Ordering::SeqCst);
            let ticks = CURRENT.ticks.fetch_add(1, Ordering::SeqCst) + 1;
            if ticks < quota {
                apic::eoi();
                return None;
            }
            apic::mask_timer();
            apic::eoi();
            serial::ev_domain_quota(CURRENT.slot.load(Ordering::SeqCst) + 1, ticks);
            Some(Outcome::QuotaExhausted)
        },
        _ => Some(Outcome::UnexpectedFault),
    }
}

fn stage_terminal(frame: &TrapFrame, fault_address: u64, outcome: Outcome) -> ! {
    serial::ev_domain_registers(
        CURRENT.slot.load(Ordering::SeqCst) + 1,
        CURRENT.generation.load(Ordering::SeqCst),
        frame.cs & 3,
        frame.rdi,
        frame.rsp,
        frame.rax,
        frame.rbx,
        frame.rcx,
        frame.rdx,
        frame.rsi,
        frame.rbp,
        frame.r8,
        frame.r9,
        frame.r10,
        frame.r11,
        frame.r12,
        frame.r13,
        frame.r14,
        frame.r15,
    );
    let context = TrapContext {
        slot: CURRENT.slot.load(Ordering::SeqCst),
        generation: CURRENT.generation.load(Ordering::SeqCst),
        vector: frame.vector as u8,
        error_code: frame.error_code,
        rip: frame.rip,
        cs: frame.cs,
        fault_address,
        outcome,
    };
    *TERMINAL_CONTEXT.lock() = Some(context);
    switch_to_resume(resume_stack_end());
}

#[cfg(not(test))]
pub fn handle_domain_trap(frame: &mut TrapFrame, fault_address: u64) -> bool {
    if !CURRENT.active.load(Ordering::SeqCst) || frame.cs & 3 != 3 {
        return false;
    }
    if !trap_context_matches() {
        reject_cr3();
    }
    if !CURRENT.entered.swap(true, Ordering::SeqCst) {
        record_guest_entry(frame);
    }
    let vector = frame.vector as u8;
    if let Some(resumed) = handle_ipc_syscall(frame) {
        return resumed;
    }
    if vector == 14 {
        super::super::harness::record_fault(fault_address);
    }
    let scenario = CURRENT.scenario.load(Ordering::SeqCst);
    if ipc_cancel_guest_resume(frame).is_some() {
        return true;
    }
    if vector == super::readiness::RESERVED_VECTOR {
        if scenario != Scenario::RunningStop.value() {
            return true;
        }
        let handle = super::super::wait::current_handle();
        return match super::readiness::signal_from_trap(handle, frame.cs & 3) {
            Ok(_) => {
                serial::ev_test(READINESS_TRAP_GATE, true);
                let observed_live = super::readiness::observe_current(handle).is_some();
                serial::ev_test(READINESS_BOUND_GATE, observed_live);
                serial::ev_test(READINESS_OBSERVED_GATE, observed_live);
                if !observed_live {
                    fail_terminal("readiness_receipt_not_live");
                }
                true
            },
            Err(
                error @ (super::readiness::ReadinessError::AlreadySignaled
                | super::readiness::ReadinessError::Invalidated),
            ) => {
                serial::ev_test(READINESS_REPEAT_GATE, true);
                fail_terminal(error.as_reason())
            },
            Err(error) => fail_terminal(error.as_reason()),
        };
    }
    if vector == apic::TIMER_VECTOR && scenario == Scenario::RunningStop.value() {
        super::stage_returning_trap(frame).unwrap_or_else(|error| fail_terminal(error.as_reason()));
        apic::mask_timer();
        apic::eoi();
        let _ = (vector, fault_address);
        super::switch_to_return(super::resume_stack_end());
    }
    if vector == apic::TIMER_VECTOR && scenario >= Scenario::IpcServer.value() {
        // The landed #1704 dispatch is byte-frozen and has no path for the
        // new scenarios. Timer preemption is the one transition to the
        // appended private-IPC entry that scenarios 0-5 never take.
        apic::eoi();
        frame.rip = CODE_BASE + IPC_APPEND_OFFSET;
        return true;
    }
    let Some(outcome) = terminal_outcome(frame, scenario, vector) else {
        return true;
    };
    let readiness_invalidated =
        super::readiness::invalidate_for_terminal(super::super::wait::current_handle());
    if !readiness_invalidated {
        fail_terminal("readiness_terminal_not_invalidated");
    }
    if !super::super::stop::abort_for_terminal(super::super::wait::current_handle()) {
        fail_terminal("stop_terminal_conflict");
    }
    stage_terminal(frame, fault_address, outcome)
}

#[cfg(not(test))]
#[unsafe(naked)]
pub extern "C" fn switch_to_resume(stack_end: usize) -> ! {
    core::arch::naked_asm!(
        "mov rsp, rdi",
        "xor ebp, ebp",
        "call {terminal}",
        "ud2",
        terminal = sym domain_terminal,
    );
}

#[cfg(not(test))]
extern "C" fn domain_terminal() -> ! {
    let mut terminal = TERMINAL_CONTEXT.lock();
    let Some(context) = terminal.as_ref().copied() else {
        serial::ev_domain_harness(false);
        serial::ev_halt(false);
        serial::exit_qemu(false);
    };
    let handle = DomainHandle::new(
        super::super::types::DomainId(context.slot),
        super::super::types::DomainGeneration(context.generation),
    );
    let stats = MANAGER.lock().terminate(handle, context.outcome, &context);
    CURRENT.active.store(false, Ordering::SeqCst);
    CURRENT.root.store(0, Ordering::SeqCst);
    CURRENT.root_flags.store(0, Ordering::SeqCst);
    let stop_requested =
        context.vector == crate::apic::TIMER_VECTOR && context.outcome == Outcome::Cancelled;
    if stop_requested {
        serial::ev_stop_current_inactive(handle.id().0 + 1, handle.generation().0);
    }
    if !stats.exactly_once() {
        if stop_requested {
            serial::ev_stop_completed(handle.id().0 + 1, handle.generation().0, false);
        }
        serial::ev_domain_harness(false);
        serial::ev_halt(false);
        serial::exit_qemu(false);
    }
    *terminal = None;
    drop(terminal);
    super::super::harness::record_outcome(context.outcome, stats.exactly_once());
    if stop_requested {
        serial::ev_stop_completed(handle.id().0 + 1, handle.generation().0, true);
    }
    let (kernel_code, kernel_data) = gdt::kernel_selectors();
    let return_stack = resume_stack_end();
    let rip = scheduler_resume as *const () as usize as u64;
    let cs = kernel_code.0 as u64;
    let rflags = 0x002u64;
    let rsp = return_stack as u64;
    let ss = kernel_data.0 as u64;
    // SAFETY: terminal teardown has restored the kernel CR3. All return
    // values are held in registers while moving to the kernel resume stack.
    unsafe {
        core::arch::asm!(
            "mov rsp, {return_stack}",
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            return_stack = in(reg) return_stack,
            ss = in(reg) ss,
            rsp = in(reg) rsp,
            rflags = in(reg) rflags,
            cs = in(reg) cs,
            rip = in(reg) rip,
            options(noreturn)
        );
    }
}
