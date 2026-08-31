//! Negative-first q35/TCG semantic harness for isolated native domains.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use astrid_system_generation::ContentId;
use astrid_system_generation::emulator_fixture::EMULATOR_COMPONENT_LEN;

use super::admission;
use super::manager::{self, CancelError, DomainIdentity, DomainState, PrepareError};
use super::stage;
use super::stop;
use super::types::{BindError, ComponentImage, DomainGeneration, DomainHandle, DomainId};
use super::types::{Outcome, Scenario};
use crate::closure::{authenticated_component, authenticated_component_id};
use crate::memory::FRAME_SIZE;
use crate::serial;

const AUTH_GATE: &str = "authenticated_nonempty_component_binds_payload";
const ENTRY_GATE: &str = "ring3_entry_return";
const INVALID_OPCODE_GATE: &str = "real_invalid_opcode_is_domain_scoped";
const PAGING_GATE: &str = "per_domain_page_table_exclusion";
const QUOTA_GATE: &str = "quota_preempts_infinite_loop_and_preserves_peer";
const FAULT_GATE: &str = "fault_is_domain_scoped";
const RECLAIM_GATE: &str = "reclaim_exactly_once_under_fault_kill_cancel";
const CLEAN_RESTART_GATE: &str = "hostile_first_then_clean_second_domain";
const ENTRY_STATE_GATE: &str = "guest_gp_fs_gs_entry_contract";
const ACTIVE_GUARD_GATE: &str = "active_domain_lifecycle_exclusion";
const STALE_GATE: &str = "stale_handle_rejection";
const OVERFLOW_GATE: &str = "generation_overflow_is_fail_closed";
const RESTORE_GATE: &str = "exact_kernel_cr3_restore";
const IPC_EXCHANGE_GATE: &str = "authenticated_domains_exchange_bounded_capability_message";
const IPC_FAULT_GATE: &str = "peer_fault_wakes_blocked_recv_with_typed_status";
const IPC_CANCEL_GATE: &str = "cancel_reclaims_blocked_ipc_exactly_once";
const RUNNING_STOP_GATE: &str = "returned_control_stop_reclaims_exactly_once";

const PHASE_ENTRY: u64 = 0;
const PHASE_INVALID_PREPARE: u64 = 1;
const PHASE_FAULT_PREPARE: u64 = 2;
const PHASE_QUOTA_PREPARE: u64 = 3;
const PHASE_PEER_DONE: u64 = 4;
const PHASE_HOSTILE_PREPARE: u64 = 5;
const PHASE_DONE: u64 = 7;
const PHASE_IPC_SERVER_PREPARE: u64 = 8;
const PHASE_IPC_CLIENT_PREPARE: u64 = 10;
const PHASE_IPC_SERVER_RESUMED: u64 = 12;
const PHASE_IPC_CLIENT_RESUMED: u64 = 13;
const PHASE_IPC_FAULT_SERVER_PREPARE: u64 = 14;
const PHASE_IPC_FAULT_CLIENT_PREPARE: u64 = 16;
const PHASE_IPC_FAULT_SERVER_RESUMED: u64 = 17;
const PHASE_IPC_CANCEL_SERVER_PREPARE: u64 = 18;
const PHASE_IPC_CANCEL_SERVER_DONE: u64 = 20;
const PHASE_RUNNING_STOP_PREPARE: u64 = 21;
const PHASE_RUNNING_STOP_DONE: u64 = 23;

static PHASE: AtomicU64 = AtomicU64::new(PHASE_ENTRY);
static ENTRY_HANDLE: AtomicU64 = AtomicU64::new(0);
static INVALID_HANDLE: AtomicU64 = AtomicU64::new(0);
static FAULT_HANDLE: AtomicU64 = AtomicU64::new(0);
static QUOTA_HANDLE: AtomicU64 = AtomicU64::new(0);
static PEER_HANDLE: AtomicU64 = AtomicU64::new(0);
static HOSTILE_HANDLE: AtomicU64 = AtomicU64::new(0);
static HOSTILE_PEER_PROBE: AtomicU64 = AtomicU64::new(0);
static LAST_FAULT: AtomicU64 = AtomicU64::new(0);
static IPC_SERVER_HANDLE: AtomicU64 = AtomicU64::new(0);
static IPC_CLIENT_HANDLE: AtomicU64 = AtomicU64::new(0);

static AUTH_OK: AtomicBool = AtomicBool::new(false);
static ENTRY_OK: AtomicBool = AtomicBool::new(false);
static INVALID_OPCODE_OK: AtomicBool = AtomicBool::new(false);
static PAGING_OK: AtomicBool = AtomicBool::new(false);
static QUOTA_OK: AtomicBool = AtomicBool::new(false);
static FAULT_SCOPED_OK: AtomicBool = AtomicBool::new(false);
static RUNTIME_PEER_EXCLUDED: AtomicBool = AtomicBool::new(false);
static RECLAIM_ONCE: AtomicBool = AtomicBool::new(true);
static ENTERED_CPL3: AtomicBool = AtomicBool::new(false);
static CLEAN_RESTART_OK: AtomicBool = AtomicBool::new(false);
static ENTRY_STATE_OK: AtomicBool = AtomicBool::new(false);
static ENTRY_STATE_OBSERVED: AtomicBool = AtomicBool::new(false);
static ACTIVE_GUARD_OK: AtomicBool = AtomicBool::new(false);
static STALE_OK: AtomicBool = AtomicBool::new(false);
static OVERFLOW_OK: AtomicBool = AtomicBool::new(false);
static RESTORE_OK: AtomicBool = AtomicBool::new(false);
static IPC_EXCHANGE_OK: AtomicBool = AtomicBool::new(false);
static IPC_FAULT_OK: AtomicBool = AtomicBool::new(false);
static IPC_CANCEL_OK: AtomicBool = AtomicBool::new(false);
static RUNNING_STOP_OK: AtomicBool = AtomicBool::new(false);

fn handle(storage: &AtomicU64) -> DomainHandle {
    let bits = storage.load(Ordering::SeqCst);
    DomainHandle::new(DomainId(bits >> 32), DomainGeneration(bits & 0xffff_ffff))
}

fn store_handle(storage: &AtomicU64, handle: DomainHandle) {
    let bits = (handle.id().0 << 32) | handle.generation().0;
    storage.store(bits, Ordering::SeqCst);
}

fn report(name: &'static str, pass: bool) -> bool {
    serial::ev_test(name, pass);
    pass
}

fn fail(reason: &'static str) -> ! {
    serial::ev_domain_auth_reject(reason);
    serial::ev_domain_harness(false);
    serial::ev_halt(false);
    serial::exit_qemu(false);
}

fn start_domain(handle: DomainHandle, scenario: Scenario) -> ! {
    let staged = match stage::stage_start(handle, authenticated_component_id(), scenario) {
        Ok(staged) => staged,
        Err(error) => fail(error.as_reason()),
    };
    if let Err(error) = stage::dispatch_start(staged) {
        fail(error.as_reason());
    }
    unreachable!("domain start is terminal until the trap returns to the scheduler")
}

fn prepare_domain(raw: &[u8], expected: ContentId, scenario: Scenario) -> DomainHandle {
    match admission::prepare(raw, expected, scenario) {
        Ok(handle) => handle,
        Err(error) => fail(error.as_reason()),
    }
}

fn set_phase(phase: u64) {
    PHASE.store(phase, Ordering::SeqCst);
}

pub(crate) fn record_fault(fault_address: u64) {
    LAST_FAULT.store(fault_address, Ordering::SeqCst);
}

pub(crate) fn record_outcome(outcome: Outcome, reclaim_once: bool) {
    RECLAIM_ONCE.fetch_and(reclaim_once, Ordering::SeqCst);
    let expected = match PHASE.load(Ordering::SeqCst) {
        PHASE_ENTRY | PHASE_DONE => Outcome::CleanExit,
        PHASE_INVALID_PREPARE => Outcome::InvalidInstruction,
        PHASE_FAULT_PREPARE | PHASE_HOSTILE_PREPARE => Outcome::PageFault,
        PHASE_QUOTA_PREPARE => Outcome::QuotaExhausted,
        PHASE_PEER_DONE => Outcome::CleanExit,
        PHASE_IPC_SERVER_PREPARE
        | PHASE_IPC_CLIENT_PREPARE
        | PHASE_IPC_SERVER_RESUMED
        | PHASE_IPC_CLIENT_RESUMED
        | PHASE_IPC_FAULT_SERVER_PREPARE
        | PHASE_IPC_FAULT_SERVER_RESUMED
        | PHASE_IPC_CANCEL_SERVER_PREPARE => Outcome::CleanExit,
        PHASE_IPC_FAULT_CLIENT_PREPARE => Outcome::PageFault,
        PHASE_RUNNING_STOP_PREPARE => Outcome::Cancelled,
        _ => Outcome::UnexpectedFault,
    };
    if outcome != expected {
        fail("unexpected_domain_outcome");
    }
}

pub(crate) fn record_entry(cpl: u64, entry_state_ok: bool) {
    if !ENTRY_STATE_OBSERVED.swap(true, Ordering::SeqCst) {
        ENTERED_CPL3.store(cpl == 3, Ordering::SeqCst);
        ENTRY_STATE_OK.store(entry_state_ok, Ordering::SeqCst);
    }
}

pub(crate) fn scheduler() -> ! {
    match PHASE.load(Ordering::SeqCst) {
        PHASE_ENTRY => advance_fault_prepare(),
        PHASE_INVALID_PREPARE => invalid_completed(),
        PHASE_FAULT_PREPARE => fault_completed(),
        PHASE_QUOTA_PREPARE => quota_completed(),
        PHASE_PEER_DONE => advance_hostile_prepare(),
        PHASE_HOSTILE_PREPARE => clean_second_started(),
        PHASE_DONE => advance_ipc_exchange(),
        PHASE_IPC_SERVER_PREPARE => start_ipc_client(),
        PHASE_IPC_CLIENT_PREPARE => resume_ipc_server(),
        PHASE_IPC_SERVER_RESUMED => resume_ipc_client(),
        PHASE_IPC_CLIENT_RESUMED => advance_ipc_fault_server(),
        PHASE_IPC_FAULT_SERVER_PREPARE => start_ipc_fault_client(),
        PHASE_IPC_FAULT_CLIENT_PREPARE => {
            IPC_FAULT_OK.store(true, Ordering::SeqCst);
            advance_ipc_cancel_server()
        },
        PHASE_IPC_FAULT_SERVER_RESUMED => {
            IPC_FAULT_OK.store(true, Ordering::SeqCst);
            advance_ipc_cancel_server()
        },
        PHASE_IPC_CANCEL_SERVER_PREPARE => ipc_cancel_guest_done(),
        PHASE_IPC_CANCEL_SERVER_DONE => finish(),
        PHASE_RUNNING_STOP_PREPARE => running_stop_done(),
        PHASE_RUNNING_STOP_DONE => finish(),
        _ => fail("invalid_harness_phase"),
    }
}

pub(crate) fn start(raw: &[u8], expected: ContentId) -> ! {
    OVERFLOW_OK.store(
        report(
            OVERFLOW_GATE,
            manager::generation_overflow_rejects_prepare(raw, expected),
        ),
        Ordering::SeqCst,
    );
    let authenticated = auth_gate(raw, expected);
    AUTH_OK.store(authenticated, Ordering::SeqCst);
    if !authenticated {
        fail("authenticated_component_rejected");
    }
    let handle = prepare_domain(raw, expected, Scenario::Exit);
    store_handle(&ENTRY_HANDLE, handle);
    start_domain(handle, Scenario::Exit);
}

fn auth_gate(raw: &[u8], expected: ContentId) -> bool {
    let mut passed = ComponentImage::parse(&[]).is_err();
    let image = ComponentImage::parse(raw);
    passed &= image
        .as_ref()
        .is_ok_and(|image| image.identity() == expected && image.code_len() > 0);
    let mut tampered = [0u8; EMULATOR_COMPONENT_LEN];
    if raw.len() == tampered.len() {
        tampered.copy_from_slice(raw);
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered_rejected = matches!(
            manager::prepare(&tampered, expected, Scenario::CancelOnly),
            Err(PrepareError::Bind(BindError::HashMismatch))
        );
        if tampered_rejected {
            serial::ev_domain_auth_reject("tampered_component_rejected");
        }
        passed &= tampered_rejected;
    } else {
        passed = false;
    }
    report(AUTH_GATE, passed)
}

fn advance_fault_prepare() -> ! {
    let entry_ok = manager::last_identity().is_some() && ENTERED_CPL3.load(Ordering::SeqCst);
    ENTRY_OK.store(entry_ok, Ordering::SeqCst);
    if !report(ENTRY_GATE, entry_ok) {
        fail("ring3_entry_not_observed");
    }
    ENTRY_STATE_OK.store(
        report(ENTRY_STATE_GATE, ENTRY_STATE_OK.load(Ordering::SeqCst)),
        Ordering::SeqCst,
    );
    if !ENTRY_STATE_OK.load(Ordering::SeqCst) {
        fail("guest_entry_state_not_cleared");
    }
    let raw = authenticated_component();
    let expected = authenticated_component_id();
    let invalid = prepare_domain(&raw, expected, Scenario::InvalidInstruction);
    store_handle(&INVALID_HANDLE, invalid);
    set_phase(PHASE_INVALID_PREPARE);
    start_domain(invalid, Scenario::InvalidInstruction);
}

fn invalid_completed() -> ! {
    let invalid = handle(&INVALID_HANDLE);
    let pass = manager::is_stale(invalid) && manager::outstanding_frames() == 0;
    INVALID_OPCODE_OK.store(pass, Ordering::SeqCst);
    if !report(INVALID_OPCODE_GATE, pass) {
        fail("invalid_opcode_was_not_domain_scoped");
    }

    RESTORE_OK.store(
        report(RESTORE_GATE, manager::kernel_cr3_restored()),
        Ordering::SeqCst,
    );
    let entry = handle(&ENTRY_HANDLE);
    let raw = authenticated_component();
    let expected = authenticated_component_id();
    let fault = prepare_domain(&raw, expected, Scenario::PageFault);

    let active_ok =
        manager::active_lifecycle_guard_rejects(fault, Scenario::PageFault, &raw, expected);
    ACTIVE_GUARD_OK.store(report(ACTIVE_GUARD_GATE, active_ok), Ordering::SeqCst);

    let frames_before = manager::outstanding_frames();
    let newer_generation = manager::generation(fault);
    let stale_result = manager::cancel(entry);
    let stale_ok = matches!(stale_result, Err(CancelError::StaleHandle))
        && manager::outstanding_frames() == frames_before
        && manager::generation(fault) == newer_generation
        && !manager::is_stale(fault);
    STALE_OK.store(report(STALE_GATE, stale_ok), Ordering::SeqCst);

    store_handle(&FAULT_HANDLE, fault);
    let peer = prepare_domain(&raw, expected, Scenario::CancelOnly);
    store_handle(&PEER_HANDLE, peer);
    set_phase(PHASE_FAULT_PREPARE);
    start_domain(fault, Scenario::PageFault);
}

fn fault_completed() -> ! {
    let fault = handle(&FAULT_HANDLE);
    let peer = handle(&PEER_HANDLE);
    let peer_preserved = manager::peer_is_prepared(fault);
    let Ok((expected, freed)) = manager::cancel(peer) else {
        fail("prepared_peer_cancel_rejected");
    };
    let scoped = manager::is_stale(fault) && peer_preserved && expected > 0 && expected == freed;
    FAULT_SCOPED_OK.store(scoped, Ordering::SeqCst);

    let raw = authenticated_component();
    let expected_identity = authenticated_component_id();
    let quota = prepare_domain(&raw, expected_identity, Scenario::Quota);
    store_handle(&QUOTA_HANDLE, quota);
    let peer = prepare_domain(&raw, expected_identity, Scenario::Exit);
    store_handle(&PEER_HANDLE, peer);
    set_phase(PHASE_QUOTA_PREPARE);
    start_domain(quota, Scenario::Quota);
}

fn quota_completed() -> ! {
    let quota = handle(&QUOTA_HANDLE);
    let peer = handle(&PEER_HANDLE);
    let pass = manager::is_stale(quota) && manager::peer_is_prepared(quota);
    QUOTA_OK.store(pass, Ordering::SeqCst);
    if !report(QUOTA_GATE, pass) {
        fail("quota_did_not_preserve_peer");
    }
    set_phase(PHASE_PEER_DONE);
    start_domain(peer, Scenario::Exit);
}

fn advance_hostile_prepare() -> ! {
    let peer = handle(&PEER_HANDLE);
    if !manager::is_stale(peer) || manager::outstanding_frames() != 0 {
        fail("peer_clean_exit_reclaim_failed");
    }
    let raw = authenticated_component();
    let expected_identity = authenticated_component_id();
    let hostile = prepare_domain(&raw, expected_identity, Scenario::PeerProbe);
    store_handle(&HOSTILE_HANDLE, hostile);
    let Some(identity) = manager::identity(hostile) else {
        fail("hostile_identity_missing");
    };
    let DomainIdentity { root: _, probe } = identity;
    let peer_probe = probe ^ FRAME_SIZE;
    HOSTILE_PEER_PROBE.store(peer_probe, Ordering::SeqCst);
    set_phase(PHASE_HOSTILE_PREPARE);
    start_domain(hostile, Scenario::PeerProbe);
}

fn clean_second_started() -> ! {
    let hostile = handle(&HOSTILE_HANDLE);
    let hostile_peer = HOSTILE_PEER_PROBE.load(Ordering::SeqCst);
    RUNTIME_PEER_EXCLUDED.store(
        LAST_FAULT.load(Ordering::SeqCst) == hostile_peer,
        Ordering::SeqCst,
    );

    let paging_pass = RUNTIME_PEER_EXCLUDED.load(Ordering::SeqCst)
        && manager::is_stale(hostile)
        && RECLAIM_ONCE.load(Ordering::SeqCst)
        && manager::outstanding_frames() == 0;
    PAGING_OK.store(paging_pass, Ordering::SeqCst);
    if !report(PAGING_GATE, paging_pass) {
        fail("peer_page_table_not_isolated");
    }

    let fault_pass =
        FAULT_SCOPED_OK.load(Ordering::SeqCst) && RUNTIME_PEER_EXCLUDED.load(Ordering::SeqCst);
    FAULT_SCOPED_OK.store(fault_pass, Ordering::SeqCst);
    if !report(FAULT_GATE, fault_pass) {
        fail("fault_was_not_domain_scoped");
    }

    let reclaim_pass = RECLAIM_ONCE.load(Ordering::SeqCst)
        && manager::is_stale(hostile)
        && manager::outstanding_frames() == 0;
    if !report(RECLAIM_GATE, reclaim_pass) {
        fail("reclaim_not_exactly_once");
    }

    let raw = authenticated_component();
    let expected_identity = authenticated_component_id();
    let clean = prepare_domain(&raw, expected_identity, Scenario::Exit);
    let fresh = manager::identity(clean).is_some()
        && manager::generation(clean) == Some(6)
        && !manager::is_stale(clean);
    let clean_zeroed = manager::clean_domain_zeroed(clean);
    let prior_gates = AUTH_OK.load(Ordering::SeqCst)
        && ENTRY_OK.load(Ordering::SeqCst)
        && INVALID_OPCODE_OK.load(Ordering::SeqCst)
        && ENTRY_STATE_OK.load(Ordering::SeqCst)
        && ACTIVE_GUARD_OK.load(Ordering::SeqCst)
        && STALE_OK.load(Ordering::SeqCst)
        && OVERFLOW_OK.load(Ordering::SeqCst)
        && RESTORE_OK.load(Ordering::SeqCst)
        && PAGING_OK.load(Ordering::SeqCst)
        && QUOTA_OK.load(Ordering::SeqCst)
        && FAULT_SCOPED_OK.load(Ordering::SeqCst)
        && reclaim_pass;
    let restart_ok = prior_gates && fresh && clean_zeroed && manager::outstanding_frames() > 0;
    CLEAN_RESTART_OK.store(restart_ok, Ordering::SeqCst);
    if !prior_gates {
        fail("clean_prior_gates_failed");
    }
    if !fresh {
        fail("clean_fresh_identity_failed");
    }
    if !clean_zeroed {
        fail("clean_fresh_zeroing_failed");
    }
    if manager::outstanding_frames() == 0 {
        fail("clean_fresh_frames_missing");
    }
    set_phase(PHASE_DONE);
    start_domain(clean, Scenario::Exit);
}

fn authenticated() -> ([u8; EMULATOR_COMPONENT_LEN], ContentId) {
    (authenticated_component(), authenticated_component_id())
}

fn advance_ipc_exchange() -> ! {
    let (raw, expected) = authenticated();
    let server = prepare_domain(&raw, expected, Scenario::IpcServer);
    store_handle(&IPC_SERVER_HANDLE, server);
    set_phase(PHASE_IPC_SERVER_PREPARE);
    start_domain(server, Scenario::IpcServer);
}

fn start_ipc_client() -> ! {
    let server = handle(&IPC_SERVER_HANDLE);
    let (raw, expected) = authenticated();
    let client = prepare_domain(&raw, expected, Scenario::IpcClient);
    store_handle(&IPC_CLIENT_HANDLE, client);
    let bound = crate::domains::bind_ipc_peer(
        server.id().value(),
        manager::generation(server).unwrap_or_default(),
        client.id().value(),
        manager::generation(client).unwrap_or_default(),
    );
    if !bound {
        fail("ipc_peer_binding_rejected");
    }
    set_phase(PHASE_IPC_CLIENT_PREPARE);
    start_domain(client, Scenario::IpcClient);
}

fn resume_ipc_server() -> ! {
    let server = handle(&IPC_SERVER_HANDLE);
    set_phase(PHASE_IPC_SERVER_RESUMED);
    match super::wait::resume_blocked(server) {
        Ok(()) => unreachable!("resuming a parked domain does not return"),
        Err(()) => fail("ipc_server_resume_rejected"),
    }
}

fn resume_ipc_client() -> ! {
    IPC_EXCHANGE_OK.store(true, Ordering::SeqCst);
    let client = handle(&IPC_CLIENT_HANDLE);
    set_phase(PHASE_IPC_CLIENT_RESUMED);
    match super::wait::resume_blocked(client) {
        Ok(()) => unreachable!("resuming a parked domain does not return"),
        Err(()) => fail("ipc_client_resume_rejected"),
    }
}

fn advance_ipc_fault_server() -> ! {
    IPC_EXCHANGE_OK.store(
        report(IPC_EXCHANGE_GATE, IPC_EXCHANGE_OK.load(Ordering::SeqCst)),
        Ordering::SeqCst,
    );
    if !IPC_EXCHANGE_OK.load(Ordering::SeqCst) {
        fail("ipc_exchange_flow_failed");
    }
    let (raw, expected) = authenticated();
    let server = prepare_domain(&raw, expected, Scenario::IpcServer);
    store_handle(&IPC_SERVER_HANDLE, server);
    set_phase(PHASE_IPC_FAULT_SERVER_PREPARE);
    start_domain(server, Scenario::IpcServer);
}

fn start_ipc_fault_client() -> ! {
    let server = handle(&IPC_SERVER_HANDLE);
    let (raw, expected) = authenticated();
    let client = prepare_domain(&raw, expected, Scenario::IpcPeerFault);
    store_handle(&IPC_CLIENT_HANDLE, client);
    let bound = crate::domains::bind_ipc_peer(
        server.id().value(),
        manager::generation(server).unwrap_or_default(),
        client.id().value(),
        manager::generation(client).unwrap_or_default(),
    );
    if !bound {
        fail("fault_ipc_peer_binding_rejected");
    }
    set_phase(PHASE_IPC_FAULT_CLIENT_PREPARE);
    start_domain(client, Scenario::IpcPeerFault);
}

fn advance_ipc_cancel_server() -> ! {
    IPC_FAULT_OK.store(
        report(IPC_FAULT_GATE, IPC_FAULT_OK.load(Ordering::SeqCst)),
        Ordering::SeqCst,
    );
    if !IPC_FAULT_OK.load(Ordering::SeqCst) {
        fail("ipc_peer_fault_flow_failed");
    }
    let (raw, expected) = authenticated();
    let server = prepare_domain(&raw, expected, Scenario::IpcCancelGuest);
    store_handle(&IPC_SERVER_HANDLE, server);
    set_phase(PHASE_IPC_CANCEL_SERVER_PREPARE);
    start_domain(server, Scenario::IpcCancelGuest);
}

fn ipc_cancel_guest_done() -> ! {
    let server = handle(&IPC_SERVER_HANDLE);
    let passed = manager::is_stale(server) && manager::outstanding_frames() == 0;
    IPC_CANCEL_OK.store(report(IPC_CANCEL_GATE, passed), Ordering::SeqCst);
    if !passed {
        fail("running_guest_ipc_cancel_rejected");
    }
    let (raw, expected) = authenticated();
    if stop::observe_completed_stop(server, expected, Scenario::RunningStop).is_some() {
        fail("stale_running_stop_was_observable");
    }
    let stop = prepare_domain(&raw, expected, Scenario::RunningStop);
    if stop::observe_completed_stop(stop, expected, Scenario::RunningStop).is_some() {
        fail("prepared_running_stop_was_observable");
    }
    store_handle(&IPC_SERVER_HANDLE, stop);
    set_phase(PHASE_RUNNING_STOP_PREPARE);
    start_domain(stop, Scenario::RunningStop);
}

fn completed_stop_is_current_guarded(stop: DomainHandle) -> bool {
    let current = &manager::CURRENT;
    let expected = authenticated_component_id();

    current.active.store(true, Ordering::SeqCst);
    let active_observed =
        stop::observe_completed_stop(stop, expected, Scenario::RunningStop).is_none();
    current.active.store(false, Ordering::SeqCst);

    current.root.store(1, Ordering::SeqCst);
    let root_observed =
        stop::observe_completed_stop(stop, expected, Scenario::RunningStop).is_none();
    current.root.store(0, Ordering::SeqCst);

    current.root_flags.store(1, Ordering::SeqCst);
    let flags_observed =
        stop::observe_completed_stop(stop, expected, Scenario::RunningStop).is_none();
    current.root_flags.store(0, Ordering::SeqCst);

    active_observed
        && root_observed
        && flags_observed
        && !current.active.load(Ordering::SeqCst)
        && current.root.load(Ordering::SeqCst) == 0
        && current.root_flags.load(Ordering::SeqCst) == 0
}

fn running_stop_done() -> ! {
    let stop = handle(&IPC_SERVER_HANDLE);
    let expected = authenticated_component_id();
    serial::ev_control_returned(stop.id().0 + 1, stop.generation().0);
    let returned_ok = manager::outstanding_frames() > 0
        && !manager::is_stale(stop)
        && manager::staged_state(stop) == Ok(Some((DomainState::Running, Scenario::RunningStop)))
        && !manager::CURRENT.active.load(Ordering::SeqCst)
        && manager::CURRENT.root.load(Ordering::SeqCst) == 0
        && manager::CURRENT.root_flags.load(Ordering::SeqCst) == 0
        && manager::kernel_cr3_restored();
    if !returned_ok {
        fail("running_control_return_was_not_quiescent");
    }
    let substituted_component = ContentId::from_payload(b"returned-control-substitution");
    let stale = DomainHandle::new(stop.id(), DomainGeneration(stop.generation().0 + 1));
    let foreign_slot = DomainHandle::new(DomainId((stop.id().0 + 1) % 2), stop.generation());
    let substitutions_rejected =
        manager::request_returned_stop(stop, substituted_component, Scenario::RunningStop).is_err()
            && manager::request_returned_stop(stop, expected, Scenario::Exit).is_err()
            && manager::request_returned_stop(stale, expected, Scenario::RunningStop).is_err()
            && manager::request_returned_stop(foreign_slot, expected, Scenario::RunningStop)
                .is_err()
            && manager::outstanding_frames() > 0
            && !manager::is_stale(stop);
    if !substitutions_rejected {
        fail("returned_control_substitution_accepted");
    }
    let accepted = manager::request_returned_stop(stop, expected, Scenario::RunningStop).is_ok();
    let passed = accepted
        && manager::is_stale(stop)
        && manager::outstanding_frames() == 0
        && manager::kernel_cr3_restored();
    let suppression_ok = completed_stop_is_current_guarded(stop);
    let exact =
        stop::observe_completed_stop(stop, authenticated_component_id(), Scenario::RunningStop);
    let repeated =
        stop::observe_completed_stop(stop, authenticated_component_id(), Scenario::RunningStop);
    let observation_ok =
        stop::observe_completed_stop(stale, authenticated_component_id(), Scenario::RunningStop)
            .is_none()
            && stop::observe_completed_stop(
                foreign_slot,
                authenticated_component_id(),
                Scenario::RunningStop,
            )
            .is_none()
            && stop::observe_completed_stop(stop, substituted_component, Scenario::RunningStop)
                .is_none()
            && stop::observe_completed_stop(stop, authenticated_component_id(), Scenario::Exit)
                .is_none();
    let exact_ok = exact.is_some()
        && exact == repeated
        && exact.as_ref().is_some_and(|observation| {
            observation.handle() == stop
                && *observation.component_id() == authenticated_component_id()
                && observation.scenario() == Scenario::RunningStop
                && observation.outcome() == Outcome::Cancelled
        });
    if !suppression_ok || !observation_ok || !exact_ok {
        fail("running_stop_observation_rejected");
    }
    RUNNING_STOP_OK.store(report(RUNNING_STOP_GATE, passed), Ordering::SeqCst);
    if !passed {
        fail("running_timer_stop_not_terminal");
    }
    set_phase(PHASE_RUNNING_STOP_DONE);
    scheduler()
}

fn finish() -> ! {
    let prior = CLEAN_RESTART_OK.load(Ordering::SeqCst)
        && IPC_EXCHANGE_OK.load(Ordering::SeqCst)
        && IPC_FAULT_OK.load(Ordering::SeqCst)
        && IPC_CANCEL_OK.load(Ordering::SeqCst)
        && RUNNING_STOP_OK.load(Ordering::SeqCst);
    let pass = report(CLEAN_RESTART_GATE, CLEAN_RESTART_OK.load(Ordering::SeqCst)) && prior;
    serial::ev_domain_harness(pass);
    serial::ev_halt(pass);
    serial::exit_qemu(pass);
}
