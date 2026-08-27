//! Negative-first q35/TCG semantic harness for isolated native domains.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use astrid_system_generation::ContentId;
use astrid_system_generation::emulator_fixture::EMULATOR_COMPONENT_LEN;

use super::manager::{self, DomainIdentity, PrepareError};
use super::types::{BindError, ComponentImage, DomainGeneration, DomainHandle, DomainId};
use super::types::{Outcome, Scenario};
use crate::closure::{authenticated_component, authenticated_component_id};
use crate::memory::FRAME_SIZE;
use crate::serial;

const AUTH_GATE: &str = "authenticated_nonempty_component_binds_payload";
const ENTRY_GATE: &str = "ring3_entry_return";
const PAGING_GATE: &str = "per_domain_page_table_exclusion";
const QUOTA_GATE: &str = "quota_preempts_infinite_loop_and_preserves_peer";
const FAULT_GATE: &str = "fault_is_domain_scoped";
const RECLAIM_GATE: &str = "reclaim_exactly_once_under_fault_kill_cancel";
const CLEAN_RESTART_GATE: &str = "hostile_first_then_clean_second_domain";

const PHASE_ENTRY: u64 = 0;
const PHASE_FAULT_PREPARE: u64 = 1;
const PHASE_QUOTA_PREPARE: u64 = 2;
const PHASE_PEER_DONE: u64 = 3;
const PHASE_HOSTILE_PREPARE: u64 = 4;
const PHASE_DONE: u64 = 6;

static PHASE: AtomicU64 = AtomicU64::new(PHASE_ENTRY);
static ENTRY_HANDLE: AtomicU64 = AtomicU64::new(0);
static FAULT_HANDLE: AtomicU64 = AtomicU64::new(0);
static QUOTA_HANDLE: AtomicU64 = AtomicU64::new(0);
static PEER_HANDLE: AtomicU64 = AtomicU64::new(0);
static HOSTILE_HANDLE: AtomicU64 = AtomicU64::new(0);
static HOSTILE_PEER_PROBE: AtomicU64 = AtomicU64::new(0);
static LAST_FAULT: AtomicU64 = AtomicU64::new(0);

static AUTH_OK: AtomicBool = AtomicBool::new(false);
static ENTRY_OK: AtomicBool = AtomicBool::new(false);
static PAGING_OK: AtomicBool = AtomicBool::new(false);
static QUOTA_OK: AtomicBool = AtomicBool::new(false);
static FAULT_SCOPED_OK: AtomicBool = AtomicBool::new(false);
static RUNTIME_PEER_EXCLUDED: AtomicBool = AtomicBool::new(false);
static RECLAIM_ONCE: AtomicBool = AtomicBool::new(true);
static ENTERED_CPL3: AtomicBool = AtomicBool::new(false);
static CLEAN_RESTART_OK: AtomicBool = AtomicBool::new(false);

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
    if let Err(error) = manager::start(handle, scenario) {
        fail(error.as_reason());
    }
    unreachable!("domain start is terminal until the trap returns to the scheduler")
}

fn prepare_domain(raw: &[u8], expected: ContentId, scenario: Scenario) -> DomainHandle {
    match manager::prepare(raw, expected, scenario) {
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
        PHASE_FAULT_PREPARE | PHASE_HOSTILE_PREPARE => Outcome::PageFault,
        PHASE_QUOTA_PREPARE => Outcome::QuotaExhausted,
        PHASE_PEER_DONE => Outcome::CleanExit,
        _ => Outcome::UnexpectedFault,
    };
    if outcome != expected {
        fail("unexpected_domain_outcome");
    }
}

pub(crate) fn record_entry(cpl: u64) {
    ENTERED_CPL3.store(cpl == 3, Ordering::SeqCst);
}

pub(crate) fn scheduler() -> ! {
    match PHASE.load(Ordering::SeqCst) {
        PHASE_ENTRY => advance_fault_prepare(),
        PHASE_FAULT_PREPARE => fault_completed(),
        PHASE_QUOTA_PREPARE => quota_completed(),
        PHASE_PEER_DONE => advance_hostile_prepare(),
        PHASE_HOSTILE_PREPARE => clean_second_started(),
        PHASE_DONE => finish(),
        _ => fail("invalid_harness_phase"),
    }
}

pub(crate) fn start(raw: &[u8], expected: ContentId) -> ! {
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
        passed &= matches!(
            manager::prepare(&tampered, expected, Scenario::CancelOnly),
            Err(PrepareError::Bind(BindError::HashMismatch))
        );
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
    let raw = authenticated_component();
    let expected = authenticated_component_id();
    let fault = prepare_domain(&raw, expected, Scenario::PageFault);
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
    let (expected, freed) = manager::cancel(peer);
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
        && manager::generation(clean) == Some(1)
        && !manager::is_stale(clean);
    let clean_zeroed = manager::clean_domain_zeroed(clean);
    let prior_gates = AUTH_OK.load(Ordering::SeqCst)
        && ENTRY_OK.load(Ordering::SeqCst)
        && PAGING_OK.load(Ordering::SeqCst)
        && QUOTA_OK.load(Ordering::SeqCst)
        && FAULT_SCOPED_OK.load(Ordering::SeqCst)
        && reclaim_pass;
    let restart_ok = prior_gates && fresh && clean_zeroed && manager::outstanding_frames() > 0;
    CLEAN_RESTART_OK.store(restart_ok, Ordering::SeqCst);
    if !restart_ok {
        fail("clean_second_domain_was_not_fresh");
    }
    set_phase(PHASE_DONE);
    start_domain(clean, Scenario::Exit);
}

fn finish() -> ! {
    let pass = report(CLEAN_RESTART_GATE, CLEAN_RESTART_OK.load(Ordering::SeqCst));
    serial::ev_domain_harness(pass);
    serial::ev_halt(pass);
    serial::exit_qemu(pass);
}
