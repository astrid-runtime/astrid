//! Protection domains (ADR-K1), the capability table (ADR-K2), generation-based
//! revocation (ADR-K4), tick-quota preemption (ADR-K6 seed), and the seven
//! ring-3 scenarios that prove them.
//!
//! A domain is a fixed-layout slot from a pool of [`DOMAIN_SLOTS`]. Every
//! resource is drawn from a bounded pool and every mint is fallible (charter
//! §6). The scheduler runs exactly one domain at a time and is single-threaded;
//! while a domain runs, the scheduler is parked inside
//! [`crate::syscall::context_enter`] and does not touch [`DOMAINS`], so the only
//! code reaching a domain slot during the ring-3 excursion is the syscall
//! dispatcher and the interrupt/fault handlers — all single-hart, interrupts
//! off in the kernel. `DOMAINS` is therefore a `static mut` accessed through
//! raw pointers under that discipline (the continuation save slot needs a
//! stable address a lock guard could not provide); [`OBJECTS`], which no
//! interrupt path must reach while the scheduler holds it, uses a plain lock.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use spin::Mutex;
use x86_64::registers::control::Cr3;

use crate::memory::{self, Frame};
use crate::{payloads, serial, syscall, vm};

/// Number of domain slots (charter: bounded by construction).
const DOMAIN_SLOTS: usize = 8;
/// Maximum frames a single domain may own; minting past it fails cleanly.
const MAX_FRAMES_PER_DOMAIN: usize = 32;
/// Global object-table slots (ADR-K2).
const OBJECT_SLOTS: usize = 128;
/// Per-domain capability-table entries (ADR-K2).
const CAP_ENTRIES: usize = 64;
/// Bytes of ring-3 payload copied into a domain's code frame.
pub const PAYLOAD_MAX: usize = 512;
/// Timer-tick quota granted on entry (ADR-K6 seed).
const TICK_QUOTA: u32 = 32;

/// Status codes returned to ring 3 in `rax` (i64).
const OK: i64 = 0;
const BAD_CAP: i64 = -2;
const STALE_CAP: i64 = -3;
const DENIED: i64 = -4;

/// `CURRENT_DOMAIN` sentinel meaning "no domain running".
const NONE: usize = usize::MAX;

/// The running domain's slot index, or [`NONE`]. Read by the interrupt/fault
/// handlers to attribute preemption and faults.
static CURRENT_DOMAIN: AtomicUsize = AtomicUsize::new(NONE);

// Kernel-side scenario observation (never influenced by ring-3 strings).
static NOTE_SEEN: AtomicBool = AtomicBool::new(false);
static NOTE_VALUE: AtomicU64 = AtomicU64::new(0);
/// Armed object (index + 1) to revoke on the next `sys_note`; 0 = disarmed.
static REVOKE_ON_NOTE: AtomicU32 = AtomicU32::new(0);
static REVOKE_DONE: AtomicBool = AtomicBool::new(false);

/// Domain lifecycle state: `Free -> Ready -> Running -> Dead -> Free`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    Ready,
    Running,
    Dead,
}

/// The reserved death record (ADR-K5): reserved at create, filled by the kill
/// path. Reserving it can never fail after create succeeds. Its fields are
/// recorded evidence; supervisor delivery over a fault endpoint is explicitly
/// out of scope for M2 (deferred to a later milestone), so nothing consumes
/// them yet — the terminal lifecycle events carry the observable cause.
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct DeathRecord {
    cause: Cause,
    vector: u64,
    error_code: u64,
    rip: u64,
}

impl DeathRecord {
    const EMPTY: Self = Self {
        cause: Cause::None,
        vector: 0,
        error_code: 0,
        rip: 0,
    };
}

#[derive(Clone, Copy)]
enum Cause {
    None,
    PageFault,
    GeneralProtection,
    Quota,
}

/// A per-domain, bounded frame list — the reclaim unit for the kill path.
pub(crate) struct FrameList {
    frames: [u64; MAX_FRAMES_PER_DOMAIN],
    len: usize,
}

impl FrameList {
    const EMPTY: Self = Self {
        frames: [0; MAX_FRAMES_PER_DOMAIN],
        len: 0,
    };

    /// Record a frame; returns `false` (mint fails cleanly) once full.
    pub(crate) fn push(&mut self, frame_phys: u64) -> bool {
        if self.len >= MAX_FRAMES_PER_DOMAIN {
            return false;
        }
        self.frames[self.len] = frame_phys;
        self.len += 1;
        true
    }
}

/// A capability-table entry (ADR-K2).
#[derive(Clone, Copy)]
struct CapEntry {
    occupied: bool,
    object_index: u32,
    generation: u32,
    rights: u32,
    /// Recorded for provenance; the derivation-graph walk lands with transfer
    /// in M3 (ADR-K3). A field, not machinery — deliberately unread here.
    #[allow(dead_code)]
    derivation_parent: u16,
}

impl CapEntry {
    const EMPTY: Self = Self {
        occupied: false,
        object_index: 0,
        generation: 0,
        rights: 0,
        derivation_parent: 0,
    };
}

/// A domain slot.
struct Domain {
    state: State,
    frames: FrameList,
    pml4_phys: u64,
    kstack_top: u64,
    /// Continuation save slot written by [`crate::syscall::context_enter`].
    kctx_rsp: u64,
    quota: u32,
    death: DeathRecord,
    caps: [CapEntry; CAP_ENTRIES],
    domain_object: u32,
    free_census_at_create: usize,
}

impl Domain {
    const EMPTY: Self = Self {
        state: State::Free,
        frames: FrameList::EMPTY,
        pml4_phys: 0,
        kstack_top: 0,
        kctx_rsp: 0,
        quota: 0,
        death: DeathRecord::EMPTY,
        caps: [CapEntry::EMPTY; CAP_ENTRIES],
        domain_object: 0,
        free_census_at_create: 0,
    };
}

/// The domain pool. `static mut` accessed only through [`domain_ptr`] under the
/// single-hart / interrupts-off discipline documented at the module top.
static mut DOMAINS: [Domain; DOMAIN_SLOTS] = [const { Domain::EMPTY }; DOMAIN_SLOTS];

/// A global object-table slot (ADR-K2): class, generation, occupancy.
#[derive(Clone, Copy)]
struct Object {
    occupied: bool,
    class: ObjectClass,
    generation: u32,
}

impl Object {
    const EMPTY: Self = Self {
        occupied: false,
        class: ObjectClass::Domain,
        generation: 0,
    };
}

/// M2 object classes.
#[derive(Clone, Copy)]
enum ObjectClass {
    Domain,
    /// An inert object class existing purely to prove the capability mechanism.
    TestArtifact,
}

static OBJECTS: Mutex<[Object; OBJECT_SLOTS]> = Mutex::new([Object::EMPTY; OBJECT_SLOTS]);

/// The scheduler's view of a completed ring-3 run.
#[derive(Clone, Copy)]
pub enum RunOutcome {
    Exited(u64),
    Killed(KillCause),
    QuotaExpired,
}

#[derive(Clone, Copy)]
pub enum KillCause {
    PageFault,
    GeneralProtection,
}

impl RunOutcome {
    fn from_tag(tag: u64) -> Self {
        match tag {
            syscall::OUT_EXITED => Self::Exited(syscall::LAST_EXIT_CODE.load(Ordering::SeqCst)),
            syscall::OUT_KILLED_PF => Self::Killed(KillCause::PageFault),
            syscall::OUT_KILLED_GP => Self::Killed(KillCause::GeneralProtection),
            _ => Self::QuotaExpired,
        }
    }
}

#[inline]
fn domain_ptr(idx: usize) -> *mut Domain {
    // SAFETY: `idx < DOMAIN_SLOTS` for every caller; computes an address into
    // the pool without forming a reference (no aliasing with concurrent raw
    // accesses under the single-hart discipline).
    unsafe { core::ptr::addr_of_mut!(DOMAINS).cast::<Domain>().add(idx) }
}

fn find_free_domain() -> Option<usize> {
    // SAFETY: single-hart; no concurrent domain create.
    (0..DOMAIN_SLOTS).find(|&i| unsafe { (*domain_ptr(i)).state } == State::Free)
}

// ---- object table + capability table (ADR-K2 / ADR-K4) ---------------------

fn object_alloc(class: ObjectClass) -> Option<u32> {
    let mut objs = OBJECTS.lock();
    for (i, obj) in objs.iter_mut().enumerate() {
        if !obj.occupied {
            obj.occupied = true;
            obj.class = class;
            // Generation is monotonic across reuse, so a stale handle from a
            // prior tenant of this slot never validates against a new tenant.
            return Some(i as u32);
        }
    }
    None
}

fn object_release(idx: u32) {
    let mut objs = OBJECTS.lock();
    let obj = &mut objs[idx as usize];
    obj.occupied = false;
    obj.generation = obj.generation.wrapping_add(1);
}

/// Revoke an object (ADR-K4 mass invalidation): bump its generation so every
/// capability referencing the old generation is dead at once, O(1).
fn revoke_object(idx: u32) {
    let generation = {
        let mut objs = OBJECTS.lock();
        let obj = &mut objs[idx as usize];
        // M2 only ever revokes the inert TestArtifact object.
        debug_assert!(matches!(obj.class, ObjectClass::TestArtifact));
        obj.generation = obj.generation.wrapping_add(1);
        obj.generation
    };
    serial::ev_cap_revoked(idx, generation);
    REVOKE_DONE.store(true, Ordering::SeqCst);
}

fn cap_mint(idx: usize, slot: usize, object_index: u32, rights: u32) {
    let generation = OBJECTS.lock()[object_index as usize].generation;
    // SAFETY: scheduler context, single hart; the domain is not running.
    unsafe {
        (*domain_ptr(idx)).caps[slot] = CapEntry {
            occupied: true,
            object_index,
            generation,
            rights,
            derivation_parent: 0,
        };
    }
}

/// The ADR-K2 check order: index in range -> entry occupied -> generation match
/// (else StaleCap) -> rights superset of required (else Denied).
fn check_cap(idx: usize, slot: u64, required: u32) -> Result<u32, i64> {
    if slot >= CAP_ENTRIES as u64 {
        return Err(BAD_CAP);
    }
    // SAFETY: syscall-dispatch context, single hart; CapEntry is Copy.
    let entry = unsafe { (*domain_ptr(idx)).caps[slot as usize] };
    if !entry.occupied {
        return Err(BAD_CAP);
    }
    let object_generation = OBJECTS.lock()[entry.object_index as usize].generation;
    if entry.generation != object_generation {
        return Err(STALE_CAP);
    }
    if entry.rights & required != required {
        return Err(DENIED);
    }
    Ok(entry.rights)
}

// ---- syscalls (called from the dispatcher / handlers) ----------------------

/// The running domain's slot index (for fault attribution). Only meaningful
/// while a domain is executing in ring 3.
pub fn current() -> usize {
    CURRENT_DOMAIN.load(Ordering::SeqCst)
}

pub fn sys_note(value: u64) {
    let idx = CURRENT_DOMAIN.load(Ordering::SeqCst);
    serial::ev_domain_note(idx, value);
    NOTE_SEEN.store(true, Ordering::SeqCst);
    NOTE_VALUE.store(value, Ordering::SeqCst);
    let armed = REVOKE_ON_NOTE.swap(0, Ordering::SeqCst);
    if armed != 0 {
        revoke_object(armed - 1);
    }
}

pub fn sys_cap_rights(slot: u64) -> (i64, u64) {
    let idx = CURRENT_DOMAIN.load(Ordering::SeqCst);
    match check_cap(idx, slot, 0) {
        Ok(rights) => (OK, rights as u64),
        Err(status) => (status, 0),
    }
}

pub fn sys_exit(code: u64) -> ! {
    syscall::LAST_EXIT_CODE.store(code, Ordering::SeqCst);
    let save_slot = syscall::CURRENT_SAVE_SLOT.load(Ordering::SeqCst) as *mut u64;
    // SAFETY: `save_slot` is the live continuation slot armed for this run.
    unsafe { syscall::context_switch_back(save_slot, syscall::OUT_EXITED) }
}

/// Fill the death record for a ring-3 fault and terminate the domain via the
/// continuation (does not `iretq` back to user).
pub fn fault_kill(vector: u64, error_code: u64, rip: u64) -> ! {
    let idx = CURRENT_DOMAIN.load(Ordering::SeqCst);
    let cause = if vector == 14 {
        Cause::PageFault
    } else {
        Cause::GeneralProtection
    };
    // SAFETY: a domain is running (fault came from CPL=3); single hart.
    unsafe {
        (*domain_ptr(idx)).death = DeathRecord {
            cause,
            vector,
            error_code,
            rip,
        };
    }
    let tag = if vector == 14 {
        syscall::OUT_KILLED_PF
    } else {
        syscall::OUT_KILLED_GP
    };
    let save_slot = syscall::CURRENT_SAVE_SLOT.load(Ordering::SeqCst) as *mut u64;
    // SAFETY: `save_slot` is the live continuation slot armed for this run.
    unsafe { syscall::context_switch_back(save_slot, tag) }
}

/// Charge one timer tick to the running domain. Returns `true` if the quota is
/// now exhausted (the caller must then [`quota_kill`]).
pub fn timer_tick() -> bool {
    let idx = CURRENT_DOMAIN.load(Ordering::SeqCst);
    if idx == NONE {
        return false;
    }
    // SAFETY: the parked scheduler does not touch DOMAINS during the ring-3
    // excursion; single hart, interrupts off in the handler.
    unsafe {
        let quota = (*domain_ptr(idx)).quota.saturating_sub(1);
        (*domain_ptr(idx)).quota = quota;
        quota == 0
    }
}

pub fn quota_kill() -> ! {
    let idx = CURRENT_DOMAIN.load(Ordering::SeqCst);
    // SAFETY: a domain is running; single hart.
    unsafe {
        (*domain_ptr(idx)).death = DeathRecord {
            cause: Cause::Quota,
            vector: 0,
            error_code: 0,
            rip: 0,
        };
    }
    let save_slot = syscall::CURRENT_SAVE_SLOT.load(Ordering::SeqCst) as *mut u64;
    // SAFETY: `save_slot` is the live continuation slot armed for this run.
    unsafe { syscall::context_switch_back(save_slot, syscall::OUT_QUOTA) }
}

// ---- lifecycle -------------------------------------------------------------

fn free_frames(frames: &FrameList) {
    for &phys in &frames.frames[..frames.len] {
        memory::free_frame(Frame(phys));
    }
}

/// Free a slot's frames in place and return how many were freed.
///
/// # Safety
/// `idx < DOMAIN_SLOTS` and the domain must not be running.
unsafe fn reclaim_frames(idx: usize) -> usize {
    let d = domain_ptr(idx);
    // SAFETY: forwarded; single hart, domain not running.
    unsafe {
        let len = (*d).frames.len;
        for i in 0..len {
            memory::free_frame(Frame((*d).frames.frames[i]));
        }
        (*d).frames.len = 0;
        len
    }
}

fn domain_create(payload: extern "C" fn()) -> Option<usize> {
    let idx = find_free_domain()?;
    let census = memory::free_frame_count();
    let boot_pml4 = Cr3::read().0.start_address().as_u64();

    let mut frames = FrameList::EMPTY;
    let space = match vm::build(&mut frames, boot_pml4) {
        Some(space) => space,
        None => {
            free_frames(&frames);
            return None;
        },
    };

    let kframe = match memory::alloc_frame() {
        Some(frame) if frames.push(frame.0) => frame,
        Some(frame) => {
            memory::free_frame(frame);
            free_frames(&frames);
            return None;
        },
        None => {
            free_frames(&frames);
            return None;
        },
    };
    let kstack_top = memory::phys_offset_addr() + kframe.0 + 4096;

    // SAFETY: `payload` is a naked function in the kernel image; we copy
    // PAYLOAD_MAX bytes of its position-independent code into the code frame.
    unsafe {
        vm::load_payload(
            space.code_frame_phys,
            payload as usize as *const u8,
            PAYLOAD_MAX,
        );
    }

    let domain_object = match object_alloc(ObjectClass::Domain) {
        Some(object) => object,
        None => {
            free_frames(&frames);
            return None;
        },
    };

    let frames_count = frames.len;
    // SAFETY: committing a fully-initialized domain into a Free slot; single
    // hart, no concurrent access to this slot.
    unsafe {
        *domain_ptr(idx) = Domain {
            state: State::Ready,
            frames,
            pml4_phys: space.pml4_phys,
            kstack_top,
            kctx_rsp: 0,
            quota: 0,
            death: DeathRecord::EMPTY,
            caps: [CapEntry::EMPTY; CAP_ENTRIES],
            domain_object,
            free_census_at_create: census,
        };
    }
    serial::ev_domain_create(idx, frames_count);
    Some(idx)
}

/// Create failed to reach a run: reclaim frames + object, return slot to Free.
fn discard_domain(idx: usize) {
    // SAFETY: single hart, domain not running.
    let object = unsafe {
        reclaim_frames(idx);
        let object = (*domain_ptr(idx)).domain_object;
        (*domain_ptr(idx)).state = State::Free;
        object
    };
    object_release(object);
}

fn run_domain(idx: usize) -> RunOutcome {
    // SAFETY: single hart; the slot is Ready and not yet running.
    let (kstack_top, pml4, save_slot) = unsafe {
        let d = domain_ptr(idx);
        (*d).state = State::Running;
        (*d).quota = TICK_QUOTA;
        (*d).kctx_rsp = 0;
        (
            (*d).kstack_top,
            (*d).pml4_phys,
            core::ptr::addr_of_mut!((*d).kctx_rsp) as u64,
        )
    };
    CURRENT_DOMAIN.store(idx, Ordering::SeqCst);
    syscall::arm(kstack_top, save_slot);
    serial::ev_domain_enter(idx);
    // SAFETY: `pml4` maps the kernel; `save_slot` is a live u64 in the slot;
    // the user entry VA and stack are mapped RX / RW in that space.
    let tag = unsafe {
        syscall::context_enter(
            save_slot as *mut u64,
            vm::USER_CODE_VA,
            vm::USER_STACK_TOP,
            pml4,
        )
    };
    CURRENT_DOMAIN.store(NONE, Ordering::SeqCst);
    RunOutcome::from_tag(tag)
}

/// Emit the terminal lifecycle event, reclaim every frame, and check the
/// allocator balance against the create-time census.
fn finish_domain(idx: usize, outcome: RunOutcome) -> bool {
    match outcome {
        RunOutcome::Exited(code) => serial::ev_domain_exit(idx, code),
        RunOutcome::Killed(KillCause::PageFault) => serial::ev_domain_killed(idx, "pf"),
        RunOutcome::Killed(KillCause::GeneralProtection) => serial::ev_domain_killed(idx, "gp"),
        RunOutcome::QuotaExpired => serial::ev_domain_killed(idx, "quota"),
    }
    // SAFETY: single hart, domain no longer running.
    let (census_at_create, object) = unsafe {
        (*domain_ptr(idx)).state = State::Dead;
        (
            (*domain_ptr(idx)).free_census_at_create,
            (*domain_ptr(idx)).domain_object,
        )
    };
    // SAFETY: single hart, domain not running.
    let freed = unsafe { reclaim_frames(idx) };
    let census_after = memory::free_frame_count();
    let balance_ok = census_after == census_at_create;
    serial::ev_domain_reclaimed(idx, freed, balance_ok);
    object_release(object);
    // SAFETY: single hart; slot returns to the pool.
    unsafe {
        (*domain_ptr(idx)).state = State::Free;
    }
    balance_ok
}

// ---- scenarios -------------------------------------------------------------

fn reset_scenario_state() {
    NOTE_SEEN.store(false, Ordering::SeqCst);
    NOTE_VALUE.store(0, Ordering::SeqCst);
    REVOKE_ON_NOTE.store(0, Ordering::SeqCst);
    REVOKE_DONE.store(false, Ordering::SeqCst);
}

fn report(name: &'static str, pass: bool) -> bool {
    serial::ev_test(name, pass);
    pass
}

fn scenario_happy() -> bool {
    reset_scenario_state();
    let Some(idx) = domain_create(payloads::ring3_happy) else {
        return report("ring3_happy", false);
    };
    let outcome = run_domain(idx);
    let balance_ok = finish_domain(idx, outcome);
    let pass = matches!(outcome, RunOutcome::Exited(7))
        && NOTE_SEEN.load(Ordering::SeqCst)
        && NOTE_VALUE.load(Ordering::SeqCst) == 42
        && balance_ok;
    report("ring3_happy", pass)
}

fn scenario_kernel_read() -> bool {
    reset_scenario_state();
    let Some(idx) = domain_create(payloads::ring3_kernel_read) else {
        return report("ring3_kernel_read", false);
    };
    let outcome = run_domain(idx);
    let balance_ok = finish_domain(idx, outcome);
    let pass = matches!(outcome, RunOutcome::Killed(KillCause::PageFault)) && balance_ok;
    report("ring3_kernel_read", pass)
}

fn scenario_priv_insn() -> bool {
    reset_scenario_state();
    let Some(idx) = domain_create(payloads::ring3_priv_insn) else {
        return report("ring3_priv_insn", false);
    };
    let outcome = run_domain(idx);
    let balance_ok = finish_domain(idx, outcome);
    let pass = matches!(outcome, RunOutcome::Killed(KillCause::GeneralProtection)) && balance_ok;
    report("ring3_priv_insn", pass)
}

fn scenario_bad_cap() -> bool {
    reset_scenario_state();
    let Some(idx) = domain_create(payloads::ring3_bad_cap) else {
        return report("ring3_bad_cap", false);
    };
    let outcome = run_domain(idx);
    let balance_ok = finish_domain(idx, outcome);
    let pass = matches!(outcome, RunOutcome::Exited(0)) && balance_ok;
    report("ring3_bad_cap", pass)
}

fn scenario_stale_cap() -> bool {
    reset_scenario_state();
    let Some(idx) = domain_create(payloads::ring3_stale_cap) else {
        return report("ring3_stale_cap", false);
    };
    let Some(object) = object_alloc(ObjectClass::TestArtifact) else {
        discard_domain(idx);
        return report("ring3_stale_cap", false);
    };
    // Mint a capability into slot 5 with rights 0b111, then arm revoke-on-note.
    cap_mint(idx, 5, object, 0b111);
    REVOKE_ON_NOTE.store(object + 1, Ordering::SeqCst);

    let outcome = run_domain(idx);
    let balance_ok = finish_domain(idx, outcome);
    object_release(object);

    let pass = matches!(outcome, RunOutcome::Exited(0))
        && REVOKE_DONE.load(Ordering::SeqCst)
        && balance_ok;
    report("ring3_stale_cap", pass)
}

fn scenario_runaway() -> bool {
    reset_scenario_state();
    let Some(idx) = domain_create(payloads::ring3_runaway) else {
        return report("ring3_runaway", false);
    };
    let outcome = run_domain(idx);
    let balance_ok = finish_domain(idx, outcome);
    let pass = matches!(outcome, RunOutcome::QuotaExpired) && balance_ok;
    report("ring3_runaway", pass)
}

fn scenario_reuse() -> bool {
    reset_scenario_state();
    let Some(idx) = domain_create(payloads::ring3_reuse) else {
        return report("ring3_reuse", false);
    };
    let outcome = run_domain(idx);
    let balance_ok = finish_domain(idx, outcome);
    let pass = matches!(outcome, RunOutcome::Exited(0)) && balance_ok;
    report("ring3_reuse", pass)
}

/// Run all seven ring-3 scenarios in order. Returns `true` iff all passed.
pub fn run_all() -> bool {
    let mut all = true;
    all &= scenario_happy();
    all &= scenario_kernel_read();
    all &= scenario_priv_insn();
    all &= scenario_bad_cap();
    all &= scenario_stale_cap();
    all &= scenario_runaway();
    all &= scenario_reuse();
    all
}
