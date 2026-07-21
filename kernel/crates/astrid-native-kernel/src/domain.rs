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

/// M3 endpoint pool (bounded, charter §6).
const ENDPOINT_SLOTS: usize = 16;
/// Bounded per-endpoint message queue depth; a send past this returns `Full`.
const EP_QUEUE_DEPTH: usize = 4;
/// M3 derivation-graph node pool (bounded).
const DERIV_NODES: usize = 128;
/// Derivation `parent` sentinel: a root node (never derived from a transfer).
const NODE_NONE: u32 = u32::MAX;
/// Slot-argument sentinel meaning "no capability" for `send`/`recv`.
const XFER_NONE: u64 = 0xFFFF_FFFF;
/// Endpoint capability right bits (ADR-K3 IPC).
const EP_SEND: u32 = 0b01;
const EP_RECV: u32 = 0b10;
/// Round-robin scheduler step budget (charter: bounded by construction).
const SCHED_MAX_STEPS: usize = 256;

/// Status codes returned to ring 3 in `rax` (i64).
const OK: i64 = 0;
const BAD_CAP: i64 = -2;
const STALE_CAP: i64 = -3;
const DENIED: i64 = -4;
/// A `send` to a full endpoint queue with no waiting receiver.
const FULL: i64 = -5;
/// A capability whose derivation node was killed by a scoped revoke (ADR-K4).
const REVOKED: i64 = -6;
/// Any bounded pool (object/endpoint/deriv/cap slot) was exhausted.
const NO_RESOURCE: i64 = -7;
/// A legibility syscall argument (relation/row/column index) was out of range.
const BAD_ARG: i64 = -8;

/// `CURRENT_DOMAIN` sentinel meaning "no domain running".
const NONE: usize = usize::MAX;

/// The running domain's slot index, or [`NONE`]. Read by the interrupt/fault
/// handlers to attribute preemption and faults.
static CURRENT_DOMAIN: AtomicUsize = AtomicUsize::new(NONE);

// Kernel-side scenario observation (never influenced by ring-3 strings).
static NOTE_SEEN: AtomicBool = AtomicBool::new(false);
static NOTE_VALUE: AtomicU64 = AtomicU64::new(0);
/// Armed object (index + 1) to mass-invalidate (generation bump) on the next
/// `sys_note`; 0 = disarmed. (M2 stale-cap scenario.)
static REVOKE_ON_NOTE: AtomicU32 = AtomicU32::new(0);
static REVOKE_DONE: AtomicBool = AtomicBool::new(false);
/// Armed object (index + 1) whose derivation subtree is scope-revoked on the
/// next `sys_note`; 0 = disarmed. (M3 scoped-revoke scenario.)
static REVOKE_TREE_ON_NOTE: AtomicU32 = AtomicU32::new(0);
static REVOKE_TREE_DONE: AtomicBool = AtomicBool::new(false);

/// Domain lifecycle state: `Free -> Ready -> Running -> {Blocked -> Ready ->
/// Running}* -> Dead -> Free`. `Blocked` (M3) is a domain suspended at a `recv`
/// boundary waiting for a delivery.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    Ready,
    Running,
    Blocked,
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
    Deadlock,
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

/// A capability-table entry (ADR-K2). `deriv_node` is live machinery in M3
/// (ADR-K3 transfer, ADR-K4 scoped revoke): [`NODE_NONE`] for a minted/root cap
/// that has never participated in a transfer, else the index of this cap's node
/// in the [`DERIV`] graph.
#[derive(Clone, Copy)]
struct CapEntry {
    occupied: bool,
    object_index: u32,
    generation: u32,
    rights: u32,
    deriv_node: u32,
}

impl CapEntry {
    const EMPTY: Self = Self {
        occupied: false,
        object_index: 0,
        generation: 0,
        rights: 0,
        deriv_node: NODE_NONE,
    };
}

/// A capability in flight over an endpoint (ADR-K3). Serialization-clean: it
/// names an object handle + generation + rights + derivation node, never a
/// pointer.
#[derive(Clone, Copy)]
struct XferCap {
    object_index: u32,
    generation: u32,
    rights: u32,
    deriv_node: u32,
}

/// One bounded endpoint message: a single data word plus an optional
/// transferred capability. `from` is the sender domain index, needed only to
/// attribute the `cap.transfer` event emitted at delivery.
#[derive(Clone, Copy)]
struct Msg {
    data: u64,
    cap: Option<XferCap>,
    from: usize,
}

impl Msg {
    const EMPTY: Self = Self {
        data: 0,
        cap: None,
        from: 0,
    };
}

/// A bounded IPC endpoint (ADR-K3). It holds EITHER one blocked receiver OR up
/// to [`EP_QUEUE_DEPTH`] queued messages, never an unbounded backlog.
struct Endpoint {
    occupied: bool,
    waiting_receiver: Option<usize>,
    queue: [Msg; EP_QUEUE_DEPTH],
    qlen: usize,
}

impl Endpoint {
    const EMPTY: Self = Self {
        occupied: false,
        waiting_receiver: None,
        queue: [Msg::EMPTY; EP_QUEUE_DEPTH],
        qlen: 0,
    };
}

/// The endpoint pool. Not reached by any interrupt handler, so a plain spin
/// `Mutex` (matching [`OBJECTS`]) is the correct lock model.
static ENDPOINTS: Mutex<[Endpoint; ENDPOINT_SLOTS]> =
    Mutex::new([const { Endpoint::EMPTY }; ENDPOINT_SLOTS]);

/// A derivation-graph node (ADR-K2/K3/K4): the single store threading the
/// parent→child transfer edges. `alive=false` is a scope-revoked node.
#[derive(Clone, Copy)]
struct DerivNode {
    occupied: bool,
    alive: bool,
    parent: u32,
    object_index: u32,
}

impl DerivNode {
    const EMPTY: Self = Self {
        occupied: false,
        alive: false,
        parent: NODE_NONE,
        object_index: 0,
    };
}

static DERIV: Mutex<[DerivNode; DERIV_NODES]> = Mutex::new([DerivNode::EMPTY; DERIV_NODES]);

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
    /// M3 suspend/resume: true while this domain is `Blocked` at a `recv` and
    /// must be resumed (not first-run) when next scheduled.
    suspended: bool,
    /// Saved user continuation captured from the `SyscallFrame` at block time.
    blocked_rip: u64,
    blocked_rsp: u64,
    /// Cap slot the blocked `recv` will install a transferred cap into
    /// ([`XFER_NONE`] = decline any cap).
    recv_cap_slot: u32,
    /// Endpoint pool slot this domain is blocked on (for events + delivery).
    ep_slot: u8,
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
        suspended: false,
        blocked_rip: 0,
        blocked_rsp: 0,
        recv_cap_slot: XFER_NONE as u32,
        ep_slot: 0,
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

/// Object classes. The `Endpoint(slot)` variant carries the endpoint's runtime
/// pool slot: it is the ONLY link from an object to its endpoint state, so there
/// is no parallel object→endpoint map that could drift (charter: one authority
/// per fact — the Barrelfish lesson).
#[derive(Clone, Copy)]
enum ObjectClass {
    Domain,
    /// An inert object class existing purely to prove the capability mechanism.
    TestArtifact,
    /// A bounded IPC endpoint; the `u8` is its [`ENDPOINTS`] pool slot.
    Endpoint(u8),
    /// M4: the legibility object (ADR legibility). A capability to a `Legible`
    /// object authorizes enumerate/schema/subscribe/get of ALL relations at v0
    /// (per-relation scoping is a future refinement).
    Legible,
}

impl ObjectClass {
    /// Frozen v0 class code (never a string — charter "no strings as authority").
    fn code(self) -> u64 {
        match self {
            ObjectClass::Domain => CLASS_DOMAIN,
            ObjectClass::TestArtifact => CLASS_TEST_ARTIFACT,
            ObjectClass::Endpoint(_) => CLASS_ENDPOINT,
            ObjectClass::Legible => CLASS_LEGIBLE,
        }
    }
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
    Deadlock,
}

impl RunOutcome {
    /// Map a TERMINAL continuation tag to an outcome. [`syscall::OUT_BLOCKED`]
    /// is not terminal and is handled by the scheduler before this is called.
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
    let allocated = {
        let mut objs = OBJECTS.lock();
        let mut found = None;
        for (i, obj) in objs.iter_mut().enumerate() {
            if !obj.occupied {
                obj.occupied = true;
                obj.class = class;
                // Generation is monotonic across reuse, so a stale handle from a
                // prior tenant of this slot never validates against a new tenant.
                found = Some(i as u32);
                break;
            }
        }
        found
    };
    if let Some(idx) = allocated {
        delta_object_add(idx);
    }
    allocated
}

fn object_release(idx: u32) {
    // Project the deletion BEFORE the slot is cleared, while the row is still
    // readable (single-store delta from the mutation site).
    delta_object_del(idx);
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
        // M2 revokes the inert TestArtifact object; M4 also revokes the Legible
        // object (scenario `legible_revoked_cap`) — legibility authority is a
        // normal capability, revocable by generation bump like any other.
        debug_assert!(matches!(
            obj.class,
            ObjectClass::TestArtifact | ObjectClass::Legible
        ));
        obj.generation = obj.generation.wrapping_add(1);
        obj.generation
    };
    serial::ev_cap_revoked(idx, generation);
    // A generation bump keeps the object occupied: project it as a change to the
    // REL_OBJECT row (single-store delta from the mutation site).
    delta_object_chg(idx);
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
            deriv_node: NODE_NONE,
        };
    }
    delta_cap_add(idx, slot);
}

/// The ADR-K2/K4 check order: (1) index in range else `BadCap`; (2) entry
/// occupied else `BadCap`; (3) generation matches the object else `StaleCap`
/// (ADR-K4 mass invalidation); (4) derivation node absent or alive else
/// `Revoked` (ADR-K4 scoped revocation); (5) rights superset of `required` else
/// `Denied`. Returns the rights on success.
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
    if entry.deriv_node != NODE_NONE && !DERIV.lock()[entry.deriv_node as usize].alive {
        return Err(REVOKED);
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
    // M3 scoped revoke (ADR-K4): revoke the derivation subtree rooted at the
    // armed object's root node, keeping the object alive. Mirrors the M2
    // stale-cap note-hook, but derivation-scoped rather than generation-wide.
    let armed_tree = REVOKE_TREE_ON_NOTE.swap(0, Ordering::SeqCst);
    if armed_tree != 0 {
        if let Some(root) = deriv_find_root(armed_tree - 1) {
            revoke_tree(root);
            REVOKE_TREE_DONE.store(true, Ordering::SeqCst);
        }
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
            suspended: false,
            blocked_rip: 0,
            blocked_rsp: 0,
            recv_cap_slot: XFER_NONE as u32,
            ep_slot: 0,
        };
    }
    serial::ev_domain_create(idx, frames_count);
    delta_domain_add(idx);
    Some(idx)
}

/// Reclaim a created-but-never-run domain (a create rollback, or an M4 ring-0
/// scenario's driver domain): free its frames + object and return the slot to
/// Free. Emits `domain.reclaimed` with the same balance accounting as
/// [`finish_domain`] so the create/reclaim census stays paired (callers must
/// discard in reverse creation order, LIFO, for the balance to hold — mirroring
/// how the scheduler finishes participants).
fn discard_domain(idx: usize) {
    // SAFETY: single hart, domain not running.
    let (census_at_create, object) = unsafe {
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
    delta_domain_del(idx);
    object_release(object);
    // SAFETY: single hart; slot returns to the pool.
    unsafe {
        (*domain_ptr(idx)).state = State::Free;
    }
}

/// First-run entry: enter the domain at the fixed user VA/stack with zeroed
/// entry registers, returning the raw continuation tag (which may be
/// [`syscall::OUT_BLOCKED`] under M3). The M2 single-domain path wraps this in
/// [`run_domain`]; the M3 scheduler consumes the tag directly.
fn enter_first(idx: usize) -> u64 {
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
    delta_domain_chg(idx);
    // SAFETY: `pml4` maps the kernel; `save_slot` is a live u64 in the slot;
    // the user entry VA and stack are mapped RX / RW in that space.
    let tag = unsafe {
        syscall::context_enter(
            save_slot as *mut u64,
            vm::USER_CODE_VA,
            vm::USER_STACK_TOP,
            pml4,
            0,
            0,
        )
    };
    CURRENT_DOMAIN.store(NONE, Ordering::SeqCst);
    tag
}

fn run_domain(idx: usize) -> RunOutcome {
    RunOutcome::from_tag(enter_first(idx))
}

/// Emit the terminal lifecycle event, reclaim every frame, and check the
/// allocator balance against the create-time census.
fn finish_domain(idx: usize, outcome: RunOutcome) -> bool {
    match outcome {
        RunOutcome::Exited(code) => serial::ev_domain_exit(idx, code),
        RunOutcome::Killed(KillCause::PageFault) => serial::ev_domain_killed(idx, "pf"),
        RunOutcome::Killed(KillCause::GeneralProtection) => serial::ev_domain_killed(idx, "gp"),
        RunOutcome::Killed(KillCause::Deadlock) => serial::ev_domain_killed(idx, "deadlock"),
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
    delta_domain_chg(idx);
    // Implicit unsubscribe on the subscriber's death (charter: bounded, no
    // dangling subscription).
    if LEGIBLE_SUBSCRIBER.load(Ordering::SeqCst) == idx {
        legible_clear_subscriber();
    }
    // SAFETY: single hart, domain not running.
    let freed = unsafe { reclaim_frames(idx) };
    let census_after = memory::free_frame_count();
    let balance_ok = census_after == census_at_create;
    serial::ev_domain_reclaimed(idx, freed, balance_ok);
    object_release(object);
    delta_domain_del(idx);
    // SAFETY: single hart; slot returns to the pool.
    unsafe {
        (*domain_ptr(idx)).state = State::Free;
    }
    balance_ok
}

// ---- M3: endpoint pool + derivation graph ----------------------------------

fn endpoint_alloc() -> Option<u8> {
    let mut eps = ENDPOINTS.lock();
    for (i, ep) in eps.iter_mut().enumerate() {
        if !ep.occupied {
            *ep = Endpoint::EMPTY;
            ep.occupied = true;
            return Some(i as u8);
        }
    }
    None
}

fn endpoint_free(slot: u8) {
    ENDPOINTS.lock()[slot as usize] = Endpoint::EMPTY;
}

/// Dequeue the front message of an endpoint (FIFO shift). Returns `None` if
/// empty.
fn endpoint_dequeue(slot: u8) -> Option<Msg> {
    let mut eps = ENDPOINTS.lock();
    let ep = &mut eps[slot as usize];
    if ep.qlen == 0 {
        return None;
    }
    let msg = ep.queue[0];
    for i in 1..ep.qlen {
        ep.queue[i - 1] = ep.queue[i];
    }
    ep.qlen -= 1;
    ep.queue[ep.qlen] = Msg::EMPTY;
    Some(msg)
}

/// Resolve an endpoint capability slot to its endpoint pool slot via the object
/// table (the single authority — `ObjectClass::Endpoint(slot)`).
fn resolve_endpoint(idx: usize, ep_cap_slot: u64) -> Option<u8> {
    // SAFETY: caller validated the slot with `check_cap`; CapEntry is Copy.
    let entry = unsafe { (*domain_ptr(idx)).caps[ep_cap_slot as usize] };
    match OBJECTS.lock()[entry.object_index as usize].class {
        ObjectClass::Endpoint(slot) => Some(slot),
        _ => None,
    }
}

/// The object index whose class is `Endpoint(slot)`, if any.
fn find_endpoint_object(slot: u8) -> Option<u32> {
    let objs = OBJECTS.lock();
    objs.iter().enumerate().find_map(|(i, o)| match o.class {
        ObjectClass::Endpoint(s) if o.occupied && s == slot => Some(i as u32),
        _ => None,
    })
}

fn find_free_cap(idx: usize) -> Option<usize> {
    // SAFETY: single hart; the domain is not running.
    (0..CAP_ENTRIES).find(|&s| !unsafe { (*domain_ptr(idx)).caps[s].occupied })
}

/// Allocate a derivation node under `parent` for `object_index`. Returns its
/// pool index, or `None` on exhaustion.
fn deriv_alloc(
    deriv: &mut [DerivNode; DERIV_NODES],
    parent: u32,
    object_index: u32,
) -> Option<u32> {
    for (i, node) in deriv.iter_mut().enumerate() {
        if !node.occupied {
            *node = DerivNode {
                occupied: true,
                alive: true,
                parent,
                object_index,
            };
            // DERIV is locked by the caller: project the add from the local row
            // (re-locking here would deadlock).
            delta_emit(REL_DERIVATION, OP_ADD, &deriv_row(i as u32, node));
            return Some(i as u32);
        }
    }
    None
}

/// The root derivation node (parent == NONE) for `object_index`, if any.
fn deriv_find_root(object_index: u32) -> Option<u32> {
    let deriv = DERIV.lock();
    deriv.iter().enumerate().find_map(|(i, n)| {
        if n.occupied && n.parent == NODE_NONE && n.object_index == object_index {
            Some(i as u32)
        } else {
            None
        }
    })
}

/// Scoped revocation (ADR-K4): mark `node` and every node whose parent chain
/// reaches it dead, in a single bounded pass over the fixed pool (no unbounded
/// recursion). Emits `cap.revoke_tree` and returns the count of newly-dead
/// nodes.
fn revoke_tree(node: u32) -> usize {
    let mut deriv = DERIV.lock();
    let mut in_tree = [false; DERIV_NODES];
    in_tree[node as usize] = true;
    // Bounded fixpoint: each pass can only add nodes, so it converges in at most
    // DERIV_NODES passes.
    loop {
        let mut changed = false;
        for i in 0..DERIV_NODES {
            if deriv[i].occupied && !in_tree[i] {
                let p = deriv[i].parent;
                if p != NODE_NONE && in_tree[p as usize] {
                    in_tree[i] = true;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let mut killed = 0;
    for i in 0..DERIV_NODES {
        if in_tree[i] && deriv[i].occupied && deriv[i].alive {
            deriv[i].alive = false;
            killed += 1;
            // Alive flip → project as a REL_DERIVATION change from the local row
            // (DERIV is held here).
            delta_emit(REL_DERIVATION, OP_CHG, &deriv_row(i as u32, &deriv[i]));
        }
    }
    drop(deriv);
    serial::ev_cap_revoke_tree(node, killed);
    killed
}

/// Build the child derivation node for a transfer, lazily rooting the source
/// cap first (ADR-K3). On deriv-pool exhaustion, rolls back any lazily-allocated
/// root and returns `None` (no partial state). On success, writes the root back
/// into the source cap entry and returns the transferred [`XferCap`].
fn make_child_cap(
    idx: usize,
    source_slot: usize,
    object_index: u32,
    generation: u32,
    granted_rights: u32,
) -> Option<XferCap> {
    let mut deriv = DERIV.lock();
    // SAFETY: single hart; the sending domain is running but its own cap table
    // is only touched here on the syscall path.
    let source_node = unsafe { (*domain_ptr(idx)).caps[source_slot].deriv_node };
    let (root, allocated_root) = if source_node == NODE_NONE {
        (deriv_alloc(&mut deriv, NODE_NONE, object_index)?, true)
    } else {
        (source_node, false)
    };
    let child = match deriv_alloc(&mut deriv, root, object_index) {
        Some(c) => c,
        None => {
            if allocated_root {
                // Undo the lazily-rooted node: project its removal from the
                // local row before clearing it (DERIV is held here).
                delta_emit(
                    REL_DERIVATION,
                    OP_DEL,
                    &deriv_row(root, &deriv[root as usize]),
                );
                deriv[root as usize] = DerivNode::EMPTY;
            }
            return None;
        },
    };
    drop(deriv);
    if allocated_root {
        // SAFETY: single hart; writing the freshly-rooted node back.
        unsafe {
            (*domain_ptr(idx)).caps[source_slot].deriv_node = root;
        }
        // The source cap's derivation link changed: project it as a REL_CAPABILITY
        // change (DERIV is now unlocked).
        delta_cap_chg(idx, source_slot);
    }
    Some(XferCap {
        object_index,
        generation,
        rights: granted_rights,
        deriv_node: child,
    })
}

/// Complete a `recv` delivery to `idx`: install any transferred cap into
/// `recv_slot` (or drop it if `recv_slot == XFER_NONE`) and emit `ipc.recv`
/// plus `cap.transfer` / `ipc.cap_dropped`. Shared by the queue-dequeue path
/// and the resume path so delivery events are emitted exactly once, at true
/// delivery.
fn deliver_recv(idx: usize, ep: u8, from: usize, data: u64, cap: Option<XferCap>, recv_slot: u32) {
    match cap {
        Some(xc) if recv_slot != XFER_NONE as u32 => {
            debug_assert!((recv_slot as usize) < CAP_ENTRIES);
            // SAFETY: single hart; installing into a validated cap slot of the
            // (not currently running) receiver.
            unsafe {
                (*domain_ptr(idx)).caps[recv_slot as usize] = CapEntry {
                    occupied: true,
                    object_index: xc.object_index,
                    generation: xc.generation,
                    rights: xc.rights,
                    deriv_node: xc.deriv_node,
                };
            }
            delta_cap_add(idx, recv_slot as usize);
            serial::ev_ipc_recv(ep, idx, data, true);
            serial::ev_cap_transfer(xc.object_index, from, idx, xc.rights, xc.deriv_node);
        },
        Some(_) => {
            // A cap rode along but the receiver declined to accept one: drop it.
            serial::ev_ipc_cap_dropped(ep);
            serial::ev_ipc_recv(ep, idx, data, false);
        },
        None => serial::ev_ipc_recv(ep, idx, data, false),
    }
}

// ---- M3 syscalls -----------------------------------------------------------

/// `4 sys_ep_create() -> (status, ep_cap_slot)`. Allocate an endpoint object +
/// pool slot and mint a root `EP_SEND|EP_RECV` cap into the caller's first free
/// cap slot. Any pool exhaustion → `NoResource`.
pub fn sys_ep_create() -> (i64, u64) {
    let idx = CURRENT_DOMAIN.load(Ordering::SeqCst);
    let Some(ep) = endpoint_alloc() else {
        return (NO_RESOURCE, 0);
    };
    let Some(object) = object_alloc(ObjectClass::Endpoint(ep)) else {
        endpoint_free(ep);
        return (NO_RESOURCE, 0);
    };
    let Some(slot) = find_free_cap(idx) else {
        object_release(object);
        endpoint_free(ep);
        return (NO_RESOURCE, 0);
    };
    cap_mint(idx, slot, object, EP_SEND | EP_RECV);
    serial::ev_ep_create(object, ep, idx);
    (OK, slot as u64)
}

/// `5 sys_send(ep_slot, data, xfer_cap_slot, rights_mask) -> (status, 0)`.
/// Validate `EP_SEND`; optionally shrink-and-derive a transferred cap; deliver
/// directly to a blocked receiver or enqueue (bounded). Derivation nodes are
/// allocated only once delivery/enqueue is committed (no partial state).
pub fn sys_send(ep_cap_slot: u64, data: u64, xfer_slot: u64, rights_mask: u64) -> (i64, u64) {
    let idx = CURRENT_DOMAIN.load(Ordering::SeqCst);
    if let Err(status) = check_cap(idx, ep_cap_slot, EP_SEND) {
        return (status, 0);
    }
    let Some(ep) = resolve_endpoint(idx, ep_cap_slot) else {
        return (BAD_CAP, 0);
    };

    // Validate the transfer source (any rights) WITHOUT yet allocating deriv
    // nodes; capture what a committed transfer would need.
    let mut xfer: Option<(u32, u32, u32, usize)> = None; // (object, gen, granted, slot)
    if xfer_slot != XFER_NONE {
        match check_cap(idx, xfer_slot, 0) {
            Err(status) => return (status, 0),
            Ok(source_rights) => {
                // SAFETY: slot validated by check_cap; CapEntry is Copy.
                let entry = unsafe { (*domain_ptr(idx)).caps[xfer_slot as usize] };
                let granted = source_rights & rights_mask as u32; // monotonic shrink
                xfer = Some((
                    entry.object_index,
                    entry.generation,
                    granted,
                    xfer_slot as usize,
                ));
            },
        }
    }

    // Decide delivery vs enqueue vs Full, holding the endpoint lock only to read
    // the receiver/queue state.
    let waiting = {
        let eps = ENDPOINTS.lock();
        eps[ep as usize].waiting_receiver
    };

    // Commit: allocate the child node now (only on the committed path).
    let build_cap = || -> Result<Option<XferCap>, i64> {
        match xfer {
            Some((object, gen, granted, sslot)) => {
                match make_child_cap(idx, sslot, object, gen, granted) {
                    Some(xc) => Ok(Some(xc)),
                    None => Err(NO_RESOURCE),
                }
            },
            None => Ok(None),
        }
    };

    if let Some(receiver) = waiting {
        // Direct delivery to a blocked receiver: enqueue exactly one message
        // (the queue is empty by the endpoint invariant), clear the waiter, and
        // mark it Ready. The scheduler resumes it later; the sender keeps
        // running.
        let cap = match build_cap() {
            Ok(c) => c,
            Err(status) => return (status, 0),
        };
        {
            let mut eps = ENDPOINTS.lock();
            let e = &mut eps[ep as usize];
            let q = e.qlen;
            e.queue[q] = Msg {
                data,
                cap,
                from: idx,
            };
            e.qlen = q + 1;
            e.waiting_receiver = None;
        }
        // SAFETY: single hart; the receiver is Blocked and not running.
        unsafe {
            (*domain_ptr(receiver)).state = State::Ready;
        }
        serial::ev_ipc_send(ep, idx, data, cap.is_some());
        serial::ev_ipc_wakeup(receiver, ep);
        (OK, 0)
    } else {
        // No waiter: enqueue if there is room, else Full (no deriv allocated).
        let full = {
            let eps = ENDPOINTS.lock();
            eps[ep as usize].qlen >= EP_QUEUE_DEPTH
        };
        if full {
            return (FULL, 0);
        }
        let cap = match build_cap() {
            Ok(c) => c,
            Err(status) => return (status, 0),
        };
        {
            let mut eps = ENDPOINTS.lock();
            let e = &mut eps[ep as usize];
            let q = e.qlen;
            e.queue[q] = Msg {
                data,
                cap,
                from: idx,
            };
            e.qlen = q + 1;
        }
        serial::ev_ipc_send(ep, idx, data, cap.is_some());
        (OK, 0)
    }
}

/// `6 sys_recv(ep_slot, recv_cap_slot) -> (status, data)`. On a non-empty queue,
/// deliver inline. On an empty queue, block: capture the user continuation from
/// the syscall frame, set `Blocked`, and switch back to the scheduler with
/// [`syscall::OUT_BLOCKED`] (this path diverges and never returns here).
pub fn sys_recv(ep_cap_slot: u64, recv_cap_slot: u64, user_rip: u64, user_rsp: u64) -> (i64, u64) {
    let idx = CURRENT_DOMAIN.load(Ordering::SeqCst);
    if let Err(status) = check_cap(idx, ep_cap_slot, EP_RECV) {
        return (status, 0);
    }
    let Some(ep) = resolve_endpoint(idx, ep_cap_slot) else {
        return (BAD_CAP, 0);
    };
    if recv_cap_slot != XFER_NONE && recv_cap_slot >= CAP_ENTRIES as u64 {
        return (BAD_CAP, 0);
    }
    let recv_slot32 = if recv_cap_slot == XFER_NONE {
        XFER_NONE as u32
    } else {
        recv_cap_slot as u32
    };

    // Non-empty queue: deliver the front message now.
    if let Some(msg) = endpoint_dequeue(ep) {
        deliver_recv(idx, ep, msg.from, msg.data, msg.cap, recv_slot32);
        return (OK, msg.data);
    }

    // Empty: only one receiver may wait at a time (bounded; no receiver queue).
    {
        let mut eps = ENDPOINTS.lock();
        if eps[ep as usize].waiting_receiver.is_some() {
            return (DENIED, 0);
        }
        eps[ep as usize].waiting_receiver = Some(idx);
    }
    // Capture the user continuation and suspend at this syscall boundary.
    // SAFETY: single hart; the domain is the running one.
    unsafe {
        let d = domain_ptr(idx);
        (*d).recv_cap_slot = recv_slot32;
        (*d).blocked_rip = user_rip;
        (*d).blocked_rsp = user_rsp;
        (*d).ep_slot = ep;
        (*d).suspended = true;
        (*d).state = State::Blocked;
    }
    delta_domain_chg(idx);
    serial::ev_ipc_blocked(idx, ep);
    let save_slot = syscall::CURRENT_SAVE_SLOT.load(Ordering::SeqCst) as *mut u64;
    // SAFETY: `save_slot` is the live continuation armed for this run; this
    // returns the scheduler to its `context_enter` call site with OUT_BLOCKED
    // and does not return here.
    unsafe { syscall::context_switch_back(save_slot, syscall::OUT_BLOCKED) }
}

/// `7 sys_revoke_tree(cap_slot) -> (status, killed_count)`. Scoped revocation
/// (ADR-K4) of the derivation subtree rooted at the named cap's node, lazily
/// rooting a never-transferred cap first. Shares [`revoke_tree`] with the
/// scenario note-hook.
pub fn sys_revoke_tree(cap_slot: u64) -> (i64, u64) {
    let idx = CURRENT_DOMAIN.load(Ordering::SeqCst);
    if let Err(status) = check_cap(idx, cap_slot, 0) {
        return (status, 0);
    }
    // SAFETY: cap_slot validated in range + occupied by check_cap.
    let entry = unsafe { (*domain_ptr(idx)).caps[cap_slot as usize] };
    let node = if entry.deriv_node == NODE_NONE {
        let mut deriv = DERIV.lock();
        let Some(root) = deriv_alloc(&mut deriv, NODE_NONE, entry.object_index) else {
            return (NO_RESOURCE, 0);
        };
        drop(deriv);
        // SAFETY: single hart; write the freshly-rooted node back.
        unsafe {
            (*domain_ptr(idx)).caps[cap_slot as usize].deriv_node = root;
        }
        root
    } else {
        entry.deriv_node
    };
    let killed = revoke_tree(node);
    (OK, killed as u64)
}

// ---- M3 scheduler ----------------------------------------------------------

#[inline]
fn state_of(idx: usize) -> State {
    // SAFETY: single hart; State is Copy.
    unsafe { (*domain_ptr(idx)).state }
}

/// Resume a `Blocked -> Ready` domain: dequeue the message that woke it, run the
/// delivery events, then re-enter ring 3 at its saved continuation with the
/// delivered `(OK, data)` in `rax`/`rdx`. Returns the terminal (or next-block)
/// tag.
fn resume_domain(idx: usize) -> u64 {
    // SAFETY: single hart; the domain is Blocked and not running.
    let (ep, recv_slot) = unsafe {
        let d = domain_ptr(idx);
        ((*d).ep_slot, (*d).recv_cap_slot)
    };
    let msg = endpoint_dequeue(ep).unwrap_or(Msg::EMPTY);
    deliver_recv(idx, ep, msg.from, msg.data, msg.cap, recv_slot);

    // SAFETY: single hart; arm the resume continuation.
    let (rip, rsp, pml4, kstack_top, save_slot) = unsafe {
        let d = domain_ptr(idx);
        (*d).state = State::Running;
        (*d).quota = TICK_QUOTA;
        (*d).kctx_rsp = 0;
        (*d).suspended = false;
        (
            (*d).blocked_rip,
            (*d).blocked_rsp,
            (*d).pml4_phys,
            (*d).kstack_top,
            core::ptr::addr_of_mut!((*d).kctx_rsp) as u64,
        )
    };
    CURRENT_DOMAIN.store(idx, Ordering::SeqCst);
    syscall::arm(kstack_top, save_slot);
    serial::ev_domain_enter(idx);
    delta_domain_chg(idx);
    // SAFETY: nothing touched this domain's memory or page table between block
    // and resume; the saved rip/rsp are valid user mappings in `pml4`.
    let tag = unsafe {
        syscall::context_enter(save_slot as *mut u64, rip, rsp, pml4, OK as u64, msg.data)
    };
    CURRENT_DOMAIN.store(NONE, Ordering::SeqCst);
    tag
}

fn run_or_resume(idx: usize) -> u64 {
    if state_of(idx) == State::Blocked {
        // Should not happen: a Blocked domain is not Ready. Kept total.
        return syscall::OUT_BLOCKED;
    }
    // SAFETY: single hart; read the suspended flag.
    if unsafe { (*domain_ptr(idx)).suspended } {
        resume_domain(idx)
    } else {
        enter_first(idx)
    }
}

/// Fill a domain's death record with a cause (ADR-K5 evidence).
fn set_death_cause(idx: usize, cause: Cause) {
    // SAFETY: single hart; the domain is not running.
    unsafe {
        (*domain_ptr(idx)).death = DeathRecord {
            cause,
            vector: 0,
            error_code: 0,
            rip: 0,
        };
    }
}

/// Force-kill every still-live participant as a deadlock (ADR-K4/K6 liveness
/// guard). Emits `ipc.deadlock` once, then each terminal `domain.killed`.
fn deadlock_kill(parts: &[usize], outcomes: &mut [Option<RunOutcome>], live: usize) {
    serial::ev_ipc_deadlock(live);
    for (pi, &idx) in parts.iter().enumerate() {
        match state_of(idx) {
            State::Blocked | State::Ready | State::Running => {
                set_death_cause(idx, Cause::Deadlock);
                let outcome = RunOutcome::Killed(KillCause::Deadlock);
                outcomes[pi] = Some(outcome);
                finish_domain(idx, outcome);
            },
            _ => {},
        }
    }
}

/// Drive a set of already-created, `Ready` domains to quiescence over a bounded
/// step budget, recording each participant's terminal [`RunOutcome`]. A one-
/// participant call reproduces the M2 single-domain path.
fn scheduler_run(parts: &[usize], outcomes: &mut [Option<RunOutcome>]) {
    let n = parts.len();
    let mut next = 0usize;
    let mut converged = false;
    for _ in 0..SCHED_MAX_STEPS {
        // Round-robin: next Ready participant starting at `next`.
        let mut picked = None;
        for k in 0..n {
            let pi = (next + k) % n;
            if state_of(parts[pi]) == State::Ready {
                picked = Some(pi);
                break;
            }
        }
        match picked {
            Some(pi) => {
                next = (pi + 1) % n;
                let tag = run_or_resume(parts[pi]);
                if tag == syscall::OUT_BLOCKED {
                    continue;
                }
                let outcome = RunOutcome::from_tag(tag);
                outcomes[pi] = Some(outcome);
                finish_domain(parts[pi], outcome);
            },
            None => {
                // No Ready participant. If any is Blocked, it is a deadlock;
                // otherwise every participant has terminated.
                let blocked = parts
                    .iter()
                    .filter(|&&i| state_of(i) == State::Blocked)
                    .count();
                if blocked > 0 {
                    deadlock_kill(parts, outcomes, blocked);
                }
                converged = true;
                break;
            },
        }
    }
    if !converged {
        // Step budget exhausted: treat as deadlock and kill everything live.
        let live = parts
            .iter()
            .filter(|&&i| matches!(state_of(i), State::Blocked | State::Ready | State::Running))
            .count();
        deadlock_kill(parts, outcomes, live);
    }
}

// ---- M3 kernel-brokered setup + pool teardown ------------------------------

/// Ring-0 endowment: create an endpoint object + pool slot (the M3 stand-in for
/// spawn-time endpoint distribution). Returns `(object, ep_slot)`.
fn kernel_create_endpoint() -> Option<(u32, u8)> {
    let ep = endpoint_alloc()?;
    match object_alloc(ObjectClass::Endpoint(ep)) {
        Some(object) => Some((object, ep)),
        None => {
            endpoint_free(ep);
            None
        },
    }
}

/// Ring-0 endowment: mint an endpoint cap with `rights` into a domain's slot.
fn kernel_mint_ep(domain: usize, cap_slot: usize, ep_object: u32, rights: u32) {
    cap_mint(domain, cap_slot, ep_object, rights);
}

/// Ring-0 endowment: mint a fresh `TestArtifact` cap (the transferable object)
/// with `rights` into a domain's slot. Returns the object index.
fn kernel_mint_artifact(domain: usize, cap_slot: usize, rights: u32) -> Option<u32> {
    let object = object_alloc(ObjectClass::TestArtifact)?;
    cap_mint(domain, cap_slot, object, rights);
    Some(object)
}

/// Reclaim every endpoint pool slot and its backing object at scenario
/// quiescence (all participant domains have terminated). Bounded pass.
fn endpoint_teardown_all() {
    for s in 0..ENDPOINT_SLOTS {
        let occupied = ENDPOINTS.lock()[s].occupied;
        if occupied {
            if let Some(object) = find_endpoint_object(s as u8) {
                object_release(object);
            }
            endpoint_free(s as u8);
        }
    }
}

/// Reclaim every derivation node at scenario quiescence. In M3 the incremental
/// ADR-K4 reclamation sweep is collapsed to a single teardown pass; invalidation
/// (alive=false) is already immediate under `revoke_tree`.
fn deriv_teardown_all() {
    let mut deriv = DERIV.lock();
    for node in deriv.iter_mut() {
        *node = DerivNode::EMPTY;
    }
}

/// Emit the free counts of the three M3 pools (objects/endpoints/deriv). The
/// harness compares the baseline (first) census against the final one to prove
/// no leak across all scenarios.
fn emit_census() {
    let objects_free = OBJECTS.lock().iter().filter(|o| !o.occupied).count();
    let endpoints_free = ENDPOINTS.lock().iter().filter(|e| !e.occupied).count();
    let deriv_free = DERIV.lock().iter().filter(|n| !n.occupied).count();
    serial::ev_pools_census(objects_free, endpoints_free, deriv_free);
}

// ---- M4: legibility ABI v0 -------------------------------------------------
//
// The kernel serializes its five live object tables as typed, versioned,
// integer-columned relations (charter §3 legibility). SINGLE STORE (Barrelfish
// lesson): a relation is NOT a second copy — it is COMPUTED by reading the live
// tables (`DOMAINS`, `OBJECTS`, `ENDPOINTS`, `DERIV`, per-domain `caps`) at
// enumerate time, and every delta is a typed projection emitted from the SAME
// code path that mutates a table, so no relation storage can drift from the
// tables. There is exactly one legibility subscriber at v0; while it is
// registered, each instrumented mutation ALSO emits a bounded typed delta.
//
// v0 quantization (charter procfs side-channel note): deltas are row-granular,
// carry NO timestamps, and have NO ordering beyond the existing global `seq` —
// coarse and timing-free. A scheduled ring-3 subscriber observing high-frequency
// mutations would need explicit per-subscriber rate-limiting first; deferred.
// Per-relation capability scoping is also deferred: a `Legible` cap grants ALL
// relations at v0.

/// Frozen relation ids (v0).
const REL_DOMAIN: u64 = 0;
const REL_OBJECT: u64 = 1;
const REL_CAPABILITY: u64 = 2;
const REL_ENDPOINT: u64 = 3;
const REL_DERIVATION: u64 = 4;

/// Frozen column type codes (v0).
const COL_DOMAIN_ID: u64 = 0;
const COL_STATE: u64 = 1;
const COL_OBJECT_ID: u64 = 2;
const COL_CLASS: u64 = 3;
const COL_GENERATION: u64 = 4;
const COL_CAP_SLOT: u64 = 5;
const COL_RIGHTS: u64 = 6;
const COL_DERIV_NODE: u64 = 7;
const COL_EP_SLOT: u64 = 8;
const COL_QLEN: u64 = 9;
const COL_WAITING: u64 = 10;
const COL_PARENT_NODE: u64 = 11;
const COL_ALIVE: u64 = 12;

/// Frozen object-class codes (v0).
const CLASS_DOMAIN: u64 = 0;
const CLASS_TEST_ARTIFACT: u64 = 1;
const CLASS_ENDPOINT: u64 = 2;
const CLASS_LEGIBLE: u64 = 3;

/// Delta ops (v0): add/del/chg carry the FULL row (fold simplicity).
const OP_ADD: u64 = 0;
const OP_DEL: u64 = 1;
const OP_CHG: u64 = 2;

/// The one legibility right: a cap to a `Legible` object holding this bit
/// authorizes schema/enumerate/subscribe/get of ALL relations at v0.
const LEGIBLE_READ: u32 = 0b1;

/// REL_ENDPOINT `waiting` sentinel: no blocked receiver on this endpoint.
const NO_DOMAIN: u64 = u64::MAX;

/// The single (bounded) legibility subscriber, or [`NONE`]. While set, mutations
/// emit typed deltas. Unsubscribed implicitly on the subscriber's death.
static LEGIBLE_SUBSCRIBER: AtomicUsize = AtomicUsize::new(NONE);

#[inline]
fn subscribed() -> bool {
    LEGIBLE_SUBSCRIBER.load(Ordering::SeqCst) != NONE
}

fn legible_clear_subscriber() {
    LEGIBLE_SUBSCRIBER.store(NONE, Ordering::SeqCst);
}

/// Emit a typed delta iff a subscriber is registered (single-store projection).
fn delta_emit(rel: u64, op: u64, cols: &[u64]) {
    if subscribed() {
        serial::ev_legible_delta(rel, op, cols);
    }
}

// ---- row builders (read the LIVE tables; the single source of truth) --------

fn state_code(state: State) -> u64 {
    match state {
        State::Free => 0,
        State::Ready => 1,
        State::Running => 2,
        State::Blocked => 3,
        State::Dead => 4,
    }
}

fn domain_row(idx: usize) -> [u64; 2] {
    [idx as u64, state_code(state_of(idx))]
}

fn object_row(idx: u32) -> [u64; 3] {
    let obj = OBJECTS.lock()[idx as usize];
    [idx as u64, obj.class.code(), obj.generation as u64]
}

fn cap_row(domain: usize, slot: usize) -> [u64; 6] {
    // SAFETY: single hart; CapEntry is Copy.
    let e = unsafe { (*domain_ptr(domain)).caps[slot] };
    [
        domain as u64,
        slot as u64,
        e.object_index as u64,
        e.rights as u64,
        e.deriv_node as u64,
        e.generation as u64,
    ]
}

fn endpoint_row(object_idx: u32) -> [u64; 4] {
    let ep = match OBJECTS.lock()[object_idx as usize].class {
        ObjectClass::Endpoint(slot) => slot,
        _ => 0,
    };
    let (qlen, waiting) = {
        let eps = ENDPOINTS.lock();
        (eps[ep as usize].qlen, eps[ep as usize].waiting_receiver)
    };
    let waiting_col = match waiting {
        Some(d) => d as u64,
        None => NO_DOMAIN,
    };
    [object_idx as u64, ep as u64, qlen as u64, waiting_col]
}

fn deriv_row(node: u32, n: &DerivNode) -> [u64; 4] {
    [
        node as u64,
        n.parent as u64,
        n.object_index as u64,
        u64::from(n.alive),
    ]
}

// ---- gated delta wrappers (skip all locking when unsubscribed) --------------

fn delta_domain_add(idx: usize) {
    if subscribed() {
        delta_emit(REL_DOMAIN, OP_ADD, &domain_row(idx));
    }
}
fn delta_domain_chg(idx: usize) {
    if subscribed() {
        delta_emit(REL_DOMAIN, OP_CHG, &domain_row(idx));
    }
}
fn delta_domain_del(idx: usize) {
    if subscribed() {
        delta_emit(REL_DOMAIN, OP_DEL, &domain_row(idx));
    }
}
fn delta_object_add(idx: u32) {
    if subscribed() {
        delta_emit(REL_OBJECT, OP_ADD, &object_row(idx));
    }
}
fn delta_object_chg(idx: u32) {
    if subscribed() {
        delta_emit(REL_OBJECT, OP_CHG, &object_row(idx));
    }
}
fn delta_object_del(idx: u32) {
    if subscribed() {
        delta_emit(REL_OBJECT, OP_DEL, &object_row(idx));
    }
}
fn delta_cap_add(domain: usize, slot: usize) {
    if subscribed() {
        delta_emit(REL_CAPABILITY, OP_ADD, &cap_row(domain, slot));
    }
}
fn delta_cap_chg(domain: usize, slot: usize) {
    if subscribed() {
        delta_emit(REL_CAPABILITY, OP_CHG, &cap_row(domain, slot));
    }
}
fn delta_cap_del(domain: usize, slot: usize) {
    if subscribed() {
        delta_emit(REL_CAPABILITY, OP_DEL, &cap_row(domain, slot));
    }
}
fn delta_endpoint_add(object_idx: u32) {
    if subscribed() {
        delta_emit(REL_ENDPOINT, OP_ADD, &endpoint_row(object_idx));
    }
}
fn delta_endpoint_chg(object_idx: u32) {
    if subscribed() {
        delta_emit(REL_ENDPOINT, OP_CHG, &endpoint_row(object_idx));
    }
}
fn delta_endpoint_del(object_idx: u32) {
    if subscribed() {
        delta_emit(REL_ENDPOINT, OP_DEL, &endpoint_row(object_idx));
    }
}

// ---- relation schema + live-row iteration -----------------------------------

/// The frozen v0 column-type-code sequence for `rel` (empty for an unknown id).
fn relation_schema(rel: u64) -> &'static [u64] {
    match rel {
        REL_DOMAIN => &[COL_DOMAIN_ID, COL_STATE],
        REL_OBJECT => &[COL_OBJECT_ID, COL_CLASS, COL_GENERATION],
        REL_CAPABILITY => &[
            COL_DOMAIN_ID,
            COL_CAP_SLOT,
            COL_OBJECT_ID,
            COL_RIGHTS,
            COL_DERIV_NODE,
            COL_GENERATION,
        ],
        REL_ENDPOINT => &[COL_OBJECT_ID, COL_EP_SLOT, COL_QLEN, COL_WAITING],
        REL_DERIVATION => &[COL_DERIV_NODE, COL_PARENT_NODE, COL_OBJECT_ID, COL_ALIVE],
        _ => &[],
    }
}

fn relation_arity(rel: u64) -> u64 {
    relation_schema(rel).len() as u64
}

/// Apply `f` to every LIVE fact of `rel`, in deterministic ascending subject/
/// slot order — the row set is bounded by the pool sizes (charter: bounded by
/// construction). Rows are read from the live tables at call time; there is no
/// cached relation store.
fn for_each_row(rel: u64, mut f: impl FnMut(&[u64])) {
    match rel {
        REL_DOMAIN => {
            for i in 0..DOMAIN_SLOTS {
                if state_of(i) != State::Free {
                    f(&domain_row(i));
                }
            }
        },
        REL_OBJECT => {
            for i in 0..OBJECT_SLOTS {
                if OBJECTS.lock()[i].occupied {
                    f(&object_row(i as u32));
                }
            }
        },
        REL_CAPABILITY => {
            for d in 0..DOMAIN_SLOTS {
                if state_of(d) == State::Free {
                    continue;
                }
                for s in 0..CAP_ENTRIES {
                    // SAFETY: single hart; CapEntry is Copy.
                    if unsafe { (*domain_ptr(d)).caps[s].occupied } {
                        f(&cap_row(d, s));
                    }
                }
            }
        },
        REL_ENDPOINT => {
            for i in 0..OBJECT_SLOTS {
                let obj = OBJECTS.lock()[i];
                if obj.occupied && matches!(obj.class, ObjectClass::Endpoint(_)) {
                    f(&endpoint_row(i as u32));
                }
            }
        },
        REL_DERIVATION => {
            for n in 0..DERIV_NODES {
                let node = DERIV.lock()[n];
                if node.occupied {
                    f(&deriv_row(n as u32, &node));
                }
            }
        },
        _ => {},
    }
}

// ---- capability gate --------------------------------------------------------

/// A legibility syscall requires a cap that (1) passes the exact ADR-K2
/// `check_cap` order for [`LEGIBLE_READ`] AND (2) references a `Legible`-class
/// object — a rights bit alone on any other object is not legibility authority.
fn check_legible_cap(idx: usize, cap_slot: u64) -> Result<(), i64> {
    check_cap(idx, cap_slot, LEGIBLE_READ)?;
    // SAFETY: check_cap validated slot in-range + occupied; CapEntry is Copy.
    let object = unsafe { (*domain_ptr(idx)).caps[cap_slot as usize].object_index };
    match OBJECTS.lock()[object as usize].class {
        ObjectClass::Legible => Ok(()),
        _ => Err(DENIED),
    }
}

// ---- legibility operations (ring-0 core; syscall wrappers below) ------------

/// `sys_legible_schema`: emit the frozen column-code list for `rel` and return
/// its arity. Capability-checked.
fn legible_schema_at(idx: usize, cap_slot: u64, rel: u64) -> (i64, u64) {
    if let Err(status) = check_legible_cap(idx, cap_slot) {
        serial::ev_legible_denied(idx, rel);
        return (status, 0);
    }
    if rel > REL_DERIVATION {
        return (BAD_ARG, 0);
    }
    serial::ev_legible_schema(rel, relation_schema(rel));
    (OK, relation_arity(rel))
}

/// `sys_legible_enumerate`: emit a bounded, framed snapshot of `rel` computed
/// live from the tables, and return the row count. Capability-checked.
fn legible_enumerate_at(idx: usize, cap_slot: u64, rel: u64) -> (i64, u64) {
    if let Err(status) = check_legible_cap(idx, cap_slot) {
        serial::ev_legible_denied(idx, rel);
        return (status, 0);
    }
    if rel > REL_DERIVATION {
        return (BAD_ARG, 0);
    }
    serial::ev_legible_begin(rel, relation_arity(rel));
    let mut count = 0u64;
    for_each_row(rel, |cols| {
        serial::ev_legible_row(rel, cols);
        count += 1;
    });
    serial::ev_legible_end(rel, count);
    (OK, count)
}

/// `sys_legible_get`: read a single relation cell by (row_index, col_index)
/// without parsing the event stream — the tenant read path. O(rows) at v0 pool
/// sizes; would need an index at scale. Capability-checked. Silent (no events).
fn legible_get_at(
    idx: usize,
    cap_slot: u64,
    rel: u64,
    row_index: u64,
    col_index: u64,
) -> (i64, u64) {
    if let Err(status) = check_legible_cap(idx, cap_slot) {
        return (status, 0);
    }
    if rel > REL_DERIVATION || col_index >= relation_arity(rel) {
        return (BAD_ARG, 0);
    }
    let mut i = 0u64;
    let mut value = None;
    for_each_row(rel, |cols| {
        if i == row_index {
            value = Some(cols[col_index as usize]);
        }
        i += 1;
    });
    match value {
        Some(v) => (OK, v),
        None => (BAD_ARG, 0),
    }
}

/// `sys_legible_subscribe`: register the caller as the single legibility
/// subscriber and PRIME the fold by replaying the current live snapshot as
/// `add` deltas (initial-state sync), so a folder that only ever sees deltas
/// reconstructs the true current state and stays in lockstep thereafter.
/// A second subscribe returns `Denied`. Capability-checked.
fn legible_subscribe_at(idx: usize, cap_slot: u64) -> (i64, u64) {
    if let Err(status) = check_legible_cap(idx, cap_slot) {
        return (status, 0);
    }
    if LEGIBLE_SUBSCRIBER.load(Ordering::SeqCst) != NONE {
        return (DENIED, 0);
    }
    LEGIBLE_SUBSCRIBER.store(idx, Ordering::SeqCst);
    for rel in [
        REL_DOMAIN,
        REL_OBJECT,
        REL_CAPABILITY,
        REL_ENDPOINT,
        REL_DERIVATION,
    ] {
        for_each_row(rel, |cols| serial::ev_legible_delta(rel, OP_ADD, cols));
    }
    (OK, 0)
}

/// `sys_cap_object`: return the object id a cap references (legitimate
/// self-introspection). Capability-checked on the slot (any rights).
fn cap_object_at(idx: usize, cap_slot: u64) -> (i64, u64) {
    match check_cap(idx, cap_slot, 0) {
        Ok(_) => {
            // SAFETY: check_cap validated slot in-range + occupied; Copy.
            let object = unsafe { (*domain_ptr(idx)).caps[cap_slot as usize].object_index };
            (OK, object as u64)
        },
        Err(status) => (status, 0),
    }
}

/// Clear a capability slot (a real mutation: the "cap slot cleared → del"
/// projection). Emits the del BEFORE clearing, while the row is still readable.
fn cap_clear(idx: usize, slot: usize) {
    // SAFETY: single hart; the domain is not running.
    let occupied = unsafe { (*domain_ptr(idx)).caps[slot].occupied };
    if !occupied {
        return;
    }
    delta_cap_del(idx, slot);
    // SAFETY: single hart; clearing a slot of a not-running domain.
    unsafe {
        (*domain_ptr(idx)).caps[slot] = CapEntry::EMPTY;
    }
}

// ---- legibility syscall wrappers (use CURRENT_DOMAIN) -----------------------

pub fn sys_legible_schema(cap_slot: u64, rel: u64) -> (i64, u64) {
    legible_schema_at(current(), cap_slot, rel)
}

pub fn sys_legible_enumerate(cap_slot: u64, rel: u64) -> (i64, u64) {
    legible_enumerate_at(current(), cap_slot, rel)
}

pub fn sys_legible_subscribe(cap_slot: u64) -> (i64, u64) {
    legible_subscribe_at(current(), cap_slot)
}

pub fn sys_legible_get(cap_slot: u64, rel: u64, row_index: u64, col_index: u64) -> (i64, u64) {
    legible_get_at(current(), cap_slot, rel, row_index, col_index)
}

pub fn sys_cap_object(cap_slot: u64) -> (i64, u64) {
    cap_object_at(current(), cap_slot)
}

// ---- scenarios -------------------------------------------------------------

fn reset_scenario_state() {
    NOTE_SEEN.store(false, Ordering::SeqCst);
    NOTE_VALUE.store(0, Ordering::SeqCst);
    REVOKE_ON_NOTE.store(0, Ordering::SeqCst);
    REVOKE_DONE.store(false, Ordering::SeqCst);
    REVOKE_TREE_ON_NOTE.store(0, Ordering::SeqCst);
    REVOKE_TREE_DONE.store(false, Ordering::SeqCst);
    legible_clear_subscriber();
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

// ---- M3 scenarios ----------------------------------------------------------

/// Tear down every pool an IPC scenario may have touched, once all its domains
/// have terminated: endpoints (+ their objects), derivation nodes.
fn ipc_scenario_teardown() {
    endpoint_teardown_all();
    deriv_teardown_all();
}

/// Scenario one, `ipc_rendezvous`: R blocks on `recv`, S delivers `0xBEEF`;
/// both exit 0.
fn scenario_ipc_rendezvous() -> bool {
    reset_scenario_state();
    let Some((ep_obj, ep)) = kernel_create_endpoint() else {
        return report("ipc_rendezvous", false);
    };
    let Some(r) = domain_create(payloads::ring3_ipc_r_rendezvous) else {
        object_release(ep_obj);
        endpoint_free(ep);
        return report("ipc_rendezvous", false);
    };
    let Some(s) = domain_create(payloads::ring3_ipc_s_rendezvous) else {
        discard_domain(r);
        object_release(ep_obj);
        endpoint_free(ep);
        return report("ipc_rendezvous", false);
    };
    kernel_mint_ep(r, 0, ep_obj, EP_RECV);
    kernel_mint_ep(s, 0, ep_obj, EP_SEND);
    let mut outcomes = [None, None];
    scheduler_run(&[r, s], &mut outcomes);
    ipc_scenario_teardown();
    let pass = matches!(outcomes[0], Some(RunOutcome::Exited(0)))
        && matches!(outcomes[1], Some(RunOutcome::Exited(0)));
    report("ipc_rendezvous", pass)
}

/// Shared body for the two transfer scenarios: mint a TestArtifact with
/// `src_rights` into S.slot10, run R (blocks) then S (transfers), assert both
/// exit 0 (R's exit code encodes the observed rights).
fn run_transfer_scenario(
    name: &'static str,
    r_payload: extern "C" fn(),
    s_payload: extern "C" fn(),
    src_rights: u32,
) -> bool {
    reset_scenario_state();
    let Some((ep_obj, ep)) = kernel_create_endpoint() else {
        return report(name, false);
    };
    let Some(r) = domain_create(r_payload) else {
        object_release(ep_obj);
        endpoint_free(ep);
        return report(name, false);
    };
    let Some(s) = domain_create(s_payload) else {
        discard_domain(r);
        object_release(ep_obj);
        endpoint_free(ep);
        return report(name, false);
    };
    kernel_mint_ep(r, 0, ep_obj, EP_RECV);
    kernel_mint_ep(s, 0, ep_obj, EP_SEND);
    let Some(ta) = kernel_mint_artifact(s, 10, src_rights) else {
        discard_domain(r);
        discard_domain(s);
        object_release(ep_obj);
        endpoint_free(ep);
        return report(name, false);
    };
    let mut outcomes = [None, None];
    scheduler_run(&[r, s], &mut outcomes);
    ipc_scenario_teardown();
    object_release(ta);
    let pass = matches!(outcomes[0], Some(RunOutcome::Exited(0)))
        && matches!(outcomes[1], Some(RunOutcome::Exited(0)));
    report(name, pass)
}

/// Scenario two, `ipc_cap_transfer`: transfer 0b111∩0b011 so R observes 0b011.
fn scenario_ipc_cap_transfer() -> bool {
    run_transfer_scenario(
        "ipc_cap_transfer",
        payloads::ring3_ipc_r_xfer_check3,
        payloads::ring3_ipc_s_xfer3,
        0b111,
    )
}

/// Scenario three, `ipc_no_widen`: source holds 0b001, sends mask 0b111, and R
/// still observes 0b001 (rights never widen).
fn scenario_ipc_no_widen() -> bool {
    run_transfer_scenario(
        "ipc_no_widen",
        payloads::ring3_ipc_r_xfer_check1,
        payloads::ring3_ipc_s_xfer7,
        0b001,
    )
}

/// Scenario four, `ipc_scoped_revoke`: after the transfer, R's `note` fires a
/// scoped revoke of S's source subtree; R must then observe `Revoked` on the
/// transferred cap.
fn scenario_ipc_scoped_revoke() -> bool {
    reset_scenario_state();
    let Some((ep_obj, ep)) = kernel_create_endpoint() else {
        return report("ipc_scoped_revoke", false);
    };
    let Some(r) = domain_create(payloads::ring3_ipc_r_revoke) else {
        object_release(ep_obj);
        endpoint_free(ep);
        return report("ipc_scoped_revoke", false);
    };
    let Some(s) = domain_create(payloads::ring3_ipc_s_revoke) else {
        discard_domain(r);
        object_release(ep_obj);
        endpoint_free(ep);
        return report("ipc_scoped_revoke", false);
    };
    kernel_mint_ep(r, 0, ep_obj, EP_RECV);
    kernel_mint_ep(s, 0, ep_obj, EP_SEND);
    let Some(ta) = kernel_mint_artifact(s, 10, 0b111) else {
        discard_domain(r);
        discard_domain(s);
        object_release(ep_obj);
        endpoint_free(ep);
        return report("ipc_scoped_revoke", false);
    };
    // Arm the scoped revoke on R's checkpoint note (fired inside sys_note).
    REVOKE_TREE_ON_NOTE.store(ta + 1, Ordering::SeqCst);
    let mut outcomes = [None, None];
    scheduler_run(&[r, s], &mut outcomes);
    ipc_scenario_teardown();
    object_release(ta);
    let pass = matches!(outcomes[0], Some(RunOutcome::Exited(0)))
        && matches!(outcomes[1], Some(RunOutcome::Exited(0)))
        && REVOKE_TREE_DONE.load(Ordering::SeqCst);
    report("ipc_scoped_revoke", pass)
}

/// Scenario five, `ipc_authority`: R (EP_RECV only) is denied a send; S is
/// BadCap'd on an empty transfer slot, then delivers legitimately. Both exit 0.
fn scenario_ipc_authority() -> bool {
    reset_scenario_state();
    let Some((ep_obj, ep)) = kernel_create_endpoint() else {
        return report("ipc_authority", false);
    };
    let Some(r) = domain_create(payloads::ring3_ipc_r_auth) else {
        object_release(ep_obj);
        endpoint_free(ep);
        return report("ipc_authority", false);
    };
    let Some(s) = domain_create(payloads::ring3_ipc_s_auth) else {
        discard_domain(r);
        object_release(ep_obj);
        endpoint_free(ep);
        return report("ipc_authority", false);
    };
    kernel_mint_ep(r, 0, ep_obj, EP_RECV);
    kernel_mint_ep(s, 0, ep_obj, EP_SEND);
    let mut outcomes = [None, None];
    scheduler_run(&[r, s], &mut outcomes);
    ipc_scenario_teardown();
    let pass = matches!(outcomes[0], Some(RunOutcome::Exited(0)))
        && matches!(outcomes[1], Some(RunOutcome::Exited(0)));
    report("ipc_authority", pass)
}

/// Scenario six, `ipc_ep_full`: a lone domain creates a self-endpoint
/// (`ep_create`), fills the bounded queue (4 OK), and the 5th send is `Full`.
/// Exits 0.
fn scenario_ipc_ep_full() -> bool {
    reset_scenario_state();
    let Some(d) = domain_create(payloads::ring3_ipc_d_full) else {
        return report("ipc_ep_full", false);
    };
    let mut outcomes = [None];
    scheduler_run(&[d], &mut outcomes);
    ipc_scenario_teardown();
    let pass = matches!(outcomes[0], Some(RunOutcome::Exited(0)));
    report("ipc_ep_full", pass)
}

/// Scenario seven, `ipc_deadlock_guard`: a lone receiver blocks with no sender;
/// the scheduler detects all-blocked and kills it with cause `deadlock`.
fn scenario_ipc_deadlock_guard() -> bool {
    reset_scenario_state();
    let Some((ep_obj, ep)) = kernel_create_endpoint() else {
        return report("ipc_deadlock_guard", false);
    };
    let Some(r) = domain_create(payloads::ring3_ipc_r_deadlock) else {
        object_release(ep_obj);
        endpoint_free(ep);
        return report("ipc_deadlock_guard", false);
    };
    kernel_mint_ep(r, 0, ep_obj, EP_RECV);
    let mut outcomes = [None];
    scheduler_run(&[r], &mut outcomes);
    ipc_scenario_teardown();
    let pass = matches!(outcomes[0], Some(RunOutcome::Killed(KillCause::Deadlock)));
    report("ipc_deadlock_guard", pass)
}

// ---- M4 legibility scenarios -----------------------------------------------

/// Scenario one, `legible_schema_ok`: a domain with a `Legible` cap reads the
/// schema of all five relations; each returned arity matches the frozen table
/// (2,3,6,4,4) and each `legible.schema` event carries the frozen column codes.
fn scenario_legible_schema_ok() -> bool {
    reset_scenario_state();
    let Some(d) = domain_create(payloads::ring3_reuse) else {
        return report("legible_schema_ok", false);
    };
    let Some(l) = object_alloc(ObjectClass::Legible) else {
        discard_domain(d);
        return report("legible_schema_ok", false);
    };
    cap_mint(d, 1, l, LEGIBLE_READ);
    let expected = [
        (REL_DOMAIN, 2u64),
        (REL_OBJECT, 3),
        (REL_CAPABILITY, 6),
        (REL_ENDPOINT, 4),
        (REL_DERIVATION, 4),
    ];
    let mut pass = true;
    for (rel, arity) in expected {
        let (status, got) = legible_schema_at(d, 1, rel);
        pass &= status == OK && got == arity;
    }
    discard_domain(d);
    object_release(l);
    report("legible_schema_ok", pass)
}

/// Scenario two, `legible_enumerate_gated`: an unauthorized domain (holding a
/// non-`Legible` cap whose rights include the read bit) is `Denied` on
/// enumerate; a domain WITH a `Legible` cap enumerates REL_DOMAIN (rows >= 1).
fn scenario_legible_enumerate_gated() -> bool {
    reset_scenario_state();
    let Some(u) = domain_create(payloads::ring3_reuse) else {
        return report("legible_enumerate_gated", false);
    };
    let Some(ta) = object_alloc(ObjectClass::TestArtifact) else {
        discard_domain(u);
        return report("legible_enumerate_gated", false);
    };
    // Rights include the read bit, but the object is NOT Legible → must Denied.
    cap_mint(u, 3, ta, 0b111);
    let (denied, _) = legible_enumerate_at(u, 3, REL_DOMAIN);
    let Some(a) = domain_create(payloads::ring3_reuse) else {
        discard_domain(u);
        object_release(ta);
        return report("legible_enumerate_gated", false);
    };
    let Some(l) = object_alloc(ObjectClass::Legible) else {
        discard_domain(a);
        discard_domain(u);
        object_release(ta);
        return report("legible_enumerate_gated", false);
    };
    cap_mint(a, 1, l, LEGIBLE_READ);
    let (ok, count) = legible_enumerate_at(a, 1, REL_DOMAIN);
    // Discard in reverse creation order (LIFO) so each frame-census balances.
    discard_domain(a);
    discard_domain(u);
    object_release(ta);
    object_release(l);
    let pass = denied == DENIED && ok == OK && count >= 1;
    report("legible_enumerate_gated", pass)
}

/// The killer mutation script (ring 0, subscribed): touch every relation, leave
/// a mix of live facts and torn-down parts, then enumerate the live snapshot.
/// Every mutation rides an already-present state change and emits its typed
/// delta (single-store projection). Returns the surviving `TestArtifact` object
/// for the caller to release, or `None` on any pool exhaustion.
fn legible_consistency_script(d: usize) -> Option<u32> {
    // Subscribe as D's Legible cap (slot 0): primes the fold with the current
    // live snapshot, then live deltas keep it in lockstep with the tables.
    if legible_subscribe_at(d, 0).0 != OK {
        return None;
    }
    // (a,b) a TestArtifact object + a cap to it in D slot 10.
    let ta = object_alloc(ObjectClass::TestArtifact)?;
    cap_mint(d, 10, ta, 0b111);
    // (c) an endpoint object + its REL_ENDPOINT row.
    let ep = endpoint_alloc()?;
    let Some(ep_obj) = object_alloc(ObjectClass::Endpoint(ep)) else {
        endpoint_free(ep);
        return None;
    };
    delta_endpoint_add(ep_obj);
    // (d) enqueue one message: qlen 0 -> 1 (a REL_ENDPOINT change).
    {
        let mut eps = ENDPOINTS.lock();
        let e = &mut eps[ep as usize];
        e.queue[0] = Msg {
            data: 0xABC,
            cap: None,
            from: d,
        };
        e.qlen = 1;
    }
    delta_endpoint_chg(ep_obj);
    // (e) transfer: derive a child of D slot 10 into D slot 11 (spawns a root +
    //     child derivation node and changes the source cap's derivation link).
    let generation = OBJECTS.lock()[ta as usize].generation;
    let xc = make_child_cap(d, 10, ta, generation, 0b011)?;
    // SAFETY: single hart; installing the derived cap into D slot 11.
    unsafe {
        (*domain_ptr(d)).caps[11] = CapEntry {
            occupied: true,
            object_index: xc.object_index,
            generation: xc.generation,
            rights: xc.rights,
            deriv_node: xc.deriv_node,
        };
    }
    delta_cap_add(d, 11);
    // (f) revoke the subtree rooted at D slot 10's node (flips alive on both).
    // SAFETY: single hart; reading the source cap's node index.
    let root = unsafe { (*domain_ptr(d)).caps[10].deriv_node };
    revoke_tree(root);
    // (g) tear PARTS down: drop the derived cap and the endpoint (keep the rest).
    cap_clear(d, 11);
    delta_endpoint_del(ep_obj);
    endpoint_free(ep);
    object_release(ep_obj);
    // (4) enumerate every relation: the live snapshot the harness folds against.
    for rel in [
        REL_DOMAIN,
        REL_OBJECT,
        REL_CAPABILITY,
        REL_ENDPOINT,
        REL_DERIVATION,
    ] {
        legible_enumerate_at(d, 0, rel);
    }
    Some(ta)
}

/// Scenario three, `legible_snapshot_delta_consistency`: the killer invariant.
/// Bracketed by `legible.check.begin`/`legible.check.end` so the harness folds
/// only these deltas and collects only this snapshot; it then asserts
/// snapshot == fold(deltas) for every relation by construction.
fn scenario_legible_snapshot_delta_consistency() -> bool {
    reset_scenario_state();
    let Some(d) = domain_create(payloads::ring3_reuse) else {
        return report("legible_snapshot_delta_consistency", false);
    };
    let Some(l) = object_alloc(ObjectClass::Legible) else {
        discard_domain(d);
        return report("legible_snapshot_delta_consistency", false);
    };
    cap_mint(d, 0, l, LEGIBLE_READ);
    serial::ev_legible_check_begin();
    let ta = legible_consistency_script(d);
    serial::ev_legible_check_end();
    legible_clear_subscriber();
    let pass = ta.is_some();
    deriv_teardown_all();
    endpoint_teardown_all();
    if let Some(ta) = ta {
        object_release(ta);
    }
    discard_domain(d);
    object_release(l);
    report("legible_snapshot_delta_consistency", pass)
}

/// Scenario four, `legible_revoked_cap`: legibility authority is itself
/// revocable. A domain enumerates OK, then the kernel revokes its `Legible` cap
/// (generation bump); the next enumerate must return `StaleCap`.
fn scenario_legible_revoked_cap() -> bool {
    reset_scenario_state();
    let Some(d) = domain_create(payloads::ring3_reuse) else {
        return report("legible_revoked_cap", false);
    };
    let Some(l) = object_alloc(ObjectClass::Legible) else {
        discard_domain(d);
        return report("legible_revoked_cap", false);
    };
    cap_mint(d, 1, l, LEGIBLE_READ);
    let (pre, _) = legible_enumerate_at(d, 1, REL_DOMAIN);
    // Revoke the Legible cap by bumping its object's generation (ADR-K4 mass
    // invalidation) — the exact same path M2 uses for a TestArtifact cap.
    revoke_object(l);
    let (post, _) = legible_enumerate_at(d, 1, REL_DOMAIN);
    discard_domain(d);
    object_release(l);
    let pass = pre == OK && post == STALE_CAP;
    report("legible_revoked_cap", pass)
}

/// Scenario five, `legible_reasoner`: a ring-3 tenant counts, from relation rows
/// ALONE, how many capabilities in the system reference its transferred object.
/// The kernel places exactly two references to object O in the live reasoner
/// (one via a real IPC derivation transfer from S, one pre-minted), so the true
/// count is 2; pass iff the reasoner's noted value equals it.
fn scenario_legible_reasoner() -> bool {
    reset_scenario_state();
    let Some((ep_obj, ep)) = kernel_create_endpoint() else {
        return report("legible_reasoner", false);
    };
    let Some(r) = domain_create(payloads::ring3_reasoner) else {
        object_release(ep_obj);
        endpoint_free(ep);
        return report("legible_reasoner", false);
    };
    let Some(s) = domain_create(payloads::ring3_reasoner_source) else {
        discard_domain(r);
        object_release(ep_obj);
        endpoint_free(ep);
        return report("legible_reasoner", false);
    };
    kernel_mint_ep(r, 0, ep_obj, EP_RECV);
    kernel_mint_ep(s, 0, ep_obj, EP_SEND);
    let Some(o) = object_alloc(ObjectClass::TestArtifact) else {
        discard_domain(s);
        discard_domain(r);
        object_release(ep_obj);
        endpoint_free(ep);
        return report("legible_reasoner", false);
    };
    // S holds a transferable cap to O; R holds a second, direct reference to O.
    cap_mint(s, 10, o, 0b111);
    cap_mint(r, 21, o, 0b100);
    let Some(lg) = object_alloc(ObjectClass::Legible) else {
        discard_domain(s);
        discard_domain(r);
        object_release(o);
        object_release(ep_obj);
        endpoint_free(ep);
        return report("legible_reasoner", false);
    };
    cap_mint(r, 1, lg, LEGIBLE_READ);
    let mut outcomes = [None, None];
    scheduler_run(&[r, s], &mut outcomes);
    ipc_scenario_teardown();
    object_release(o);
    object_release(lg);
    let pass = matches!(outcomes[0], Some(RunOutcome::Exited(0)))
        && matches!(outcomes[1], Some(RunOutcome::Exited(0)))
        && NOTE_SEEN.load(Ordering::SeqCst)
        && NOTE_VALUE.load(Ordering::SeqCst) == 2;
    report("legible_reasoner", pass)
}

/// Run every ring-3 scenario in order: the seven M2 single-domain scenarios,
/// then the seven M3 IPC scenarios, then the five M4 legibility scenarios,
/// bracketed by pool censuses. Returns `true` iff all passed.
pub fn run_all() -> bool {
    let mut all = true;
    all &= scenario_happy();
    all &= scenario_kernel_read();
    all &= scenario_priv_insn();
    all &= scenario_bad_cap();
    all &= scenario_stale_cap();
    all &= scenario_runaway();
    all &= scenario_reuse();

    // Baseline census, captured fully-free at the M2→M3 boundary (M2 releases
    // every object and never touches the endpoint/deriv pools). Emitting it here
    // rather than at absolute kernel start keeps the M1/M2 serial stream
    // byte-identical (no `seq` shift); the final census is compared against it
    // to prove no object/endpoint/deriv-node leak across the M3 scenarios.
    emit_census();

    all &= scenario_ipc_rendezvous();
    all &= scenario_ipc_cap_transfer();
    all &= scenario_ipc_no_widen();
    all &= scenario_ipc_scoped_revoke();
    all &= scenario_ipc_authority();
    all &= scenario_ipc_ep_full();
    all &= scenario_ipc_deadlock_guard();

    emit_census();

    // M4 legibility ABI v0 (appended AFTER the M3 scenarios + census; no existing
    // `seq` shifts). Each scenario fully tears down, so the final census below
    // still returns to the same baseline — proving no leak from the new Legible
    // objects/caps.
    all &= scenario_legible_schema_ok();
    all &= scenario_legible_enumerate_gated();
    all &= scenario_legible_snapshot_delta_consistency();
    all &= scenario_legible_revoked_cap();
    all &= scenario_legible_reasoner();

    emit_census();
    all
}
