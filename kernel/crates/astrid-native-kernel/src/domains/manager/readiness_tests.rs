//! Host falsifiers for the private readiness receipt state machine.

use super::super::stop::DomainStop;
use super::super::types::{DomainGeneration, DomainHandle, DomainId, Scenario};
use super::DomainState;
use super::readiness::{
    LeaseIdentity, LiveContext, Readiness, ReadinessError, ReadinessReceipt, ReadinessState,
};
use super::{Domain, DomainControl, MANAGER};
use spin::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TestManifest(u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TestComponent(u8);

const MANIFEST: TestManifest = TestManifest(11);
const COMPONENT: TestComponent = TestComponent(17);

static GLOBAL_READYNESS_LOCK: Mutex<()> = Mutex::new(());

fn handle(slot: u64, generation: u64) -> DomainHandle {
    DomainHandle::new(DomainId(slot), DomainGeneration(generation))
}

fn lease() -> LeaseIdentity {
    LeaseIdentity::new(0xfeed_1000, 0, 0x101_000, 0, 0xfeed_f000)
}

fn live() -> LiveContext {
    LiveContext::new(3, 0xfeed_1000, 0, 0xfeed_f000, 0x101_000, 0)
}

fn armed(slot: u64, generation: u64) -> Readiness<TestManifest, TestComponent> {
    Readiness::arm(
        handle(slot, generation),
        MANIFEST,
        COMPONENT,
        Scenario::RunningStop,
        lease(),
    )
    .unwrap()
}

fn global_lock() -> spin::MutexGuard<'static, ()> {
    GLOBAL_READYNESS_LOCK.lock()
}

fn readiness_component() -> astrid_system_generation::ContentId {
    astrid_system_generation::ContentId::from_payload(b"stored-readiness-falsifier")
}

fn install_manager_with_readiness(
    handle: DomainHandle,
    state: DomainState,
) -> spin::MutexGuard<'static, super::Manager> {
    let mut manager = MANAGER.lock();
    manager.slots[handle.id().0 as usize] = Some(Domain {
        generation: handle.generation().0,
        state,
        scenario: Scenario::RunningStop,
        quota_ticks: 0,
        space: Some(()),
        ipc_enabled: false,
        stop: DomainStop::inactive(),
        control: DomainControl::inactive(),
    });
    manager.used_frames = 3;
    manager
}

fn armed_global(handle: DomainHandle) {
    super::readiness::clear_slot(handle.id());
    super::readiness::arm(
        handle,
        (),
        readiness_component(),
        Scenario::RunningStop,
        lease(),
    )
    .unwrap();
}

fn signal(
    readiness: &mut Readiness<TestManifest, TestComponent>,
    slot: u64,
    generation: u64,
    manifest: TestManifest,
    component_id: TestComponent,
    scenario: Scenario,
    state: DomainState,
) -> Result<ReadinessReceipt<TestManifest, TestComponent>, ReadinessError> {
    readiness.signal(
        handle(slot, generation),
        manifest,
        component_id,
        scenario,
        state,
        live(),
    )
}

fn observe(
    readiness: &Readiness<TestManifest, TestComponent>,
    slot: u64,
    generation: u64,
    manifest: TestManifest,
    component_id: TestComponent,
    state: DomainState,
) -> Option<ReadinessReceipt<TestManifest, TestComponent>> {
    readiness.observe(
        handle(slot, generation),
        manifest,
        component_id,
        state,
        live(),
    )
}

#[test]
fn running_admission_signal_is_exact_and_observable_once() {
    let mut readiness = armed(0, 5);
    assert_eq!(
        signal(
            &mut readiness,
            0,
            5,
            MANIFEST,
            COMPONENT,
            Scenario::RunningStop,
            DomainState::Prepared
        ),
        Err(ReadinessError::StateMismatch)
    );
    let receipt = signal(
        &mut readiness,
        0,
        5,
        MANIFEST,
        COMPONENT,
        Scenario::RunningStop,
        DomainState::Running,
    )
    .unwrap();
    assert_eq!(receipt.handle(), handle(0, 5));
    assert_eq!(receipt.manifest_identity(), &MANIFEST);
    assert_eq!(receipt.component_id(), &COMPONENT);
    assert_eq!(receipt.scenario(), Scenario::RunningStop);
    assert_eq!(
        signal(
            &mut readiness,
            0,
            5,
            MANIFEST,
            COMPONENT,
            Scenario::RunningStop,
            DomainState::Running
        ),
        Err(ReadinessError::AlreadySignaled)
    );
    let observation = observe(&readiness, 0, 5, MANIFEST, COMPONENT, DomainState::Running).unwrap();
    assert_eq!(receipt, observation);
}

#[test]
fn substituted_caller_or_lifecycle_context_fails_closed() {
    let mut readiness = armed(0, 6);
    assert_eq!(
        signal(
            &mut readiness,
            1,
            6,
            MANIFEST,
            COMPONENT,
            Scenario::RunningStop,
            DomainState::Running
        ),
        Err(ReadinessError::HandleMismatch)
    );
    assert_eq!(
        signal(
            &mut readiness,
            0,
            7,
            MANIFEST,
            COMPONENT,
            Scenario::RunningStop,
            DomainState::Running
        ),
        Err(ReadinessError::HandleMismatch)
    );
    assert_eq!(
        signal(
            &mut readiness,
            0,
            6,
            TestManifest(12),
            COMPONENT,
            Scenario::RunningStop,
            DomainState::Running
        ),
        Err(ReadinessError::ManifestMismatch)
    );
    assert_eq!(
        signal(
            &mut readiness,
            0,
            6,
            MANIFEST,
            TestComponent(18),
            Scenario::RunningStop,
            DomainState::Running
        ),
        Err(ReadinessError::ComponentMismatch)
    );
    assert_eq!(
        signal(
            &mut readiness,
            0,
            6,
            MANIFEST,
            COMPONENT,
            Scenario::Exit,
            DomainState::Running
        ),
        Err(ReadinessError::ScenarioMismatch)
    );
    assert_eq!(
        signal(
            &mut readiness,
            0,
            6,
            MANIFEST,
            COMPONENT,
            Scenario::RunningStop,
            DomainState::Blocked
        ),
        Err(ReadinessError::StateMismatch)
    );
    assert_eq!(readiness, armed(0, 6));
    assert!(observe(&readiness, 0, 6, MANIFEST, COMPONENT, DomainState::Running).is_none());
}

#[test]
fn lease_context_mismatch_is_rejected() {
    let contexts = [
        LiveContext::new(0, 0xfeed_1000, 0, 0xfeed_f000, 0x101_000, 0),
        LiveContext::new(3, 0xfeed_2000, 0, 0xfeed_f000, 0x101_000, 0),
        LiveContext::new(3, 0xfeed_1000, 1, 0xfeed_f000, 0x101_000, 0),
        LiveContext::new(3, 0xfeed_1000, 0, 0xfeed_e000, 0x101_000, 0),
        LiveContext::new(3, 0xfeed_1000, 0, 0xfeed_f000, 0x102_000, 0),
        LiveContext::new(3, 0xfeed_1000, 0, 0xfeed_f000, 0x101_000, 1),
    ];
    for live_context in contexts {
        let mut readiness = armed(1, 4);
        assert_eq!(
            readiness.signal(
                handle(1, 4),
                MANIFEST,
                COMPONENT,
                Scenario::RunningStop,
                DomainState::Running,
                live_context
            ),
            Err(ReadinessError::LeaseMismatch)
        );
        assert_eq!(readiness, armed(1, 4));
    }
}

#[test]
fn terminal_invalidation_precedes_receipt_observation() {
    let mut pending = armed(0, 8);
    assert!(pending.invalidate(handle(0, 8)));
    assert_eq!(
        signal(
            &mut pending,
            0,
            8,
            MANIFEST,
            COMPONENT,
            Scenario::RunningStop,
            DomainState::Running
        ),
        Err(ReadinessError::Invalidated)
    );
    assert!(observe(&pending, 0, 8, MANIFEST, COMPONENT, DomainState::Running).is_none());
    assert!(!pending.invalidate(handle(0, 8)));

    let mut ready = armed(0, 9);
    signal(
        &mut ready,
        0,
        9,
        MANIFEST,
        COMPONENT,
        Scenario::RunningStop,
        DomainState::Running,
    )
    .unwrap();
    assert!(ready.invalidate(handle(0, 9)));
    assert!(observe(&ready, 0, 9, MANIFEST, COMPONENT, DomainState::Running).is_none());

    let mut ready = armed(1, 10);
    signal(
        &mut ready,
        1,
        10,
        MANIFEST,
        COMPONENT,
        Scenario::RunningStop,
        DomainState::Running,
    )
    .unwrap();
    assert!(!ready.invalidate(handle(1, 11)));
    assert!(observe(&ready, 1, 10, MANIFEST, COMPONENT, DomainState::Running).is_some());
}

#[test]
fn stored_state_requires_the_exact_handle_generation() {
    let _lock = global_lock();
    let exact = handle(0, 21);
    let stale = handle(0, 22);
    armed_global(exact);
    assert_eq!(
        super::readiness::stored_state(stale),
        None,
        "a newer or older slot occupant must not satisfy an exact handle"
    );

    super::readiness::install_ready(
        exact,
        (),
        readiness_component(),
        Scenario::RunningStop,
        lease(),
    )
    .unwrap();
    assert_eq!(
        super::readiness::stored_state(exact),
        Some(ReadinessState::Ready)
    );
    assert_eq!(super::readiness::stored_state(stale), None);
    super::readiness::clear_slot(exact.id());
}

#[test]
fn returned_stop_terminal_invalidation_seam_preserves_exact_state() {
    // Residual: the full `accept_returned_stop` path is native-only. This
    // drives the exact terminal-invalidation seam that method calls before
    // event/release handling; q35 remains the full returned-stop path proof.
    let _lock = global_lock();
    let exact = handle(0, 23);
    armed_global(exact);
    super::readiness::install_ready(
        exact,
        (),
        readiness_component(),
        Scenario::RunningStop,
        lease(),
    )
    .unwrap();
    assert_eq!(
        super::readiness::stored_state(exact),
        Some(ReadinessState::Ready)
    );

    let manager = install_manager_with_readiness(exact, DomainState::Running);
    assert!(manager.invalidate_admitted_for_terminal(exact));
    assert_eq!(
        manager.slots[0].as_ref().unwrap().state,
        DomainState::Running
    );
    assert_eq!(
        super::readiness::stored_state(exact),
        Some(ReadinessState::Invalidated)
    );

    drop(manager);
    super::readiness::clear_slot(exact.id());
}

#[test]
fn blocked_cancel_invalidates_exact_stored_state_before_release() {
    let _lock = global_lock();
    let _ipc_lock = crate::ipc::test_support::test_lock();
    crate::ipc::test_support::reset();
    crate::ipc::prepare_domain(crate::ipc::DomainToken::new(0, 24).unwrap());
    let exact = handle(0, 24);
    armed_global(exact);
    super::readiness::install_ready(
        exact,
        (),
        readiness_component(),
        Scenario::RunningStop,
        lease(),
    )
    .unwrap();
    let mut manager = install_manager_with_readiness(exact, DomainState::Blocked);
    assert_eq!(
        super::readiness::stored_state(exact),
        Some(ReadinessState::Ready)
    );
    assert_eq!(manager.cancel_prepared(exact), Ok((3, 3)));
    assert_eq!(
        manager.slots[0].as_ref().unwrap().state,
        DomainState::Reclaimed
    );
    assert_eq!(
        super::readiness::stored_state(exact),
        Some(ReadinessState::Invalidated)
    );

    manager.slots[0] = None;
    super::readiness::clear_slot(exact.id());
}

#[test]
fn prepared_cancel_succeeds_without_a_readiness_record() {
    let _lock = global_lock();
    let _ipc_lock = crate::ipc::test_support::test_lock();
    crate::ipc::test_support::reset();
    crate::ipc::prepare_domain(crate::ipc::DomainToken::new(0, 25).unwrap());
    let exact = handle(0, 25);
    let mut manager = install_manager_with_readiness(exact, DomainState::Prepared);
    assert_eq!(super::readiness::stored_state(exact), None);
    assert_eq!(manager.cancel_prepared(exact), Ok((3, 3)));
    assert_eq!(
        manager.slots[0].as_ref().unwrap().state,
        DomainState::Reclaimed
    );
    assert_eq!(super::readiness::stored_state(exact), None);
    manager.slots[0] = None;
}
