//! Host falsifiers for the private readiness receipt state machine.

use super::super::types::{DomainGeneration, DomainHandle, DomainId, Scenario};
use super::DomainState;
use super::readiness::{LeaseIdentity, LiveContext, Readiness, ReadinessError, ReadinessReceipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TestManifest(u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TestComponent(u8);

const MANIFEST: TestManifest = TestManifest(11);
const COMPONENT: TestComponent = TestComponent(17);

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
