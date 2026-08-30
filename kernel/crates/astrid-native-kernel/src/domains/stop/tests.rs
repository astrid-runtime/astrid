//! Host falsifiers for the private stop lifecycle state machine.

use super::super::types::{DomainGeneration, DomainHandle, DomainId, Scenario};
use super::{StopError, StopLifecycle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TestManifest(u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TestComponent(u8);

const MANIFEST: TestManifest = TestManifest(7);
const COMPONENT: TestComponent = TestComponent(11);

fn handle(slot: u64, generation: u64) -> DomainHandle {
    DomainHandle::new(DomainId(slot), DomainGeneration(generation))
}

fn staged(slot: u64, generation: u64) -> StopLifecycle<TestManifest, TestComponent> {
    StopLifecycle::stage(
        handle(slot, generation),
        MANIFEST,
        COMPONENT,
        Scenario::RunningStop,
    )
    .unwrap()
}

fn armed(slot: u64, generation: u64) -> StopLifecycle<TestManifest, TestComponent> {
    staged(slot, generation)
        .into_armed(
            handle(slot, generation),
            MANIFEST,
            COMPONENT,
            Scenario::RunningStop,
        )
        .unwrap()
}

fn taken(slot: u64, generation: u64) -> StopLifecycle<TestManifest, TestComponent> {
    let mut stop = armed(slot, generation);
    stop.take_timer(handle(slot, generation), Scenario::RunningStop)
        .unwrap();
    stop
}

#[test]
fn non_running_stop_starts_inactive() {
    assert_eq!(
        StopLifecycle::<TestManifest, TestComponent>::stage(
            handle(0, 1),
            MANIFEST,
            COMPONENT,
            Scenario::Exit,
        ),
        Ok(StopLifecycle::Inactive)
    );
    assert_eq!(
        StopLifecycle::<TestManifest, TestComponent>::inactive(),
        StopLifecycle::Inactive
    );
    assert_eq!(
        StopLifecycle::<TestManifest, TestComponent>::inactive().into_armed(
            handle(0, 1),
            MANIFEST,
            COMPONENT,
            Scenario::Exit
        ),
        Ok(StopLifecycle::Inactive)
    );
}

#[test]
fn staged_is_not_accepted_without_exact_arm() {
    let stop = staged(0, 1);
    assert_eq!(
        stop.clone()
            .into_armed(handle(0, 2), MANIFEST, COMPONENT, Scenario::RunningStop),
        Err(StopError::HandleMismatch)
    );
    assert_eq!(
        stop.clone().into_armed(
            handle(0, 1),
            TestManifest(8),
            COMPONENT,
            Scenario::RunningStop
        ),
        Err(StopError::ManifestMismatch)
    );
    assert_eq!(
        stop.clone().into_armed(
            handle(0, 1),
            MANIFEST,
            TestComponent(12),
            Scenario::RunningStop
        ),
        Err(StopError::ComponentMismatch)
    );
    assert_eq!(
        stop.clone()
            .into_armed(handle(0, 1), MANIFEST, COMPONENT, Scenario::Exit),
        Err(StopError::ScenarioMismatch)
    );
    assert_eq!(
        stop,
        StopLifecycle::Staged(super::StopTicket {
            handle: handle(0, 1),
            manifest_identity: MANIFEST,
            component_id: COMPONENT,
            scenario: Scenario::RunningStop,
        })
    );
}

#[test]
fn failed_arm_leaves_staged_then_exact_arm_succeeds_once() {
    let stop = staged(1, 4);
    assert_eq!(
        stop.clone()
            .into_armed(handle(1, 5), MANIFEST, COMPONENT, Scenario::RunningStop),
        Err(StopError::HandleMismatch)
    );
    assert_eq!(
        stop.into_armed(handle(1, 4), MANIFEST, COMPONENT, Scenario::RunningStop),
        Ok(armed(1, 4))
    );
    assert_eq!(
        armed(1, 4).into_armed(handle(1, 4), MANIFEST, COMPONENT, Scenario::RunningStop),
        Err(StopError::StateMismatch)
    );
}

#[test]
fn timer_take_is_exact_and_one_shot() {
    let mut stop = armed(0, 3);
    assert_eq!(
        stop.take_timer(handle(1, 3), Scenario::RunningStop),
        Err(StopError::HandleMismatch)
    );
    assert_eq!(
        stop.take_timer(handle(0, 3), Scenario::Exit),
        Err(StopError::ScenarioMismatch)
    );
    assert_eq!(stop, armed(0, 3));
    assert_eq!(stop.take_timer(handle(0, 3), Scenario::RunningStop), Ok(()));
    assert_eq!(stop, taken(0, 3));
    assert_eq!(
        stop.take_timer(handle(0, 3), Scenario::RunningStop),
        Err(StopError::NotArmed)
    );
    assert_eq!(stop, taken(0, 3));
}

#[test]
fn competing_terminal_abort_is_one_shot_and_prevents_stop_success() {
    let mut stop = armed(0, 2);
    assert_eq!(stop.abort(handle(0, 2)), Ok(()));
    assert_eq!(
        stop.take_timer(handle(0, 2), Scenario::RunningStop),
        Err(StopError::NotArmed)
    );
    assert_eq!(stop.finish(handle(0, 2), true), Ok(()));
    assert_eq!(
        stop,
        StopLifecycle::Aborted(super::StopTicket {
            handle: handle(0, 2),
            manifest_identity: MANIFEST,
            component_id: COMPONENT,
            scenario: Scenario::RunningStop,
        })
    );
}

#[test]
fn release_failure_remains_aborted_and_cannot_later_pass() {
    let mut stop = taken(0, 6);
    assert_eq!(stop.finish(handle(0, 6), false), Ok(()));
    assert!(matches!(stop, StopLifecycle::Aborted(_)));
    assert_eq!(
        stop.take_timer(handle(0, 6), Scenario::RunningStop),
        Err(StopError::NotArmed)
    );
    assert_eq!(stop.finish(handle(0, 6), true), Ok(()));
    assert!(matches!(stop, StopLifecycle::Aborted(_)));
}

#[test]
fn only_taken_finishes_completed_and_failure_is_non_reusable() {
    let mut stop = taken(0, 1);
    assert_eq!(stop.finish(handle(0, 1), false), Ok(()));
    assert!(matches!(stop, StopLifecycle::Aborted(_)));
    assert_eq!(stop.finish(handle(0, 1), true), Ok(()));
    assert!(matches!(stop, StopLifecycle::Aborted(_)));

    let mut stop = taken(0, 1);
    assert_eq!(stop.finish(handle(0, 1), true), Ok(()));
    assert!(matches!(stop, StopLifecycle::Completed(_)));
    assert_eq!(stop.finish(handle(0, 1), true), Err(StopError::NotArmed));
    assert!(matches!(stop, StopLifecycle::Completed(_)));
}

#[test]
fn fresh_same_slot_generation_starts_clean_and_old_ticket_stays_dead() {
    let mut old = taken(0, 9);
    assert_eq!(old.finish(handle(0, 9), true), Ok(()));
    let fresh = staged(0, 10);
    assert!(matches!(fresh, StopLifecycle::Staged(_)));
    assert_eq!(
        old.take_timer(handle(0, 9), Scenario::RunningStop),
        Err(StopError::NotArmed)
    );
    assert_eq!(
        fresh
            .clone()
            .into_armed(handle(0, 10), MANIFEST, COMPONENT, Scenario::RunningStop),
        Ok(armed(0, 10))
    );
    assert!(matches!(fresh, StopLifecycle::Staged(_)));
}

#[test]
fn inactive_stale_and_completed_reject_armed_take() {
    assert_eq!(
        StopLifecycle::<TestManifest, TestComponent>::inactive().into_armed(
            handle(0, 1),
            MANIFEST,
            COMPONENT,
            Scenario::RunningStop
        ),
        Err(StopError::NotArmed)
    );
    let stale = staged(0, 1);
    assert_eq!(
        stale
            .clone()
            .into_armed(handle(0, 2), MANIFEST, COMPONENT, Scenario::RunningStop),
        Err(StopError::HandleMismatch)
    );
    assert!(matches!(stale, StopLifecycle::Staged(_)));
}
