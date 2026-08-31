//! Host falsifiers for the private returned-control lease state machine.

use super::super::super::types::{DomainGeneration, DomainHandle, DomainId, Scenario};
use super::{ContextGuard, Control, ControlError, LeaseContext, TrapSnapshot};
use crate::platform::TrapFrame;
use astrid_system_generation::ContentId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TestManifest(u8);

const MANIFEST: TestManifest = TestManifest(7);

fn handle(slot: u64, generation: u64) -> DomainHandle {
    DomainHandle::new(DomainId(slot), DomainGeneration(generation))
}

fn component() -> ContentId {
    ContentId::from_payload(b"returned-control-falsifier")
}

fn substituted() -> ContentId {
    ContentId::from_payload(b"returned-control-substitution")
}

fn context() -> LeaseContext {
    LeaseContext::new(0xfeed_1000, 0, 0x101_000, 0, 0xfeed_f000)
}

const fn frame(vector: u64) -> TrapFrame {
    TrapFrame {
        rax: 1,
        rbx: 2,
        rcx: 3,
        rdx: 4,
        rsi: 5,
        rdi: Scenario::RunningStop.value(),
        rbp: 6,
        r8: 8,
        r9: 9,
        r10: 10,
        r11: 11,
        r12: 12,
        r13: 13,
        r14: 14,
        r15: 15,
        vector,
        error_code: 0,
        rip: 0x2000,
        cs: 3,
        rflags: 0x202,
        rsp: 0xfeed_f000,
        ss: 0x1b,
    }
}

static TIMER_FRAME: TrapFrame = frame(32);
const fn frame_with_stack(vector: u64, rsp: u64) -> TrapFrame {
    let mut frame = frame(vector);
    frame.rsp = rsp;
    frame
}
static WRONG_STACK_FRAME: TrapFrame = frame_with_stack(32, 0xfeed_e000);

fn snapshot(root: u64) -> TrapSnapshot<'static> {
    snapshot_with_frame(root, &TIMER_FRAME)
}

fn snapshot_with_frame(root: u64, frame: &TrapFrame) -> TrapSnapshot<'_> {
    TrapSnapshot {
        root,
        root_flags: 0,
        frame,
    }
}

fn guard(current_root: u64, current_flags: u64, source: u64) -> ContextGuard {
    ContextGuard::new(current_root, current_flags, source, 0)
}

fn admitted(slot: u64, generation: u64) -> Control<TestManifest, ContentId> {
    Control::admit(
        handle(slot, generation),
        MANIFEST,
        component(),
        Scenario::RunningStop,
        context(),
    )
    .unwrap()
}

fn returned(slot: u64, generation: u64) -> Control<TestManifest, ContentId> {
    let (control, run) = admitted(slot, generation)
        .return_at_trap(
            handle(slot, generation),
            MANIFEST,
            component(),
            Scenario::RunningStop,
            snapshot(0xfeed_1000),
        )
        .unwrap();
    assert_eq!(run.vector(), 32);
    assert_eq!(run.cs(), 3);
    control
}

fn request(
    control: Control<TestManifest, ContentId>,
    slot: u64,
    generation: u64,
    manifest: TestManifest,
    component_id: ContentId,
    scenario: Scenario,
    current_root: u64,
    current_flags: u64,
    source: u64,
) -> Result<Control<TestManifest, ContentId>, ControlError> {
    control
        .request_stop(
            handle(slot, generation),
            manifest,
            component_id,
            scenario,
            guard(current_root, current_flags, source),
        )
        .map(|(control, _)| control)
}

#[test]
fn admitted_lease_binds_exact_dispatch_identity() {
    let wrong_handle = admitted(0, 4)
        .return_at_trap(
            handle(1, 4),
            MANIFEST,
            component(),
            Scenario::RunningStop,
            snapshot(0xfeed_1000),
        )
        .err();
    let wrong_manifest = admitted(0, 4)
        .return_at_trap(
            handle(0, 4),
            TestManifest(8),
            component(),
            Scenario::RunningStop,
            snapshot(0xfeed_1000),
        )
        .err();
    let wrong_component = admitted(0, 4)
        .return_at_trap(
            handle(0, 4),
            MANIFEST,
            substituted(),
            Scenario::RunningStop,
            snapshot(0xfeed_1000),
        )
        .err();
    let wrong_scenario = admitted(0, 4)
        .return_at_trap(
            handle(0, 4),
            MANIFEST,
            component(),
            Scenario::Exit,
            snapshot(0xfeed_1000),
        )
        .err();
    let wrong_root = admitted(0, 4)
        .return_at_trap(
            handle(0, 4),
            MANIFEST,
            component(),
            Scenario::RunningStop,
            snapshot(0xfeed_2000),
        )
        .err();
    let wrong_stack = admitted(0, 4)
        .return_at_trap(
            handle(0, 4),
            MANIFEST,
            component(),
            Scenario::RunningStop,
            snapshot_with_frame(0xfeed_1000, &WRONG_STACK_FRAME),
        )
        .err();
    assert_eq!(wrong_handle, Some(ControlError::HandleMismatch));
    assert_eq!(wrong_manifest, Some(ControlError::ManifestMismatch));
    assert_eq!(wrong_component, Some(ControlError::ComponentMismatch));
    assert_eq!(wrong_scenario, Some(ControlError::ScenarioMismatch));
    assert_eq!(wrong_root, Some(ControlError::ContextMismatch));
    assert_eq!(wrong_stack, Some(ControlError::ContextMismatch));
    assert_eq!(returned(0, 4), returned(0, 4));
}

#[test]
fn ring3_timer_returns_once_without_terminal_request() {
    let control = returned(0, 4);
    let repeat = control
        .clone()
        .return_at_trap(
            handle(0, 4),
            MANIFEST,
            component(),
            Scenario::RunningStop,
            snapshot(0xfeed_1000),
        )
        .err();
    assert_eq!(repeat, Some(ControlError::AlreadyReturned));
    assert_eq!(control, returned(0, 4));
}

#[test]
fn returned_request_rejects_identity_and_context_before_transition() {
    let control = returned(0, 4);
    let cases = [
        request(
            control.clone(),
            0,
            5,
            MANIFEST,
            component(),
            Scenario::RunningStop,
            0,
            0,
            0x101_000,
        ),
        request(
            control.clone(),
            0,
            4,
            TestManifest(8),
            component(),
            Scenario::RunningStop,
            0,
            0,
            0x101_000,
        ),
        request(
            control.clone(),
            0,
            4,
            MANIFEST,
            substituted(),
            Scenario::RunningStop,
            0,
            0,
            0x101_000,
        ),
        request(
            control.clone(),
            0,
            4,
            MANIFEST,
            component(),
            Scenario::Exit,
            0,
            0,
            0x101_000,
        ),
        request(
            control.clone(),
            0,
            4,
            MANIFEST,
            component(),
            Scenario::RunningStop,
            0xfeed_1000,
            0,
            0x101_000,
        ),
        request(
            control.clone(),
            0,
            4,
            MANIFEST,
            component(),
            Scenario::RunningStop,
            0,
            1,
            0x101_000,
        ),
        request(
            control,
            0,
            4,
            MANIFEST,
            component(),
            Scenario::RunningStop,
            0,
            0,
            0x102_000,
        ),
    ];
    assert_eq!(cases[0], Err(ControlError::HandleMismatch));
    assert_eq!(cases[1], Err(ControlError::ManifestMismatch));
    assert_eq!(cases[2], Err(ControlError::ComponentMismatch));
    assert_eq!(cases[3], Err(ControlError::ScenarioMismatch));
    for result in &cases[4..] {
        assert_eq!(*result, Err(ControlError::ContextMismatch));
    }
    assert_eq!(returned(0, 4), returned(0, 4));
}

#[test]
fn exact_quiescent_request_is_one_shot() {
    let requested = request(
        returned(1, 6),
        1,
        6,
        MANIFEST,
        component(),
        Scenario::RunningStop,
        0,
        0,
        0x101_000,
    )
    .unwrap();
    assert!(matches!(requested, Control::StopRequested(_, _, _)));
    let repeated = request(
        requested.clone(),
        1,
        6,
        MANIFEST,
        component(),
        Scenario::RunningStop,
        0,
        0,
        0x101_000,
    );
    assert_eq!(repeated, Err(ControlError::AlreadyRequested));
    assert_eq!(requested, requested);
}

#[test]
fn admitted_lifecycle_states_are_not_returned() {
    for control in [admitted(0, 2), admitted(0, 2)] {
        assert_eq!(
            request(
                control,
                0,
                2,
                MANIFEST,
                component(),
                Scenario::RunningStop,
                0,
                0,
                0x101_000
            ),
            Err(ControlError::NotReturned)
        );
    }
}

#[test]
fn zero_generation_is_not_admitted() {
    assert_eq!(
        Control::<TestManifest, ContentId>::admit(
            handle(0, 0),
            MANIFEST,
            component(),
            Scenario::RunningStop,
            context()
        ),
        Err(ControlError::HandleMismatch)
    );
}
