use super::{ADMISSION_RELEASES, RELATION_RELEASE_FAILURE, ReclaimStats, SPACE_RELEASE_FAILURE};
use super::{Domain, DomainControl, DomainState, DomainStop, Manager, Scenario};
use crate::domains::types::{DomainGeneration, DomainHandle, DomainId};
use crate::ipc::{DomainToken, prepare_domain};
use astrid_system_generation::ContentId;
use core::sync::atomic::Ordering;
use spin::{Mutex, MutexGuard};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock_fixture() -> MutexGuard<'static, ()> {
    TEST_LOCK.lock()
}

fn handle() -> DomainHandle {
    DomainHandle::new(DomainId(0), DomainGeneration(12))
}

fn release_component_id() -> ContentId {
    ContentId::from_payload(b"manager-stop-release-failure")
}

fn reset_release_fixture() {
    RELATION_RELEASE_FAILURE.store(false, Ordering::SeqCst);
    SPACE_RELEASE_FAILURE.store(0, Ordering::SeqCst);
    let mut manager = super::MANAGER.lock();
    manager.slots[0] = None;
}

fn install_taken_domain(space: Option<()>) -> spin::MutexGuard<'static, Manager> {
    let handle = handle();
    let component_id = release_component_id();
    let mut stop = DomainStop::stage(handle, (), component_id, Scenario::RunningStop)
        .unwrap()
        .into_armed(handle, (), component_id, Scenario::RunningStop)
        .unwrap();
    stop.take_timer(handle, Scenario::RunningStop).unwrap();
    let mut manager = super::MANAGER.lock();
    manager.slots[0] = Some(Domain {
        generation: 12,
        state: DomainState::Running,
        scenario: Scenario::RunningStop,
        quota_ticks: 0,
        space,
        ipc_enabled: false,
        stop,
        control: DomainControl::inactive(),
    });
    manager.used_frames = 3;
    manager
}

#[test]
fn relation_release_failure_fails_closed_and_forbids_reuse() {
    let _fixture = lock_fixture();
    reset_release_fixture();
    RELATION_RELEASE_FAILURE.store(true, Ordering::SeqCst);
    ADMISSION_RELEASES.store(0, Ordering::SeqCst);
    let mut manager = install_taken_domain(Some(()));

    assert_eq!(
        manager.release_slot_with_stop(handle(), None),
        ReclaimStats::zero()
    );
    {
        let domain = manager.slots[0].as_ref().unwrap();
        assert_eq!(domain.state, DomainState::ReleaseFailed);
        assert!(matches!(domain.stop, DomainStop::Aborted(_)));
        assert_eq!(manager.used_frames, 3);
    }
    assert_eq!(ADMISSION_RELEASES.load(Ordering::SeqCst), 0);
    assert!(!Manager::slot_is_preparable(manager.slots[0].as_ref()));
    assert!(
        manager
            .completed_running_stop(handle(), release_component_id(), Scenario::RunningStop)
            .is_none()
    );

    manager.slots[0] = None;
    RELATION_RELEASE_FAILURE.store(false, Ordering::SeqCst);
}

#[test]
fn missing_space_fails_taken_stop_without_accounting_release() {
    let _fixture = lock_fixture();
    let _ipc_fixture = crate::ipc::test_support::test_lock();
    reset_release_fixture();
    crate::ipc::test_support::reset();
    prepare_domain(DomainToken::new(0, 12).unwrap());
    ADMISSION_RELEASES.store(0, Ordering::SeqCst);
    let mut manager = install_taken_domain(None);

    assert_eq!(
        manager.release_slot_with_stop(handle(), None),
        ReclaimStats::zero()
    );
    {
        let domain = manager.slots[0].as_ref().unwrap();
        assert_eq!(domain.state, DomainState::ReleaseFailed);
        assert!(matches!(domain.stop, DomainStop::Aborted(_)));
        assert_eq!(manager.used_frames, 3);
    }
    assert_eq!(ADMISSION_RELEASES.load(Ordering::SeqCst), 0);
    assert!(!Manager::slot_is_preparable(manager.slots[0].as_ref()));
    assert!(
        manager
            .completed_running_stop(handle(), release_component_id(), Scenario::RunningStop)
            .is_none()
    );

    manager.slots[0] = None;
}

#[test]
fn cr3_restore_failure_finishes_aborted_and_keeps_accounting() {
    let _fixture = lock_fixture();
    let _ipc_fixture = crate::ipc::test_support::test_lock();
    reset_release_fixture();
    crate::ipc::test_support::reset();
    prepare_domain(DomainToken::new(0, 12).unwrap());
    SPACE_RELEASE_FAILURE.store(1, Ordering::SeqCst);
    ADMISSION_RELEASES.store(0, Ordering::SeqCst);
    let mut manager = install_taken_domain(Some(()));

    assert_eq!(
        manager.release_slot_with_stop(handle(), None),
        ReclaimStats::zero()
    );
    {
        let domain = manager.slots[0].as_ref().unwrap();
        assert_eq!(domain.state, DomainState::ReleaseFailed);
        assert!(matches!(domain.stop, DomainStop::Aborted(_)));
        assert_eq!(manager.used_frames, 3);
    }
    assert_eq!(ADMISSION_RELEASES.load(Ordering::SeqCst), 0);
    assert!(!Manager::slot_is_preparable(manager.slots[0].as_ref()));
    assert!(
        manager
            .completed_running_stop(handle(), release_component_id(), Scenario::RunningStop)
            .is_none()
    );

    manager.slots[0] = None;
    SPACE_RELEASE_FAILURE.store(0, Ordering::SeqCst);
}

#[test]
fn reclaim_blocked_fails_taken_stop_and_keeps_accounting() {
    let _fixture = lock_fixture();
    let _ipc_fixture = crate::ipc::test_support::test_lock();
    reset_release_fixture();
    crate::ipc::test_support::reset();
    prepare_domain(DomainToken::new(0, 12).unwrap());
    SPACE_RELEASE_FAILURE.store(2, Ordering::SeqCst);
    ADMISSION_RELEASES.store(0, Ordering::SeqCst);
    let mut manager = install_taken_domain(Some(()));

    assert_eq!(
        manager.release_slot_with_stop(handle(), None),
        ReclaimStats::from_parts(3, 2, true, true)
    );
    {
        let domain = manager.slots[0].as_ref().unwrap();
        assert_eq!(domain.state, DomainState::ReleaseFailed);
        assert!(matches!(domain.stop, DomainStop::Aborted(_)));
        assert_eq!(manager.used_frames, 3);
    }
    assert_eq!(ADMISSION_RELEASES.load(Ordering::SeqCst), 0);
    assert!(!Manager::slot_is_preparable(manager.slots[0].as_ref()));
    assert!(
        manager
            .completed_running_stop(handle(), release_component_id(), Scenario::RunningStop)
            .is_none()
    );

    manager.slots[0] = None;
    SPACE_RELEASE_FAILURE.store(0, Ordering::SeqCst);
}

#[test]
fn successful_stop_reclaims_once_releases_admission_and_frees_slot() {
    let _fixture = lock_fixture();
    let _ipc_fixture = crate::ipc::test_support::test_lock();
    reset_release_fixture();
    crate::ipc::test_support::reset();
    prepare_domain(DomainToken::new(0, 12).unwrap());
    ADMISSION_RELEASES.store(0, Ordering::SeqCst);
    let mut manager = install_taken_domain(Some(()));

    let stats = manager.release_slot_with_stop(handle(), None);
    assert_eq!(stats, ReclaimStats::from_parts(3, 3, true, true));
    {
        let domain = manager.slots[0].as_ref().unwrap();
        assert_eq!(domain.state, DomainState::Reclaimed);
        assert!(matches!(domain.stop, DomainStop::Completed(_)));
        assert_eq!(manager.used_frames, 0);
    }
    assert_eq!(ADMISSION_RELEASES.load(Ordering::SeqCst), 1);
    assert!(Manager::slot_is_preparable(manager.slots[0].as_ref()));

    let exact = manager
        .completed_running_stop(handle(), release_component_id(), Scenario::RunningStop)
        .unwrap();
    let repeated = manager
        .completed_running_stop(handle(), release_component_id(), Scenario::RunningStop)
        .unwrap();
    assert_eq!(exact, repeated);
    assert_eq!(exact.handle(), handle());
    assert_eq!(exact.manifest_identity(), &());
    assert_eq!(exact.component_id(), &release_component_id());
    assert_eq!(exact.scenario(), Scenario::RunningStop);
    assert_eq!(exact.outcome(), crate::domains::types::Outcome::Cancelled);

    let wrong_generation = DomainHandle::new(DomainId(0), DomainGeneration(13));
    let wrong_slot = DomainHandle::new(DomainId(1), DomainGeneration(12));
    let substituted_component =
        astrid_system_generation::ContentId::from_payload(b"substituted-stop-release");
    assert!(
        manager
            .completed_running_stop(
                wrong_generation,
                release_component_id(),
                Scenario::RunningStop
            )
            .is_none()
    );
    assert!(
        manager
            .completed_running_stop(wrong_slot, release_component_id(), Scenario::RunningStop)
            .is_none()
    );
    assert!(
        manager
            .completed_running_stop(handle(), substituted_component, Scenario::RunningStop)
            .is_none()
    );
    assert!(
        manager
            .completed_running_stop(handle(), release_component_id(), Scenario::Exit)
            .is_none()
    );

    manager.slots[0] = None;
}

#[test]
fn releasing_state_forbids_completed_observation() {
    let _fixture = lock_fixture();
    let mut manager = install_taken_domain(Some(()));
    if let Some(domain) = manager.slots[0].as_mut() {
        domain.state = DomainState::Releasing;
    }

    assert!(
        manager
            .completed_running_stop(handle(), release_component_id(), Scenario::RunningStop)
            .is_none()
    );
    assert_eq!(
        manager.slots[0].as_ref().unwrap().state,
        DomainState::Releasing
    );
    manager.slots[0] = None;
}

#[test]
fn same_slot_fresh_generation_hides_old_completed_observation() {
    let _fixture = lock_fixture();
    let old_component = ContentId::from_payload(b"manager-stop-old-generation");
    let fresh_component = ContentId::from_payload(b"manager-stop-fresh-generation");
    let mut manager = super::MANAGER.lock();
    manager.slots[0] = Some(Domain {
        generation: 12,
        state: DomainState::Reclaimed,
        scenario: Scenario::RunningStop,
        quota_ticks: 0,
        space: None,
        ipc_enabled: false,
        stop: completed_stop(handle(), old_component),
        control: DomainControl::inactive(),
    });

    assert!(
        manager
            .completed_running_stop(handle(), old_component, Scenario::RunningStop)
            .is_some()
    );

    let fresh = DomainHandle::new(DomainId(0), DomainGeneration(13));
    manager.slots[0] = Some(Domain {
        generation: 13,
        state: DomainState::Reclaimed,
        scenario: Scenario::RunningStop,
        quota_ticks: 0,
        space: None,
        ipc_enabled: false,
        stop: completed_stop(fresh, fresh_component),
        control: DomainControl::inactive(),
    });
    assert!(
        manager
            .completed_running_stop(handle(), old_component, Scenario::RunningStop)
            .is_none()
    );
    let observation = manager
        .completed_running_stop(fresh, fresh_component, Scenario::RunningStop)
        .unwrap();
    assert_eq!(observation.handle(), fresh);
    assert_eq!(observation.component_id(), &fresh_component);
    manager.slots[0] = None;
}

fn completed_stop(handle: DomainHandle, component_id: ContentId) -> DomainStop {
    let mut stop = DomainStop::stage(handle, (), component_id, Scenario::RunningStop)
        .unwrap()
        .into_armed(handle, (), component_id, Scenario::RunningStop)
        .unwrap();
    stop.take_timer(handle, Scenario::RunningStop).unwrap();
    stop.finish(handle, true).unwrap();
    stop
}
