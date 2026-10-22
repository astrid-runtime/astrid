//! Regressions for the one audited EndpointCreate transaction.

use super::test_support::{endpoint_create, test_lock};
use super::*;

fn domain(slot: u64) -> DomainToken {
    DomainToken::new(slot, 1).unwrap()
}

fn reset_transaction_state() {
    *IPC.lock() = IpcState::empty();
    crate::audit::reset_for_test();
    crate::platform::reset_for_test();
}

fn audit_state() -> (u64, [u8; 32]) {
    crate::audit::state_for_test().expect("test audit runtime is installed")
}

#[test]
fn forced_audit_failure_leaves_ipc_and_audit_unchanged() {
    let _guard = test_lock();
    reset_transaction_state();
    let creator = domain(0);
    prepare_domain(creator);

    let before = audit_state();
    let relations_before = IPC.lock().relations.runtime_evidence(creator).unwrap();
    super::audit::force_failure_for_test(true);
    let result = endpoint_create(creator);
    super::audit::force_failure_for_test(false);

    assert_eq!(result, Err(IpcError::AuditRejected));
    assert_eq!(audit_state(), before);
    let state = IPC.lock();
    assert!(state.objects.iter().all(Option::is_none));
    assert!(
        state.capabilities[creator.slot().index()]
            .capability_slots()
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(state.next_object_generation, 1);
    assert_eq!(
        state.relations.runtime_evidence(creator).unwrap(),
        relations_before
    );
}

#[test]
fn forced_relay_failure_leaves_ipc_and_audit_unchanged() {
    let _guard = test_lock();
    reset_transaction_state();
    let creator = domain(0);
    prepare_domain(creator);
    crate::audit::fill_relay_for_test().unwrap();

    let before = audit_state();
    let relations_before = IPC.lock().relations.runtime_evidence(creator).unwrap();
    let result = endpoint_create(creator);

    assert_eq!(result, Err(IpcError::AuditRejected));
    assert_eq!(audit_state(), before);
    let state = IPC.lock();
    assert!(state.objects.iter().all(Option::is_none));
    assert!(
        state.capabilities[creator.slot().index()]
            .capability_slots()
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(state.next_object_generation, 1);
    assert_eq!(
        state.relations.runtime_evidence(creator).unwrap(),
        relations_before
    );
}
