//! Production-path regression for non-IPC relation retirement at reclaim.

use crate::ipc::{self, DomainToken};

#[test]
fn non_ipc_registered_generation_is_retired_without_object_resurrection() {
    let _guard = ipc::test_support::test_lock();
    ipc::test_support::reset();
    let domain = DomainToken::new(0, 1).unwrap();
    ipc::prepare_domain(domain);
    assert_eq!(
        ipc::relations_projection_observation(domain)
            .unwrap()
            .0
            .len(),
        1
    );
    let outcome = ipc::teardown_domain(domain);
    assert!(outcome.relation_released);
    assert!(ipc::relations_projection_observation(domain).is_none());

    let fresh = DomainToken::new(0, 2).unwrap();
    ipc::prepare_domain(fresh);
    assert_eq!(
        ipc::relations_projection_observation(fresh)
            .unwrap()
            .0
            .len(),
        1
    );
    assert!(ipc::relations_projection_observation(domain).is_none());
    let outcome = ipc::teardown_domain(fresh);
    assert!(outcome.relation_released);
    assert!(ipc::relations_projection_observation(fresh).is_none());
}
