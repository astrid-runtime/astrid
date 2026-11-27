//! Removal of a shared generation through the authenticated registry entry point.
use super::*;

#[test]
fn removing_system_owner_revokes_every_dependent_view() {
    let mut registry = CapsuleRegistry::new();
    let owner = PrincipalId::default();
    let alice = pid("alice");
    let bob = pid("bob");
    let id = CapsuleId::from_static("operator-service");
    let artifact = test_hash("operator-service-bytes");
    registry
        .register_system_runtime(
            Box::new(MockCapsule::new("operator-service")),
            artifact.clone(),
            &owner,
        )
        .unwrap();
    registry.register_existing(&id, &artifact, &alice).unwrap();
    registry.register_existing(&id, &artifact, &bob).unwrap();

    let sibling = CapsuleId::from_static("peer-package");
    registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("peer-package")),
            test_hash("peer-bytes"),
            &alice,
            uid(1),
        )
        .unwrap();
    let survivor = registry.get_for(&alice, &sibling).unwrap();

    let retiring_generation = registry.runtime_id_for(&owner, &id).unwrap();
    let retiring_handle = registry.get_for(&owner, &id).unwrap();
    let removed = registry.unregister_for(&owner, &id).unwrap();
    assert!(removed.torn_down);
    assert!(!registry.instances.contains_key(&retiring_generation));
    assert!(Arc::ptr_eq(&removed.capsule, &retiring_handle));
    assert!(registry.get_for(&alice, &id).is_none());
    assert!(registry.get_for(&bob, &id).is_none());
    assert_eq!(registry.len(), 1);
    assert!(Arc::ptr_eq(
        &registry.get_for(&alice, &sibling).unwrap(),
        &survivor
    ));
    assert_eq!(removed.removed_principals.len(), 3);
    for principal in [&owner, &alice, &bob] {
        assert!(removed.removed_principals.contains(principal));
    }
}
