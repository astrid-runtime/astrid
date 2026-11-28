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

    let legacy = Uuid::new_v4();
    let second_alias = Uuid::new_v4();
    let survivor_alias = Uuid::new_v4();
    registry.register_instance_uuid(legacy, artifact.clone());
    registry.register_instance_uuid(second_alias, artifact.clone());
    registry.register_instance_uuid(survivor_alias, test_hash("peer-bytes"));

    let retiring_generation = registry.runtime_id_for(&owner, &id).unwrap();
    let retiring_handle = registry.get_for(&owner, &id).unwrap();
    let departing_source = registry.source_id_for(&owner, &id).unwrap();
    let surviving_source = registry.source_id_for(&alice, &sibling).unwrap();
    for principal in [&owner, &alice, &bob] {
        assert!(Arc::ptr_eq(
            &registry
                .find_instance_by_uuid_for(principal, &departing_source)
                .unwrap(),
            &retiring_handle,
        ));
    }
    let detached = registry.unregister_for(&bob, &id).unwrap();
    assert!(!detached.torn_down);
    assert_eq!(registry.legacy_uuid_map.get(&legacy), Some(&artifact));
    assert!(
        registry
            .find_instance_by_uuid_for(&bob, &departing_source)
            .is_none()
    );
    assert!(Arc::ptr_eq(
        &registry
            .find_instance_by_uuid_for(&alice, &departing_source)
            .unwrap(),
        &retiring_handle,
    ));
    assert_eq!(registry.find_by_uuid(&departing_source), Some(&id));
    registry.register_existing(&id, &artifact, &bob).unwrap();
    let removed = registry.unregister_for(&owner, &id).unwrap();
    assert!(removed.torn_down);
    assert!(!registry.legacy_uuid_map.contains_key(&legacy));
    assert!(!registry.legacy_uuid_map.contains_key(&second_alias));
    assert!(Arc::ptr_eq(
        &registry
            .find_instance_by_uuid_for(&alice, &survivor_alias)
            .unwrap(),
        &survivor,
    ));
    assert!(registry.find_by_uuid(&departing_source).is_none());
    assert_eq!(registry.find_by_uuid(&surviving_source), Some(&sibling));
    assert!(!registry.instances.contains_key(&retiring_generation));
    assert!(Arc::ptr_eq(&removed.capsule, &retiring_handle));
    assert!(registry.get_for(&alice, &id).is_none());
    assert!(registry.get_for(&bob, &id).is_none());
    assert_eq!(registry.len(), 1);
    assert!(Arc::ptr_eq(
        &registry.get_for(&alice, &sibling).unwrap(),
        &survivor
    ));
    assert!(Arc::ptr_eq(
        &registry
            .find_instance_by_uuid_for(&alice, &surviving_source)
            .unwrap(),
        &survivor,
    ));
    assert_eq!(removed.removed_principals.len(), 3);
    for principal in [&owner, &alice, &bob] {
        assert!(removed.removed_principals.contains(principal));
        assert!(
            !registry
                .uuid_map
                .contains_key(&(departing_source, principal.clone()))
        );
        assert!(
            registry
                .find_instance_by_uuid_for(principal, &departing_source)
                .is_none()
        );
    }
}

#[test]
fn legacy_alias_table_survives_departure_of_one_of_two_generations() {
    let mut registry = CapsuleRegistry::new();
    let package = CapsuleId::from_static("shared-artifact");
    let artifact = test_hash("shared-bytes");
    let alice = pid("alice");
    let bob = pid("bob");
    for (principal, user) in [(&alice, uid(1)), (&bob, uid(2))] {
        registry
            .register_principal_runtime(
                Box::new(MockCapsule::new("shared-artifact")),
                artifact.clone(),
                principal,
                user,
            )
            .unwrap();
    }
    let aliases = [Uuid::new_v4(), Uuid::new_v4()];
    for alias in aliases {
        registry.register_instance_uuid(alias, artifact.clone());
    }

    let before = registry.legacy_uuid_map.clone();
    let peer = registry.get_for(&bob, &package).unwrap();
    assert!(registry.unregister_for(&alice, &package).unwrap().torn_down);
    assert_eq!(registry.legacy_uuid_map, before);
    for alias in aliases {
        assert!(Arc::ptr_eq(
            &registry.find_instance_by_uuid_for(&bob, &alias).unwrap(),
            &peer
        ));
    }
    assert!(registry.unregister_for(&bob, &package).unwrap().torn_down);
    assert!(registry.legacy_uuid_map.is_empty());
}

#[test]
fn removing_one_system_package_preserves_the_owners_other_generation() {
    let mut registry = CapsuleRegistry::new();
    let owner = pid("owner");
    let peer = pid("peer");
    let retiring = CapsuleId::from_static("retiring-service");
    let remaining = CapsuleId::from_static("remaining-service");
    let artifact = test_hash("retiring-bytes");
    registry
        .register_system_runtime(
            Box::new(MockCapsule::new("retiring-service")),
            artifact.clone(),
            &owner,
        )
        .unwrap();
    registry
        .register_existing(&retiring, &artifact, &peer)
        .unwrap();
    registry
        .register_system_runtime(
            Box::new(MockCapsule::new("remaining-service")),
            test_hash("remaining-bytes"),
            &owner,
        )
        .unwrap();
    let survivor = registry.get_for(&owner, &remaining).unwrap();

    let removed = registry.unregister_for(&owner, &retiring).unwrap();
    assert!(removed.torn_down);
    assert_eq!(
        removed.removed_principals,
        vec![owner.clone(), peer.clone()]
    );
    assert!(registry.get_for(&owner, &retiring).is_none());
    assert!(registry.get_for(&peer, &retiring).is_none());
    assert!(Arc::ptr_eq(
        &survivor,
        &registry.get_for(&owner, &remaining).unwrap()
    ));
}
