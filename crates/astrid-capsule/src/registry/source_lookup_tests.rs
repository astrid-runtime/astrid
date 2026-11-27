use super::*;

#[test]
fn stable_wire_source_resolves_only_in_the_current_registry()
-> Result<(), Box<dyn std::error::Error>> {
    let principal = pid("operator");
    let name = CapsuleId::from_static("service");
    let install = |registry: &mut CapsuleRegistry, owner| {
        registry.register_principal_runtime(
            Box::new(MockCapsule::new("service")),
            test_hash("unchanged"),
            &principal,
            uid(owner),
        )
    };

    let mut before = CapsuleRegistry::new();
    let prior_id = install(&mut before, 1)?;
    let source = before
        .source_id_for(&principal, &name)
        .expect("installed source");
    let prior = before
        .get_for(&principal, &name)
        .expect("installed capsule");
    drop(before);

    let mut after = CapsuleRegistry::new();
    assert!(
        after
            .find_instance_by_uuid_for(&principal, &source)
            .is_none()
    );
    let current_id = install(&mut after, 2)?;
    assert_eq!(prior_id.generation(), current_id.generation());
    assert!(!after.is_current_runtime(&principal, &name, &prior_id));
    assert_eq!(after.source_id_for(&principal, &name), Some(source));
    let current = after
        .get_for(&principal, &name)
        .expect("reinstalled capsule");
    assert!(matches!(
        after.restart_snapshot_for(&principal, &name, Some(&prior_id)),
        RestartSnapshot::Superseded
    ));
    for expected in [None, Some(&current_id)] {
        let RestartSnapshot::Current(selected, handle) =
            after.restart_snapshot_for(&principal, &name, expected)
        else {
            panic!("installed generation must be available for restart");
        };
        assert_eq!(selected, current_id);
        assert!(Arc::ptr_eq(&handle, &current));
    }
    let resolved = after
        .find_instance_by_uuid_for(&principal, &source)
        .expect("current source");
    assert!(Arc::ptr_eq(&resolved, &current));
    assert!(!Arc::ptr_eq(&resolved, &prior));

    let mut same_owner = CapsuleRegistry::new();
    let reissued = install(&mut same_owner, 1)?;
    assert_eq!(reissued, prior_id);
    let RestartSnapshot::Current(_, reloaded) =
        same_owner.restart_snapshot_for(&principal, &name, Some(&prior_id))
    else {
        panic!("identical registry inputs reissue the identity");
    };
    assert!(!Arc::ptr_eq(&reloaded, &prior));
    Ok(())
}

#[test]
fn ambiguous_legacy_artifact_refuses_both_matching_slots() -> Result<(), Box<dyn std::error::Error>>
{
    let mut registry = CapsuleRegistry::new();
    let principal = pid("operator");
    let artifact = test_hash("shared-artifact");
    let source = Uuid::new_v4();
    registry.register_instance_uuid(source, artifact.clone());
    for name in ["first", "second"] {
        registry.register_principal_runtime(
            Box::new(MockCapsule::new(name)),
            artifact.clone(),
            &principal,
            uid(1),
        )?;
    }
    assert!(
        registry
            .find_instance_by_uuid_for(&principal, &source)
            .is_none()
    );
    Ok(())
}

#[test]
fn missing_scoped_instance_shadows_live_legacy_alias() -> Result<(), Box<dyn std::error::Error>> {
    let principal = pid("operator");
    let mut registry = CapsuleRegistry::new();
    let artifact = test_hash("live");
    let scoped = registry.register_principal_runtime(
        Box::new(MockCapsule::new("scoped")),
        test_hash("gone"),
        &principal,
        uid(1),
    )?;
    registry.register_principal_runtime(
        Box::new(MockCapsule::new("legacy")),
        artifact.clone(),
        &principal,
        uid(1),
    )?;
    let source = registry
        .source_id_for(&principal, &CapsuleId::from_static("scoped"))
        .expect("registered source");
    registry.register_instance_uuid(source, artifact);
    registry.instances.remove(&scoped);
    assert!(matches!(
        registry.restart_snapshot_for(&principal, &CapsuleId::from_static("scoped"), Some(&scoped)),
        RestartSnapshot::Missing
    ));
    assert!(
        registry
            .find_instance_by_uuid_for(&principal, &source)
            .is_none()
    );
    Ok(())
}

#[test]
fn shared_attachment_routes_to_the_selected_package_and_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = CapsuleRegistry::new();
    let owner = pid("owner");
    let peer = pid("peer");
    let artifact = test_hash("identical-bytes");
    let wanted = CapsuleId::from_static("service");
    let sibling = CapsuleId::from_static("sibling");
    for package in [&wanted, &sibling] {
        registry.register_system_runtime(
            Box::new(MockCapsule::new(package.as_str())),
            artifact.clone(),
            &owner,
        )?;
    }
    let original = registry.get_for(&owner, &wanted).unwrap();
    registry.register_existing(&sibling, &artifact, &peer)?;
    let sibling_handle = registry.get_for(&peer, &sibling).unwrap();
    assert!(
        registry
            .register_existing(&wanted, &test_hash("other-bytes"), &peer)
            .is_err()
    );
    assert!(registry.get_for(&peer, &wanted).is_none());

    registry.register_existing(&wanted, &artifact, &peer)?;
    let source = registry.source_id_for(&owner, &wanted).unwrap();
    assert!(Arc::ptr_eq(
        &original,
        &registry.find_instance_by_uuid_for(&peer, &source).unwrap()
    ));
    assert!(Arc::ptr_eq(
        &sibling_handle,
        &registry.get_for(&peer, &sibling).unwrap()
    ));
    assert!(!Arc::ptr_eq(&original, &sibling_handle));
    Ok(())
}

#[test]
fn private_registration_dispatch_and_removal_restore_existing_source_indexes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = CapsuleRegistry::new();
    let peer = pid("peer");
    let principal = pid("new-owner");
    let existing = CapsuleId::from_static("existing-service");
    let package = CapsuleId::from_static("fresh-service");
    let artifact = test_hash("new-bytes");
    let peer_artifact = test_hash("peer-bytes");
    registry.register_principal_runtime(
        Box::new(MockCapsule::new(existing.as_str())),
        peer_artifact.clone(),
        &peer,
        uid(1),
    )?;
    let peer_handle = registry.get_for(&peer, &existing).unwrap();
    let source = capsule_source_uuid(&package, &artifact);
    registry.register_instance_uuid(source, peer_artifact);
    let views = registry.views.clone();
    let routes = registry.uuid_map.clone();
    let sources = registry.source_uuid_by_runtime.clone();
    let names = registry.uuid_id_map.clone();

    let generation = registry.register_principal_runtime(
        Box::new(MockCapsule::new(package.as_str())),
        artifact,
        &principal,
        uid(2),
    )?;
    let handle = registry.get_for(&principal, &package).unwrap();
    assert_eq!(
        registry.runtime_id_for(&principal, &package),
        Some(generation.clone())
    );
    assert!(Arc::ptr_eq(
        &handle,
        &registry
            .find_instance_by_uuid_for(&principal, &source)
            .unwrap()
    ));
    assert!(Arc::ptr_eq(
        &peer_handle,
        &registry.find_instance_by_uuid_for(&peer, &source).unwrap()
    ));
    let removed = registry.unregister_for(&principal, &package)?;
    assert!(removed.torn_down);
    assert_eq!(removed.removed_principals, vec![principal]);
    assert!(Arc::ptr_eq(&removed.capsule, &handle));
    assert!(!registry.instances.contains_key(&generation));
    assert_eq!(registry.instances.len(), 1);
    assert!(Arc::ptr_eq(
        &peer_handle,
        &registry.get_for(&peer, &existing).unwrap()
    ));
    assert_eq!(registry.views, views);
    assert_eq!(registry.uuid_map, routes);
    assert_eq!(registry.source_uuid_by_runtime, sources);
    assert_eq!(registry.uuid_id_map, names);
    Ok(())
}
