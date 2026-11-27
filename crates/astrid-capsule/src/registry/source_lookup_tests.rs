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
