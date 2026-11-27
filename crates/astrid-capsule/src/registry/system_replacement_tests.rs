use super::*;

#[test]
fn system_generation_replacement_swaps_every_view() {
    let mut registry = CapsuleRegistry::new();
    let alice = pid("alice");
    let bob = pid("bob");
    let id = CapsuleId::from_static("system-service");
    let old_hash = test_hash("system-old");
    let old = registry
        .register_system_runtime(
            Box::new(MockCapsule::new("system-service")),
            old_hash.clone(),
            &alice,
        )
        .unwrap();
    registry.register_existing(&id, &old_hash, &bob).unwrap();

    let replaced = registry
        .replace_system_runtime(
            &old,
            Box::new(MockCapsule::new("system-service")),
            test_hash("system-new"),
        )
        .unwrap();

    assert_eq!(
        registry.runtime_id_for(&alice, &id),
        Some(replaced.runtime_id.clone())
    );
    assert_eq!(
        registry.runtime_id_for(&bob, &id),
        Some(replaced.runtime_id)
    );
    assert!(Arc::ptr_eq(
        &registry.get_for(&alice, &id).unwrap(),
        &registry.get_for(&bob, &id).unwrap()
    ));
}

#[test]
fn system_replacement_builds_the_published_uplink_descriptors_once() -> CapsuleResult<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut registry = CapsuleRegistry::new();
    let owner = pid("operator");
    let name = "system-provider";
    let mut expected = registry.register_system_runtime(
        Box::new(MockCapsule::new(name)),
        test_hash("old"),
        &owner,
    )?;
    for preallocated in [false, true] {
        let mut candidate = MockCapsule::new(name);
        let reads = Arc::new(AtomicUsize::new(0));
        candidate.manifest_reads = Some(Arc::clone(&reads));
        candidate.manifest.uplinks.push(crate::manifest::UplinkDef {
            name: "console".into(),
            platform: "cli".into(),
            profile: astrid_core::UplinkProfile::Chat,
        });
        let old_ids: Vec<_> = registry
            .all_uplink_descriptors()
            .iter()
            .map(|d| d.id)
            .collect();
        let next = if preallocated {
            let reserved = registry.reserve_runtime_id(
                candidate.id.clone(),
                test_hash("new"),
                RuntimeScope::SystemResident,
            )?;
            registry.replace_system_runtime_reserved(&expected, Box::new(candidate), reserved)?
        } else {
            registry.replace_system_runtime(&expected, Box::new(candidate), test_hash("new"))?
        };
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        let descriptors = registry.all_uplink_descriptors();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].name, "console");
        assert!(old_ids.iter().all(|id| registry.get_uplink(id).is_none()));
        expected = next.runtime_id;
    }
    Ok(())
}

#[test]
fn rejected_system_publication_returns_the_candidate_and_preserves_the_old_runtime()
-> CapsuleResult<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut registry = CapsuleRegistry::new();
    let package = CapsuleId::from_static("service");
    let principal = pid("operator");
    let expected = registry.register_system_runtime(
        Box::new(MockCapsule::new("service")),
        test_hash("old"),
        &principal,
    )?;
    let old_handle = registry.get_for(&principal, &package).unwrap();
    let uplink = astrid_core::UplinkDescriptor::builder("console", "cli").build();
    let old_uplink = uplink.id;
    registry.register_uplink(&package, uplink)?;

    let invalid = registry.reserve_runtime_id(
        package.clone(),
        test_hash("new"),
        RuntimeScope::Principal(uid(1)),
    )?;
    let mut candidate = MockCapsule::new("service");
    let reads = Arc::new(AtomicUsize::new(0));
    candidate.manifest_reads = Some(reads.clone());
    let Err(rejected) =
        registry.try_replace_system_runtime_reserved(&expected, Box::new(candidate), invalid)
    else {
        panic!("principal reservation was accepted as a system replacement");
    };
    assert!(matches!(rejected.error, CapsuleError::ExecutionFailed(_)));
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert_eq!(rejected.capsule.manifest().package.name, "service");
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    assert_eq!(
        registry.runtime_id_for(&principal, &package),
        Some(expected)
    );
    assert!(Arc::ptr_eq(
        &old_handle,
        &registry.get_for(&principal, &package).unwrap()
    ));
    assert_eq!(registry.get_uplink(&old_uplink).unwrap().name, "console");
    Ok(())
}
