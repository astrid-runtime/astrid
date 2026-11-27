//! Reserved principal and system replacement must fail closed.

use std::sync::Arc;

use astrid_core::{UplinkDescriptor, UplinkProfile};

use super::{MockCapsule, pid, test_hash, uid};
use crate::manifest::UplinkDef;
use crate::registry::{CapsuleId, CapsuleRegistry, RuntimeId, RuntimeScope};

fn with_uplink(mut capsule: MockCapsule, platform: &str) -> MockCapsule {
    capsule.manifest.uplinks.push(UplinkDef {
        name: platform.to_string(),
        platform: platform.to_string(),
        profile: UplinkProfile::Notify,
    });
    capsule
}

fn uplink_names(registry: &CapsuleRegistry) -> Vec<String> {
    let mut names = registry
        .all_uplink_descriptors()
        .iter()
        .map(|descriptor| descriptor.name.clone())
        .collect::<Vec<_>>();
    names.sort();
    names
}

struct Installed {
    principal: astrid_core::PrincipalId,
    id: CapsuleId,
    runtime: RuntimeId,
    capsule: Arc<dyn crate::capsule::Capsule>,
}

fn assert_unchanged(
    registry: &CapsuleRegistry,
    kept: &Installed,
    other: &Installed,
    uplinks: &[String],
) {
    assert_eq!(
        registry.runtime_id_for(&kept.principal, &kept.id).as_ref(),
        Some(&kept.runtime)
    );
    assert!(Arc::ptr_eq(
        &registry.get_for(&kept.principal, &kept.id).unwrap(),
        &kept.capsule
    ));
    assert_eq!(
        registry
            .runtime_id_for(&other.principal, &other.id)
            .as_ref(),
        Some(&other.runtime)
    );
    assert!(Arc::ptr_eq(
        &registry.get_for(&other.principal, &other.id).unwrap(),
        &other.capsule
    ));
    assert_eq!(uplink_names(registry), uplinks);
}

#[test]
fn principal_reserved_replacement_refuses_without_mutating() {
    let mut registry = CapsuleRegistry::new();
    let alice = pid("alice");
    let bob = pid("bob");
    let id = CapsuleId::from_static("replaceable");
    let other_id = CapsuleId::from_static("unrelated");
    let retired = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("replaceable")),
            test_hash("retired-artifact"),
            &alice,
            uid(1),
        )
        .unwrap();
    let current = registry
        .replace_principal_runtime(
            &retired,
            Box::new(MockCapsule::new("replaceable")),
            test_hash("current-artifact"),
            &alice,
            uid(1),
        )
        .unwrap()
        .runtime_id;
    let current_capsule = registry.get_for(&alice, &id).unwrap();
    let unrelated = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("unrelated")),
            test_hash("unrelated-artifact"),
            &bob,
            uid(2),
        )
        .unwrap();
    let unrelated_capsule = registry.get_for(&bob, &other_id).unwrap();
    registry
        .register_uplink(
            &other_id,
            UplinkDescriptor::builder("unrelated-uplink", "notes").build(),
        )
        .unwrap();
    let newer = registry
        .reserve_runtime_id(
            id.clone(),
            test_hash("prepared-newer"),
            RuntimeScope::Principal(uid(1)),
        )
        .unwrap();
    let newer_still = registry
        .reserve_runtime_id(
            id.clone(),
            test_hash("prepared-newer-still"),
            RuntimeScope::Principal(uid(1)),
        )
        .unwrap();
    let uplinks = uplink_names(&registry);
    let length = registry.len();
    let current_installed = Installed {
        principal: alice.clone(),
        id: id.clone(),
        runtime: current.clone(),
        capsule: Arc::clone(&current_capsule),
    };
    let unrelated_installed = Installed {
        principal: bob.clone(),
        id: other_id.clone(),
        runtime: unrelated.clone(),
        capsule: Arc::clone(&unrelated_capsule),
    };

    for (label, reservation) in [
        ("current generation", current.clone()),
        ("older reservation", retired.clone()),
        ("live unrelated runtime", unrelated.clone()),
    ] {
        let error = match registry.replace_principal_runtime_reserved(
            &current,
            Box::new(MockCapsule::new("replaceable")),
            reservation,
            &alice,
            uid(1),
        ) {
            Ok(_) => panic!("{label} published a refused reservation"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("cannot replace")
                || error.to_string().contains("does not match"),
            "{label}: {error}"
        );
        assert_unchanged(
            &registry,
            &current_installed,
            &unrelated_installed,
            &uplinks,
        );
        assert_eq!(registry.len(), length);
        assert!(
            registry
                .cloned_runtimes()
                .iter()
                .all(|(runtime_id, _)| runtime_id != &newer && runtime_id != &newer_still)
        );
    }

    let published = registry
        .replace_principal_runtime_reserved(
            &current,
            Box::new(MockCapsule::new("replaceable")),
            newer.clone(),
            &alice,
            uid(1),
        )
        .unwrap();
    assert_eq!(published.runtime_id, newer);
    assert_eq!(registry.runtime_id_for(&alice, &id), Some(newer.clone()));
    assert!(Arc::ptr_eq(&published.previous, &current_capsule));
    assert!(Arc::ptr_eq(
        &registry.get_for(&bob, &other_id).unwrap(),
        &unrelated_capsule
    ));

    let published_later = registry
        .replace_principal_runtime_reserved(
            &newer,
            Box::new(MockCapsule::new("replaceable")),
            newer_still.clone(),
            &alice,
            uid(1),
        )
        .unwrap();
    assert_eq!(published_later.runtime_id, newer_still);
    assert_eq!(
        registry.runtime_id_for(&alice, &id),
        Some(newer_still.clone())
    );
    assert!(
        registry
            .cloned_runtimes()
            .iter()
            .all(|(runtime_id, _)| runtime_id != &newer)
    );
    assert!(Arc::ptr_eq(
        &registry.get_for(&bob, &other_id).unwrap(),
        &unrelated_capsule
    ));
    assert_eq!(uplink_names(&registry), uplinks);
}

#[test]
fn system_reserved_replacement_refuses_without_mutating() {
    let mut registry = CapsuleRegistry::new();
    let alice = pid("alice");
    let bob = pid("bob");
    let carol = pid("carol");
    let id = CapsuleId::from_static("system-service");
    let other_id = CapsuleId::from_static("unrelated");
    let retired = registry
        .register_system_runtime(
            Box::new(with_uplink(
                MockCapsule::new("system-service"),
                "service-platform",
            )),
            test_hash("system-retired"),
            &alice,
        )
        .unwrap();
    let current = registry
        .replace_system_runtime(
            &retired,
            Box::new(with_uplink(
                MockCapsule::new("system-service"),
                "service-platform",
            )),
            test_hash("system-current"),
        )
        .unwrap()
        .runtime_id;
    let current_capsule = registry.get_for(&alice, &id).unwrap();
    let other_live = registry
        .register_system_runtime(
            Box::new(with_uplink(
                MockCapsule::new("system-service"),
                "other-view-platform",
            )),
            test_hash("system-other-live"),
            &bob,
        )
        .expect("a different system artifact can occupy another view");
    let other_capsule = registry.get_for(&bob, &id).unwrap();
    let unrelated = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("unrelated")),
            test_hash("unrelated-artifact"),
            &carol,
            uid(3),
        )
        .unwrap();
    let unrelated_capsule = registry.get_for(&carol, &other_id).unwrap();
    registry
        .register_uplink(
            &other_id,
            UplinkDescriptor::builder("unrelated-uplink", "notes").build(),
        )
        .unwrap();
    let newer = registry
        .reserve_runtime_id(
            id.clone(),
            test_hash("prepared-system-newer"),
            RuntimeScope::SystemResident,
        )
        .unwrap();
    let uplinks = uplink_names(&registry);
    let length = registry.len();
    let current_installed = Installed {
        principal: alice.clone(),
        id: id.clone(),
        runtime: current.clone(),
        capsule: Arc::clone(&current_capsule),
    };
    let unrelated_installed = Installed {
        principal: carol.clone(),
        id: other_id.clone(),
        runtime: unrelated.clone(),
        capsule: Arc::clone(&unrelated_capsule),
    };

    for (label, reservation) in [
        ("current generation", current.clone()),
        ("older reservation", retired),
        ("already live generation", other_live.clone()),
    ] {
        let error = registry
            .validate_system_runtime_replacement(
                &current,
                &MockCapsule::new("system-service"),
                &reservation,
            )
            .expect_err(label);
        assert!(
            error.to_string().contains("cannot replace"),
            "{label}: {error}"
        );
        let error = match registry.replace_system_runtime_reserved(
            &current,
            Box::new(MockCapsule::new("system-service")),
            reservation,
        ) {
            Ok(_) => panic!("{label} published a refused reservation"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("cannot replace"),
            "{label}: {error}"
        );
        assert_unchanged(
            &registry,
            &current_installed,
            &unrelated_installed,
            &uplinks,
        );
        assert_eq!(registry.len(), length);
        assert_eq!(
            registry.runtime_id_for(&bob, &id).as_ref(),
            Some(&other_live)
        );
        assert!(Arc::ptr_eq(
            &registry.get_for(&bob, &id).unwrap(),
            &other_capsule
        ));
        assert!(
            registry
                .cloned_runtimes()
                .iter()
                .all(|(runtime_id, _)| runtime_id != &newer)
        );
    }

    let published = registry
        .replace_system_runtime_reserved(
            &current,
            Box::new(with_uplink(
                MockCapsule::new("system-service"),
                "service-platform",
            )),
            newer.clone(),
        )
        .unwrap();
    assert_eq!(published.runtime_id, newer);
    assert_eq!(registry.runtime_id_for(&alice, &id), Some(newer));
    assert!(Arc::ptr_eq(&published.previous, &current_capsule));
    assert!(Arc::ptr_eq(
        &registry.get_for(&bob, &id).unwrap(),
        &other_capsule
    ));
    assert!(Arc::ptr_eq(
        &registry.get_for(&carol, &other_id).unwrap(),
        &unrelated_capsule
    ));
    assert!(
        uplink_names(&registry)
            .iter()
            .any(|name| name == "unrelated-uplink")
    );
    assert!(
        uplink_names(&registry)
            .iter()
            .any(|name| name == "service-platform")
    );
}
