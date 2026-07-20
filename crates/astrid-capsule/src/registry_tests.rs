//! Tests for [`crate::registry`]. Kept in a sibling file (referenced via
//! `#[path]`) so `registry.rs` stays under the per-file CI line cap while the
//! shared-by-hash instance model and its regression coverage grow.

use super::*;

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;

use crate::capsule::{CapsuleState, ReadyStatus};
use crate::context::CapsuleContext;
use crate::error::CapsuleResult;
use crate::manifest::{CapabilitiesDef, CapsuleManifest, PackageDef};

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).expect("valid principal")
}

fn test_hash(value: &str) -> WasmHash {
    WasmHash::from_raw(value)
}

struct MockCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
}

impl MockCapsule {
    fn new(name: &str) -> Self {
        Self {
            id: CapsuleId::from_static(name),
            manifest: CapsuleManifest {
                package: PackageDef {
                    name: name.to_string(),
                    version: "0.0.1".to_string(),
                    description: None,
                    authors: Vec::new(),
                    repository: None,
                    homepage: None,
                    documentation: None,
                    license: None,
                    license_file: None,
                    readme: None,
                    keywords: Vec::new(),
                    categories: Vec::new(),
                    astrid_version: None,
                    publish: None,
                    include: None,
                    exclude: None,
                    metadata: None,
                },
                components: Vec::new(),
                imports: std::collections::HashMap::new(),
                exports: std::collections::HashMap::new(),
                capabilities: CapabilitiesDef::default(),
                env: std::collections::HashMap::new(),
                context_files: Vec::new(),
                commands: Vec::new(),
                mcp_servers: Vec::new(),
                uplinks: Vec::new(),
                publishes: ::std::collections::HashMap::new(),
                subscribes: ::std::collections::HashMap::new(),
                tools: ::std::vec::Vec::new(),
            },
        }
    }
}

#[async_trait]
impl crate::capsule::Capsule for MockCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }
    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }
    fn state(&self) -> CapsuleState {
        CapsuleState::Ready
    }
    async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
        Ok(())
    }
    async fn unload(&mut self) -> CapsuleResult<()> {
        Ok(())
    }
    fn take_inbound_rx(
        &mut self,
    ) -> Option<tokio::sync::mpsc::Receiver<astrid_core::InboundMessage>> {
        None
    }
    async fn wait_ready(&self, _timeout: Duration) -> ReadyStatus {
        ReadyStatus::Ready
    }
    async fn invoke_interceptor(
        &self,
        _action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<crate::capsule::InterceptResult> {
        Ok(crate::capsule::InterceptResult::Continue(Vec::new()))
    }
    fn check_health(&self) -> CapsuleState {
        CapsuleState::Ready
    }
    fn source_dir(&self) -> Option<&Path> {
        None
    }
}

#[test]
fn unregister_not_found_returns_not_found_error() {
    let mut registry = CapsuleRegistry::new();
    let id = CapsuleId::from_static("nonexistent");
    match registry.unregister(&id) {
        Err(CapsuleError::NotFound(msg)) => {
            assert!(
                msg.contains("nonexistent"),
                "message should contain the id: {msg}"
            );
        },
        Err(other) => panic!("expected NotFound, got: {other:?}"),
        Ok(_) => panic!("expected error for nonexistent capsule"),
    }
}

#[test]
fn uuid_mapping_register_and_find() {
    let mut registry = CapsuleRegistry::new();
    let uuid = Uuid::new_v4();
    let hash = test_hash("hash-a");

    registry
        .register_for(
            Box::new(MockCapsule::new("test-capsule")),
            hash.clone(),
            &pid("alice"),
        )
        .expect("register");
    registry.register_uuid(uuid, CapsuleId::from_static("test-capsule"));
    registry.register_instance_uuid(uuid, hash);

    assert!(
        registry.find_instance_by_uuid(&uuid).is_some(),
        "uuid should resolve to the loaded capsule instance"
    );
    assert_eq!(
        registry
            .find_by_uuid(&uuid)
            .expect("legacy uuid mapped")
            .as_str(),
        "test-capsule"
    );
    assert!(registry.find_instance_by_uuid(&Uuid::new_v4()).is_none());
    assert_eq!(
        registry.source_id_for(&pid("alice"), &CapsuleId::from_static("test-capsule")),
        Some(uuid)
    );
    assert_eq!(
        registry.source_id_for(&pid("bob"), &CapsuleId::from_static("test-capsule")),
        None
    );
}

#[test]
fn uuid_mapping_overwrite_on_duplicate() {
    let mut registry = CapsuleRegistry::new();
    let uuid = Uuid::new_v4();
    let first = test_hash("first-hash");
    let second = test_hash("second-hash");

    registry
        .register_for(
            Box::new(MockCapsule::new("first")),
            first.clone(),
            &pid("alice"),
        )
        .expect("register first");
    registry
        .register_for(
            Box::new(MockCapsule::new("second")),
            second.clone(),
            &pid("alice"),
        )
        .expect("register second");
    registry.register_instance_uuid(uuid, first);
    registry.register_instance_uuid(uuid, second);
    assert_eq!(
        registry.source_id_for(&pid("alice"), &CapsuleId::from_static("first")),
        None,
        "remapping a source UUID must remove the stale reverse mapping"
    );
    assert_eq!(
        registry
            .find_instance_by_uuid(&uuid)
            .expect("uuid mapped")
            .id()
            .as_str(),
        "second"
    );
}

#[test]
fn uuid_mapping_cleanup_on_unregister() {
    let mut registry = CapsuleRegistry::new();
    let uuid = Uuid::new_v4();
    let capsule_id = CapsuleId::from_static("removable");
    let hash = test_hash("removable-hash");

    registry
        .register_for(
            Box::new(MockCapsule::new("removable")),
            hash.clone(),
            &pid("alice"),
        )
        .expect("register");
    registry.register_instance_uuid(uuid, hash);
    assert!(registry.find_instance_by_uuid(&uuid).is_some());

    registry
        .unregister_for(&pid("alice"), &capsule_id)
        .expect("unregister");
    assert!(registry.find_instance_by_uuid(&uuid).is_none());
    assert_eq!(registry.source_id_for(&pid("alice"), &capsule_id), None);
}

#[test]
fn uuid_mapping_cleanup_on_drain() {
    let mut registry = CapsuleRegistry::new();
    let uuid = Uuid::new_v4();
    let hash = test_hash("test-hash");
    registry
        .register_for(
            Box::new(MockCapsule::new("test")),
            hash.clone(),
            &pid("alice"),
        )
        .expect("register");
    registry.register_instance_uuid(uuid, hash);
    assert!(registry.find_instance_by_uuid(&uuid).is_some());

    let _ = registry.drain();
    assert!(registry.find_instance_by_uuid(&uuid).is_none());
    assert_eq!(
        registry.source_id_for(&pid("alice"), &CapsuleId::from_static("test")),
        None
    );
}

#[test]
fn same_hash_shared_across_principals_single_instance() {
    // INTENDED behaviour (#1069): two principals viewing the SAME content hash
    // share ONE runtime instance. The share is added via `register_existing`
    // (the production path), NOT a second `register_for` under a different owner
    // — which is now REJECTED so a shared instance can never be owned by a real
    // non-default principal whose load-time fields would be a cross-principal
    // fallback (#1069 host-state isolation).
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("same-wasm-hash");
    let id = CapsuleId::from_static("shared-capsule");
    let alice = pid("alice");
    let bob = pid("bob");

    registry
        .register_for(
            Box::new(MockCapsule::new("shared-capsule")),
            hash.clone(),
            &alice,
        )
        .expect("register alice");
    // A second `register_for` under a DIFFERENT owner is rejected: the guard
    // forces callers onto `register_existing` for cross-principal shares.
    let cross_owner = registry.register_for(
        Box::new(MockCapsule::new("shared-capsule")),
        hash.clone(),
        &bob,
    );
    assert!(
        cross_owner.is_err(),
        "register_for must reject sharing a hash already owned by a different principal"
    );
    // Bob shares the SAME runtime via the production view-add path, no rebuild.
    registry
        .register_existing(&id, &hash, &bob)
        .expect("register bob's view");

    let alice_capsule = registry.get_for(&alice, &id).expect("alice sees capsule");
    let bob_capsule = registry.get_for(&bob, &id).expect("bob sees capsule");
    assert!(
        Arc::ptr_eq(&alice_capsule, &bob_capsule),
        "same content hash must resolve to ONE shared runtime for both principals"
    );

    // Exactly one runtime instance; both principals hold a view of it.
    assert_eq!(
        registry.len(),
        1,
        "N principals on one hash = one runtime instance"
    );
    assert_eq!(registry.refcount_for_hash(&hash), Some(2));

    // The view snapshot expands the single instance to one pair per
    // viewing principal.
    let mut views: Vec<_> = registry
        .cloned_values_with_principal()
        .into_iter()
        .map(|(principal, capsule)| (principal.to_string(), capsule.id().to_string()))
        .collect();
    views.sort();
    assert_eq!(
        views,
        vec![
            ("alice".to_string(), "shared-capsule".to_string()),
            ("bob".to_string(), "shared-capsule".to_string()),
        ]
    );
}

#[test]
fn different_hashes_are_distinct_instances() {
    // Guard the other half of the invariant: distinct content hashes never
    // collapse into one runtime, even for the same capsule id / principal.
    let mut registry = CapsuleRegistry::new();
    let alice = pid("alice");
    let h1 = test_hash("hash-one");
    let h2 = test_hash("hash-two");

    registry
        .register_for(Box::new(MockCapsule::new("cap-a")), h1.clone(), &alice)
        .expect("register cap-a");
    registry
        .register_for(Box::new(MockCapsule::new("cap-b")), h2.clone(), &alice)
        .expect("register cap-b");

    assert_eq!(registry.len(), 2, "distinct hashes = distinct instances");
    assert_eq!(registry.refcount_for_hash(&h1), Some(1));
    assert_eq!(registry.refcount_for_hash(&h2), Some(1));
}

#[test]
fn adding_view_via_register_existing_does_not_build_second_instance() {
    // Lean single-build regression: loading a hash for A then adding it to
    // B's view goes through `contains_hash` / `register_existing` and does
    // NOT construct a second runtime.
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("lean-hash");
    let id = CapsuleId::from_static("lean-capsule");
    let alice = pid("alice");
    let bob = pid("bob");

    registry
        .register_for(
            Box::new(MockCapsule::new("lean-capsule")),
            hash.clone(),
            &alice,
        )
        .expect("register alice");
    assert!(registry.contains_hash(&hash));
    assert_eq!(registry.len(), 1);

    // Simulate the kernel's dedup branch: hash already loaded, so only a
    // view is added — no capsule runtime is constructed for bob.
    registry
        .register_existing(&id, &hash, &bob)
        .expect("add bob's view");

    assert_eq!(
        registry.len(),
        1,
        "register_existing must not build a second runtime"
    );
    assert_eq!(registry.refcount_for_hash(&hash), Some(2));
    let a = registry.get_for(&alice, &id).expect("alice");
    let b = registry.get_for(&bob, &id).expect("bob");
    assert!(Arc::ptr_eq(&a, &b), "both views share one Arc");
}

#[test]
fn register_existing_missing_hash_is_not_found() {
    let mut registry = CapsuleRegistry::new();
    let id = CapsuleId::from_static("absent");
    match registry.register_existing(&id, &test_hash("nope"), &pid("alice")) {
        Err(CapsuleError::NotFound(_)) => {},
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn unregister_one_principal_retains_shared_instance() {
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("same-wasm-hash");
    let id = CapsuleId::from_static("shared-capsule");
    let alice = pid("alice");
    let bob = pid("bob");

    registry
        .register_for(
            Box::new(MockCapsule::new("shared-capsule")),
            hash.clone(),
            &alice,
        )
        .expect("register alice");
    registry
        .register_existing(&id, &hash, &bob)
        .expect("register bob's view");

    let removed = registry
        .unregister_for(&alice, &id)
        .expect("alice unregister");
    assert_eq!(removed.capsule.id().as_str(), "shared-capsule");
    assert!(
        !removed.torn_down,
        "shared runtime must NOT be torn down while bob still references it"
    );
    assert!(
        registry.get_for(&alice, &id).is_none(),
        "alice's view no longer contains the capsule"
    );
    assert!(
        registry.get_for(&bob, &id).is_some(),
        "bob's view still references the shared runtime instance"
    );
    // The shared runtime is retained while bob still references it.
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.refcount_for_hash(&hash), Some(1));
}

#[test]
fn shared_instance_torn_down_only_when_last_view_releases() {
    // Refcount lifecycle regression: the shared runtime survives until the
    // LAST principal view releases it, then is fully removed.
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("lifecycle-hash");
    let id = CapsuleId::from_static("lifecycle-capsule");
    let alice = pid("alice");
    let bob = pid("bob");

    registry
        .register_for(
            Box::new(MockCapsule::new("lifecycle-capsule")),
            hash.clone(),
            &alice,
        )
        .expect("register alice");
    registry
        .register_existing(&id, &hash, &bob)
        .expect("add bob's view");
    assert_eq!(registry.refcount_for_hash(&hash), Some(2));

    // First release: instance alive, refcount drops, NOT torn down.
    let first = registry.unregister_for(&alice, &id).expect("alice release");
    assert!(!first.torn_down, "not the last view → runtime retained");
    assert!(registry.contains_hash(&hash), "still alive for bob");
    assert_eq!(registry.refcount_for_hash(&hash), Some(1));

    // Last release: instance torn down.
    let last = registry.unregister_for(&bob, &id).expect("bob release");
    assert!(last.torn_down, "last view released → runtime torn down");
    assert!(
        !registry.contains_hash(&hash),
        "last view released → runtime torn down"
    );
    assert_eq!(registry.refcount_for_hash(&hash), None);
    assert_eq!(registry.len(), 0);
    assert!(registry.is_empty());
}

#[test]
fn principals_viewing_returns_all_views_of_shared_runtime() {
    // Bleed #4 mechanism: `restart_capsule` rebuilds EVERY view of a shared
    // failed runtime, and it discovers those views via `principals_viewing`.
    // Pin that it returns all N viewing principals (not just one).
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("multi-view-hash");
    let id = CapsuleId::from_static("multi-view");
    let alice = pid("alice");
    let bob = pid("bob");
    let carol = pid("carol");

    registry
        .register_for(
            Box::new(MockCapsule::new("multi-view")),
            hash.clone(),
            &alice,
        )
        .expect("register alice");
    registry
        .register_existing(&id, &hash, &bob)
        .expect("bob view");
    registry
        .register_existing(&id, &hash, &carol)
        .expect("carol view");

    let mut viewing: Vec<String> = registry
        .principals_viewing(&id)
        .into_iter()
        .map(|p| p.to_string())
        .collect();
    viewing.sort();
    assert_eq!(
        viewing,
        vec!["alice".to_string(), "bob".to_string(), "carol".to_string()],
        "principals_viewing must return every view of the shared runtime"
    );

    // An absent capsule has no viewers.
    assert!(
        registry
            .principals_viewing(&CapsuleId::from_static("absent"))
            .is_empty()
    );
}

#[test]
fn hash_for_and_principals_viewing_hash_separate_two_versions_of_one_id() {
    // One capsule id can be loaded at TWO distinct content hashes at once
    // (per-principal installs of different versions). `hash_for` must resolve the
    // SPECIFIC hash each principal views, and `principals_viewing_hash` must
    // partition viewers by hash so a per-`(id, hash)` restart only rebuilds the
    // views of the failed hash — never a viewer of the other, healthy version.
    let mut registry = CapsuleRegistry::new();
    let id = CapsuleId::from_static("two-versions");
    let hash_v1 = test_hash("two-versions-v1");
    let hash_v2 = test_hash("two-versions-v2");
    let default_p = PrincipalId::default();
    let alice = pid("alice");
    let bob = pid("bob");

    // default + bob on v1; alice on v2.
    registry
        .register_owned_by_default(
            Box::new(MockCapsule::new("two-versions")),
            hash_v1.clone(),
            &default_p,
        )
        .expect("register default v1");
    registry
        .register_existing(&id, &hash_v1, &bob)
        .expect("bob v1 view");
    registry
        .register_owned_by_default(
            Box::new(MockCapsule::new("two-versions")),
            hash_v2.clone(),
            &alice,
        )
        .expect("register alice v2");

    // hash_for resolves each principal's specific version.
    assert_eq!(registry.hash_for(&default_p, &id), Some(hash_v1.clone()));
    assert_eq!(registry.hash_for(&bob, &id), Some(hash_v1.clone()));
    assert_eq!(registry.hash_for(&alice, &id), Some(hash_v2.clone()));
    assert_eq!(registry.hash_for(&pid("nobody"), &id), None);

    // principals_viewing_hash partitions viewers by hash.
    let mut v1_viewers: Vec<String> = registry
        .principals_viewing_hash(&id, &hash_v1)
        .into_iter()
        .map(|p| p.to_string())
        .collect();
    v1_viewers.sort();
    assert_eq!(
        v1_viewers,
        vec!["bob".to_string(), "default".to_string()],
        "only v1 viewers, not alice on v2"
    );
    assert_eq!(
        registry
            .principals_viewing_hash(&id, &hash_v2)
            .into_iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>(),
        vec!["alice".to_string()],
        "only the v2 viewer"
    );

    // Two distinct runtimes are actually loaded.
    assert_eq!(
        registry.len(),
        2,
        "two distinct hashes → two runtime instances"
    );
}
