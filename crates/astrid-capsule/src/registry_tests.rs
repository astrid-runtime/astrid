//! Tests for [`crate::registry`]. Kept in a sibling file (referenced via
//! `#[path]`) so `registry.rs` stays under the per-file CI line cap while the
//! authority-scoped runtime model and its regression coverage grow.

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

fn uid(byte: u8) -> PrincipalUid {
    PrincipalUid::from_bytes([byte; 32])
}

#[test]
fn identical_artifact_has_distinct_principal_runtime_generations() {
    let mut registry = CapsuleRegistry::new();
    let artifact = test_hash("same-verified-bytes");
    let alice = pid("alice");
    let bob = pid("bob");

    let alice_runtime = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("isolated")),
            artifact.clone(),
            &alice,
            uid(1),
        )
        .unwrap();
    let bob_runtime = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("isolated")),
            artifact,
            &bob,
            uid(2),
        )
        .unwrap();

    assert_ne!(alice_runtime, bob_runtime);
    assert_ne!(alice_runtime.key().scope(), bob_runtime.key().scope());
    assert!(!Arc::ptr_eq(
        &registry
            .get_for(&alice, &CapsuleId::from_static("isolated"))
            .unwrap(),
        &registry
            .get_for(&bob, &CapsuleId::from_static("isolated"))
            .unwrap(),
    ));
}

#[test]
fn recreated_alias_cannot_inherit_old_runtime_generation() {
    let mut registry = CapsuleRegistry::new();
    let alias = pid("alice");
    let id = CapsuleId::from_static("isolated");
    let artifact = test_hash("same-verified-bytes");
    let old = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("isolated")),
            artifact.clone(),
            &alias,
            uid(1),
        )
        .unwrap();
    let old_source = registry.source_id_for(&alias, &id).unwrap();
    let removed = registry.unregister_for(&alias, &id).unwrap();
    assert!(removed.torn_down);
    let new = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("isolated")),
            artifact,
            &alias,
            uid(9),
        )
        .unwrap();
    let new_source = registry.source_id_for(&alias, &id).unwrap();

    assert_ne!(old.key().scope(), new.key().scope());
    assert!(new.generation() > old.generation());
    assert_eq!(
        old_source, new_source,
        "wire source format stays compatible"
    );
    let current = registry
        .find_instance_by_uuid_for(&alias, &old_source)
        .expect("source resolves current generation");
    assert!(!Arc::ptr_eq(&removed.capsule, &current));
}

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

    let removed = registry.unregister_for(&owner, &id).unwrap();
    assert!(removed.torn_down);
    assert!(registry.get_for(&alice, &id).is_none());
    assert!(registry.get_for(&bob, &id).is_none());
    assert!(registry.is_empty());
}

#[test]
fn artifact_replacement_removes_retired_public_source_identity() {
    let mut registry = CapsuleRegistry::new();
    let alice = pid("alice");
    let id = CapsuleId::from_static("replace-source");
    let old = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("replace-source")),
            test_hash("old-artifact"),
            &alice,
            uid(1),
        )
        .unwrap();
    let old_source = registry.source_id_for(&alice, &id).unwrap();

    registry
        .replace_principal_runtime(
            &old,
            Box::new(MockCapsule::new("replace-source")),
            test_hash("new-artifact"),
            &alice,
            uid(1),
        )
        .unwrap();

    assert!(registry.find_by_uuid(&old_source).is_none());
    assert!(
        registry
            .find_instance_by_uuid_for(&alice, &old_source)
            .is_none()
    );
}

#[test]
fn only_explicit_system_runtime_may_share_views() {
    let mut registry = CapsuleRegistry::new();
    let artifact = test_hash("system-artifact");
    let alice = pid("alice");
    let bob = pid("bob");
    registry
        .register_system_runtime(
            Box::new(MockCapsule::new("service")),
            artifact.clone(),
            &alice,
        )
        .unwrap();
    registry
        .register_existing(&CapsuleId::from_static("service"), &artifact, &bob)
        .unwrap();

    assert!(Arc::ptr_eq(
        &registry
            .get_for(&alice, &CapsuleId::from_static("service"))
            .unwrap(),
        &registry
            .get_for(&bob, &CapsuleId::from_static("service"))
            .unwrap(),
    ));
}

#[test]
fn default_owned_compatibility_wrapper_retains_requested_view() {
    let mut registry = CapsuleRegistry::new();
    let alice = pid("alice");
    let id = CapsuleId::from_static("service");
    registry
        .register_owned_by_default(
            Box::new(MockCapsule::new("service")),
            test_hash("system-artifact"),
            &alice,
        )
        .unwrap();

    assert!(registry.get_for(&alice, &id).is_some());
    assert!(registry.get_for(&PrincipalId::default(), &id).is_none());
    assert!(registry.unregister_for(&alice, &id).unwrap().torn_down);
    assert!(registry.is_empty());
}

#[test]
fn default_owned_wrapper_rejects_matching_non_default_system_owner() {
    let mut registry = CapsuleRegistry::new();
    let artifact = test_hash("system-artifact");
    let alice = pid("alice");
    let bob = pid("bob");
    registry
        .register_system_runtime(
            Box::new(MockCapsule::new("service")),
            artifact.clone(),
            &alice,
        )
        .unwrap();

    let error = registry
        .register_owned_by_default(Box::new(MockCapsule::new("service")), artifact, &bob)
        .unwrap_err();

    assert!(error.to_string().contains("non-default system owner"));
    assert!(
        registry
            .get_for(&bob, &CapsuleId::from_static("service"))
            .is_none()
    );
}

#[test]
fn principal_generation_replacement_is_atomic_and_stale_safe() {
    let mut registry = CapsuleRegistry::new();
    let alice = pid("alice");
    let id = CapsuleId::from_static("replaceable");
    let old = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("replaceable")),
            test_hash("old"),
            &alice,
            uid(1),
        )
        .unwrap();
    let source = registry.source_id_for(&alice, &id).unwrap();
    let old_arc = registry.get_for(&alice, &id).unwrap();

    let replaced = registry
        .replace_principal_runtime(
            &old,
            Box::new(MockCapsule::new("replaceable")),
            test_hash("new"),
            &alice,
            uid(1),
        )
        .unwrap();

    assert!(replaced.runtime_id.generation() > old.generation());
    assert_eq!(
        registry.runtime_id_for(&alice, &id),
        Some(replaced.runtime_id)
    );
    assert!(Arc::ptr_eq(&replaced.previous, &old_arc));
    assert!(!Arc::ptr_eq(
        &old_arc,
        &registry.get_for(&alice, &id).unwrap()
    ));
    assert!(
        registry
            .find_instance_by_uuid_for(&alice, &source)
            .is_none(),
        "a source id for old bytes must not resolve the replacement"
    );
}

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
                skills: Vec::new(),
                uplinks: Vec::new(),
                publishes: ::std::collections::HashMap::new(),
                subscribes: ::std::collections::HashMap::new(),
                tools: ::std::vec::Vec::new(),
            },
        }
    }

    fn with_uplink_capability(mut self) -> Self {
        self.manifest.capabilities.uplink = true;
        self
    }
}

#[test]
fn uplink_host_capability_does_not_require_system_runtime_scope() {
    let mut registry = CapsuleRegistry::new();
    let alice = pid("alice");
    let bob = pid("bob");
    let id = CapsuleId::from_static("uplink-client");
    let artifact = test_hash("uplink-client-artifact");

    let alice_runtime = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("uplink-client").with_uplink_capability()),
            artifact.clone(),
            &alice,
            uid(1),
        )
        .expect("uplink host access is an ordinary capability grant");
    let bob_runtime = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("uplink-client").with_uplink_capability()),
            artifact,
            &bob,
            uid(2),
        )
        .expect("each principal gets an isolated uplink-capable daemon");

    assert_eq!(alice_runtime.key().scope(), RuntimeScope::Principal(uid(1)));
    assert_eq!(bob_runtime.key().scope(), RuntimeScope::Principal(uid(2)));
    assert_ne!(alice_runtime, bob_runtime);
    assert!(registry.get_for(&alice, &id).is_some());
    assert!(registry.get_for(&bob, &id).is_some());
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
    let hash = test_hash("hash-a");

    registry
        .register_for(
            Box::new(MockCapsule::new("test-capsule")),
            hash.clone(),
            &pid("alice"),
        )
        .expect("register");
    let uuid = registry
        .source_id_for(&pid("alice"), &CapsuleId::from_static("test-capsule"))
        .expect("runtime source id");
    registry.register_uuid(uuid, CapsuleId::from_static("test-capsule"));

    assert!(
        registry
            .find_instance_by_uuid_for(&pid("alice"), &uuid)
            .is_some(),
        "uuid should resolve within the owning principal view"
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
    let artifact = test_hash("same-artifact");
    let alice = pid("alice");
    let bob = pid("bob");

    registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("isolated")),
            artifact.clone(),
            &alice,
            uid(1),
        )
        .expect("register alice");
    registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("isolated")),
            artifact,
            &bob,
            uid(2),
        )
        .expect("register bob");
    let alice_uuid = registry
        .source_id_for(&alice, &CapsuleId::from_static("isolated"))
        .expect("alice source id");
    let bob_uuid = registry
        .source_id_for(&bob, &CapsuleId::from_static("isolated"))
        .expect("bob source id");
    assert_eq!(
        alice_uuid, bob_uuid,
        "wire identity remains artifact-derived"
    );
    assert!(
        registry
            .find_instance_by_uuid_for(&alice, &alice_uuid)
            .is_some()
    );
    assert!(
        registry
            .find_instance_by_uuid_for(&bob, &bob_uuid)
            .is_some()
    );
    assert!(
        registry.find_instance_by_uuid(&alice_uuid).is_none(),
        "unscoped lookup fails closed across distinct principal runtimes"
    );
}

#[test]
fn uuid_mapping_cleanup_on_unregister() {
    let mut registry = CapsuleRegistry::new();
    let capsule_id = CapsuleId::from_static("removable");
    let hash = test_hash("removable-hash");

    registry
        .register_for(
            Box::new(MockCapsule::new("removable")),
            hash.clone(),
            &pid("alice"),
        )
        .expect("register");
    let uuid = registry
        .source_id_for(&pid("alice"), &capsule_id)
        .expect("runtime source id");
    assert!(
        registry
            .find_instance_by_uuid_for(&pid("alice"), &uuid)
            .is_some()
    );

    registry
        .unregister_for(&pid("alice"), &capsule_id)
        .expect("unregister");
    assert!(registry.find_instance_by_uuid(&uuid).is_none());
    assert_eq!(registry.source_id_for(&pid("alice"), &capsule_id), None);
}

#[test]
fn legacy_artifact_uuid_resolves_within_each_principal_view() {
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("legacy-shared-hash");
    let legacy_uuid = Uuid::new_v4();
    let alice = pid("alice");
    let bob = pid("bob");

    registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("legacy")),
            hash.clone(),
            &alice,
            uid(1),
        )
        .expect("register alice");
    registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("legacy")),
            hash.clone(),
            &bob,
            uid(2),
        )
        .expect("register bob");
    registry.register_instance_uuid(legacy_uuid, hash);

    assert!(
        registry
            .find_instance_by_uuid_for(&alice, &legacy_uuid)
            .is_some()
    );
    assert!(
        registry
            .find_instance_by_uuid_for(&bob, &legacy_uuid)
            .is_some()
    );
    assert!(
        registry.find_instance_by_uuid(&legacy_uuid).is_none(),
        "unscoped legacy lookup must not choose between authority runtimes"
    );
}

#[test]
fn legacy_artifact_uuid_is_retained_until_last_runtime_leaves() {
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("legacy-lifecycle-hash");
    let legacy_uuid = Uuid::new_v4();
    let id = CapsuleId::from_static("legacy-lifecycle");
    let alice = pid("alice");
    let bob = pid("bob");

    registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("legacy-lifecycle")),
            hash.clone(),
            &alice,
            uid(1),
        )
        .expect("register alice");
    registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("legacy-lifecycle")),
            hash.clone(),
            &bob,
            uid(2),
        )
        .expect("register bob");
    registry.register_instance_uuid(legacy_uuid, hash);

    registry.unregister_for(&alice, &id).expect("remove alice");
    assert!(
        registry.find_instance_by_uuid(&legacy_uuid).is_some(),
        "the sole remaining runtime is unambiguous"
    );
    assert!(
        registry
            .find_instance_by_uuid_for(&bob, &legacy_uuid)
            .is_some()
    );

    registry.unregister_for(&bob, &id).expect("remove bob");
    assert!(registry.find_instance_by_uuid(&legacy_uuid).is_none());
}

#[test]
fn uuid_mapping_cleanup_on_drain() {
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("test-hash");
    registry
        .register_for(
            Box::new(MockCapsule::new("test")),
            hash.clone(),
            &pid("alice"),
        )
        .expect("register");
    let uuid = registry
        .source_id_for(&pid("alice"), &CapsuleId::from_static("test"))
        .expect("runtime source id");
    assert!(
        registry
            .find_instance_by_uuid_for(&pid("alice"), &uuid)
            .is_some()
    );

    let _ = registry.drain();
    assert!(registry.find_instance_by_uuid(&uuid).is_none());
    assert_eq!(
        registry.source_id_for(&pid("alice"), &CapsuleId::from_static("test")),
        None
    );
}

#[test]
fn same_hash_creates_one_runtime_per_principal() {
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("same-wasm-hash");
    let id = CapsuleId::from_static("shared-capsule");
    let alice = pid("alice");
    let bob = pid("bob");

    let alice_runtime = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("shared-capsule")),
            hash.clone(),
            &alice,
            uid(1),
        )
        .expect("register alice");
    let bob_runtime = registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("shared-capsule")),
            hash.clone(),
            &bob,
            uid(2),
        )
        .expect("register bob");

    let alice_capsule = registry.get_for(&alice, &id).expect("alice sees capsule");
    let bob_capsule = registry.get_for(&bob, &id).expect("bob sees capsule");
    assert!(!Arc::ptr_eq(&alice_capsule, &bob_capsule));
    assert_ne!(alice_runtime, bob_runtime);
    assert_eq!(registry.len(), 2);
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
fn register_existing_rejects_principal_runtime_sharing() {
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

    assert!(registry.register_existing(&id, &hash, &bob).is_err());
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.refcount_for_hash(&hash), Some(1));
    assert!(registry.get_for(&alice, &id).is_some());
    assert!(registry.get_for(&bob, &id).is_none());
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
fn unregister_one_principal_does_not_touch_peer_runtime() {
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("same-wasm-hash");
    let id = CapsuleId::from_static("shared-capsule");
    let alice = pid("alice");
    let bob = pid("bob");

    registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("shared-capsule")),
            hash.clone(),
            &alice,
            uid(1),
        )
        .expect("register alice");
    registry
        .register_principal_runtime(
            Box::new(MockCapsule::new("shared-capsule")),
            hash.clone(),
            &bob,
            uid(2),
        )
        .expect("register bob");
    let peer_source = registry.source_id_for(&bob, &id).unwrap();

    let removed = registry
        .unregister_for(&alice, &id)
        .expect("alice unregister");
    assert_eq!(removed.capsule.id().as_str(), "shared-capsule");
    assert!(removed.torn_down);
    assert!(
        registry.get_for(&alice, &id).is_none(),
        "alice's view no longer contains the capsule"
    );
    assert!(
        registry.get_for(&bob, &id).is_some(),
        "bob's independent runtime remains registered"
    );
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.refcount_for_hash(&hash), Some(1));
    assert_eq!(
        registry.find_by_uuid(&peer_source),
        Some(&id),
        "removing Alice must retain Bob's compatible public source mapping"
    );
}

#[test]
fn system_instance_torn_down_only_when_last_view_releases() {
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("lifecycle-hash");
    let id = CapsuleId::from_static("lifecycle-capsule");
    let alice = pid("alice");
    let bob = pid("bob");

    registry
        .register_system_runtime(
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
    let first = registry.unregister_for(&bob, &id).expect("bob release");
    assert!(!first.torn_down, "not the last view → runtime retained");
    assert!(registry.contains_hash(&hash), "still alive for owner alice");
    assert_eq!(registry.refcount_for_hash(&hash), Some(1));

    // Last release: instance torn down.
    let last = registry.unregister_for(&alice, &id).expect("alice release");
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
fn principals_viewing_returns_all_views_of_system_runtime() {
    let mut registry = CapsuleRegistry::new();
    let hash = test_hash("multi-view-hash");
    let id = CapsuleId::from_static("multi-view");
    let alice = pid("alice");
    let bob = pid("bob");
    let carol = pid("carol");

    registry
        .register_system_runtime(
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
        "principals_viewing must return every view of the system runtime"
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
        .register_system_runtime(
            Box::new(MockCapsule::new("two-versions")),
            hash_v1.clone(),
            &default_p,
        )
        .expect("register default v1");
    registry
        .register_existing(&id, &hash_v1, &bob)
        .expect("bob v1 view");
    registry
        .register_system_runtime(
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
