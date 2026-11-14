use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use astrid_capsule::capsule::{Capsule, CapsuleState};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::error::{CapsuleError, CapsuleResult};
use astrid_capsule::registry::WasmHash;
use astrid_capsule_types::CapsuleId;
use astrid_capsule_types::manifest::CapsuleManifest;
use astrid_core::PrincipalId;

use super::test_kernel_with_home;

fn scratch_home() -> (tempfile::TempDir, astrid_core::dirs::AstridHome) {
    let dir = tempfile::tempdir().expect("scratch directory");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path().join(".astrid"));
    (dir, home)
}

struct InventoryProbeCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
    describe_calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Capsule for InventoryProbeCapsule {
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

    async fn invoke_interceptor(
        &self,
        action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<astrid_capsule::capsule::InterceptResult> {
        assert_eq!(action, "tool_describe");
        self.describe_calls.fetch_add(1, Ordering::Relaxed);
        Err(CapsuleError::NotSupported(
            "inventory probe has no tools".to_string(),
        ))
    }
}

#[tokio::test]
async fn targeted_capsule_inventory_describes_only_the_selected_principal() {
    const FLEET_SIZE: usize = 612;

    let (_d, home) = scratch_home();
    let kernel = test_kernel_with_home(home).await;
    let target = PrincipalId::new("fleet-73").unwrap();
    let mut counters = Vec::with_capacity(FLEET_SIZE);
    let expected_source_id;

    {
        let mut registry = kernel.capsules.write().await;
        for index in 0..FLEET_SIZE {
            let principal = PrincipalId::new(format!("fleet-{index}")).unwrap();
            let id = CapsuleId::new(format!("inventory-probe-{index}")).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            registry
                .register_for(
                    Box::new(InventoryProbeCapsule {
                        id,
                        manifest: CapsuleManifest::default(),
                        describe_calls: Arc::clone(&calls),
                    }),
                    WasmHash::from_raw(format!("inventory-hash-{index}")),
                    &principal,
                )
                .unwrap();
            counters.push(calls);
        }
        expected_source_id = registry
            .source_id_for(
                &target,
                &CapsuleId::new("inventory-probe-73").expect("target capsule id"),
            )
            .expect("registered capsule has a live source identity")
            .to_string();
    }

    let mut events = kernel
        .event_bus
        .subscribe_topic("astrid.v1.capsules_loaded");
    kernel.publish_capsules_loaded_for(&target).await;

    assert_eq!(
        counters
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .sum::<usize>(),
        1,
        "one principal mutation must not probe every capsule in the fleet"
    );
    assert_eq!(counters[73].load(Ordering::Relaxed), 1);

    let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
        .await
        .expect("target inventory event")
        .expect("event bus remains open");
    let astrid_events::AstridEvent::Ipc { message, .. } = event.as_ref() else {
        panic!("capsule inventory must be an IPC event");
    };
    assert_eq!(message.principal.as_deref(), Some(target.as_str()));
    let astrid_events::ipc::IpcPayload::RawJson(payload) = &message.payload else {
        panic!("capsule inventory must carry raw JSON");
    };
    let capsules = payload["capsules"].as_array().expect("capsule inventory");
    assert_eq!(capsules.len(), 1);
    assert_eq!(capsules[0]["name"], "inventory-probe-73");
    assert_eq!(capsules[0]["source_id"], expected_source_id);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), events.recv())
            .await
            .is_err(),
        "targeted refresh must emit exactly one principal inventory"
    );

    let absent = PrincipalId::new("fleet-absent").unwrap();
    kernel.publish_capsules_loaded_for(&absent).await;
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
        .await
        .expect("empty target inventory event")
        .expect("event bus remains open");
    let astrid_events::AstridEvent::Ipc { message, .. } = event.as_ref() else {
        panic!("capsule inventory must be an IPC event");
    };
    assert_eq!(message.principal.as_deref(), Some(absent.as_str()));
    let astrid_events::ipc::IpcPayload::RawJson(payload) = &message.payload else {
        panic!("capsule inventory must carry raw JSON");
    };
    assert_eq!(payload["capsules"], serde_json::json!([]));
    assert_eq!(
        counters
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .sum::<usize>(),
        1,
        "an empty target view must publish without probing fleet peers"
    );
}

#[tokio::test]
async fn global_capsule_inventory_still_describes_every_principal_view() {
    let (_d, home) = scratch_home();
    let kernel = test_kernel_with_home(home).await;
    let mut counters = Vec::new();

    {
        let mut registry = kernel.capsules.write().await;
        for index in 0..3 {
            let principal = PrincipalId::new(format!("global-{index}")).unwrap();
            let id = CapsuleId::new(format!("global-probe-{index}")).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            registry
                .register_for(
                    Box::new(InventoryProbeCapsule {
                        id,
                        manifest: CapsuleManifest::default(),
                        describe_calls: Arc::clone(&calls),
                    }),
                    WasmHash::from_raw(format!("global-hash-{index}")),
                    &principal,
                )
                .unwrap();
            counters.push(calls);
        }
    }

    kernel.publish_capsules_loaded().await;

    assert!(
        counters
            .iter()
            .all(|counter| counter.load(Ordering::Relaxed) == 1),
        "a genuine global refresh must retain every-principal behavior"
    );
}

#[tokio::test]
async fn capsule_unload_refreshes_only_the_affected_principal() {
    for retain_another_capsule in [false, true] {
        let (_directory, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let affected = PrincipalId::new("unload-target").unwrap();
        let peer = PrincipalId::new("unload-peer").unwrap();
        let removed_id = CapsuleId::new("removed-probe").unwrap();
        let mut counters = Vec::new();
        {
            let mut registry = kernel.capsules.write().await;
            let views = [(&affected, "removed-probe"), (&peer, "peer-probe")]
                .into_iter()
                .chain(retain_another_capsule.then_some((&affected, "remaining-probe")));
            for (principal, name) in views {
                let calls = Arc::new(AtomicUsize::new(0));
                registry
                    .register_for(
                        Box::new(InventoryProbeCapsule {
                            id: CapsuleId::new(name).unwrap(),
                            manifest: CapsuleManifest::default(),
                            describe_calls: Arc::clone(&calls),
                        }),
                        WasmHash::from_raw(format!("unload-hash-{name}")),
                        principal,
                    )
                    .unwrap();
                counters.push((name, calls));
            }
        }
        let mut events = kernel
            .event_bus
            .subscribe_topic("astrid.v1.capsules_loaded");
        assert!(
            kernel
                .unload_one_capsule(&removed_id, &affected)
                .await
                .unwrap()
        );
        for (name, calls) in counters {
            assert_eq!(
                calls.load(Ordering::Relaxed),
                usize::from(name == "remaining-probe"),
                "unload must describe only the affected principal's remaining capsules: {name}"
            );
        }
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .expect("affected principal inventory")
            .expect("event bus remains open");
        let astrid_events::AstridEvent::Ipc { message, .. } = event.as_ref() else {
            panic!("capsule inventory must be an IPC event");
        };
        assert_eq!(message.principal.as_deref(), Some(affected.as_str()));
        let astrid_events::ipc::IpcPayload::RawJson(payload) = &message.payload else {
            panic!("capsule inventory must carry raw JSON");
        };
        let capsules = payload["capsules"].as_array().expect("capsule inventory");
        assert_eq!(capsules.len(), usize::from(retain_another_capsule));
        if retain_another_capsule {
            assert_eq!(capsules[0]["name"], "remaining-probe");
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), events.recv())
                .await
                .is_err(),
            "one unload must publish exactly one affected-principal inventory"
        );
        let registry = kernel.capsules.read().await;
        assert_eq!(registry.cloned_values_for(&peer).len(), 1);
        assert_eq!(
            registry.cloned_values_for(&affected).len(),
            usize::from(retain_another_capsule)
        );
    }
}

fn inventory_probe(id: CapsuleId, calls: &Arc<AtomicUsize>) -> Box<dyn Capsule> {
    Box::new(InventoryProbeCapsule {
        id,
        manifest: CapsuleManifest::default(),
        describe_calls: Arc::clone(calls),
    })
}

#[tokio::test]
async fn system_owner_unload_refreshes_every_detached_view_without_probing_peers() {
    for retain_dependent_capsule in [false, true] {
        let (_directory, home) = scratch_home();
        let kernel = test_kernel_with_home(home).await;
        let owner = PrincipalId::default();
        let dependent = PrincipalId::new("system-dependent").unwrap();
        let unrelated = PrincipalId::new("system-unrelated").unwrap();
        let shared_id = CapsuleId::new("shared-probe").unwrap();
        let kept_id = CapsuleId::new("dependent-kept").unwrap();
        let artifact = WasmHash::from_raw("shared-probe-bytes".to_owned());
        let shared_calls = Arc::new(AtomicUsize::new(0));
        let kept_calls = Arc::new(AtomicUsize::new(0));
        let unrelated_calls = Arc::new(AtomicUsize::new(0));
        {
            let mut registry = kernel.capsules.write().await;
            registry
                .register_system_runtime(
                    inventory_probe(shared_id.clone(), &shared_calls),
                    artifact.clone(),
                    &owner,
                )
                .unwrap();
            registry
                .register_existing(&shared_id, &artifact, &dependent)
                .unwrap();
            if retain_dependent_capsule {
                registry
                    .register_for(
                        inventory_probe(kept_id.clone(), &kept_calls),
                        WasmHash::from_raw("dependent-kept-bytes".to_owned()),
                        &dependent,
                    )
                    .unwrap();
            }
            // The same id and bytes do not make a principal runtime dependent
            // on the explicit System runtime's lifetime.
            registry
                .register_for(
                    inventory_probe(shared_id.clone(), &unrelated_calls),
                    artifact,
                    &unrelated,
                )
                .unwrap();
        }
        let mut events = kernel
            .event_bus
            .subscribe_topic("astrid.v1.capsules_loaded");
        assert!(kernel.unload_one_capsule(&shared_id, &owner).await.unwrap());
        assert_eq!(shared_calls.load(Ordering::Relaxed), 0);
        assert_eq!(unrelated_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            kept_calls.load(Ordering::Relaxed),
            usize::from(retain_dependent_capsule)
        );
        let mut snapshots = std::collections::HashMap::new();
        for _ in 0..2 {
            let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
                .await
                .expect("every detached view receives an inventory")
                .expect("event bus remains open");
            let astrid_events::AstridEvent::Ipc { message, .. } = event.as_ref() else {
                panic!("capsule inventory must be an IPC event");
            };
            let astrid_events::ipc::IpcPayload::RawJson(payload) = &message.payload else {
                panic!("capsule inventory must carry raw JSON");
            };
            let principal = PrincipalId::new(message.principal.as_deref().unwrap()).unwrap();
            assert!(
                snapshots
                    .insert(principal, payload["capsules"].clone())
                    .is_none()
            );
        }
        assert_eq!(snapshots[&owner], serde_json::json!([]));
        let dependent_capsules = snapshots[&dependent].as_array().unwrap();
        assert_eq!(
            dependent_capsules.len(),
            usize::from(retain_dependent_capsule)
        );
        if retain_dependent_capsule {
            assert_eq!(dependent_capsules[0]["name"], kept_id.as_str());
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), events.recv())
                .await
                .is_err()
        );
        let registry = kernel.capsules.read().await;
        assert!(registry.get_for(&owner, &shared_id).is_none());
        assert!(registry.get_for(&dependent, &shared_id).is_none());
        assert!(registry.get_for(&unrelated, &shared_id).is_some());
    }
}
