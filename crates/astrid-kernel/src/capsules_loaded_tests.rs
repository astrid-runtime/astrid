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
