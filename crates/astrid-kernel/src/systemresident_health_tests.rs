//! Test-only proof of the hosted `SystemResident` lifecycle boundary.
//!
//! The fixture deliberately uses the production residency classifier, capsule
//! registry, `HostState` effective accessors, readiness gate, health snapshot,
//! generation replacement, and unload/drain paths.  It does not add a capsule,
//! endpoint, wire contract, or policy surface.

#![cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use astrid_capsule::capsule::{Capsule, CapsuleState, InterceptResult, ReadyStatus};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::engine::wasm::host::process::{PersistentProcessRegistry, ProcessTracker};
use astrid_capsule::engine::wasm::host_state::{HookHostStateParams, HostState};
use astrid_capsule::memory_ledger::StoreMemoryMeter;
use astrid_capsule::registry::WasmHash;
use astrid_capsule_types::error::CapsuleResult;
use astrid_capsule_types::manifest::{CapsuleManifest, UplinkDef};
use astrid_core::PrincipalId;
use astrid_core::identity::PrincipalUid;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_storage::{KvStore, MemoryKvStore, ScopedKvStore};

use crate::kernel_router::AuthorizedPrincipal;

#[derive(Clone, Default)]
struct LifecycleCounters {
    activated: Arc<AtomicUsize>,
    published: Arc<AtomicUsize>,
    retired: Arc<AtomicUsize>,
    cancelled: Arc<AtomicUsize>,
    unloaded: Arc<AtomicUsize>,
    cancelled_for: Arc<std::sync::Mutex<Vec<PrincipalId>>>,
}

struct ProbeCapsule {
    id: astrid_capsule::capsule::CapsuleId,
    manifest: CapsuleManifest,
    ready: ReadyStatus,
    health: CapsuleState,
    counters: LifecycleCounters,
}

impl ProbeCapsule {
    fn new(
        id: &str,
        ready: ReadyStatus,
        health: CapsuleState,
        counters: LifecycleCounters,
    ) -> Self {
        let mut manifest = CapsuleManifest::default();
        id.clone_into(&mut manifest.package.name);
        "0.0.1".clone_into(&mut manifest.package.version);
        Self {
            id: astrid_capsule::capsule::CapsuleId::new(id).expect("fixture capsule id"),
            manifest,
            ready,
            health,
            counters,
        }
    }
}

#[async_trait::async_trait]
impl Capsule for ProbeCapsule {
    fn id(&self) -> &astrid_capsule::capsule::CapsuleId {
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
        self.counters.unloaded.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn activate(&mut self) -> CapsuleResult<()> {
        self.counters.activated.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn publish(&self) {
        self.counters.published.fetch_add(1, Ordering::SeqCst);
    }

    fn retire(&self) {
        self.counters.retired.fetch_add(1, Ordering::SeqCst);
    }

    fn request_cancel(&self) {
        self.counters.cancelled.fetch_add(1, Ordering::SeqCst);
    }

    fn request_cancel_for(&self, principal: &PrincipalId) {
        self.counters
            .cancelled_for
            .lock()
            .expect("cancellation counter lock")
            .push(principal.clone());
    }

    async fn wait_ready(&self, _timeout: Duration) -> ReadyStatus {
        self.ready
    }

    fn check_health(&self) -> CapsuleState {
        self.health.clone()
    }

    async fn invoke_interceptor(
        &self,
        _action: &str,
        _payload: &[u8],
        _caller: Option<&IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        Ok(InterceptResult::Continue(Vec::new()))
    }
}

fn test_host_state() -> (HostState, Arc<dyn KvStore>) {
    let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let kv = ScopedKvStore::new(Arc::clone(&backend), "system:capsule:health").expect("KV scope");
    let vfs = Arc::new(astrid_vfs::HostVfs::new());
    let params = HookHostStateParams {
        store_meter: StoreMemoryMeter::new(
            usize::MAX,
            PrincipalId::default(),
            astrid_capsule::MemoryLedger::default(),
        ),
        capsule_id: astrid_capsule::capsule::CapsuleId::from_static("systemresident-health"),
        workspace_root: PathBuf::from("/tmp"),
        vfs,
        vfs_root_handle: astrid_capabilities::DirHandle::new(),
        kv,
        kv_backend: Arc::clone(&backend),
        secret_store: HostState::neutral_secret_store(),
        http_limits: astrid_capsule::HttpLimits::default(),
        event_bus: astrid_events::EventBus::new(),
        runtime_handle: tokio::runtime::Handle::current(),
        process_tracker: Arc::new(ProcessTracker::new()),
        persistent_processes: Arc::new(PersistentProcessRegistry::new(
            tokio::runtime::Handle::current(),
        )),
    };
    let mut state = HostState::for_hook(params);
    state.system_runtime = true;
    state.kv = HostState::neutral_kv();
    (state, backend)
}

fn caller(principal: &str) -> IpcMessage {
    IpcMessage::new(
        Topic::from_raw("systemresident.health.probe"),
        IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::nil(),
    )
    .with_principal(principal)
}

fn system_probe(id: &str, health: CapsuleState, counters: LifecycleCounters) -> ProbeCapsule {
    ProbeCapsule::new(id, ReadyStatus::Ready, health, counters)
}

#[test]
fn operator_allowlist_is_the_only_systemresident_admission() {
    let id = astrid_capsule_types::CapsuleId::new("health-uplink").expect("capsule id");
    let mut manifest = CapsuleManifest::default();
    manifest.package.name = id.to_string();
    manifest.package.version = "0.0.1".to_owned();
    manifest.capabilities.uplink = true;
    manifest.uplinks.push(UplinkDef {
        name: "health".to_owned(),
        platform: "test".to_owned(),
        profile: astrid_core::UplinkProfile::Chat,
    });

    assert!(
        super::classify_runtime_residency(&manifest, &id, false).is_err(),
        "an uplink absent from the operator allowlist must fail closed"
    );
    assert_eq!(
        super::classify_runtime_residency(&manifest, &id, true).unwrap(),
        super::RuntimeResidency::SystemResident
    );
}

#[tokio::test]
async fn systemresident_host_state_is_neutral_until_each_caller_overlay() {
    let (mut state, backend) = test_host_state();
    assert!(state.system_runtime);
    assert_eq!(
        state.effective_kv().namespace(),
        HostState::NEUTRAL_KV_NAMESPACE
    );
    assert!(state.effective_home().is_none());
    assert!(state.effective_tmp().is_none());

    let alice = ScopedKvStore::new(
        Arc::clone(&backend),
        format!("alice:capsule:{}", state.capsule_id),
    )
    .expect("alice overlay");
    state.invocation_kv = Some(alice);
    state.caller_context = Some(caller("alice"));
    assert_eq!(
        state.effective_principal(),
        PrincipalId::new("alice").unwrap()
    );
    assert_eq!(
        state.effective_kv().namespace(),
        "alice:capsule:systemresident-health"
    );
    state
        .effective_kv()
        .set("same-key", b"alice".to_vec())
        .await
        .unwrap();

    let bob = ScopedKvStore::new(
        Arc::clone(&backend),
        format!("bob:capsule:{}", state.capsule_id),
    )
    .expect("bob overlay");
    state.invocation_kv = Some(bob);
    state.caller_context = Some(caller("bob"));
    assert_eq!(
        state.effective_principal(),
        PrincipalId::new("bob").unwrap()
    );
    assert_eq!(
        state.effective_kv().namespace(),
        "bob:capsule:systemresident-health"
    );
    assert_eq!(state.effective_kv().get("same-key").await.unwrap(), None);
    state
        .effective_kv()
        .set("same-key", b"bob".to_vec())
        .await
        .unwrap();

    state.invocation_kv = None;
    state.caller_context = None;
    assert_eq!(
        state.effective_kv().namespace(),
        HostState::NEUTRAL_KV_NAMESPACE
    );
    assert_eq!(state.effective_kv().get("same-key").await.unwrap(), None);
}

#[tokio::test]
async fn deleting_and_recreating_an_alias_rejects_the_stale_uid() {
    let (_dir, kernel) = {
        let dir = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(dir.path());
        (dir, crate::test_kernel_with_home(home).await)
    };
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    let old_uid = PrincipalUid::from_bytes([0x11; 32]);
    let stale = AuthorizedPrincipal::bound(alice.clone(), old_uid);

    let bob_uid = PrincipalUid::from_bytes([0x33; 32]);
    kernel
        .principal_directory
        .register(bob.clone(), bob_uid)
        .unwrap();
    let system_id = astrid_capsule::capsule::CapsuleId::new("identity-survivor").unwrap();
    let system_hash = WasmHash::from_raw("identity-survivor");
    {
        let mut registry = kernel.capsules.write().await;
        registry
            .register_system_runtime(
                Box::new(system_probe(
                    system_id.as_str(),
                    CapsuleState::Ready,
                    LifecycleCounters::default(),
                )),
                system_hash.clone(),
                &PrincipalId::default(),
            )
            .unwrap();
        registry
            .register_existing(&system_id, &system_hash, &bob)
            .unwrap();
    }

    assert!(
        stale.confirm_live(&kernel).is_err(),
        "deleted alias is not live"
    );
    let replacement_uid = PrincipalUid::from_bytes([0x22; 32]);
    kernel
        .principal_directory
        .register(alice.clone(), replacement_uid)
        .unwrap();
    assert!(
        stale.confirm_live(&kernel).is_err(),
        "alias recreation under a new UID must not revive the old authorization"
    );
    assert!(
        AuthorizedPrincipal::bound(alice, replacement_uid)
            .confirm_live(&kernel)
            .is_ok()
    );
    assert!(
        kernel
            .capsules
            .read()
            .await
            .get_for(&bob, &system_id)
            .is_some(),
        "revoking and recreating Alice must not tear down Bob's live view"
    );
}

#[tokio::test]
async fn readiness_failure_never_publishes_a_candidate_generation() {
    for ready in [ReadyStatus::Timeout, ReadyStatus::Crashed] {
        let dir = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(dir.path());
        let kernel = crate::test_kernel_with_home(home).await;
        let id = astrid_capsule::capsule::CapsuleId::new("readiness-candidate").unwrap();
        let counters = LifecycleCounters::default();
        let mut candidate =
            ProbeCapsule::new(id.as_str(), ready, CapsuleState::Ready, counters.clone());
        let reserved = kernel
            .capsules
            .write()
            .await
            .reserve_runtime_id(
                id.clone(),
                WasmHash::from_raw("readiness-candidate"),
                astrid_capsule::registry::RuntimeScope::SystemResident,
            )
            .unwrap();

        assert!(
            super::activate_and_wait_ready(&id, &mut candidate)
                .await
                .is_err()
        );
        candidate.request_cancel();
        candidate.unload().await.unwrap();
        assert_eq!(counters.activated.load(Ordering::SeqCst), 1);
        assert_eq!(counters.cancelled.load(Ordering::SeqCst), 1);
        assert_eq!(counters.published.load(Ordering::SeqCst), 0);
        assert_eq!(counters.unloaded.load(Ordering::SeqCst), 1);
        let registry = kernel.capsules.read().await;
        assert!(registry.get_for(&PrincipalId::default(), &id).is_none());
        assert!(
            registry
                .runtime_id_for(&PrincipalId::default(), &id)
                .is_none()
        );
        drop(reserved);
    }
}

#[tokio::test]
async fn failing_systemresident_health_is_deduplicated_and_replaced_once() {
    let dir = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let id = astrid_capsule::capsule::CapsuleId::new("health-singleton").unwrap();
    let operator = PrincipalId::default();
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    let old_hash = WasmHash::from_raw("health-singleton-v1");
    let new_hash = WasmHash::from_raw("health-singleton-v2");
    let old_counters = LifecycleCounters::default();

    {
        let mut registry = kernel.capsules.write().await;
        registry
            .register_system_runtime(
                Box::new(system_probe(
                    id.as_str(),
                    CapsuleState::Failed("probe failed".to_owned()),
                    old_counters.clone(),
                )),
                old_hash.clone(),
                &operator,
            )
            .unwrap();
        let singleton = registry
            .register_system_runtime(
                Box::new(system_probe(
                    id.as_str(),
                    CapsuleState::Ready,
                    LifecycleCounters::default(),
                )),
                old_hash.clone(),
                &alice,
            )
            .unwrap();
        assert_eq!(
            registry.runtime_id_for(&operator, &id),
            Some(singleton),
            "reloading one allowlisted SystemResident artifact must reuse its singleton"
        );
        registry.register_existing(&id, &old_hash, &bob).unwrap();
        assert_eq!(registry.len(), 1);
    }

    let ready = {
        let registry = kernel.capsules.read().await;
        registry.cloned_runtimes_with_principal()
    };
    let failures = super::collect_failed_runtimes(&ready);
    assert_eq!(
        failures.len(),
        1,
        "one singleton means one health replacement"
    );
    let expected = failures[0].2.clone();
    drop(ready);

    let replacement_counters = LifecycleCounters::default();
    let previous = {
        let mut registry = kernel.capsules.write().await;
        registry
            .replace_system_runtime(
                &expected,
                Box::new(system_probe(
                    id.as_str(),
                    CapsuleState::Ready,
                    replacement_counters.clone(),
                )),
                new_hash,
            )
            .unwrap()
            .previous
    };
    let replacement = {
        let registry = kernel.capsules.read().await;
        let new_id = registry
            .runtime_id_for(&operator, &id)
            .expect("replacement operator view");
        assert_ne!(new_id, expected);
        assert_eq!(registry.runtime_id_for(&alice, &id), Some(new_id.clone()));
        assert_eq!(registry.runtime_id_for(&bob, &id), Some(new_id));
        assert_eq!(registry.len(), 1);
        registry
            .get_for(&operator, &id)
            .expect("replacement runtime")
    };
    replacement.publish();

    let mut previous = previous;
    previous.retire();
    previous.request_cancel();
    assert_eq!(
        super::unload_replaced_runtime(&id, &mut previous).await,
        super::RestartOutcome::Clean
    );
    assert_eq!(old_counters.retired.load(Ordering::SeqCst), 1);
    assert_eq!(old_counters.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(old_counters.unloaded.load(Ordering::SeqCst), 1);
    assert_eq!(replacement_counters.published.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn releasing_one_system_view_cancels_only_that_principal_and_final_drain_unloads_once() {
    let dir = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let id = astrid_capsule::capsule::CapsuleId::new("cleanup-singleton").unwrap();
    let operator = PrincipalId::default();
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    let counters = LifecycleCounters::default();
    let hash = WasmHash::from_raw("cleanup-singleton");

    {
        let mut registry = kernel.capsules.write().await;
        registry
            .register_system_runtime(
                Box::new(system_probe(
                    id.as_str(),
                    CapsuleState::Ready,
                    counters.clone(),
                )),
                hash.clone(),
                &operator,
            )
            .unwrap();
        registry.register_existing(&id, &hash, &alice).unwrap();
        registry.register_existing(&id, &hash, &bob).unwrap();
    }

    assert!(kernel.unload_one_capsule(&id, &alice).await.unwrap());
    assert_eq!(
        counters
            .cancelled_for
            .lock()
            .expect("cancellation counter lock")
            .as_slice(),
        std::slice::from_ref(&alice)
    );
    assert_eq!(counters.cancelled.load(Ordering::SeqCst), 0);
    assert_eq!(counters.unloaded.load(Ordering::SeqCst), 0);
    assert!(kernel.capsules.read().await.get_for(&bob, &id).is_some());

    // The final production shutdown drain is intentionally exercised through
    // the registry's distinct-runtime drain here. Calling Kernel::shutdown in
    // a unit test would remove the process-global socket/readiness sentinel;
    // `drain` is the exact capsule teardown phase and remains home-isolated.
    assert!(kernel.unload_one_capsule(&id, &bob).await.unwrap());
    assert!(kernel.unload_one_capsule(&id, &operator).await.unwrap());
    assert_eq!(counters.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(counters.retired.load(Ordering::SeqCst), 1);
    assert_eq!(counters.unloaded.load(Ordering::SeqCst), 1);
    assert_eq!(
        counters
            .cancelled_for
            .lock()
            .expect("cancellation counter lock")
            .as_slice(),
        &[alice, bob, operator]
    );
    let drained = {
        let mut registry = kernel.capsules.write().await;
        registry.drain()
    };
    assert!(drained.is_empty(), "all views were explicitly cleaned up");
}

#[tokio::test]
async fn distinct_runtime_drain_cancels_and_unloads_each_generation_once() {
    let dir = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let id = astrid_capsule::capsule::CapsuleId::new("shutdown-generation").unwrap();
    let counters = LifecycleCounters::default();
    let hash = WasmHash::from_raw("shutdown-generation");
    {
        let mut registry = kernel.capsules.write().await;
        registry
            .register_system_runtime(
                Box::new(system_probe(
                    id.as_str(),
                    CapsuleState::Ready,
                    counters.clone(),
                )),
                hash,
                &PrincipalId::default(),
            )
            .unwrap();
    }
    let drained = {
        let mut registry = kernel.capsules.write().await;
        registry.drain()
    };
    assert_eq!(
        drained.len(),
        1,
        "one singleton is drained once despite views"
    );
    for mut runtime in drained {
        runtime.request_cancel();
        Arc::get_mut(&mut runtime)
            .expect("drain owns the sole runtime handle")
            .unload()
            .await
            .unwrap();
    }
    assert_eq!(counters.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(counters.unloaded.load(Ordering::SeqCst), 1);
}
