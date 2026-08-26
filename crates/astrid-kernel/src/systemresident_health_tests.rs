//! Test-only proof of the hosted `SystemResident` lifecycle boundary.
//!
//! The fixture deliberately uses the production residency classifier, capsule
//! registry, `HostState` effective accessors, readiness gate, health snapshot,
//! generation replacement, and unload/drain paths.  It does not add a capsule,
//! endpoint, wire contract, or policy surface.

#![cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use astrid_capsule::capsule::{Capsule, CapsuleState, InterceptResult, ReadyStatus};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::engine::wasm::host::process::{PersistentProcessRegistry, ProcessTracker};
use astrid_capsule::engine::wasm::host_state::{HookHostStateParams, HostState};
use astrid_capsule::memory_ledger::StoreMemoryMeter;
use astrid_capsule::registry::WasmHash;
use astrid_capsule_install::{
    AuthorityDecision, CapsuleMeta, authorize_install, canonical_capsule_archive,
    inspect_directory_for_principal_in_workspace, materialize_capsule_package, publish_package,
    resolve_cache_target_dir,
};
use astrid_capsule_types::error::CapsuleResult;
use astrid_capsule_types::manifest::{CapsuleManifest, UplinkDef};
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use astrid_core::identity::PrincipalUid;
use astrid_core::{PrincipalId, PrincipalProfile};
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_storage::{CapsulePackage, KvStore, MemoryKvStore, ScopedKvStore};

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
    source_dir: Option<PathBuf>,
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
            source_dir: None,
        }
    }

    fn with_manifest_source(
        id: &str,
        manifest: CapsuleManifest,
        health: CapsuleState,
        counters: LifecycleCounters,
        source_dir: PathBuf,
    ) -> Self {
        Self {
            id: astrid_capsule::capsule::CapsuleId::new(id).expect("fixture capsule id"),
            manifest,
            ready: ReadyStatus::Ready,
            health,
            counters,
            source_dir: Some(source_dir),
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

    fn source_dir(&self) -> Option<&Path> {
        self.source_dir.as_deref()
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

fn system_manifest(id: &str, version: &str) -> CapsuleManifest {
    let mut manifest = CapsuleManifest::default();
    id.clone_into(&mut manifest.package.name);
    version.clone_into(&mut manifest.package.version);
    manifest.capabilities.uplink = true;
    manifest.uplinks.push(UplinkDef {
        name: "health".to_owned(),
        platform: "test".to_owned(),
        profile: astrid_core::UplinkProfile::Chat,
    });
    manifest
}

/// Build the same durable package plus cache projection that `load_capsule`
/// consumes.  The test then reaches the real operator allowlist and
/// operator-first admission gates rather than calling the classifier alone.
fn materialize_system_package(
    kernel: &crate::Kernel,
    home: &AstridHome,
    principal: &PrincipalId,
    id: &str,
    version: &str,
) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let source = tempfile::tempdir().expect("system source tempdir");
    let manifest = system_manifest(id, version);
    let manifest_bytes = toml::to_string(&manifest).expect("serialize system manifest");
    std::fs::write(source.path().join("Capsule.toml"), manifest_bytes)
        .expect("write system manifest");

    let layout = WorkspaceLayout::default();
    let inspection = inspect_directory_for_principal_in_workspace(
        source.path(),
        home,
        principal,
        false,
        None,
        &layout,
    )
    .expect("inspect system source");
    let authority = authorize_install(
        &inspection,
        &AuthorityDecision::ExplicitApproval {
            content_digest: inspection.content_digest.clone(),
        },
    )
    .expect("authorize system package");
    let archive = canonical_capsule_archive(source.path()).expect("archive system source");
    let package = CapsulePackage::new(
        archive.clone(),
        serde_json::to_vec(&CapsuleMeta {
            version: version.to_owned(),
            ..Default::default()
        })
        .expect("serialize system metadata"),
        serde_json::to_vec(&authority).expect("serialize system authority"),
    );
    let store = Arc::new(
        kernel
            .principal_store
            .as_ref()
            .expect("test kernel durable principal store")
            .clone(),
    );
    let default = PrincipalId::default();
    let archive_digest = blake3::hash(&archive).to_hex().to_string();
    let mut targets = Vec::new();
    for owner in [&default, principal] {
        if *owner != default {
            PrincipalProfile::default()
                .save_to_path(&PrincipalProfile::path_for(home, owner))
                .expect("seed system package owner profile");
        }
        let uid = kernel
            .principal_directory
            .uid_for(owner)
            .expect("system package owner UID");
        publish_package(&store, uid, id, &package).expect("publish system package");
        let target = resolve_cache_target_dir(home, uid, id, &archive_digest, false, None, &layout)
            .expect("resolve system materialization");
        materialize_capsule_package(&package, &target).expect("materialize system package");
        targets.push(target);
    }
    (source, targets.remove(0), targets.remove(0))
}

#[tokio::test]
async fn operator_allowlist_is_the_only_systemresident_admission() {
    let dir = tempfile::tempdir().expect("allowlist home tempdir");
    let home = AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let id = "health-uplink";
    let capsule_id = astrid_capsule_types::CapsuleId::new(id).expect("capsule id");
    let alice = PrincipalId::new("alice").expect("alice principal");
    kernel
        .identity_store
        .create_principal(alice.clone(), [0xA1; 32])
        .await
        .expect("create Alice identity");
    let (_source, operator_dir, alice_dir) =
        materialize_system_package(&kernel, &home, &alice, id, "0.0.1");

    kernel.set_system_capsules(Vec::<String>::new()).await;
    assert!(
        kernel
            .load_capsule(operator_dir.clone(), &PrincipalId::default())
            .await
            .is_err(),
        "an uplink absent from the operator allowlist must fail closed at load"
    );

    kernel.set_system_capsules([id.to_owned()]).await;
    assert!(
        kernel
            .load_capsule(alice_dir.clone(), &alice)
            .await
            .is_err(),
        "a dependent principal cannot directly create the operator-owned runtime"
    );
    kernel
        .load_capsule(operator_dir, &PrincipalId::default())
        .await
        .expect("operator creates allowlisted system runtime");
    kernel
        .load_capsule(alice_dir, &alice)
        .await
        .expect("dependent principal attaches to published system runtime");

    let registry = kernel.capsules.read().await;
    let operator_runtime = registry
        .runtime_id_for(&PrincipalId::default(), &capsule_id)
        .expect("operator runtime view");
    assert_eq!(
        registry.runtime_id_for(&alice, &capsule_id),
        Some(operator_runtime)
    );
    assert_eq!(
        registry.len(),
        1,
        "operator and dependent share one generation"
    );
}

#[tokio::test]
async fn systemresident_host_state_hook_is_neutral_until_each_caller_overlay() {
    // This proves the production HostState::for_hook neutral baseline and its
    // effective caller overlays.  The capsule-crate recv-context installer is
    // intentionally not widened across the kernel test boundary; its
    // production-path coverage remains in astrid-capsule's own tests.
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
    let old_user = kernel
        .identity_store
        .create_principal(alice.clone(), [0x11; 32])
        .await
        .expect("create original Alice identity");
    let old_uid = kernel
        .principal_directory
        .uid_for(&alice)
        .expect("original Alice UID");
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
            .register_existing(&system_id, &system_hash, &alice)
            .unwrap();
        registry
            .register_existing(&system_id, &system_hash, &bob)
            .unwrap();
    }

    assert!(kernel.unload_one_capsule(&system_id, &alice).await.unwrap());
    assert!(
        kernel
            .capsules
            .read()
            .await
            .get_for(&alice, &system_id)
            .is_none(),
        "production unload removes the recycled alias view before deletion"
    );
    kernel
        .identity_store
        .delete_user(old_user.id)
        .await
        .expect("delete original Alice identity");
    assert!(
        stale.confirm_live(&kernel).is_err(),
        "deleted alias is not live"
    );
    kernel
        .identity_store
        .create_principal(alice.clone(), [0x22; 32])
        .await
        .expect("recreate Alice identity");
    let replacement_uid = kernel
        .principal_directory
        .uid_for(&alice)
        .expect("replacement Alice UID");
    assert_ne!(
        replacement_uid, old_uid,
        "alias recycle gets a distinct UID"
    );
    kernel
        .capsules
        .write()
        .await
        .register_existing(&system_id, &system_hash, &alice)
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
        let candidate =
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
            super::prepare_capsule_candidate(&id, Box::new(candidate))
                .await
                .is_err()
        );
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
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let id = astrid_capsule::capsule::CapsuleId::new("health-singleton").unwrap();
    let operator = PrincipalId::default();
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    kernel
        .identity_store
        .create_principal(alice.clone(), [0xB1; 32])
        .await
        .expect("create replacement viewer identity");
    let (_source, replacement_dir, _alice_dir) =
        materialize_system_package(&kernel, &home, &alice, id.as_str(), "0.0.2");
    let old_hash = WasmHash::from_raw("health-singleton-v1");
    let old_counters = LifecycleCounters::default();

    {
        let mut registry = kernel.capsules.write().await;
        registry
            .register_system_runtime(
                Box::new(ProbeCapsule::with_manifest_source(
                    id.as_str(),
                    system_manifest(id.as_str(), "0.0.1"),
                    CapsuleState::Failed("probe failed".to_owned()),
                    old_counters.clone(),
                    replacement_dir.clone(),
                )),
                old_hash.clone(),
                &operator,
            )
            .unwrap();
        registry.register_existing(&id, &old_hash, &alice).unwrap();
        registry.register_existing(&id, &old_hash, &bob).unwrap();
        assert_eq!(registry.len(), 1);
    }
    kernel.set_system_capsules([id.to_string()]).await;

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

    let outcome = kernel
        .restart_capsule(&id, &operator, Some(&expected))
        .await
        .expect("production restart orchestration");
    assert_eq!(outcome, super::RestartOutcome::Clean);
    assert_eq!(old_counters.retired.load(Ordering::SeqCst), 1);
    assert_eq!(old_counters.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(old_counters.unloaded.load(Ordering::SeqCst), 1);

    let registry = kernel.capsules.read().await;
    let replacement = registry
        .runtime_id_for(&operator, &id)
        .expect("replacement operator view");
    assert_ne!(replacement, expected);
    assert_eq!(
        replacement.key().artifact(),
        &WasmHash::synthetic(id.as_str(), "0.0.2")
    );
    assert_eq!(
        registry.runtime_id_for(&alice, &id),
        Some(replacement.clone())
    );
    assert_eq!(registry.runtime_id_for(&bob, &id), Some(replacement));
    assert_eq!(registry.len(), 1);
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
    let operator = PrincipalId::default();
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    let carol = PrincipalId::new("carol").unwrap();
    let first_counters = LifecycleCounters::default();
    let second_counters = LifecycleCounters::default();
    let first_hash = WasmHash::from_raw("shutdown-generation-v1");
    let second_hash = WasmHash::from_raw("shutdown-generation-v2");
    {
        let mut registry = kernel.capsules.write().await;
        registry
            .register_system_runtime(
                Box::new(system_probe(
                    id.as_str(),
                    CapsuleState::Ready,
                    first_counters.clone(),
                )),
                first_hash.clone(),
                &operator,
            )
            .unwrap();
        registry
            .register_existing(&id, &first_hash, &alice)
            .unwrap();
        registry
            .register_system_runtime(
                Box::new(system_probe(
                    id.as_str(),
                    CapsuleState::Ready,
                    second_counters.clone(),
                )),
                second_hash.clone(),
                &bob,
            )
            .unwrap();
        registry
            .register_existing(&id, &second_hash, &carol)
            .unwrap();
    }
    let drained = {
        let mut registry = kernel.capsules.write().await;
        let generations = registry.cloned_runtimes();
        assert_eq!(generations.len(), 2);
        assert_ne!(
            generations[0].0.key().artifact(),
            generations[1].0.key().artifact(),
            "same capsule id retains two distinct artifact generations"
        );
        assert_ne!(
            generations[0].0.generation(),
            generations[1].0.generation(),
            "same capsule id retains two distinct runtime generations"
        );
        registry.drain()
    };
    assert_eq!(
        drained.len(),
        2,
        "two artifact generations are drained independently despite shared id and views"
    );
    for mut runtime in drained {
        runtime.request_cancel();
        Arc::get_mut(&mut runtime)
            .expect("drain owns the sole runtime handle")
            .unload()
            .await
            .unwrap();
    }
    assert_eq!(first_counters.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(first_counters.unloaded.load(Ordering::SeqCst), 1);
    assert_eq!(second_counters.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(second_counters.unloaded.load(Ordering::SeqCst), 1);
}
