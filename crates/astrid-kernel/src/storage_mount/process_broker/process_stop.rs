//! Bounded STOP/reap for a native process storage provider.

use std::{path::PathBuf, time::Duration};

use astrid_core::local_transport::{self, ConnectOutcome};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status", deny_unknown_fields)]
enum ProcessProviderStopResponse {
    Stopped,
    Ready,
    Failure { code: String, message: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProcessStopOutcome {
    Stopped { acknowledged: bool },
    ChildReap,
    ControlEndpoint,
}

pub(crate) mod cleanup_evidence {
    #[cfg(test)]
    use std::{
        collections::BTreeMap,
        sync::{
            LazyLock, Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    use super::ProcessStopOutcome;
    use astrid_core::storage_provider::StorageMountId;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ProviderComponent {
        Branch,
        OwnerHome,
        FleetShared,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ProjectionCleanupStage {
        Binding,
        ProviderStop {
            component: ProviderComponent,
            mount_id: StorageMountId,
            outcome: ProcessStopOutcome,
        },
        ListenerSettlement,
        LeaseResources {
            mount_id: StorageMountId,
        },
        CleanupLedger {
            mount_id: StorageMountId,
        },
        ProjectionRoot,
        CacheRemoval,
        Complete,
    }

    #[cfg(test)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ProjectionCleanupEvent {
        pub(crate) failed: bool,
        pub(crate) stage: ProjectionCleanupStage,
    }

    #[cfg(test)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct CleanupEvidenceScope {
        pub(crate) legacy_label: &'static str,
        pub(crate) execution: u64,
    }

    #[cfg(test)]
    type EvidenceLog = (&'static str, Vec<ProjectionCleanupEvent>);

    #[cfg(test)]
    static NEXT_EVIDENCE_EXECUTION: AtomicU64 = AtomicU64::new(0);

    #[cfg(test)]
    tokio::task_local! {
        static CURRENT_EVIDENCE_SCOPE: CleanupEvidenceScope;
    }

    #[cfg(test)]
    static EVIDENCE: LazyLock<Mutex<BTreeMap<u64, EvidenceLog>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));

    #[cfg(test)]
    pub(crate) async fn scoped_with_label<T>(
        legacy_label: &'static str,
        future: impl std::future::Future<Output = T>,
    ) -> T {
        let execution = NEXT_EVIDENCE_EXECUTION.fetch_add(1, Ordering::Relaxed);
        let scope = CleanupEvidenceScope {
            legacy_label,
            execution,
        };
        CURRENT_EVIDENCE_SCOPE
            .scope(scope, async move {
                EVIDENCE
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(scope.execution, (legacy_label, Vec::new()));
                future.await
            })
            .await
    }

    #[cfg(test)]
    pub(crate) async fn scoped<T>(future: impl std::future::Future<Output = T>) -> T {
        if CURRENT_EVIDENCE_SCOPE.try_with(|_| {}).is_ok() {
            future.await
        } else {
            scoped_with_label("process-cleanup", future).await
        }
    }

    #[cfg(not(test))]
    pub(crate) async fn scoped<T>(future: impl std::future::Future<Output = T>) -> T {
        future.await
    }

    #[cfg(not(test))]
    pub(crate) fn begin() {}

    #[cfg(test)]
    pub(crate) fn begin() {
        // The outer execution owns initialization. A nested cleanup must not
        // discard earlier evidence collected by a retry or invalidation.
    }

    #[cfg(not(test))]
    pub(crate) fn record(_stage: ProjectionCleanupStage, _failed: bool) {}

    #[cfg(test)]
    pub(crate) fn record(stage: ProjectionCleanupStage, failed: bool) {
        if let Ok(scope) = CURRENT_EVIDENCE_SCOPE.try_with(|scope| *scope)
            && let Ok(mut evidence) = EVIDENCE.lock()
        {
            evidence
                .entry(scope.execution)
                .or_default()
                .1
                .push(ProjectionCleanupEvent { failed, stage });
        }
    }

    #[cfg(test)]
    pub(crate) fn take_for_test(scope: CleanupEvidenceScope) -> Vec<ProjectionCleanupEvent> {
        EVIDENCE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&scope.execution)
            .filter(|(label, _)| *label == scope.legacy_label)
            .map(|(_, events)| events)
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn current_scope_for_test() -> Option<CleanupEvidenceScope> {
        CURRENT_EVIDENCE_SCOPE.try_with(|scope| *scope).ok()
    }
}

/// Typed operator policy for bounded native provider STOP and reaping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessStopPolicy {
    stop_acknowledgement: std::time::Duration,
    reap_grace: std::time::Duration,
    killed_reap: std::time::Duration,
}

impl Default for ProcessStopPolicy {
    fn default() -> Self {
        // Ten seconds bounds a wedged protocol reply without making normal
        // unmount latency depend on provider I/O or child startup.
        let timeout = std::time::Duration::from_secs(10);
        Self {
            stop_acknowledgement: timeout,
            reap_grace: timeout,
            killed_reap: timeout,
        }
    }
}

impl From<&astrid_config::TimeoutsSection> for ProcessStopPolicy {
    fn from(timeouts: &astrid_config::TimeoutsSection) -> Self {
        Self {
            stop_acknowledgement: Duration::from_secs(timeouts.process_stop_ack_secs),
            reap_grace: Duration::from_secs(timeouts.process_reap_grace_secs),
            killed_reap: Duration::from_secs(timeouts.process_killed_reap_secs),
        }
    }
}

pub(super) async fn stop_process_provider(
    child: &mut tokio::process::Child,
    control_path: PathBuf,
    token: String,
    policy: ProcessStopPolicy,
) -> bool {
    match stop_process_provider_outcome(child, control_path, token, policy).await {
        ProcessStopOutcome::Stopped { .. } => true,
        ProcessStopOutcome::ChildReap | ProcessStopOutcome::ControlEndpoint => false,
    }
}

pub(super) async fn stop_process_provider_outcome(
    child: &mut tokio::process::Child,
    control_path: PathBuf,
    token: String,
    policy: ProcessStopPolicy,
) -> ProcessStopOutcome {
    let acknowledged = match local_transport::connect_outcome(&control_path).await {
        Ok(ConnectOutcome::Connected(stream)) => {
            send_stop_request(stream, &token, policy).await.is_ok()
        },
        Ok(ConnectOutcome::Absent | ConnectOutcome::Stale) | Err(_) => false,
    };
    if !acknowledged {
        let _ = child.start_kill();
    }
    if !reap_child(child, policy).await {
        return ProcessStopOutcome::ChildReap;
    }
    // Reaping is not ownership release. A provider can acknowledge STOP,
    // exit, and still leave a replacement or inherited listener at the
    // control endpoint. Probe after every STOP/reap outcome so only a dead
    // endpoint can clear the projection key.
    match local_transport::connect_outcome(&control_path).await {
        Ok(ConnectOutcome::Absent | ConnectOutcome::Stale) => {
            ProcessStopOutcome::Stopped { acknowledged }
        },
        Ok(ConnectOutcome::Connected(stream)) => {
            drop(stream);
            ProcessStopOutcome::ControlEndpoint
        },
        Err(_) => ProcessStopOutcome::ControlEndpoint,
    }
}

async fn send_stop_request(
    mut stream: local_transport::LocalStream,
    token: &str,
    policy: ProcessStopPolicy,
) -> Result<(), String> {
    let request = serde_json::json!({"operation": "stop", "token": token});
    let bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("encode provider stop request: {error}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| format!("write provider stop request: {error}"))?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|error| format!("write provider stop frame: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("flush provider stop request: {error}"))?;
    let mut line = String::new();
    let reader = tokio::io::BufReader::new(stream);
    let read = tokio::time::timeout(
        policy.stop_acknowledgement,
        reader.take((64 * 1024 + 1) as u64).read_line(&mut line),
    )
    .await
    .map_err(|_| "timed out waiting for provider stop acknowledgement".to_owned())?
    .map_err(|error| format!("read provider stop acknowledgement: {error}"))?;
    if read == 0 || read > 64 * 1024 || !line.ends_with('\n') {
        return Err("provider stop acknowledgement frame is malformed or oversized".to_owned());
    }
    match serde_json::from_str(&line)
        .map_err(|error| format!("decode provider stop acknowledgement: {error}"))?
    {
        ProcessProviderStopResponse::Stopped => Ok(()),
        ProcessProviderStopResponse::Ready => {
            Err("provider remained mounted after stop request".to_owned())
        },
        ProcessProviderStopResponse::Failure { code, message } => {
            Err(format!("provider refused stop ({code}): {message}"))
        },
    }
}

async fn reap_child(child: &mut tokio::process::Child, policy: ProcessStopPolicy) -> bool {
    if let Ok(Ok(_)) = tokio::time::timeout(policy.reap_grace, child.wait()).await {
        return true;
    }
    let _ = child.start_kill();
    matches!(
        tokio::time::timeout(policy.killed_reap, child.wait()).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
#[path = "process_stop_tests.rs"]
mod process_stop_tests;

#[cfg(test)]
pub(crate) mod owned_test_tasks {
    use std::{
        future::Future,
        panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    use tokio::{runtime::Handle, task::spawn_blocking};

    pub(crate) struct OwnedTask<T> {
        handle: Mutex<Option<tokio::task::JoinHandle<T>>>,
        cancelled: AtomicBool,
        joined: AtomicBool,
    }

    impl<T: Send + 'static> OwnedTask<T> {
        pub(crate) fn spawn<F>(task: F) -> Self
        where
            F: Future<Output = T> + Send + 'static,
        {
            Self {
                handle: Mutex::new(Some(tokio::spawn(task))),
                cancelled: AtomicBool::new(false),
                joined: AtomicBool::new(false),
            }
        }

        pub(crate) async fn join(&self) -> T {
            let Some(handle) = self.take_handle() else {
                assert!(!self.was_joined(), "owned test task cannot be joined twice");
                panic!("owned test task join handle detached before settlement");
            };
            OwnedJoin {
                owner: self,
                handle: Some(handle),
                taken: true,
            }
            .await
        }

        pub(crate) fn was_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::Acquire)
        }

        pub(crate) fn was_joined(&self) -> bool {
            self.joined.load(Ordering::Acquire)
        }

        fn take_handle(&self) -> Option<tokio::task::JoinHandle<T>> {
            self.handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        }
    }

    impl<T> OwnedTask<T> {
        fn restore_handle(&self, handle: tokio::task::JoinHandle<T>) {
            *self
                .handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
        }
    }

    struct OwnedJoin<'task, T> {
        owner: &'task OwnedTask<T>,
        handle: Option<tokio::task::JoinHandle<T>>,
        taken: bool,
    }

    impl<T> Future for OwnedJoin<'_, T> {
        type Output = T;

        fn poll(
            mut self: Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            let Some(handle) = self.handle.as_mut() else {
                return std::task::Poll::Pending;
            };
            let outcome = std::task::ready!(<_ as Future>::poll(Pin::new(handle), context));
            self.taken = false;
            self.owner.joined.store(true, Ordering::Release);
            match outcome {
                Ok(value) => std::task::Poll::Ready(value),
                Err(error) => panic!("owned test task failed while joining: {error}"),
            }
        }
    }

    impl<T> Drop for OwnedJoin<'_, T> {
        fn drop(&mut self) {
            if self.taken
                && let Some(handle) = self.handle.take()
            {
                self.owner.restore_handle(handle);
            }
        }
    }

    impl<T> Drop for OwnedTask<T> {
        fn drop(&mut self) {
            if let Some(handle) = self
                .handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                handle.abort();
            }
        }
    }

    pub(crate) trait OwnedTestTask: Send + Sync {
        fn finish<'task>(
            &'task self,
        ) -> Pin<Box<dyn Future<Output = Result<(), OwnedTaskJoinFailure>> + Send + 'task>>
        where
            Self: 'task;
    }

    impl<T: Send + 'static> OwnedTestTask for OwnedTask<T> {
        fn finish<'task>(
            &'task self,
        ) -> Pin<Box<dyn Future<Output = Result<(), OwnedTaskJoinFailure>> + Send + 'task>>
        where
            Self: 'task,
        {
            Box::pin(async move {
                let Some(handle) = self.take_handle() else {
                    return if self.was_joined() {
                        Ok(())
                    } else {
                        Err(OwnedTaskJoinFailure::Detached)
                    };
                };
                handle.abort();
                let outcome = handle.await;
                self.joined.store(true, Ordering::Release);
                match outcome {
                    Ok(_) => Ok(()),
                    Err(error) if error.is_cancelled() => {
                        self.cancelled.store(true, Ordering::Release);
                        Ok(())
                    },
                    Err(error) => Err(OwnedTaskJoinFailure::Join(error.to_string())),
                }
            })
        }
    }

    #[derive(Debug)]
    pub(crate) enum OwnedTaskJoinFailure {
        Detached,
        Join(String),
    }

    pub(crate) struct OwnedBodyOutcome<T> {
        pub(crate) outcome: Result<T, Box<dyn std::any::Any + Send>>,
        pub(crate) cleanup_failures: Vec<(usize, OwnedTaskJoinFailure)>,
    }

    pub(crate) async fn run_owned_test_body_detailed<T, F, Fut>(
        tasks: &[Arc<dyn OwnedTestTask>],
        body: F,
    ) -> OwnedBodyOutcome<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let runtime = Handle::current();
        let outcome =
            spawn_blocking(move || catch_unwind(AssertUnwindSafe(|| runtime.block_on(body()))))
                .await
                .expect("owned test body worker");
        let mut cleanup_failures = Vec::new();
        for (index, task) in tasks.iter().enumerate() {
            if let Err(failure) = task.finish().await {
                cleanup_failures.push((index, failure));
            }
        }
        OwnedBodyOutcome {
            outcome,
            cleanup_failures,
        }
    }

    pub(crate) async fn run_owned_test_body<T, F, Fut>(
        tasks: &[Arc<dyn OwnedTestTask>],
        body: F,
    ) -> T
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let result = run_owned_test_body_detailed(tasks, body).await;
        let value = match result.outcome {
            Ok(value) => value,
            Err(payload) => resume_unwind(payload),
        };
        assert!(
            result.cleanup_failures.is_empty(),
            "owned test task cleanup failures: {:?}",
            result.cleanup_failures
        );
        value
    }
}

#[cfg(test)]
mod owned_task_tests {
    use std::{sync::Arc, time::Duration};

    use super::owned_test_tasks::{
        OwnedTask, OwnedTaskJoinFailure, OwnedTestTask, run_owned_test_body_detailed,
    };

    fn assertion_payload(outcome: &Result<(), Box<dyn std::any::Any + Send>>) -> String {
        let payload = &outcome.as_ref().expect_err("body panic");
        payload
            .downcast_ref::<&str>()
            .map(|message| (*message).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .expect("string body panic payload")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn join_timeout_catches_panic_aborts_and_joins_owned_task() {
        let never = Arc::new(OwnedTask::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        }));
        let finishers = [Arc::clone(&never) as Arc<dyn OwnedTestTask>];
        let body_task = Arc::clone(&never);

        let outcome = run_owned_test_body_detailed(&finishers, move || async move {
            panic!(
                "{:?}",
                tokio::time::timeout(Duration::from_millis(50), body_task.join()).await
            )
        })
        .await;

        assert!(assertion_payload(&outcome.outcome).contains("Err(Elapsed"));
        assert!(outcome.cleanup_failures.is_empty());
        assert!(never.was_cancelled());
        assert!(never.was_joined());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caught_body_assertion_panic_settles_every_owned_task() {
        let joined = Arc::new(OwnedTask::spawn(async { 1usize }));
        let cancelled = Arc::new(OwnedTask::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        }));
        let finishers = [
            Arc::clone(&joined) as Arc<dyn OwnedTestTask>,
            Arc::clone(&cancelled) as Arc<dyn OwnedTestTask>,
        ];
        let body_joined = Arc::clone(&joined);

        let outcome = run_owned_test_body_detailed(&finishers, move || async move {
            assert_eq!(body_joined.join().await, 1);
            panic!("body assertion unwind");
        })
        .await;

        assert_eq!(assertion_payload(&outcome.outcome), "body assertion unwind");
        assert!(outcome.cleanup_failures.is_empty());
        assert!(joined.was_joined());
        assert!(cancelled.was_cancelled());
        assert!(cancelled.was_joined());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_panic_remains_primary_when_owned_finisher_panics() {
        let finisher = Arc::new(OwnedTask::spawn(async {
            panic!("independent finisher unwind");
        }));
        let finishers = [Arc::clone(&finisher) as Arc<dyn OwnedTestTask>];

        let outcome = run_owned_test_body_detailed(&finishers, move || async move {
            tokio::task::yield_now().await;
            panic!("distinct body assertion unwind");
        })
        .await;

        assert_eq!(
            assertion_payload(&outcome.outcome),
            "distinct body assertion unwind"
        );
        assert_eq!(outcome.cleanup_failures.len(), 1);
        assert!(
            matches!(
                &outcome.cleanup_failures[0].1,
                OwnedTaskJoinFailure::Join(message) if message.contains("independent finisher unwind")
            ),
            "{:?}",
            outcome.cleanup_failures
        );
        assert!(finisher.was_joined());
    }
}

#[cfg(test)]
pub(crate) mod cache_test_support {
    use std::{
        future::Future,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use astrid_capsule::context::ProcessStorageMountBroker as _;
    use astrid_core::PrincipalId;

    use crate::storage_mount::process_broker::{
        CachedProcessProjection, KernelProcessStorageMountBroker, PROCESS_MOUNT_TEST_ID,
    };

    pub(crate) struct CachedMount {
        pub(crate) mount: astrid_capsule::context::ProcessStorageMount,
        pub(crate) projection: Arc<CachedProcessProjection>,
    }

    static NEXT_PROCESS_MOUNT_EXECUTION: AtomicU64 = AtomicU64::new(1_000_000);

    pub(crate) fn fresh_process_mount_test_id() -> u64 {
        NEXT_PROCESS_MOUNT_EXECUTION.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) async fn bounded_phase<T>(
        phase: &'static str,
        future: impl Future<Output = T>,
    ) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .unwrap_or_else(|_| panic!("{phase} exceeded 5s"))
    }

    pub(crate) fn uuid_mount_root(
        mount: &astrid_capsule::context::ProcessStorageMount,
    ) -> std::path::PathBuf {
        mount
            .workspace_root
            .parent()
            .expect("workspace leaf has a UUID projection root")
            .to_path_buf()
    }

    pub(crate) async fn successful_fleet_mount(
        kernel: &Arc<crate::Kernel>,
        caller: &PrincipalId,
        broker: &KernelProcessStorageMountBroker,
        test_id: u64,
    ) -> CachedMount {
        let mount = bounded_phase(
            "successful fleet provider mount",
            PROCESS_MOUNT_TEST_ID.scope(test_id, broker.mount(caller)),
        )
        .await
        .expect("full successful process projection");
        let projections = broker.projections.lock().await;
        assert_eq!(projections.len(), 1);
        let projection = Arc::clone(projections.values().next().expect("cached projection"));
        drop(projections);

        assert_eq!(
            projection.component_mount_ids.len(),
            if projection.binding.targets.fleet_shared.is_some() {
                3
            } else {
                2
            }
        );
        assert_eq!(
            projection.refs.load(std::sync::atomic::Ordering::Acquire),
            1,
            "the first successful mount owns one cached reference"
        );
        assert!(
            projection
                .component_mount_ids
                .iter()
                .all(|mount_id| kernel.storage_mounts.contains_key(mount_id))
        );
        CachedMount { mount, projection }
    }

    pub(crate) async fn successful_fleet_mount_for_fresh_execution(
        kernel: &Arc<crate::Kernel>,
        caller: &PrincipalId,
        broker: &KernelProcessStorageMountBroker,
    ) -> CachedMount {
        successful_fleet_mount(kernel, caller, broker, fresh_process_mount_test_id()).await
    }

    pub(crate) async fn assert_replacement_after_unhealthy_hit(
        kernel: &Arc<crate::Kernel>,
        caller: &PrincipalId,
        broker: &KernelProcessStorageMountBroker,
        stale: CachedMount,
        test_id: u64,
    ) {
        let stale_root = stale.mount.workspace_root.clone();
        let stale_mount_root = uuid_mount_root(&stale.mount);
        let stale_projection = stale.projection;
        let replacement_mount = bounded_phase(
            "replacement fleet provider mount",
            PROCESS_MOUNT_TEST_ID.scope(test_id, broker.mount(caller)),
        )
        .await
        .expect("unhealthy hit must clean and admit a replacement");
        assert_ne!(
            replacement_mount.workspace_root, stale_root,
            "a replacement must not return the stale provider root"
        );
        assert!(
            !stale_mount_root.exists(),
            "cleanup must remove the stale UUID projection root"
        );
        assert!(
            stale_projection
                .component_mount_ids
                .iter()
                .all(|mount_id| !kernel.storage_mounts.contains_key(mount_id)),
            "stale exact set must be absent after cleanup"
        );
        assert_eq!(
            stale_projection
                .refs
                .load(std::sync::atomic::Ordering::Acquire),
            1,
            "invalidation must not increment the stale projection"
        );

        let projections = broker.projections.lock().await;
        assert_eq!(projections.len(), 1);
        let replacement_projection = projections
            .values()
            .next()
            .expect("replacement cached projection");
        assert!(!Arc::ptr_eq(replacement_projection, &stale_projection));
        assert_eq!(
            replacement_projection
                .refs
                .load(std::sync::atomic::Ordering::Acquire),
            1,
            "only the replacement guard owns a new reference"
        );
        assert!(
            replacement_projection
                .component_mount_ids
                .iter()
                .all(|mount_id| kernel.storage_mounts.contains_key(mount_id))
        );
        drop(projections);

        bounded_phase(
            "replacement provider close",
            replacement_mount.close_async(),
        )
        .await;
        bounded_phase("stale provider close", stale.mount.close_async()).await;
        assert!(
            kernel.storage_mounts.is_empty(),
            "the replacement must clean its complete new exact set"
        );
        assert!(broker.projections.lock().await.is_empty());
    }

    pub(crate) async fn assert_replacement_after_unhealthy_hit_for_fresh_execution(
        kernel: &Arc<crate::Kernel>,
        caller: &PrincipalId,
        broker: &KernelProcessStorageMountBroker,
        stale: CachedMount,
    ) {
        assert_replacement_after_unhealthy_hit(
            kernel,
            caller,
            broker,
            stale,
            fresh_process_mount_test_id(),
        )
        .await;
    }
}

#[cfg(all(test, any(unix, windows)))]
pub(crate) mod retain_gates {
    use std::sync::Arc;

    #[derive(Default)]
    struct RetainValidationGate {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    static RETAIN_VALIDATION_GATE: std::sync::Mutex<Option<Arc<RetainValidationGate>>> =
        std::sync::Mutex::new(None);

    static RETAIN_REFERENCE_GATE: std::sync::Mutex<Option<Arc<RetainValidationGate>>> =
        std::sync::Mutex::new(None);

    pub(crate) struct RetainValidationGateGuard {
        gate: Arc<RetainValidationGate>,
    }

    impl RetainValidationGateGuard {
        pub(crate) fn entered(&self) -> Arc<tokio::sync::Notify> {
            Arc::clone(&self.gate.entered)
        }

        pub(crate) fn release(&self) -> Arc<tokio::sync::Notify> {
            Arc::clone(&self.gate.release)
        }
    }

    impl Drop for RetainValidationGateGuard {
        fn drop(&mut self) {
            let mut installed = RETAIN_VALIDATION_GATE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if installed
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.gate))
            {
                *installed = None;
            }
            let mut reference_gate = RETAIN_REFERENCE_GATE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if reference_gate
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.gate))
            {
                *reference_gate = None;
            }
        }
    }

    pub(crate) fn arm_retain_validation_gate() -> RetainValidationGateGuard {
        let gate = Arc::new(RetainValidationGate::default());
        *RETAIN_VALIDATION_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&gate));
        RetainValidationGateGuard { gate }
    }

    pub(crate) fn arm_retain_reference_gate() -> RetainValidationGateGuard {
        let gate = Arc::new(RetainValidationGate::default());
        *RETAIN_REFERENCE_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&gate));
        RetainValidationGateGuard { gate }
    }

    pub(crate) async fn pause_retain_validation_for_test() {
        let gate = RETAIN_VALIDATION_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(Arc::clone);
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
    }

    pub(crate) async fn pause_retain_reference_for_test() {
        let gate = RETAIN_REFERENCE_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(Arc::clone);
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
    }
}
