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
        sync::{LazyLock, Mutex},
    };

    #[cfg(test)]
    use super::super::PROCESS_MOUNT_TEST_ID;
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
    static EVIDENCE: LazyLock<Mutex<BTreeMap<u64, Vec<ProjectionCleanupEvent>>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));

    #[cfg(test)]
    fn current_test_id() -> Option<u64> {
        PROCESS_MOUNT_TEST_ID.try_with(|test_id| *test_id).ok()
    }

    #[cfg(not(test))]
    pub(crate) fn begin() {}

    #[cfg(test)]
    pub(crate) fn begin() {
        if let Some(test_id) = current_test_id()
            && let Ok(mut evidence) = EVIDENCE.lock()
        {
            evidence.insert(test_id, Vec::new());
        }
    }

    #[cfg(not(test))]
    pub(crate) fn record(_stage: ProjectionCleanupStage, _failed: bool) {}

    #[cfg(test)]
    pub(crate) fn record(stage: ProjectionCleanupStage, failed: bool) {
        if let Some(test_id) = current_test_id()
            && let Ok(mut evidence) = EVIDENCE.lock()
        {
            evidence
                .entry(test_id)
                .or_default()
                .push(ProjectionCleanupEvent { failed, stage });
        }
    }

    #[cfg(test)]
    pub(crate) fn take_for_test(test_id: u64) -> Vec<ProjectionCleanupEvent> {
        EVIDENCE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&test_id)
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn assert_successful_for_test(test_id: u64, lease_resources: usize) {
        let events = take_for_test(test_id);
        assert!(
            !events.iter().any(|event| event.failed),
            "typed cleanup evidence must not name a failed stage: {events:?}"
        );
        assert!(
            events.iter().any(|event| matches!(
                event.stage,
                ProjectionCleanupStage::ProviderStop { .. }
            ) && !event.failed),
            "typed evidence must record provider STOP/reap/endpoint settlement: {events:?}"
        );
        for stage in [
            ProjectionCleanupStage::ListenerSettlement,
            ProjectionCleanupStage::ProjectionRoot,
            ProjectionCleanupStage::CacheRemoval,
            ProjectionCleanupStage::Complete,
        ] {
            assert!(
                events
                    .iter()
                    .any(|event| event.stage == stage && !event.failed),
                "typed evidence is missing {stage:?}: {events:?}"
            );
        }
        assert!(
            events
                .iter()
                .filter(|event| matches!(
                    event.stage,
                    ProjectionCleanupStage::LeaseResources { .. }
                ))
                .count()
                >= lease_resources,
            "typed evidence must record every lease-resource cleanup: {events:?}"
        );
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
mod tests {
    use super::{ProcessStopPolicy, stop_process_provider};
    use astrid_core::local_transport;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::Notify;

    fn spawn_exited_child() -> tokio::process::Child {
        #[cfg(unix)]
        {
            tokio::process::Command::new("true")
                .spawn()
                .expect("spawn exited child")
        }
        #[cfg(windows)]
        {
            tokio::process::Command::new("cmd")
                .args(["/C", "exit", "0"])
                .spawn()
                .expect("spawn exited child")
        }
    }

    #[test]
    fn default_stop_policy_preserves_the_protocol_and_reap_hard_guard() {
        let policy = ProcessStopPolicy::default();
        assert_eq!(policy.stop_acknowledgement, Duration::from_secs(10));
        assert_eq!(policy.reap_grace, Duration::from_secs(10));
        assert_eq!(policy.killed_reap, Duration::from_secs(10));
    }

    #[test]
    fn timeout_config_derives_each_stop_and_reap_budget() {
        let timeouts = astrid_config::TimeoutsSection {
            process_stop_ack_secs: 7,
            process_reap_grace_secs: 11,
            process_killed_reap_secs: 13,
            ..astrid_config::TimeoutsSection::default()
        };
        let policy = ProcessStopPolicy::from(&timeouts);
        assert_eq!(policy.stop_acknowledgement, Duration::from_secs(7));
        assert_eq!(policy.reap_grace, Duration::from_secs(11));
        assert_eq!(policy.killed_reap, Duration::from_secs(13));
    }

    #[tokio::test]
    async fn absent_control_endpoint_is_stopped_after_child_reap() {
        let mut child = spawn_exited_child();
        let directory = tempfile::tempdir().expect("temporary control dir");
        let path = directory.path().join("missing.sock");
        assert!(
            stop_process_provider(
                &mut child,
                path,
                "unused-token".to_owned(),
                ProcessStopPolicy::default()
            )
            .await,
            "reaped child with no control endpoint must not wedge the projection key"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stale_control_endpoint_is_stopped_after_child_reap() {
        let mut child = spawn_exited_child();
        let directory = tempfile::tempdir().expect("temporary control dir");
        let path = directory.path().join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).expect("stale listener"));
        assert!(
            stop_process_provider(
                &mut child,
                path,
                "unused-token".to_owned(),
                ProcessStopPolicy::default(),
            )
            .await,
            "reaped child with a stale control endpoint must not wedge the projection key"
        );
    }

    #[cfg(any(unix, windows))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_stop_with_live_endpoint_is_retained_after_child_reap() {
        let mut child = spawn_exited_child();
        let directory = tempfile::tempdir().expect("temporary control dir");
        let path = directory.path().join("still-live.sock");
        let listener = local_transport::bind(&path).expect("bind live control endpoint");
        let release = Arc::new(Notify::new());
        let responder = tokio::spawn({
            let release = Arc::clone(&release);
            async move {
                let mut stream = local_transport::accept(&listener)
                    .await
                    .expect("accept authenticated stop request");
                stream
                    .write_all(b"{\"status\":\"stopped\"}\n")
                    .await
                    .expect("write canonical stop acknowledgement");
                let _ = stream.read_u8().await;
                release.notified().await;
            }
        });

        assert!(
            !stop_process_provider(
                &mut child,
                path,
                "unused-token".to_owned(),
                ProcessStopPolicy::default(),
            )
            .await,
            "a canonical STOP followed by reap must not release a live endpoint"
        );
        release.notify_waiters();
        responder.await.expect("live endpoint responder");
    }
}

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
                panic!("owned test task cannot be joined twice");
            };
            let value = handle
                .await
                .expect("owned test task must finish without panicking");
            self.joined.store(true, Ordering::Release);
            value
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
        fn finish<'task>(&'task self) -> Pin<Box<dyn Future<Output = ()> + Send + 'task>>
        where
            Self: 'task;
    }

    impl<T: Send + 'static> OwnedTestTask for OwnedTask<T> {
        fn finish<'task>(&'task self) -> Pin<Box<dyn Future<Output = ()> + Send + 'task>>
        where
            Self: 'task,
        {
            Box::pin(async move {
                let Some(handle) = self.take_handle() else {
                    return;
                };
                handle.abort();
                match handle.await {
                    Ok(_) => {},
                    Err(error) if error.is_cancelled() => {
                        self.cancelled.store(true, Ordering::Release);
                    },
                    Err(error) => panic!("owned test task failed while joining: {error}"),
                }
            })
        }
    }

    pub(crate) async fn run_owned_test_body_catching<T, F, Fut>(
        tasks: &[Arc<dyn OwnedTestTask>],
        body: F,
    ) -> Result<T, Box<dyn std::any::Any + Send>>
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
        for task in tasks {
            task.finish().await;
        }
        outcome
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
        match run_owned_test_body_catching(tasks, body).await {
            Ok(value) => value,
            Err(payload) => resume_unwind(payload),
        }
    }
}

#[cfg(test)]
mod owned_task_tests {
    use std::sync::Arc;

    use super::owned_test_tasks::{OwnedTask, OwnedTestTask, run_owned_test_body_catching};

    #[tokio::test]
    async fn owned_tasks_join_on_success_and_cancel_after_body_unwind() {
        let joined = Arc::new(OwnedTask::spawn(async { 1usize }));
        let cancelled = Arc::new(OwnedTask::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        }));
        let finishers: [Arc<dyn OwnedTestTask>; 2] = [
            Arc::clone(&joined) as Arc<dyn OwnedTestTask>,
            Arc::clone(&cancelled) as Arc<dyn OwnedTestTask>,
        ];
        let body_joined = Arc::clone(&joined);

        let outcome = run_owned_test_body_catching(&finishers, move || async move {
            assert_eq!(body_joined.join().await, 1);
            panic!("body assertion unwind");
        })
        .await;

        assert!(outcome.is_err(), "the captured body panic must be visible");
        assert!(joined.was_joined());
        assert!(cancelled.was_cancelled());
    }
}

#[cfg(test)]
pub(crate) mod cache_test_support {
    use std::{future::Future, sync::Arc, time::Duration};

    use astrid_capsule::context::ProcessStorageMountBroker as _;
    use astrid_core::PrincipalId;

    use crate::storage_mount::process_broker::{
        CachedProcessProjection, KernelProcessStorageMountBroker, PROCESS_MOUNT_TEST_ID,
    };

    pub(crate) struct CachedMount {
        pub(crate) mount: astrid_capsule::context::ProcessStorageMount,
        pub(crate) projection: Arc<CachedProcessProjection>,
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
