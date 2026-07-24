//! Producer-side tests for the per-action host-audit seam.
//!
//! Drives the fs/net/process audit helpers against a recording sink double
//! and asserts each reports the expected principal, event variant, and
//! outcome. The assertions pin the contract the kernel-side sink relies on:
//! the principal is the host's `effective_principal` (never guest data), and
//! denials are reported exactly once as `Denied`.

use std::sync::{Arc, Mutex};

use astrid_core::PrincipalId;

use crate::audit_sink::{HostAuditEvent, HostAuditOutcome, HostAuditSink};
#[cfg(windows)]
use crate::engine::wasm::bindings::astrid::process1_1_0::host as process_host;
use crate::engine::wasm::host_state::HostState;
use crate::engine::wasm::test_fixtures::minimal_host_state;

#[cfg(windows)]
#[path = "audit_sink_tests/windows_signal.rs"]
mod windows_signal;

/// An owned, comparable snapshot of a reported event.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CapturedEvent {
    FileRead(String),
    FileWrite(String),
    FileDelete(String),
    NetConnect(String, u16),
    NetBind(String),
    ProcessSpawn(String),
    ProcessSignal(String, String),
}

impl CapturedEvent {
    fn from(event: HostAuditEvent<'_>) -> Self {
        match event {
            HostAuditEvent::FileRead { path } => Self::FileRead(path.to_owned()),
            HostAuditEvent::FileWrite { path } => Self::FileWrite(path.to_owned()),
            HostAuditEvent::FileDelete { path } => Self::FileDelete(path.to_owned()),
            HostAuditEvent::NetConnect { host, port } => Self::NetConnect(host.to_owned(), port),
            HostAuditEvent::NetBind { addr } => Self::NetBind(addr.to_owned()),
            HostAuditEvent::ProcessSpawn { command } => Self::ProcessSpawn(command.to_owned()),
        }
    }
}

/// An owned tag of a reported outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CapturedOutcome {
    Allowed,
    Failed(String),
    Denied(String),
}

impl CapturedOutcome {
    fn from(outcome: HostAuditOutcome<'_>) -> Self {
        match outcome {
            HostAuditOutcome::Allowed => Self::Allowed,
            HostAuditOutcome::Failed(e) => Self::Failed(e.to_owned()),
            HostAuditOutcome::Denied(r) => Self::Denied(r.to_owned()),
        }
    }
}

/// Test double that records every reported call.
#[derive(Default)]
struct RecordingSink {
    records: Mutex<Vec<(PrincipalId, CapturedEvent, CapturedOutcome)>>,
}

impl HostAuditSink for RecordingSink {
    fn record(
        &self,
        principal: &PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    ) {
        self.records.lock().expect("sink mutex").push((
            principal.clone(),
            CapturedEvent::from(event),
            CapturedOutcome::from(outcome),
        ));
    }

    fn record_process_signal(
        &self,
        principal: &PrincipalId,
        process: &str,
        signal: &str,
        outcome: HostAuditOutcome<'_>,
    ) {
        self.records.lock().expect("sink mutex").push((
            principal.clone(),
            CapturedEvent::ProcessSignal(process.to_owned(), signal.to_owned()),
            CapturedOutcome::from(outcome),
        ));
    }
}

impl RecordingSink {
    fn snapshot(&self) -> Vec<(PrincipalId, CapturedEvent, CapturedOutcome)> {
        self.records.lock().expect("sink mutex").clone()
    }
}

/// Build a `HostState` with a recording sink installed under a known
/// principal. Returns the state and a handle to the sink for assertions.
fn state_with_sink(rt: tokio::runtime::Handle) -> (HostState, Arc<RecordingSink>) {
    let sink = Arc::new(RecordingSink::default());
    let mut state = minimal_host_state(rt);
    state.principal = PrincipalId::new("alice").expect("valid principal");
    state.audit_sink = Some(sink.clone() as Arc<dyn HostAuditSink>);
    (state, sink)
}

#[tokio::test]
async fn audit_fs_reports_read_write_delete() {
    let (state, sink) = state_with_sink(tokio::runtime::Handle::current());
    let alice = PrincipalId::new("alice").unwrap();

    super::fs::audit_fs(&state, "read-file", "/w/r", &Ok::<(), ()>(()));
    super::fs::audit_fs(&state, "write-file", "/w/w", &Ok::<(), ()>(()));
    super::fs::audit_fs(&state, "unlink", "/w/d", &Ok::<(), ()>(()));

    let records = sink.snapshot();
    assert_eq!(records.len(), 3, "fs ops must each report once");
    assert_eq!(
        records[0],
        (
            alice.clone(),
            CapturedEvent::FileRead("/w/r".into()),
            CapturedOutcome::Allowed
        )
    );
    assert_eq!(
        records[1],
        (
            alice.clone(),
            CapturedEvent::FileWrite("/w/w".into()),
            CapturedOutcome::Allowed
        )
    );
    assert_eq!(
        records[2],
        (
            alice,
            CapturedEvent::FileDelete("/w/d".into()),
            CapturedOutcome::Allowed
        )
    );
}

#[tokio::test]
async fn audit_fs_reports_failure() {
    let (state, sink) = state_with_sink(tokio::runtime::Handle::current());
    let alice = PrincipalId::new("alice").unwrap();

    super::fs::audit_fs(&state, "read-file", "/w/missing", &Err::<(), _>("nope"));

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, alice);
    assert_eq!(records[0].1, CapturedEvent::FileRead("/w/missing".into()));
    assert!(
        matches!(records[0].2, CapturedOutcome::Failed(_)),
        "errored fs op must report Failed, got {:?}",
        records[0].2
    );
}

#[tokio::test]
async fn audit_net_reports_connect() {
    let (state, sink) = state_with_sink(tokio::runtime::Handle::current());
    let alice = PrincipalId::new("alice").unwrap();

    super::net::audit_net_connect(&state, "example.com", 443, &Ok::<(), ()>(()));

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0],
        (
            alice,
            CapturedEvent::NetConnect("example.com".into(), 443),
            CapturedOutcome::Allowed
        )
    );
}

#[tokio::test]
async fn audit_net_reports_bind_denied() {
    // A denied socket bind (capsule lacks `net_bind`) currently leaves no
    // trace; the producer must report the typed NetBind event as Denied so
    // the rejection lands on the chain.
    let (state, sink) = state_with_sink(tokio::runtime::Handle::current());
    let alice = PrincipalId::new("alice").unwrap();

    super::net::record_net_denied(
        &state,
        HostAuditEvent::NetBind {
            addr: "local:cli-control",
        },
        "no net_bind capability",
    );

    let records = sink.snapshot();
    assert_eq!(records.len(), 1, "denied bind must report exactly once");
    assert_eq!(records[0].0, alice);
    assert_eq!(
        records[0].1,
        CapturedEvent::NetBind("local:cli-control".into())
    );
    assert!(
        matches!(records[0].2, CapturedOutcome::Denied(_)),
        "denied bind must report Denied, got {:?}",
        records[0].2
    );
}

#[cfg(windows)]
#[tokio::test]
async fn windows_host_local_bind_denial_is_audited() {
    let (mut state, sink) = state_with_sink(tokio::runtime::Handle::current());
    let result = crate::engine::wasm::bindings::astrid::net::host::Host::bind_unix(&mut state);

    assert!(matches!(
        result,
        Err(crate::engine::wasm::bindings::astrid::net::host::ErrorCode::CapabilityDenied)
    ));
    let records = sink.snapshot();
    assert_eq!(records.len(), 1, "denied bind must report exactly once");
    assert_eq!(
        records[0].1,
        CapturedEvent::NetBind("local:cli-control".into())
    );
    assert!(matches!(records[0].2, CapturedOutcome::Denied(_)));
}

#[tokio::test]
async fn audit_process_reports_spawn() {
    let (state, sink) = state_with_sink(tokio::runtime::Handle::current());
    let alice = PrincipalId::new("alice").unwrap();

    super::process::audit_process(&state, "astrid:process/host.spawn", "ls", &Ok::<(), ()>(()));

    let records = sink.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0],
        (
            alice,
            CapturedEvent::ProcessSpawn("ls".into()),
            CapturedOutcome::Allowed
        )
    );
}

#[tokio::test]
async fn audit_process_reports_spawn_variants() {
    // spawn-background and spawn-persistent are also sensitive exec seams and
    // must reach the chain, not just `spawn`. Regression: an
    // `op.ends_with("spawn")` check silently dropped both variants.
    let (state, sink) = state_with_sink(tokio::runtime::Handle::current());
    let alice = PrincipalId::new("alice").unwrap();

    super::process::audit_process(
        &state,
        "astrid:process/host.spawn-background",
        "server",
        &Ok::<(), ()>(()),
    );
    super::process::audit_process(
        &state,
        "astrid:process/host.spawn-persistent",
        "daemon",
        &Ok::<(), ()>(()),
    );

    let records = sink.snapshot();
    assert_eq!(records.len(), 2, "both spawn variants must reach the sink");
    assert_eq!(
        records[0],
        (
            alice.clone(),
            CapturedEvent::ProcessSpawn("server".into()),
            CapturedOutcome::Allowed
        )
    );
    assert_eq!(
        records[1],
        (
            alice,
            CapturedEvent::ProcessSpawn("daemon".into()),
            CapturedOutcome::Allowed
        )
    );
}

#[tokio::test]
async fn audit_fs_reports_denied() {
    // A security-gate denial must reach the sink as `Denied` — today the
    // gate early-returns before any audit envelope, leaving denials with
    // no trace. The producer must report the typed event + Denied outcome.
    let (state, sink) = state_with_sink(tokio::runtime::Handle::current());
    let alice = PrincipalId::new("alice").unwrap();

    super::fs::record_fs_denied(
        &state,
        HostAuditEvent::FileRead {
            path: "/etc/secret",
        },
        "gate",
    );

    let records = sink.snapshot();
    assert_eq!(records.len(), 1, "denial must report exactly once");
    assert_eq!(records[0].0, alice);
    assert_eq!(records[0].1, CapturedEvent::FileRead("/etc/secret".into()));
    assert!(
        matches!(records[0].2, CapturedOutcome::Denied(_)),
        "denied fs op must report Denied, got {:?}",
        records[0].2
    );
}

/// End-to-end through a PUBLIC host fn: a denying capability checker must make
/// `connect-tcp` fail closed AND land a `Denied` `NetConnect` on the sink.
///
/// The other tests call the `record_*` producers directly; this one drives the
/// whole `net::Host::connect_tcp` gate path (validate → gate deny → record →
/// early return) to prove the denial audit is actually wired into the host fn,
/// not just reachable in isolation. A denied connect never touches the network
/// (the gate rejects before any socket effect), so no real TCP is attempted.
///
/// `multi_thread` flavour: `connect_tcp` resolves its gate check through
/// `bounded_block_on`, which uses `block_in_place` + `block_on` and therefore
/// requires a multi-threaded runtime.
#[tokio::test(flavor = "multi_thread")]
async fn connect_tcp_denial_lands_on_the_chain() {
    use crate::engine::wasm::bindings::astrid::net::host::Host as _;
    use std::sync::Arc as StdArc;

    let (mut state, sink) = state_with_sink(tokio::runtime::Handle::current());
    state.security = Some(StdArc::new(crate::security::DenyAllGate));
    let alice = PrincipalId::new("alice").unwrap();

    let result = state.connect_tcp("example.com".to_string(), 443);
    assert!(
        result.is_err(),
        "a gate-denied connect must fail closed, got {result:?}"
    );

    let records = sink.snapshot();
    assert_eq!(
        records.len(),
        1,
        "denied connect via the host fn must record exactly once"
    );
    assert_eq!(records[0].0, alice);
    assert_eq!(
        records[0].1,
        CapturedEvent::NetConnect("example.com".into(), 443)
    );
    assert!(
        matches!(records[0].2, CapturedOutcome::Denied(_)),
        "gate-denied connect must report Denied, got {:?}",
        records[0].2
    );
}

#[cfg(windows)]
fn windows_probe_request(
    mode: &str,
    mut env: Vec<process_host::EnvVar>,
) -> process_host::SpawnRequest {
    use process_host::EnvVar;

    env.push(EnvVar {
        key: "ASTRID_WINDOWS_PROCESS_PROBE".to_string(),
        value: mode.to_string(),
    });
    process_host::SpawnRequest {
        cmd: std::env::current_exe()
            .expect("current test executable")
            .to_string_lossy()
            .into_owned(),
        args: vec![
            "windows_process_probe_child".to_string(),
            "--nocapture".to_string(),
        ],
        stdin: None,
        env,
        cwd: None,
        limits: None,
        label: None,
        keep_stdin_open: None,
        overflow: None,
        log_ring_bytes: None,
        max_lifetime_ms: None,
        idle_timeout_ms: None,
        exit_retention_ms: None,
        file_injections: Vec::new(),
    }
}

#[cfg(windows)]
fn windows_touch_request(sentinel: &std::path::Path) -> process_host::SpawnRequest {
    windows_probe_request(
        "touch",
        vec![process_host::EnvVar {
            key: "ASTRID_SENTINEL".to_string(),
            value: sentinel.to_string_lossy().into_owned(),
        }],
    )
}

#[cfg(windows)]
fn authenticate_windows_process_state(state: &mut HostState) {
    state.caller_context = Some(
        astrid_events::ipc::IpcMessage::new(
            astrid_events::ipc::Topic::from_raw("test.windows.process"),
            astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
            uuid::Uuid::new_v4(),
        )
        .with_principal("alice"),
    );
}

#[cfg(windows)]
async fn windows_wait_for_file(path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !path.is_file() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(path.is_file(), "timed out waiting for {}", path.display());
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_spawn_off_executes_and_audits() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::Host as _;

    let temp = tempfile::tempdir().expect("workspace");
    let sentinel = temp.path().join("off-executed");
    let (mut state, sink) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);

    let result = state
        .spawn(windows_touch_request(&sentinel))
        .expect("explicit off policy should execute a trusted process");
    assert_eq!(result.exit.exit_code, Some(0));
    assert_eq!(
        std::fs::read(&sentinel).expect("probe sentinel"),
        b"executed"
    );

    let records = sink.snapshot();
    assert_eq!(records.len(), 1, "spawn must report exactly once");
    assert!(matches!(
        records[0],
        (_, CapturedEvent::ProcessSpawn(_), CapturedOutcome::Allowed)
    ));
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_spawn_preserves_cwd_env_stdin_output_and_exit() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::Host as _;

    let temp = tempfile::tempdir().expect("workspace");
    let child_cwd = temp.path().join("child");
    std::fs::create_dir(&child_cwd).expect("child cwd");
    let (mut state, _) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);

    let mut request = windows_probe_request(
        "host-stdio",
        vec![
            process_host::EnvVar {
                key: "ASTRID_EXPECTED_CWD".to_string(),
                value: child_cwd.to_string_lossy().into_owned(),
            },
            process_host::EnvVar {
                key: "ASTRID_WINDOWS_EDGE".to_string(),
                value: "unicode-\u{2603}-quote\"-slash\\".to_string(),
            },
        ],
    );
    request.cwd = Some("child".to_string());
    request.stdin = Some("host stdin \u{2603} \" \\".as_bytes().to_vec());

    let result = state.spawn(request).expect("foreground stdio spawn");
    assert_eq!(result.exit.exit_code, Some(37));
    assert!(result.stdout.contains("host-stdout"), "{:?}", result.stdout);
    assert!(result.stderr.contains("host-stderr"), "{:?}", result.stderr);
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_rejects_case_colliding_environment_before_exec() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{ErrorCode, Host as _};

    let temp = tempfile::tempdir().expect("workspace");
    let sentinel = temp.path().join("collision-must-not-execute");
    let (mut state, _) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);
    let mut request = windows_touch_request(&sentinel);
    request.env.extend([
        process_host::EnvVar {
            key: "ASTRID_EDGE".to_string(),
            value: "first".to_string(),
        },
        process_host::EnvVar {
            key: "astrid_edge".to_string(),
            value: "second".to_string(),
        },
    ]);

    assert!(matches!(state.spawn(request), Err(ErrorCode::InvalidInput)));
    assert!(!sentinel.exists(), "case-colliding env reached exec");
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_rejects_batch_files_before_exec() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{ErrorCode, Host as _};

    let temp = tempfile::tempdir().expect("workspace");
    let sentinel = temp.path().join("batch-must-not-execute");
    let batch = temp.path().join("probe.cmd");
    std::fs::write(
        &batch,
        format!("@echo executed>\"{}\"\r\n", sentinel.display()),
    )
    .expect("batch fixture");
    let (mut state, _) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);
    let mut request = windows_touch_request(&sentinel);
    request.cmd = batch.to_string_lossy().into_owned();

    assert!(matches!(state.spawn(request), Err(ErrorCode::InvalidInput)));
    assert!(!sentinel.exists(), "batch file reached exec");
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_foreground_root_exit_cleans_descendants() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::Host as _;

    let temp = tempfile::tempdir().expect("workspace");
    let heartbeat = temp.path().join("foreground-heartbeat");
    let (mut state, _) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);

    let request = windows_probe_request(
        "tree-root-exit",
        vec![process_host::EnvVar {
            key: "ASTRID_HEARTBEAT".to_string(),
            value: heartbeat.to_string_lossy().into_owned(),
        }],
    );
    let result = state.spawn(request).expect("foreground spawn");
    assert_eq!(result.exit.exit_code, Some(0));
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let stopped = std::fs::read_to_string(&heartbeat).expect("heartbeat after root exit");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        stopped,
        std::fs::read_to_string(&heartbeat).expect("final heartbeat"),
        "foreground descendant survived root cleanup"
    );
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_background_off_executes_and_waits() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{Host as _, ProcessHandle};
    use wasmtime::component::Resource;

    let temp = tempfile::tempdir().expect("workspace");
    let sentinel = temp.path().join("background-executed");
    let (mut state, sink) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);

    let handle = state
        .spawn_background(windows_touch_request(&sentinel))
        .expect("background spawn");
    let rep = handle.rep();
    let exit = <HostState as process_host::HostProcessHandle>::wait(
        &mut state,
        Resource::<ProcessHandle>::new_borrow(rep),
        Some(10_000),
    )
    .expect("wait for background probe");
    assert_eq!(exit.exit_code, Some(0));
    assert_eq!(
        std::fs::read(&sentinel).expect("probe sentinel"),
        b"executed"
    );
    <HostState as process_host::HostProcessHandle>::drop(&mut state, handle)
        .expect("drop process handle");

    let records = sink.snapshot();
    assert_eq!(records.len(), 1, "background spawn must audit once");
    assert!(matches!(records[0].2, CapturedOutcome::Allowed));
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_background_root_exit_cleans_descendants() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{Host as _, ProcessHandle};
    use wasmtime::component::Resource;

    let temp = tempfile::tempdir().expect("workspace");
    let heartbeat = temp.path().join("background-heartbeat");
    let (mut state, _) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);

    let request = windows_probe_request(
        "tree-root-exit",
        vec![process_host::EnvVar {
            key: "ASTRID_HEARTBEAT".to_string(),
            value: heartbeat.to_string_lossy().into_owned(),
        }],
    );
    let handle = state.spawn_background(request).expect("background spawn");
    let exit = <HostState as process_host::HostProcessHandle>::wait(
        &mut state,
        Resource::<ProcessHandle>::new_borrow(handle.rep()),
        Some(10_000),
    )
    .expect("background root exit");
    assert_eq!(exit.exit_code, Some(0));

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let stopped = std::fs::read_to_string(&heartbeat).expect("heartbeat after root exit");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        stopped,
        std::fs::read_to_string(&heartbeat).expect("final heartbeat"),
        "background descendant survived root cleanup"
    );
    <HostState as process_host::HostProcessHandle>::drop(&mut state, handle)
        .expect("drop process handle");
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_live_handle_kill_reports_true_and_cleans_descendants() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{Host as _, ProcessHandle};
    use wasmtime::component::Resource;

    let temp = tempfile::tempdir().expect("workspace");
    let heartbeat = temp.path().join("kill-heartbeat");
    let (mut state, _) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);

    let request = windows_probe_request(
        "tree-root-immediate",
        vec![process_host::EnvVar {
            key: "ASTRID_HEARTBEAT".to_string(),
            value: heartbeat.to_string_lossy().into_owned(),
        }],
    );
    let handle = state.spawn_background(request).expect("background spawn");
    windows_wait_for_file(&heartbeat).await;
    let killed = <HostState as process_host::HostProcessHandle>::kill(
        &mut state,
        Resource::<ProcessHandle>::new_borrow(handle.rep()),
    )
    .expect("kill live Job");
    assert!(
        killed.killed,
        "successful live Job termination must report true"
    );

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let stopped = std::fs::read_to_string(&heartbeat).expect("heartbeat after kill");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        stopped,
        std::fs::read_to_string(&heartbeat).expect("final heartbeat"),
        "live handle kill left a descendant running"
    );
    <HostState as process_host::HostProcessHandle>::drop(&mut state, handle)
        .expect("drop process handle");
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_signal_audit_never_persists_guest_arguments() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{
        Host as _, HostProcessHandle as _, ProcessHandle, ProcessSignal,
    };
    use wasmtime::component::Resource;

    const SECRET_ARG: &str = "guest-secret-argument-must-not-be-audited";
    let temp = tempfile::tempdir().expect("workspace");
    let heartbeat = temp.path().join("signal-audit-heartbeat");
    let (mut state, sink) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);

    let mut request = windows_probe_request(
        "tree-root-immediate",
        vec![process_host::EnvVar {
            key: "ASTRID_HEARTBEAT".to_string(),
            value: heartbeat.to_string_lossy().into_owned(),
        }],
    );
    request
        .args
        .extend(["--skip".to_string(), SECRET_ARG.to_string()]);
    let executable = request.cmd.clone();
    let handle = state.spawn_background(request).expect("background spawn");
    windows_wait_for_file(&heartbeat).await;

    process_host::HostProcessHandle::signal(
        &mut state,
        Resource::<ProcessHandle>::new_borrow(handle.rep()),
        ProcessSignal::Term,
    )
    .expect("terminate process tree");
    <HostState as process_host::HostProcessHandle>::drop(&mut state, handle)
        .expect("drop process handle");

    let records = sink.snapshot();
    assert!(records.iter().all(|(_, event, _)| match event {
        CapturedEvent::ProcessSignal(process, _) => {
            process == &executable && !process.contains(SECRET_ARG)
        },
        _ => true,
    }));
    assert!(records.iter().any(|(_, event, _)| matches!(
        event,
        CapturedEvent::ProcessSignal(process, signal)
            if process == &executable && signal == "term"
    )));
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_spawn_required_denies_before_exec_and_audits() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{ErrorCode, Host as _};

    let temp = tempfile::tempdir().expect("workspace");
    let sentinel = temp.path().join("must-not-execute");
    let (mut state, sink) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Required);

    let result = state.spawn(windows_touch_request(&sentinel));
    assert!(matches!(result, Err(ErrorCode::CapabilityDenied)));
    assert!(!sentinel.exists(), "required policy executed the child");

    let records = sink.snapshot();
    assert_eq!(records.len(), 1, "denied spawn must report exactly once");
    assert!(matches!(
        &records[0],
        (
            _,
            CapturedEvent::ProcessSpawn(_),
            CapturedOutcome::Denied(reason)
        ) if reason.contains("sandbox")
    ));
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_background_required_denies_before_exec_and_audits() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{ErrorCode, Host as _};

    let temp = tempfile::tempdir().expect("workspace");
    let sentinel = temp.path().join("background-must-not-execute");
    let (mut state, sink) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Required);

    let result = state.spawn_background(windows_touch_request(&sentinel));
    assert!(matches!(result, Err(ErrorCode::CapabilityDenied)));
    assert!(!sentinel.exists(), "required policy executed the child");

    let records = sink.snapshot();
    assert_eq!(records.len(), 1, "denied spawn must report exactly once");
    assert!(matches!(
        &records[0],
        (
            _,
            CapturedEvent::ProcessSpawn(_),
            CapturedOutcome::Denied(reason)
        ) if reason.contains("sandbox")
    ));
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_persistent_required_denies_before_exec_and_audits() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::{ErrorCode, Host as _};

    let temp = tempfile::tempdir().expect("workspace");
    let sentinel = temp.path().join("persistent-must-not-execute");
    let (mut state, sink) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.capability_names.push("allow_persistent".to_string());
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Required);
    authenticate_windows_process_state(&mut state);

    let result = state.spawn_persistent(windows_touch_request(&sentinel));
    assert!(matches!(result, Err(ErrorCode::CapabilityDenied)));
    assert!(!sentinel.exists(), "required policy executed the child");

    let records = sink.snapshot();
    assert_eq!(records.len(), 1, "denied spawn must report exactly once");
    assert!(matches!(
        &records[0],
        (
            _,
            CapturedEvent::ProcessSpawn(_),
            CapturedOutcome::Denied(reason)
        ) if reason.contains("sandbox")
    ));
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_persistent_root_exit_cleans_descendants() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::Host as _;

    let temp = tempfile::tempdir().expect("workspace");
    let heartbeat = temp.path().join("persistent-heartbeat");
    let (mut state, _) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.capability_names.push("allow_persistent".to_string());
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);
    authenticate_windows_process_state(&mut state);

    let request = windows_probe_request(
        "tree-root-exit",
        vec![process_host::EnvVar {
            key: "ASTRID_HEARTBEAT".to_string(),
            value: heartbeat.to_string_lossy().into_owned(),
        }],
    );
    let id = state.spawn_persistent(request).expect("persistent spawn");
    let exit = state
        .wait(id.clone(), 10_000)
        .expect("persistent root exit");
    assert_eq!(exit.exit_code, Some(0));

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let stopped = std::fs::read_to_string(&heartbeat).expect("heartbeat after root exit");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        stopped,
        std::fs::read_to_string(&heartbeat).expect("final heartbeat"),
        "persistent descendant survived root cleanup"
    );
    state.release_process(id).expect("release persistent entry");
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_persistent_sweep_cleans_live_descendants() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::Host as _;

    let temp = tempfile::tempdir().expect("workspace");
    let heartbeat = temp.path().join("sweep-heartbeat");
    let leaf_pid = temp.path().join("sweep-leaf-pid");
    let (mut state, _) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.capability_names.push("allow_persistent".to_string());
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);
    authenticate_windows_process_state(&mut state);

    let mut request = windows_probe_request(
        "tree-root",
        vec![
            process_host::EnvVar {
                key: "ASTRID_HEARTBEAT".to_string(),
                value: heartbeat.to_string_lossy().into_owned(),
            },
            process_host::EnvVar {
                key: "ASTRID_LEAF_PID".to_string(),
                value: leaf_pid.to_string_lossy().into_owned(),
            },
        ],
    );
    request.max_lifetime_ms = Some(50);
    let _id = state.spawn_persistent(request).expect("persistent spawn");
    windows_wait_for_file(&heartbeat).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(state.persistent_processes.reap_sweep(), 1);

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let stopped = std::fs::read_to_string(&heartbeat).expect("heartbeat after sweep");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        stopped,
        std::fs::read_to_string(&heartbeat).expect("final heartbeat"),
        "swept persistent descendant survived cleanup"
    );
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_host_persistent_shutdown_cleans_live_descendants() {
    use crate::engine::wasm::bindings::astrid::process1_1_0::host::Host as _;

    let temp = tempfile::tempdir().expect("workspace");
    let heartbeat = temp.path().join("shutdown-heartbeat");
    let leaf_pid = temp.path().join("shutdown-leaf-pid");
    let (mut state, _) = state_with_sink(tokio::runtime::Handle::current());
    state.workspace_root = temp.path().to_path_buf();
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    state.capability_names.push("allow_persistent".to_string());
    state.process_sandbox_policy = Some(astrid_workspace::SandboxPolicy::Off);
    authenticate_windows_process_state(&mut state);

    let request = windows_probe_request(
        "tree-root",
        vec![
            process_host::EnvVar {
                key: "ASTRID_HEARTBEAT".to_string(),
                value: heartbeat.to_string_lossy().into_owned(),
            },
            process_host::EnvVar {
                key: "ASTRID_LEAF_PID".to_string(),
                value: leaf_pid.to_string_lossy().into_owned(),
            },
        ],
    );
    let _id = state.spawn_persistent(request).expect("persistent spawn");
    windows_wait_for_file(&heartbeat).await;
    state.persistent_processes.shutdown();

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let stopped = std::fs::read_to_string(&heartbeat).expect("heartbeat after shutdown");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        stopped,
        std::fs::read_to_string(&heartbeat).expect("final heartbeat"),
        "shutdown persistent descendant survived cleanup"
    );
}
