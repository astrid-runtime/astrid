//! Producer-side tests for the per-action host-audit seam.
//!
//! Drives the fs/net/process audit helpers against a recording sink double
//! and asserts each reports the expected principal, event variant, and
//! outcome. The assertions pin the contract the kernel-side sink relies on:
//! the principal is the host's `effective_principal` (never guest data), and
//! denials are reported exactly once as `Denied`.

use std::sync::{Arc, Mutex};

use astrid_core::PrincipalId;

use crate::engine::wasm::host::audit_sink::{HostAuditEvent, HostAuditOutcome, HostAuditSink};
use crate::engine::wasm::host_state::HostState;
use crate::engine::wasm::test_fixtures::minimal_host_state;

/// An owned, comparable snapshot of a reported event.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CapturedEvent {
    FileRead(String),
    FileWrite(String),
    FileDelete(String),
    NetConnect(String, u16),
    NetBind(String),
    ProcessSpawn(String),
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
            addr: "unix:cli-socket",
        },
        "no net_bind capability",
    );

    let records = sink.snapshot();
    assert_eq!(records.len(), 1, "denied bind must report exactly once");
    assert_eq!(records[0].0, alice);
    assert_eq!(
        records[0].1,
        CapturedEvent::NetBind("unix:cli-socket".into())
    );
    assert!(
        matches!(records[0].2, CapturedOutcome::Denied(_)),
        "denied bind must report Denied, got {:?}",
        records[0].2
    );
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
