//! Integration tests for `PersistentProcessRegistry` against REAL child
//! processes (no sandbox wrap — these exercise the registry's lifecycle:
//! reader tasks, the monitor task, ownership re-checks, caps, and reaping).

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use astrid_core::principal::PrincipalId;

use super::{PersistentProcessRegistry, SpawnParams};

/// Spawn a real child running `sh -c <script>`, in its own process group
/// (mirroring the production sandboxed path), with stdout/stderr piped.
fn spawn_raw(
    script: &str,
) -> (
    tokio::process::Child,
    tokio::process::ChildStdout,
    tokio::process::ChildStderr,
    u32,
) {
    let mut std_cmd = std::process::Command::new("sh");
    std_cmd
        .arg("-c")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        std_cmd.process_group(0);
    }
    let mut cmd = tokio::process::Command::from(std_cmd);
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().expect("spawn test child");
    let pid = child.id().expect("child pid");
    let stdout = child.stdout.take().expect("stdout pipe");
    let stderr = child.stderr.take().expect("stderr pipe");
    (child, stdout, stderr, pid)
}

#[allow(clippy::too_many_arguments)]
fn params(
    creator: &PrincipalId,
    capsule: &str,
    child: tokio::process::Child,
    stdout: tokio::process::ChildStdout,
    stderr: tokio::process::ChildStderr,
    os_pid: u32,
    concurrent_cap: usize,
) -> SpawnParams {
    SpawnParams {
        creator: creator.clone(),
        capsule_id: Arc::from(capsule),
        command: "sh -c <test>".to_string(),
        os_pid,
        child,
        stdout,
        stderr,
        stdin: None,
        concurrent_cap,
        label: None,
        overflow: None,
        log_ring_bytes: None,
        max_lifetime_ms: None,
        idle_timeout_ms: None,
        exit_retention_ms: None,
    }
}

#[tokio::test]
async fn spawn_wait_read_and_owner_isolation() {
    let reg = PersistentProcessRegistry::new(tokio::runtime::Handle::current());
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();

    let (child, so, se, pid) = spawn_raw("echo hello; echo oops 1>&2; exit 0");
    let id = reg
        .spawn(params(&alice, "cap-a", child, so, se, pid, 8))
        .expect("spawn-persistent");

    // Visible to the owner+capsule, invisible to anyone else (no oracle).
    assert!(reg.status(&id, &alice, "cap-a").is_ok());
    assert!(reg.status(&id, &bob, "cap-a").is_err());
    assert!(reg.status(&id, &alice, "cap-b").is_err());
    assert!(reg.status("not-a-real-id", &alice, "cap-a").is_err());

    // `status` / `list` return the reattach id (the WIT `process-info.id`),
    // not an empty string — otherwise `list-processes` can't be used to
    // recover ids.
    assert_eq!(reg.status(&id, &alice, "cap-a").unwrap().id, id);
    let listed = reg.list(&alice, "cap-a", None);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, id);

    // Wait for exit (bounded) — code 0.
    let exit = reg
        .wait(&id, &alice, "cap-a", Duration::from_secs(5))
        .await
        .expect("wait");
    assert_eq!(exit.exit_code, Some(0));

    // Let the reader tasks drain the final bytes, then read (drain).
    tokio::time::sleep(Duration::from_millis(200)).await;
    let logs = reg.read_logs(&id, &alice, "cap-a").expect("read-logs");
    assert!(logs.stdout.contains("hello"), "stdout: {:?}", logs.stdout);
    assert!(logs.stderr.contains("oops"), "stderr: {:?}", logs.stderr);
    assert!(!logs.running);

    // Exited but retained → still resolvable; release reaps it.
    assert!(reg.status(&id, &alice, "cap-a").is_ok());
    reg.release(&id, &alice, "cap-a").expect("release");
    assert!(reg.status(&id, &alice, "cap-a").is_err());
}

#[tokio::test]
async fn concurrent_cap_enforced_and_stop_reaps() {
    let reg = PersistentProcessRegistry::new(tokio::runtime::Handle::current());
    let p = PrincipalId::new("alice").unwrap();

    // cap = 1: first long-runner takes the only live slot.
    let (c1, o1, e1, pid1) = spawn_raw("sleep 30");
    let id1 = reg
        .spawn(params(&p, "cap", c1, o1, e1, pid1, 1))
        .expect("first spawn");

    // Second spawn must be rejected with `quota`.
    let (c2, o2, e2, pid2) = spawn_raw("sleep 30");
    let err = reg
        .spawn(params(&p, "cap", c2, o2, e2, pid2, 1))
        .expect_err("cap should reject");
    assert!(
        matches!(
            err,
            crate::engine::wasm::bindings::astrid::process::host::ErrorCode::Quota
        ),
        "expected Quota, got {err:?}"
    );

    // Stop the first (SIGTERM kills `sleep`) → removes the id, frees the slot.
    let exit = reg.stop(&id1, &p, "cap", None).await.expect("stop");
    // Killed by signal OR a non-zero code, never a clean 0.
    assert_ne!(exit.exit_code, Some(0));
    assert!(reg.status(&id1, &p, "cap").is_err());

    // Slot freed: a fresh spawn now succeeds under cap = 1.
    let (c3, o3, e3, pid3) = spawn_raw("sleep 30");
    let id3 = reg
        .spawn(params(&p, "cap", c3, o3, e3, pid3, 1))
        .expect("third spawn after slot freed");
    reg.stop(&id3, &p, "cap", None).await.expect("cleanup stop");
}

#[tokio::test]
async fn read_since_is_non_draining_with_cursor() {
    use crate::engine::wasm::bindings::astrid::process::host::{LogCursor, LogStream};

    let reg = PersistentProcessRegistry::new(tokio::runtime::Handle::current());
    let p = PrincipalId::new("alice").unwrap();
    let (child, so, se, pid) = spawn_raw("printf 'abcXYZ'; exit 0");
    let id = reg
        .spawn(params(&p, "cap", child, so, se, pid, 8))
        .expect("spawn");
    reg.wait(&id, &p, "cap", Duration::from_secs(5))
        .await
        .expect("wait");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // First non-draining read from the start.
    let chunk = reg
        .read_since(
            &id,
            &p,
            "cap",
            LogStream::Stdout,
            &LogCursor { token: None },
            3,
        )
        .expect("read-since");
    assert_eq!(chunk.data, b"abc");
    assert_eq!(chunk.bytes_dropped, 0);

    // Resume from the returned cursor — non-draining, so a second read with a
    // FRESH cursor still sees the whole stream (nothing was consumed).
    let chunk2 = reg
        .read_since(&id, &p, "cap", LogStream::Stdout, &chunk.next, 100)
        .expect("read-since 2");
    assert_eq!(chunk2.data, b"XYZ");
    assert!(chunk2.drained_eof);

    let from_start = reg
        .read_since(
            &id,
            &p,
            "cap",
            LogStream::Stdout,
            &LogCursor { token: None },
            100,
        )
        .expect("read-since from start again");
    assert_eq!(from_start.data, b"abcXYZ"); // never drained

    reg.release(&id, &p, "cap").expect("release");
}
