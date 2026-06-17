//! Daemon-restart robustness: orphaned-lock recovery and shim reconnect.
//!
//! These tests validate the on-disk and process-level building blocks of two
//! reliability fixes. The pure decision logic (idempotent-retry allow-set,
//! PID parsing, process-liveness) is unit-tested in the `astrid` binary crate
//! (`commands::daemon_control` and `commands::mcp::server`); this file covers
//! the parts that need real OS resources (a real `ASTRID_HOME`, a real child
//! process, real signals) and therefore cannot run under the sandbox.
//!
//! ## Why `#[ignore]`
//!
//! Tests that touch process-global `ASTRID_HOME` env, spawn child processes,
//! or send signals are `#[ignore]`-gated so they neither race other tests in
//! the shared process nor fail in sandboxed CI (which forbids the syscalls).
//! Run them explicitly:
//!
//! ```sh
//! cargo test -p astrid-integration-tests --test daemon_restart_robustness -- --ignored
//! ```
//!
//! ## Manual end-to-end repro (the bugs these guard against)
//!
//! ### Bug 1 — orphaned lock wedges restart
//!
//! 1. `astrid start` — daemon boots, acquires `run/system.lock`, writes
//!    `run/system.pid`.
//! 2. Wedge it: `kill -STOP $(cat ~/.astrid/run/system.pid)` (simulates a hung
//!    daemon that still holds the state-db lock but can't service the socket).
//! 3. `astrid stop` — BEFORE the fix this just deleted the socket and returned
//!    OK, leaving the STOPPED process holding the lock. AFTER the fix it reads
//!    `system.pid`, sees the process is alive, SIGTERMs then SIGKILLs it, and
//!    only then cleans up the socket/pid files.
//! 4. `astrid start` — succeeds (lock is free). Before the fix it died with
//!    "Database … is already locked by another process".
//!
//! `astrid restart` is the same story end to end: it now verifies the old PID
//! is gone (killing it if `handle_stop` couldn't reach it over the socket)
//! before spawning, so a restart over a wedged daemon succeeds.
//!
//! ### Bug 2 — shim goes stale on daemon restart mid-wait
//!
//! 1. `astrid mcp serve` (the rmcp stdio shim) connects one long-lived uplink.
//! 2. Issue a `tools/list`, then `astrid restart` WHILE a request is awaiting
//!    its reply. Before the fix the shim only reconnected on send failure, so a
//!    death during the response wait timed out and the next request went out on
//!    a stale half-open fd. After the fix the connection-loss is detected
//!    (typed `ReadError::ConnectionLost`), the shim marks itself needs-reconnect
//!    and pre-heals before the next request; an idempotent `tools/list` is even
//!    transparently retried, while a `tools/call` surfaces the error (a mutating
//!    tool may have run) but still heals the connection for the next call.

// `std::env::set_var` is unsafe on edition 2024 (the global env table is not
// thread-safe). The PID-file round-trip test sets `ASTRID_HOME` once and is
// `#[ignore]`-gated so it never runs concurrently with other tests in the
// shared process. Mirrors `gateway_e2e.rs`.
#![allow(unsafe_code)]

use astrid_core::dirs::AstridHome;

/// `AstridHome` resolves the daemon PID file under `run/system.pid`, alongside
/// the socket/token/readiness artifacts. This is the contract the kernel
/// (writer) and the CLI (reader) both rely on; a divergence here would silently
/// break orphan detection.
#[test]
fn pid_path_lives_in_run_dir_next_to_socket() {
    let home = AstridHome::from_path("/tmp/astrid-test-home");
    assert_eq!(home.pid_path(), home.run_dir().join("system.pid"));
    assert_eq!(
        home.pid_path().parent(),
        home.socket_path().parent(),
        "pid file must sit beside the socket so both sides resolve the same run dir"
    );
}

/// End-to-end PID-file lifecycle through the kernel's public API against a real
/// `ASTRID_HOME`: write records the current PID atomically, the CLI-side path
/// helper reads the same value back, and remove clears it. Gated because it
/// mutates process-global `ASTRID_HOME`.
#[test]
#[ignore = "mutates process-global ASTRID_HOME; run with --ignored"]
fn pid_file_write_read_remove_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: single-threaded test entry; we set and restore the env var around
    // the kernel/CLI path resolution. Gated `#[ignore]` so it never races other
    // tests sharing the process.
    unsafe {
        std::env::set_var("ASTRID_HOME", dir.path());
    }

    // Kernel writes its PID after acquiring the lock at boot.
    astrid_kernel::socket::write_pid_file().expect("write_pid_file");

    let pid_path = astrid_kernel::socket::pid_path();
    assert!(pid_path.exists(), "pid file should exist after write");

    // CLI reads the same path: line 1 is the PID, line 2 (optional) is the
    // canonicalized daemon executable used for the identity guard on kill.
    let contents = std::fs::read_to_string(&pid_path).unwrap();
    let mut lines = contents.lines();
    let parsed: u32 = lines
        .next()
        .expect("pid file has a first line")
        .trim()
        .parse()
        .expect("first line is a plain integer");
    assert_eq!(parsed, std::process::id(), "recorded pid is this process");

    // The recorded exe must match this process's canonicalized executable (so
    // the orphan-kill path can confirm identity before signalling). If the
    // platform couldn't resolve current_exe, write_pid_file degrades to PID-only
    // and both sides are None.
    let recorded_exe = lines.next().map(str::trim).filter(|s| !s.is_empty());
    let expected_exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned));
    assert_eq!(
        recorded_exe.map(str::to_owned),
        expected_exe,
        "recorded exe matches this process's canonical executable"
    );

    // Graceful shutdown removes it.
    astrid_kernel::socket::remove_pid_file();
    assert!(!pid_path.exists(), "pid file should be gone after remove");

    unsafe {
        std::env::remove_var("ASTRID_HOME");
    }
}

/// The invariant the whole orphan-kill fix rests on: a process holding the
/// singleton advisory lock releases it the instant it dies (SIGKILL), so a
/// fresh daemon can immediately re-acquire it. This spawns a real child that
/// takes the lock, confirms a second acquisition is blocked, kills the child,
/// and confirms the lock is then free — exactly the sequence `astrid stop`'s
/// orphan-kill path enables on the next `astrid start`.
#[cfg(unix)]
#[test]
#[ignore = "spawns a child process and sends signals; run with --ignored"]
fn killing_lock_holder_frees_the_lock() {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join("system.lock");

    // Hold the lock in a separate process so killing it (not just dropping a
    // handle) is what frees the lock — mirroring an orphaned daemon. The
    // portable, self-contained way without a second test binary is `sh -c`
    // holding an `flock` on fd 9 for its lifetime; skip if `flock` is absent.
    if which::which("flock").is_err() {
        eprintln!("skipping: `flock` not available on this host");
        return;
    }

    // Hold the lock in a child for 30s, signalling readiness on stdout.
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "exec 9>'{}'; flock -n 9 || exit 3; echo ready; sleep 30",
            lock_path.display()
        ))
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn lock-holding child");

    // Wait for the readiness byte so we know the lock is held.
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = [0u8; 5];
    let _ = stdout.read(&mut buf);
    assert!(
        buf.starts_with(b"ready"),
        "child should have acquired the lock and printed ready, got {:?}",
        String::from_utf8_lossy(&buf)
    );

    // While the child holds it, a non-blocking acquisition must fail.
    let contender = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    assert!(
        contender.try_lock().is_err(),
        "lock must be unavailable while the child holds it"
    );
    // Drop our handle's lock attempt state (we never acquired it).
    drop(contender);

    // SIGKILL the holder — the OS releases its flock on death.
    let pid = nix::unistd::Pid::from_raw(child.id() as i32);
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL).expect("kill child");
    let _ = child.wait();

    // Poll: the lock should become acquirable promptly after reap.
    let reacquired = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    let mut got = false;
    for _ in 0..50 {
        if reacquired.try_lock().is_ok() {
            got = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        got,
        "a fresh holder must re-acquire the lock after the previous holder is killed"
    );
}
