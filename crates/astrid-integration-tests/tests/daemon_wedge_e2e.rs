//! Daemon-wedge end-to-end: the singleton boot-race and lock-release fixes.
//!
//! A live daemon wedged (alive, holding the audit `LOCK`, ignoring `SIGTERM`)
//! and, on kill, multiple daemons raced to re-boot. This file drives the boot
//! path of a real [`astrid_kernel::Kernel`] against a temp `ASTRID_HOME` to
//! prove the singleton-ordering fix: the singleton advisory flock is now the
//! FIRST fallible boot step (before the KV/audit stores open), so a boot-race
//! loser reports the actionable "already running (singleton lock held)" error
//! instead of dying on a raw surrealkv `Database ... LOCK is already locked`
//! from a store it should never have opened.
//!
//! This file covers the boot-race the wedge fixes converge on. The other halves
//! are covered where they can be exercised faithfully:
//!
//! * audit-lock release on shutdown (`AuditLog::close`) — unit-tested in
//!   `astrid-audit` (`close_releases_lock_so_same_dir_reopens`);
//! * the OS-thread signal watchdog decision logic — unit-tested in
//!   `astrid-daemon` (`signal::tests`);
//! * the exempt-run-loop cooperative yield that un-pins the worker (Fix 5), and
//!   cancellation stopping a compute-bound run-loop (Fix 6) — exercised on the
//!   real wasmtime engine in `astrid-capsule`
//!   (`epoch_integration_tests::exempt_*`).
//!
//! KNOWN GAP: a full daemon-level reproduction — a real daemon whose tokio
//! workers are all pinned by an exempt run-loop tight-compute capsule, then
//! `SIGTERM`, asserting exit within the watchdog grace — is NOT yet automated.
//! It requires a compute-pinning exempt run-loop capsule fixture and the full
//! capsule fleet the runtime bash harness assembles (a bare daemon refuses to
//! boot without the CLI proxy capsule), so it belongs in that harness rather
//! than the sandboxed workspace test matrix. The engine-level `exempt_*` tests
//! above prove the un-pinning mechanism the daemon relies on; the end-to-end
//! harness scenario is a tracked follow-up.
//!
//! ## Why `#[ignore]`
//!
//! Booting a `Kernel` binds a real Unix socket and reads the process-global
//! `ASTRID_HOME` env, so these tests are `#[ignore]`-gated: they neither race
//! other tests in the shared process nor fail in sandboxed CI (which forbids the
//! socket bind). Run them explicitly (single-threaded — the env is global):
//!
//! ```sh
//! cargo test -p astrid-integration-tests --test daemon_wedge_e2e -- --ignored --test-threads=1
//! ```

// `std::env::set_var` is unsafe on edition 2024 (the global env table is not
// thread-safe). This binary sets `ASTRID_HOME` once before any kernel boot and
// is `#[ignore]`-gated so it never runs concurrently with other tests. Mirrors
// `gateway_e2e.rs` / `daemon_restart_robustness.rs`.
#![allow(unsafe_code)]

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use tempfile::TempDir;

/// `std::env::set_var` is disallowed by the workspace lint policy; permitted
/// here because it runs once at the top of a single-test binary before any
/// other thread reads `ASTRID_HOME`, so there is no thread-safety hazard.
#[allow(clippy::disallowed_methods)]
fn set_astrid_home(dir: &TempDir) {
    // Safety: invoked once, before any kernel boot reads $ASTRID_HOME.
    unsafe {
        std::env::set_var("ASTRID_HOME", dir.path());
    }
}

/// Boot a minimal kernel with default limits against the current `ASTRID_HOME`.
/// No capsules are loaded (that is a separate step) — this exercises only the
/// native boot side-effects: lock, stores, socket, token.
async fn new_test_kernel() -> Result<Arc<astrid_kernel::Kernel>, std::io::Error> {
    astrid_kernel::Kernel::new(
        astrid_core::SessionId::new(),
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        astrid_capsule::CapsuleRuntimeLimits::default(),
        std::collections::HashMap::new(),
        astrid_capsule::HttpLimits::default(),
    )
    .await
}

/// A boot-race loser reports "already running (singleton lock held)" and never
/// leaks a raw store-lock error.
///
/// Fails on the pre-fix ordering: with the KV/audit stores opened before the
/// flock, the second boot dies on a surrealkv `LOCK is already locked` from the
/// KV open instead of the singleton message.
///
/// (The lock is released by process exit — the daemon's contract — not by
/// dropping the in-process `Kernel`, whose background tasks keep it alive; so
/// this asserts only the loser's error, not an in-process reboot.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binds a real socket + mutates process-global ASTRID_HOME; run with --ignored"]
async fn boot_race_loser_reports_already_running_not_raw_store_lock() {
    let dir = TempDir::new().expect("temp home");
    set_astrid_home(&dir);
    let home = AstridHome::from_path(dir.path());
    home.ensure().expect("prepare temp ASTRID_HOME tree");

    // A first-boot failure is environmental (sandbox blocks the socket bind, or
    // the temp path exceeds the platform's `sun_path` limit) — skip rather than
    // fail. Only the SECOND boot's error is the assertion target.
    let kernel_a = match new_test_kernel().await {
        Ok(kernel) => kernel,
        Err(e) => {
            eprintln!("skipping daemon-wedge e2e: environment cannot boot a kernel ({e})");
            return;
        },
    };

    // Fix 1: a second boot on the SAME home must lose the singleton race at the
    // flock — the FIRST fallible boot step — and say "already running", NOT die
    // on a raw surrealkv store LOCK it would only reach if the stores opened
    // before the flock (the pre-fix ordering).
    // `Kernel` is not `Debug`, so use `let...else` rather than `expect_err`.
    let Err(err) = new_test_kernel().await else {
        panic!("second boot must lose the singleton race while the first holds the lock");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("already running") && msg.contains("singleton lock held"),
        "boot-race loser must report the singleton message; got: {msg}"
    );
    assert!(
        !msg.to_lowercase().contains("lock is already locked"),
        "boot-race loser must fail at the flock, not leak a raw store-lock error: {msg}"
    );

    // Graceful shutdown must run cleanly (this is the path that now also closes
    // the audit log — Fix 2 — releasing its surrealkv LOCK before process exit).
    kernel_a.shutdown(Some("wedge-e2e".to_string())).await;
}
