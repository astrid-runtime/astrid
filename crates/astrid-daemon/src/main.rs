//! Standalone daemon binary entry point.
//!
//! Delegates to the shared `astrid_daemon::run_to_completion()` lifecycle.

// Cranelift's parallel compilation allocates heavily on every worker. MUSL's
// shared allocator lock can turn a cold capsule boot into minutes of futex
// contention. Select a concurrent Rust allocator in the executable only;
// embedders, other targets and guest resource accounting remain unchanged.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Detach the daemon into its own session as the very first action — before the
/// async runtime is built or any boot work runs.
///
/// A daemon spawned as a plain child inherits the spawner's session and process
/// group, so a spawner teardown (a controlling terminal closing → `SIGHUP`, a
/// harness `killpg`) would kill it BEFORE its own graceful shutdown could run,
/// leaking stale run files. `setsid(2)` makes it a session leader with no
/// controlling terminal, immune to that teardown. Kept byte-for-byte in step
/// with the co-installed `astrid-daemon` binary in `astrid-cli`.
///
/// Best-effort: `setsid` fails only with `EPERM`, which means the process is
/// already a process-group leader (already detached) — ignoring the result is
/// correct. Uses the safe `nix` wrapper, not raw `libc`.
fn main() -> anyhow::Result<()> {
    #[cfg(unix)]
    let _ = nix::unistd::setsid();

    astrid_daemon::run_to_completion()
}
