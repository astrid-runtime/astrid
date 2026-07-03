//! Bundled daemon binary — installed alongside `astrid` via `cargo install astrid`.
//!
//! Delegates to the shared `astrid_daemon::run()` library function. This is
//! identical to the standalone `astrid-daemon` binary but co-installed with
//! the CLI so `find_companion_binary("astrid-daemon")` always finds it.

/// Detach the daemon into its own session as the very first action — before the
/// async runtime is built or any boot work runs.
///
/// The CLI spawns the daemon as a plain child process, so without this it
/// inherits the spawner's session and process group. When that spawner tears
/// down — a smoke-test harness exiting, a controlling terminal closing — the
/// process group is signalled (`SIGHUP`/`SIGTERM`/`killpg`) and the daemon would
/// be killed BEFORE it can run its own graceful shutdown, leaking stale run
/// files (`run/system.{sock,pid,ready,token}`) for the next `start` to trip on.
/// `setsid(2)` makes the daemon a session leader with no controlling terminal,
/// immune to the spawner's teardown, so its shutdown path always runs. One call
/// covers both the ephemeral and persistent spawn modes.
///
/// Best-effort: `setsid` fails only with `EPERM`, which means the process is
/// already a process-group leader (already detached) — ignoring the result is
/// correct. Uses the safe `nix` wrapper, not raw `libc`, so this stays within
/// the crate's `#![deny(unsafe_code)]`.
fn main() -> anyhow::Result<()> {
    #[cfg(unix)]
    let _ = nix::unistd::setsid();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(astrid_daemon::run())
}
