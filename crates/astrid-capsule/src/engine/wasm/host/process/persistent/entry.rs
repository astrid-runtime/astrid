//! Per-process state, the monitor / reader tasks, and reaping primitives.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use astrid_core::principal::PrincipalId;
use tokio::sync::watch;

use crate::engine::wasm::bindings::astrid::process1_1_0::host::{
    ErrorCode, ExitInfo, ProcessInfo, ProcessPhase, ProcessSignal,
};

use super::ring::{LogRing, Stream};

/// Terminal state recorded by the monitor task when the child exits.
#[derive(Clone, Copy)]
pub(super) struct ExitRecord {
    pub(super) exit_code: Option<i32>,
    pub(super) signal: Option<i32>,
}

impl From<ExitRecord> for ExitInfo {
    fn from(e: ExitRecord) -> Self {
        ExitInfo {
            exit_code: e.exit_code,
            signal: e.signal,
        }
    }
}

/// Lifecycle phase. Maps to the WIT `process-phase`, which deliberately has
/// no `reaped` — a reaped id resolves to `no-such-process` instead. The host
/// spawns synchronously, so it never reports the WIT's transient `starting`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Running,
    Exited,
}

impl From<Phase> for ProcessPhase {
    fn from(p: Phase) -> Self {
        match p {
            Phase::Running => ProcessPhase::Running,
            Phase::Exited => ProcessPhase::Exited,
        }
    }
}

/// Mutable inner state, guarded by one `Mutex` shared between the monitor
/// task, the reader tasks, and host calls. The lock is held only for short,
/// non-`await` critical sections.
pub(super) struct ProcessCore {
    pub(super) phase: Phase,
    pub(super) exit: Option<ExitRecord>,
    pub(super) exited_at: Option<Instant>,
    pub(super) stdout: LogRing,
    pub(super) stderr: LogRing,
    pub(super) stdin: Option<tokio::process::ChildStdin>,
    pub(super) stdin_open: bool,
    pub(super) last_touch: Instant,
}

/// One persistent process. Metadata is immutable after spawn; live state
/// lives behind `core`.
pub(super) struct PersistentEntry {
    /// The raw `process-id`. Stored so `status` / `list-processes` can return
    /// the reattach key (the WIT requires `process-info.id`); the map is still
    /// *keyed* by the BLAKE3 hash of the id for lookup. Only ever returned to
    /// the owning `(principal, capsule)` — never logged (audit uses a hash).
    pub(super) id: String,
    pub(super) creator: PrincipalId,
    pub(super) capsule_id: Arc<str>,
    pub(super) label: String,
    pub(super) command: String,
    pub(super) os_pid: u32,
    pub(super) tree: Arc<super::super::platform::ProcessTree>,
    pub(super) spawned_at: Instant,
    pub(super) max_lifetime: Duration,
    pub(super) idle_timeout: Duration,
    pub(super) exit_retention: Duration,
    pub(super) core: Arc<Mutex<ProcessCore>>,
    /// Latches the exit so `wait` / `stop` await it without racing the
    /// monitor task or holding the core lock across an `await`.
    pub(super) exit_rx: watch::Receiver<Option<ExitRecord>>,
    /// The monitor task owning the `Child`. Tree termination happens before
    /// abort; dropping the child then remains the root-process reap backstop.
    pub(super) monitor: tokio::task::JoinHandle<()>,
    /// Cleanup guard for any read-only file injections wired into this child's
    /// sandbox. Held for the process's lifetime; its `Drop` (Linux scratch dir
    /// removal / macOS target unlink) fires when the entry is consumed by
    /// `reap_entry`. `None` when the spawn had no injections.
    #[allow(dead_code)] // Held purely for its Drop; never read after spawn.
    pub(super) injection_guard: Option<super::super::inject::InjectionGuard>,
}

impl PersistentEntry {
    pub(super) fn is_live(&self) -> bool {
        self.core
            .lock()
            .map(|c| c.phase != Phase::Exited)
            .unwrap_or(false)
    }

    /// Non-draining status snapshot. Returns the reattach `id` (the WIT
    /// `process-info.id`); the caller is always the owning principal+capsule.
    pub(super) fn info(&self) -> ProcessInfo {
        let c = self.core.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let running = c.phase != Phase::Exited;
        ProcessInfo {
            id: self.id.clone(),
            label: self.label.clone(),
            command: self.command.clone(),
            os_pid: running.then_some(self.os_pid),
            phase: c.phase.into(),
            exit: c.exit.map(Into::into),
            age_ms: now.saturating_duration_since(self.spawned_at).as_millis() as u64,
            idle_ms: now.saturating_duration_since(c.last_touch).as_millis() as u64,
            buffered_bytes: (c.stdout.len() + c.stderr.len()) as u64,
            bytes_dropped: c.stdout.overflow_dropped + c.stderr.overflow_dropped,
            stdin_open: c.stdin_open,
            cpu_ms: None,         // (NOT YET POPULATED — see WIT)
            mem_bytes_peak: None, // (NOT YET POPULATED — see WIT)
        }
    }
}

/// Handles cloned out of an entry so a host call can act without holding the
/// registry map lock.
pub(super) struct Resolved {
    pub(super) key: [u8; 32],
    pub(super) core: Arc<Mutex<ProcessCore>>,
    pub(super) exit_rx: watch::Receiver<Option<ExitRecord>>,
    pub(super) tree: Arc<super::super::platform::ProcessTree>,
}

/// Read the current exit (if any) without holding a lock across `await`.
pub(super) fn current_exit(core: &Arc<Mutex<ProcessCore>>) -> Option<ExitRecord> {
    core.lock().ok().and_then(|c| c.exit)
}

/// Await the next non-`None` exit value on a watch receiver.
pub(super) async fn wait_for_exit(
    rx: &mut watch::Receiver<Option<ExitRecord>>,
) -> Option<ExitRecord> {
    if let Some(e) = *rx.borrow() {
        return Some(e);
    }
    loop {
        if rx.changed().await.is_err() {
            return None;
        }
        if let Some(e) = *rx.borrow() {
            return Some(e);
        }
    }
}

/// Spawn the monitor task that owns the `Child`, records its exit into
/// `core`, and notifies `exit_tx`. Returns the join handle (aborting it
/// drops the `Child`, whose `kill_on_drop` is the root-process reap backstop).
pub(super) fn spawn_monitor(
    runtime: &tokio::runtime::Handle,
    mut child: tokio::process::Child,
    tree: Arc<super::super::platform::ProcessTree>,
    core: Arc<Mutex<ProcessCore>>,
    exit_tx: watch::Sender<Option<ExitRecord>>,
) -> tokio::task::JoinHandle<()> {
    runtime.spawn(async move {
        let status = child.wait().await;
        #[cfg(windows)]
        if let Err(error) = tree.terminate(super::super::platform::Termination::Force) {
            tracing::warn!(
                pid = tree.pid(),
                ?error,
                "failed to terminate persistent process descendants after root exit"
            );
        }
        #[cfg(not(windows))]
        let _ = tree;
        let record = match status {
            Ok(st) => ExitRecord {
                exit_code: st.code(),
                signal: exit_signal(&st),
            },
            Err(_) => ExitRecord {
                exit_code: Some(-1),
                signal: None,
            },
        };
        if let Ok(mut c) = core.lock() {
            c.phase = Phase::Exited;
            c.exit = Some(record);
            c.exited_at = Some(Instant::now());
            c.stdin = None;
            c.stdin_open = false;
        }
        let _ = exit_tx.send(Some(record));
        // `child` drops here: already exited, so `kill_on_drop` is a no-op.
        // If the task is aborted before exit, dropping the child forces its
        // root process to terminate instead.
    })
}

#[cfg(unix)]
fn exit_signal(st: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt as _;
    st.signal()
}

#[cfg(not(unix))]
fn exit_signal(_st: &std::process::ExitStatus) -> Option<i32> {
    None
}

/// Reader read size. MUST be `<=` the minimum ring capacity
/// (`config::MIN_LOG_RING_BYTES` = 4096) so a full chunk always fits in an
/// *empty* `backpressure` ring — otherwise an over-cap chunk could never be
/// accepted (all-or-nothing) and the reader would spin forever.
pub(super) const READER_CHUNK_BYTES: usize = 4096;

/// Spawn a reader task draining a child pipe into the in-core ring. Honors
/// `backpressure` by parking (not reading) when the ring is full — the OS
/// pipe fills and the child blocks on write; the WASM task is never parked.
pub(super) fn spawn_ring_reader<R>(
    runtime: &tokio::runtime::Handle,
    mut pipe: R,
    core: Arc<Mutex<ProcessCore>>,
    which: Stream,
) where
    R: tokio::io::AsyncReadExt + Unpin + Send + 'static,
{
    runtime.spawn(async move {
        let mut chunk = vec![0u8; READER_CHUNK_BYTES];
        loop {
            match pipe.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    let mut accepted = false;
                    while !accepted {
                        {
                            let mut c = core.lock().unwrap_or_else(|e| e.into_inner());
                            let ring = match which {
                                Stream::Out => &mut c.stdout,
                                Stream::Err => &mut c.stderr,
                            };
                            accepted = ring.push(&chunk[..n]);
                        }
                        if !accepted {
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                    }
                },
                Err(_) => break,
            }
        }
    });
}

/// Reap an entry removed from the map: force the tree (best effort) and abort
/// the monitor (dropping its `Child`, the `kill_on_drop` backstop).
pub(super) fn reap_entry(entry: PersistentEntry) -> Result<(), ErrorCode> {
    let result = entry
        .tree
        .terminate(super::super::platform::Termination::Force);
    entry.monitor.abort();
    result
}

/// Deliver a WIT signal through the platform backend.
pub(super) fn send_signal(
    tree: &super::super::platform::ProcessTree,
    signal: ProcessSignal,
) -> Result<(), ErrorCode> {
    super::super::platform::signal_process_tree(tree, signal)
}
