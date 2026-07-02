//! `PersistentProcessRegistry` — host-owned storage for the PERSISTENT tier
//! of `astrid:process@1.0.0`.
//!
//! # Why this exists
//!
//! The EPHEMERAL tier (`spawn-background`) stores its `ManagedProcess` inside
//! the spawning instance's wasmtime resource table, so the child is reaped
//! when that instance is reset on return to the dynamic pool. A background
//! process started in one tool invocation therefore cannot survive to the
//! next — the split `spawn → read-logs → stop` pattern is impossible on a
//! pooled, stateless instance.
//!
//! The persistent tier relocates ownership OFF the instance: the child, its
//! log rings, and its stdin pipe live in this registry, which is an `Arc`
//! cloned into every pooled `HostState` of a capsule exactly like
//! [`ProcessTracker`](super::ProcessTracker). The registry outlives any
//! single instance, so a `process-id` minted on instance A is reattachable
//! from instance B.
//!
//! # Lifetime & reaping
//!
//! Reaped by explicit [`stop`](Self::stop) / [`release`](Self::release); the
//! per-entry idle / max-lifetime / exit-retention TTLs (the
//! [`reap_sweep`](Self::reap_sweep) the engine drives on a timer); or capsule
//! unload / daemon graceful shutdown ([`shutdown`](Self::shutdown)). NOT by
//! instance reset.
//!
//! On Linux the child is spawned under `bwrap --unshare-all --die-with-parent`
//! so the kernel reaps it even on a daemon SIGKILL. macOS Seatbelt has no
//! die-with-parent, so a daemon *hard crash* can orphan a still-sandboxed
//! child; graceful shutdown and capsule unload reap correctly. A weaker
//! cleanup guarantee, not a containment gap — the orphan stays inside its
//! Seatbelt profile.
//!
//! # Security model
//!
//! The `process-id` is a 256-bit host-minted CSPRNG token (lowercase base32,
//! see [`ids`]). The registry stores only a keyed BLAKE3 hash of the id,
//! never the raw token. Possession is necessary but NOT sufficient: every
//! id-keyed call re-resolves the live `(principal, capsule)` and checks them
//! against the recorded creator before touching the entry, so a leaked token
//! is inert across the principal/capsule boundary. Unknown / wrong-owner /
//! wrong-capsule / reaped / malformed all collapse to `no-such-process` with
//! no distinguishing oracle.

mod config;
mod entry;
mod ids;
#[cfg(test)]
mod registry_tests;
mod ring;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use astrid_core::principal::PrincipalId;
use rand::{TryRng, rngs::SysRng};
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use crate::engine::wasm::bindings::astrid::process1_1_0::host::{
    ErrorCode, ExitInfo, LogChunk, LogCursor, LogStream, OverflowPolicy, ProcessInfo,
    ProcessSignal, ReadLogsResult,
};

use config::{
    DEFAULT_STOP_GRACE, MAX_READ_SINCE_BYTES, MAX_REGISTRY_ENTRIES, MAX_RETAINED_PER_PRINCIPAL,
    MAX_STDIN_WRITE, MAX_STOP_GRACE, clamp_label, clamp_log_ring, overflow_from_wit, resolve_ttls,
};
use entry::{
    PersistentEntry, Phase, ProcessCore, current_exit, map_signal, reap_entry, send_signal,
    spawn_monitor, spawn_ring_reader, wait_for_exit,
};
use ids::mint_id;
use ring::{LogRing, Stream, decode_cursor, encode_cursor};

/// Keyed-hash map key derived from a `process-id` token.
type IdHash = [u8; 32];

/// Everything the registry needs to take ownership of a freshly-spawned
/// child. The caller (`spawn-persistent` host fn) has already run the
/// `host_process` capability gate and built the sandboxed `Child`; the
/// registry normalises the request knobs and enforces the caps.
pub(in crate::engine::wasm::host::process) struct SpawnParams {
    pub(in crate::engine::wasm::host::process) creator: PrincipalId,
    pub(in crate::engine::wasm::host::process) capsule_id: Arc<str>,
    /// cmd + args, as the capsule requested it (for display / label default).
    pub(in crate::engine::wasm::host::process) command: String,
    pub(in crate::engine::wasm::host::process) os_pid: u32,
    pub(in crate::engine::wasm::host::process) child: tokio::process::Child,
    pub(in crate::engine::wasm::host::process) stdout: tokio::process::ChildStdout,
    pub(in crate::engine::wasm::host::process) stderr: tokio::process::ChildStderr,
    pub(in crate::engine::wasm::host::process) stdin: Option<tokio::process::ChildStdin>,
    /// Per-principal CONCURRENT cap (the profile's `max_background_processes`).
    pub(in crate::engine::wasm::host::process) concurrent_cap: usize,
    // ---- raw request knobs (normalised inside `spawn`) ----
    pub(in crate::engine::wasm::host::process) label: Option<String>,
    pub(in crate::engine::wasm::host::process) overflow: Option<OverflowPolicy>,
    pub(in crate::engine::wasm::host::process) log_ring_bytes: Option<u32>,
    pub(in crate::engine::wasm::host::process) max_lifetime_ms: Option<u64>,
    pub(in crate::engine::wasm::host::process) idle_timeout_ms: Option<u64>,
    pub(in crate::engine::wasm::host::process) exit_retention_ms: Option<u64>,
    /// Cleanup guard for any read-only file injections wired into the child's
    /// sandbox. Stored on the entry so it lives as long as the persistent
    /// process and cleans up when the entry is reaped (`reap_entry` consumes
    /// the entry by value on every reap path, so the guard's drop fires then).
    pub(in crate::engine::wasm::host::process) injection_guard:
        Option<super::inject::InjectionGuard>,
}

/// Host-owned registry of a capsule's persistent processes. Cloned (`Arc`)
/// into every pooled `HostState` so an id survives instance churn.
pub struct PersistentProcessRegistry {
    entries: Mutex<HashMap<IdHash, PersistentEntry>>,
    /// Per-registry random key for the keyed BLAKE3 id hash, so the stored
    /// map keys are not a precomputable function of the token alone.
    hash_key: [u8; 32],
    /// The daemon runtime — children must NOT be owned by an instance's
    /// executor or they would die with the instance.
    runtime: tokio::runtime::Handle,
}

impl std::fmt::Debug for PersistentProcessRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.entries.lock().map(|e| e.len()).unwrap_or(0);
        f.debug_struct("PersistentProcessRegistry")
            .field("entries", &n)
            .finish()
    }
}

impl PersistentProcessRegistry {
    /// Construct a registry bound to a tokio runtime handle.
    #[must_use]
    pub fn new(runtime: tokio::runtime::Handle) -> Self {
        let mut hash_key = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut hash_key)
            .expect("OS CSPRNG unavailable while creating process registry hash key");
        Self {
            entries: Mutex::new(HashMap::new()),
            hash_key,
            runtime,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<IdHash, PersistentEntry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn key_of(&self, id: &str) -> IdHash {
        *blake3::keyed_hash(&self.hash_key, id.as_bytes()).as_bytes()
    }

    /// Resolve a token to the shared handles needed to act WITHOUT holding
    /// the map lock, IF the caller owns it. Touches the idle clock.
    fn resolve(
        &self,
        id: &str,
        principal: &PrincipalId,
        capsule_id: &str,
    ) -> Result<entry::Resolved, ErrorCode> {
        let key = self.key_of(id);
        let map = self.lock();
        let entry = map.get(&key).ok_or(ErrorCode::NoSuchProcess)?;
        if &entry.creator != principal || &*entry.capsule_id != capsule_id {
            return Err(ErrorCode::NoSuchProcess);
        }
        if let Ok(mut core) = entry.core.lock() {
            core.last_touch = Instant::now();
        }
        Ok(entry::Resolved {
            key,
            core: Arc::clone(&entry.core),
            exit_rx: entry.exit_rx.clone(),
            os_pid: entry.os_pid,
        })
    }

    /// Spawn a persistent process, returning its `process-id`. Enforces the
    /// concurrent + retained + global caps atomically under the map lock.
    pub(in crate::engine::wasm::host::process) fn spawn(
        &self,
        p: SpawnParams,
    ) -> Result<String, ErrorCode> {
        let mut map = self.lock();
        if map.len() >= MAX_REGISTRY_ENTRIES {
            drop(map);
            return reject_spawn(p, ErrorCode::RegistryFull);
        }
        let (mut live, mut retained) = (0usize, 0usize);
        for e in map.values() {
            if e.creator == p.creator {
                retained += 1;
                if e.is_live() {
                    live += 1;
                }
            }
        }
        if retained >= MAX_RETAINED_PER_PRINCIPAL {
            drop(map);
            return reject_spawn(p, ErrorCode::RegistryFull);
        }
        if live >= p.concurrent_cap {
            drop(map);
            return reject_spawn(p, ErrorCode::Quota);
        }

        let label = clamp_label(p.label, &p.command);
        let log_ring = clamp_log_ring(p.log_ring_bytes);
        let overflow = overflow_from_wit(p.overflow);
        let (max_lifetime, idle_timeout, exit_retention) =
            resolve_ttls(p.max_lifetime_ms, p.idle_timeout_ms, p.exit_retention_ms);

        let core = Arc::new(Mutex::new(ProcessCore {
            phase: Phase::Running,
            exit: None,
            exited_at: None,
            stdout: LogRing::new(log_ring, overflow),
            stderr: LogRing::new(log_ring, overflow),
            stdin: p.stdin,
            stdin_open: false,
            last_touch: Instant::now(),
        }));
        {
            let mut c = core.lock().unwrap_or_else(|e| e.into_inner());
            c.stdin_open = c.stdin.is_some();
        }
        spawn_ring_reader(&self.runtime, p.stdout, Arc::clone(&core), Stream::Out);
        spawn_ring_reader(&self.runtime, p.stderr, Arc::clone(&core), Stream::Err);
        let (exit_tx, exit_rx) = watch::channel::<Option<entry::ExitRecord>>(None);
        let monitor = spawn_monitor(&self.runtime, p.child, Arc::clone(&core), exit_tx);
        let injection_guard = p.injection_guard;

        let mut id = mint_id();
        let mut key = self.key_of(&id);
        let mut tries = 0;
        while map.contains_key(&key) {
            id = mint_id();
            key = self.key_of(&id);
            tries += 1;
            if tries > 8 {
                // 256-bit space: unreachable in practice. Fail closed.
                monitor.abort();
                return Err(ErrorCode::Unknown(
                    "process-id collision space exhausted".to_string(),
                ));
            }
        }
        map.insert(
            key,
            PersistentEntry {
                id: id.clone(),
                creator: p.creator,
                capsule_id: p.capsule_id,
                label,
                command: p.command,
                os_pid: p.os_pid,
                spawned_at: Instant::now(),
                max_lifetime,
                idle_timeout,
                exit_retention,
                core,
                exit_rx,
                monitor,
                injection_guard,
            },
        );
        Ok(id)
    }

    /// Number of LIVE (not-yet-exited) persistent processes a principal owns.
    /// Lets the ephemeral `spawn-background` tier share the per-principal
    /// concurrent cap with the persistent tier (and vice-versa).
    pub(in crate::engine::wasm::host::process) fn live_count(
        &self,
        principal: &PrincipalId,
    ) -> usize {
        self.lock()
            .values()
            .filter(|e| &e.creator == principal && e.is_live())
            .count()
    }

    /// Non-draining status snapshot of one process.
    pub(in crate::engine::wasm::host::process) fn status(
        &self,
        id: &str,
        principal: &PrincipalId,
        capsule_id: &str,
    ) -> Result<ProcessInfo, ErrorCode> {
        let key = self.key_of(id);
        let map = self.lock();
        let entry = map.get(&key).ok_or(ErrorCode::NoSuchProcess)?;
        if &entry.creator != principal || &*entry.capsule_id != capsule_id {
            return Err(ErrorCode::NoSuchProcess);
        }
        Ok(entry.info())
    }

    /// `status` for many ids in one pass; unknown / unowned ids are absent.
    pub(in crate::engine::wasm::host::process) fn status_many(
        &self,
        ids: &[String],
        principal: &PrincipalId,
        capsule_id: &str,
    ) -> Vec<ProcessInfo> {
        let map = self.lock();
        ids.iter()
            .filter_map(|id| {
                let entry = map.get(&self.key_of(id))?;
                (entry.creator == *principal && &*entry.capsule_id == capsule_id)
                    .then(|| entry.info())
            })
            .collect()
    }

    /// List the caller `(capsule, principal)`'s processes, optional label
    /// substring filter.
    pub(in crate::engine::wasm::host::process) fn list(
        &self,
        principal: &PrincipalId,
        capsule_id: &str,
        label_filter: Option<&str>,
    ) -> Vec<ProcessInfo> {
        let map = self.lock();
        map.values()
            .filter(|e| e.creator == *principal && &*e.capsule_id == capsule_id)
            .filter(|e| label_filter.is_none_or(|f| e.label.contains(f)))
            .map(PersistentEntry::info)
            .collect()
    }

    /// Drain both rings (the `read-logs` semantics).
    pub(in crate::engine::wasm::host::process) fn read_logs(
        &self,
        id: &str,
        principal: &PrincipalId,
        capsule_id: &str,
    ) -> Result<ReadLogsResult, ErrorCode> {
        let r = self.resolve(id, principal, capsule_id)?;
        let mut core = r.core.lock().unwrap_or_else(|e| e.into_inner());
        let stdout = String::from_utf8_lossy(&core.stdout.drain()).into_owned();
        let stderr = String::from_utf8_lossy(&core.stderr.drain()).into_owned();
        let running = core.phase != Phase::Exited;
        let exit = core.exit.map(Into::into);
        Ok(ReadLogsResult {
            stdout,
            stderr,
            running,
            exit,
        })
    }

    /// Non-draining, cursor-addressed read over one stream.
    pub(in crate::engine::wasm::host::process) fn read_since(
        &self,
        id: &str,
        principal: &PrincipalId,
        capsule_id: &str,
        which: LogStream,
        cursor: &LogCursor,
        max_bytes: u32,
    ) -> Result<LogChunk, ErrorCode> {
        let r = self.resolve(id, principal, capsule_id)?;
        let max = (max_bytes as usize).min(MAX_READ_SINCE_BYTES);
        let from = decode_cursor(cursor)?;
        let core = r.core.lock().unwrap_or_else(|e| e.into_inner());
        let ring = match which {
            LogStream::Stdout => &core.stdout,
            LogStream::Stderr => &core.stderr,
        };
        let exited = core.phase == Phase::Exited;
        let (data, next, dropped) = ring.read_since(from, max);
        let drained_eof = exited && next >= ring.end_offset();
        Ok(LogChunk {
            data,
            next: encode_cursor(next),
            bytes_dropped: dropped,
            drained_eof,
        })
    }

    /// Fire-and-forget signal to the child's process group. A signal to an
    /// already-exited (but unreaped) id is an idempotent success.
    pub(in crate::engine::wasm::host::process) fn signal(
        &self,
        id: &str,
        principal: &PrincipalId,
        capsule_id: &str,
        sig: ProcessSignal,
    ) -> Result<(), ErrorCode> {
        let r = self.resolve(id, principal, capsule_id)?;
        if r.core
            .lock()
            .map(|c| c.phase == Phase::Exited)
            .unwrap_or(true)
        {
            return Ok(());
        }
        send_signal(r.os_pid, map_signal(sig))
    }

    /// Write to stdin (requires `keep-stdin-open`).
    pub(in crate::engine::wasm::host::process) async fn write_stdin(
        &self,
        id: &str,
        principal: &PrincipalId,
        capsule_id: &str,
        data: &[u8],
    ) -> Result<u32, ErrorCode> {
        if data.len() > MAX_STDIN_WRITE {
            return Err(ErrorCode::TooLarge);
        }
        let core = self.resolve(id, principal, capsule_id)?.core;
        // Take the pipe out under the lock, write outside it, restore it.
        let mut pipe = {
            let mut c = core.lock().unwrap_or_else(|e| e.into_inner());
            if !c.stdin_open {
                return Err(ErrorCode::Closed);
            }
            c.stdin.take().ok_or(ErrorCode::Closed)?
        };
        let res = pipe.write_all(data).await;
        let mut c = core.lock().unwrap_or_else(|e| e.into_inner());
        match res {
            Ok(()) if c.stdin_open => {
                c.stdin = Some(pipe);
                Ok(data.len() as u32)
            },
            Ok(()) => Ok(data.len() as u32), // closed concurrently; drop pipe
            Err(_) => {
                c.stdin_open = false;
                Err(ErrorCode::Closed)
            },
        }
    }

    /// Close stdin (child sees EOF). Idempotent.
    pub(in crate::engine::wasm::host::process) fn close_stdin(
        &self,
        id: &str,
        principal: &PrincipalId,
        capsule_id: &str,
    ) -> Result<(), ErrorCode> {
        let core = self.resolve(id, principal, capsule_id)?.core;
        let mut c = core.lock().unwrap_or_else(|e| e.into_inner());
        c.stdin = None;
        c.stdin_open = false;
        Ok(())
    }

    /// Await exit up to a bounded timeout. Does NOT reap.
    pub(in crate::engine::wasm::host::process) async fn wait(
        &self,
        id: &str,
        principal: &PrincipalId,
        capsule_id: &str,
        timeout: Duration,
    ) -> Result<ExitInfo, ErrorCode> {
        let r = self.resolve(id, principal, capsule_id)?;
        if let Some(e) = current_exit(&r.core) {
            return Ok(e.into());
        }
        let mut rx = r.exit_rx;
        match tokio::time::timeout(timeout, wait_for_exit(&mut rx)).await {
            Ok(Some(e)) => Ok(e.into()),
            Ok(None) => Err(ErrorCode::Unknown("exit channel closed".to_string())),
            Err(_) => Err(ErrorCode::WaitTimeout),
        }
    }

    /// Graceful terminal stop: SIGTERM → grace → SIGKILL, then REMOVE the id
    /// (frees the concurrent + retained slot).
    pub(in crate::engine::wasm::host::process) async fn stop(
        &self,
        id: &str,
        principal: &PrincipalId,
        capsule_id: &str,
        grace: Option<Duration>,
    ) -> Result<ExitInfo, ErrorCode> {
        let r = self.resolve(id, principal, capsule_id)?;
        let grace = grace.unwrap_or(DEFAULT_STOP_GRACE).min(MAX_STOP_GRACE);

        let exit = if let Some(e) = current_exit(&r.core) {
            e
        } else {
            let _ = send_signal(r.os_pid, nix::sys::signal::Signal::SIGTERM);
            let mut rx = r.exit_rx.clone();
            match tokio::time::timeout(grace, wait_for_exit(&mut rx)).await {
                Ok(Some(e)) => e,
                _ => {
                    let _ = send_signal(r.os_pid, nix::sys::signal::Signal::SIGKILL);
                    let mut rx2 = r.exit_rx.clone();
                    match tokio::time::timeout(MAX_STOP_GRACE, wait_for_exit(&mut rx2)).await {
                        Ok(Some(e)) => e,
                        _ => entry::ExitRecord {
                            exit_code: None,
                            signal: Some(9),
                        },
                    }
                },
            }
        };
        // Remove under the lock, reap (killpg + abort) OUTSIDE it so the
        // syscall never stalls other registry ops.
        let removed = self.lock().remove(&r.key);
        if let Some(entry) = removed {
            reap_entry(entry);
        }
        Ok(exit.into())
    }

    /// Drop retention of an ALREADY-EXITED process. `invalid-input` if still
    /// running. Idempotent (an unknown id is success — already gone).
    pub(in crate::engine::wasm::host::process) fn release(
        &self,
        id: &str,
        principal: &PrincipalId,
        capsule_id: &str,
    ) -> Result<(), ErrorCode> {
        let key = self.key_of(id);
        let mut map = self.lock();
        let Some(entry) = map.get(&key) else {
            return Ok(());
        };
        if entry.creator != *principal || &*entry.capsule_id != capsule_id {
            return Err(ErrorCode::NoSuchProcess);
        }
        if entry.is_live() {
            return Err(ErrorCode::InvalidInput);
        }
        let removed = map.remove(&key);
        drop(map);
        if let Some(entry) = removed {
            reap_entry(entry);
        }
        Ok(())
    }

    /// Sweep idle / over-lifetime / exit-retention-elapsed entries. The
    /// engine drives this on a timer. Returns the count reaped.
    pub fn reap_sweep(&self) -> usize {
        let now = Instant::now();
        let mut to_remove: Vec<IdHash> = Vec::new();
        {
            let map = self.lock();
            for (key, e) in map.iter() {
                let (phase, exited_at, idle) = {
                    let c = e.core.lock().unwrap_or_else(|p| p.into_inner());
                    (
                        c.phase,
                        c.exited_at,
                        now.saturating_duration_since(c.last_touch),
                    )
                };
                let reap = match phase {
                    Phase::Exited => exited_at
                        .map(|t| now.saturating_duration_since(t) >= e.exit_retention)
                        .unwrap_or(true),
                    _ => {
                        now.saturating_duration_since(e.spawned_at) >= e.max_lifetime
                            || idle >= e.idle_timeout
                    },
                };
                if reap {
                    to_remove.push(*key);
                }
            }
        }
        let mut reaped = Vec::new();
        {
            let mut map = self.lock();
            for key in to_remove {
                if let Some(entry) = map.remove(&key) {
                    reaped.push(entry);
                }
            }
        }
        // Reap (killpg + abort) outside the map lock.
        let n = reaped.len();
        for entry in reaped {
            reap_entry(entry);
        }
        n
    }

    /// Kill + clear every entry (capsule unload / daemon graceful shutdown).
    pub fn shutdown(&self) {
        let drained: Vec<PersistentEntry> = self.lock().drain().map(|(_, e)| e).collect();
        for entry in drained {
            reap_entry(entry);
        }
    }
}

fn reject_spawn(mut p: SpawnParams, err: ErrorCode) -> Result<String, ErrorCode> {
    let _ = entry::send_signal(p.os_pid, nix::sys::signal::Signal::SIGKILL);
    let _ = p.child.start_kill();
    let _ = p.child.try_wait();
    Err(err)
}
