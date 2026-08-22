//! Kernel implementation of the capsule host-audit sink.
//!
//! The WASM host engine (`astrid-capsule`) reports sensitive per-action host
//! calls — fs read/write/delete, net connect/bind, process spawn — to the
//! [`HostAuditSink`](astrid_capsule::HostAuditSink) trait. The kernel holds
//! both the durable audit log and the runtime ed25519 signing key, so it is
//! the side that can map those neutral events onto a signed, hash-chained
//! [`AuditEntry`](astrid_audit::AuditEntry). A bounded writer coalesces
//! concurrent reports and collapses identical events in the window; host
//! calls return after enqueue. Producers never block WASM/tokio workers.

use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use astrid_audit::{AuditAction, AuditLog, AuditOutcome, AuthorizationProof};
use astrid_capsule::{HostAuditEvent, HostAuditOutcome, HostAuditSink};
use astrid_config::types::AuditConfig;
use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::ContentHash;
use tracing::warn;

/// Authorization reason stamped on an allowed or failed manifest-gated host
/// call — the capsule's declared manifest allowlist is what authorized the
/// effect (there is no per-call user/capability token at this seam).
const MANIFEST_GATED_REASON: &str = "manifest-gated host call";

/// Byte cap applied to every guest-controlled string (path / host / addr /
/// command) before it is signed and persisted onto the audit chain.
///
/// # Amplification threat
///
/// These strings are chosen by the guest and are otherwise unbounded. Every
/// sensitive host call records one entry — INCLUDING gate-denied calls from a
/// zero-capability capsule, which pay nothing to be denied. A capsule can
/// therefore drive unbounded disk growth and per-append signing/hashing CPU by
/// passing multi-megabyte paths/hosts/commands to host fns it isn't even
/// allowed to use. Capping each field at a small constant removes that
/// amplification while preserving enough of the value to be forensically
/// useful.
const MAX_AUDIT_STR_BYTES: usize = 1024;

/// Operator policy for the host-audit writer. Built from [`AuditConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAuditPolicy {
    coalesce: Duration,
    max_batch: usize,
    queue_capacity: usize,
    persist_path_probes: bool,
}

impl Default for HostAuditPolicy {
    fn default() -> Self {
        Self::from(&AuditConfig::default())
    }
}

impl From<&AuditConfig> for HostAuditPolicy {
    fn from(config: &AuditConfig) -> Self {
        Self {
            coalesce: Duration::from_millis(config.host_coalesce_ms),
            max_batch: usize::try_from(config.host_batch_max)
                .unwrap_or(128)
                .clamp(8, 128),
            queue_capacity: usize::try_from(config.host_queue_capacity)
                .unwrap_or(4096)
                .clamp(64, 65_536),
            persist_path_probes: config.host_path_probes,
        }
    }
}

struct AuditWork {
    session_id: SessionId,
    principal: PrincipalId,
    action: AuditAction,
    authorization: AuthorizationProof,
    outcome: AuditOutcome,
    repeats: u32,
}

impl AuditWork {
    fn collapse_key(&self) -> String {
        // Allowed host calls with distinct payloads (paths, hosts, commands)
        // still pin ed25519 if each row is unique. Fold by action class per
        // principal/session in the window; the first payload is kept and
        // `repeats=N` records volume. Denials stay exact.
        let kind = match &self.action {
            AuditAction::FileRead { .. } => Some("fileread"),
            AuditAction::FileWrite { .. } => Some("filewrite"),
            AuditAction::FileDelete { .. } => Some("filedelete"),
            AuditAction::NetConnect { .. } => Some("netconnect"),
            AuditAction::NetBind { .. } => Some("netbind"),
            AuditAction::NetAccept { .. } => Some("netaccept"),
            AuditAction::ProcessSpawn { .. } => Some("proc"),
            _ => None,
        };
        if let Some(kind) = kind {
            // Ignore path/host/command AND principal: 27 capsules otherwise
            // still mint hundreds of unique signed rows per window.
            return format!(
                "{kind}|{}|{:?}",
                outcome_class(&self.outcome),
                self.session_id
            );
        }
        format!(
            "{:?}|{}|{:?}|{:?}|{}",
            self.session_id,
            self.principal,
            self.action,
            self.authorization,
            outcome_class(&self.outcome)
        )
    }

    fn into_request(
        self,
    ) -> (
        SessionId,
        PrincipalId,
        AuditAction,
        AuthorizationProof,
        AuditOutcome,
    ) {
        let outcome = with_repeat_count(self.outcome, self.repeats);
        (
            self.session_id,
            self.principal,
            self.action,
            self.authorization,
            outcome,
        )
    }
}

fn outcome_class(outcome: &AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Success { .. } => "ok",
        AuditOutcome::Failure { .. } => "fail",
    }
}

fn with_repeat_count(outcome: AuditOutcome, repeats: u32) -> AuditOutcome {
    if repeats <= 1 {
        return outcome;
    }
    let stamp = format!("repeats={repeats}");
    match outcome {
        AuditOutcome::Success { details } => AuditOutcome::Success {
            details: Some(match details {
                Some(existing) if existing.contains("repeats=") => existing,
                Some(existing) => format!("{existing}; {stamp}"),
                None => stamp,
            }),
        },
        AuditOutcome::Failure { error } => AuditOutcome::Failure {
            error: if error.contains("repeats=") {
                error
            } else {
                format!("{error}; {stamp}")
            },
        },
    }
}

fn fold_work(map: &mut HashMap<String, Box<AuditWork>>, work: Box<AuditWork>) -> u32 {
    let extra = work.repeats.saturating_sub(1);
    let key = work.collapse_key();
    if let Some(existing) = map.get_mut(&key) {
        existing.repeats = existing.repeats.saturating_add(work.repeats);
        work.repeats.saturating_add(extra)
    } else {
        map.insert(key, work);
        extra
    }
}

#[allow(clippy::vec_box)]
fn collapse_batch(batch: Vec<Box<AuditWork>>) -> (Vec<Box<AuditWork>>, u64) {
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<Box<AuditWork>> = Vec::new();
    let mut collapsed = 0_u64;
    for work in batch {
        let key = work.collapse_key();
        if let Some(&i) = index.get(&key) {
            collapsed = collapsed.saturating_add(u64::from(work.repeats));
            out[i].repeats = out[i].repeats.saturating_add(work.repeats);
        } else {
            index.insert(key, out.len());
            out.push(work);
        }
    }
    (out, collapsed)
}

#[derive(Default)]
struct AuditHealthState {
    accepted: u64,
    persisted: u64,
    failed: u64,
    queue_full: u64,
    queued: u64,
    collapsed_repeats: u64,
    omitted_path_probes: u64,
    worker_alive: bool,
    last_error: Option<String>,
}

/// Operator-visible health for the bounded host-audit ingestion queue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditSinkHealth {
    /// Events accepted into the bounded queue (including folded repeats).
    pub accepted: u64,
    /// Events acknowledged after durable append.
    pub persisted: u64,
    /// Events whose durable append failed.
    pub failed: u64,
    /// Number of times producers observed a full queue.
    pub queue_full: u64,
    /// Events accepted but not yet removed from the writer queue.
    pub queue_depth: u64,
    /// Identical events folded into a single signed row.
    pub collapsed_repeats: u64,
    /// Allowed path probes omitted from the signed chain.
    pub omitted_path_probes: u64,
    /// Whether the dedicated writer thread is alive.
    pub worker_alive: bool,
    /// Whether a failure or dead writer has degraded ingestion.
    pub degraded: bool,
    /// Most recent persistence/worker error, if degraded.
    pub last_error: Option<String>,
}

struct AuditQueue {
    sender: Mutex<Option<SyncSender<()>>>,
    pending: Arc<Mutex<HashMap<String, Box<AuditWork>>>>,
    health: Arc<Mutex<AuditHealthState>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl AuditQueue {
    fn new(audit_log: Arc<AuditLog>, policy: HostAuditPolicy) -> Arc<Self> {
        let (sender, receiver) = sync_channel(1);
        let health = Arc::new(Mutex::new(AuditHealthState::default()));
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let worker_health = Arc::clone(&health);
        let worker_pending = Arc::clone(&pending);
        let worker = thread::Builder::new()
            .name("astrid-audit-writer".to_owned())
            .spawn(move || {
                audit_writer(
                    &audit_log,
                    &receiver,
                    &worker_pending,
                    &worker_health,
                    policy,
                );
            })
            .ok();
        let queue = Arc::new(Self {
            sender: Mutex::new(Some(sender)),
            pending,
            health,
            worker: Mutex::new(worker),
        });
        if queue
            .worker
            .lock()
            .ok()
            .and_then(|worker| worker.as_ref().map(|_| ()))
            .is_none()
        {
            queue.record_failure("failed to spawn bounded audit writer".to_owned());
            if let Ok(mut sender) = queue.sender.lock() {
                sender.take();
            }
        }
        queue
    }

    fn submit(&self, work: Box<AuditWork>) -> Result<(), Box<AuditWork>> {
        let sender = self
            .sender
            .lock()
            .ok()
            .and_then(|sender| sender.as_ref().cloned());
        let Some(sender) = sender else {
            return Err(work);
        };
        self.fold_overflow(work);
        // Capacity 1: Full means the writer is already awake.
        let _ = sender.try_send(());
        Ok(())
    }

    fn fold_overflow(&self, work: Box<AuditWork>) {
        let repeats = work.repeats;
        if let Ok(mut pending) = self.pending.lock() {
            let extra = fold_work(&mut pending, work);
            self.note_accepted(u64::from(repeats));
            if extra > 0
                && let Ok(mut health) = self.health.lock()
            {
                health.collapsed_repeats =
                    health.collapsed_repeats.saturating_add(u64::from(extra));
            }
            return;
        }
        self.note_accepted(u64::from(repeats));
    }

    fn note_accepted(&self, n: u64) {
        if let Ok(mut health) = self.health.lock() {
            health.accepted = health.accepted.saturating_add(n);
            health.queued = health.queued.saturating_add(n);
        }
    }

    fn record_failure(&self, error: String) {
        if let Ok(mut health) = self.health.lock() {
            health.failed = health.failed.saturating_add(1);
            health.worker_alive = false;
            health.last_error = Some(error);
        }
    }


    fn omit_path_probe(&self) {
        if let Ok(mut health) = self.health.lock() {
            health.omitted_path_probes = health.omitted_path_probes.saturating_add(1);
        }
    }

    fn health(&self) -> AuditSinkHealth {
        self.health.lock().map_or_else(
            |_| AuditSinkHealth {
                failed: 1,
                worker_alive: false,
                degraded: true,
                queue_depth: 0,
                last_error: Some("audit health mutex poisoned".to_owned()),
                ..AuditSinkHealth::default()
            },
            |health| AuditSinkHealth {
                accepted: health.accepted,
                persisted: health.persisted,
                failed: health.failed,
                queue_full: health.queue_full,
                queue_depth: health.queued,
                collapsed_repeats: health.collapsed_repeats,
                omitted_path_probes: health.omitted_path_probes,
                worker_alive: health.worker_alive,
                degraded: health.failed > 0 || !health.worker_alive,
                last_error: health.last_error.clone(),
            },
        )
    }

    fn shutdown(&self) {
        self.sender.lock().ok().and_then(|mut sender| sender.take());
        if let Ok(mut worker) = self.worker.lock()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
    }
}

impl Drop for AuditQueue {
    fn drop(&mut self) {
        if let Ok(sender) = self.sender.get_mut() {
            sender.take();
        }
        if let Ok(worker) = self.worker.get_mut()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
    }
}

#[allow(clippy::vec_box)]
fn take_pending(
    pending: &Mutex<HashMap<String, Box<AuditWork>>>,
    limit: usize,
) -> Vec<Box<AuditWork>> {
    let Ok(mut map) = pending.lock() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let keys: Vec<String> = map.keys().take(limit).cloned().collect();
    for key in keys {
        if let Some(work) = map.remove(&key) {
            out.push(work);
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

#[allow(clippy::vec_box)]
fn persist_batch(
    runtime: &tokio::runtime::Runtime,
    audit_log: &Arc<AuditLog>,
    health: &Arc<Mutex<AuditHealthState>>,
    batch: Vec<Box<AuditWork>>,
) {
    let drained: u64 = batch.iter().map(|work| u64::from(work.repeats)).sum();
    let (batch, collapsed) = collapse_batch(batch);
    if batch.len() > 16 {
        warn!(
            count = batch.len(),
            "host-audit persist still has many unique rows after collapse"
        );
    }
    if let Ok(mut state) = health.lock() {
        state.queued = state.queued.saturating_sub(drained);
        if collapsed > 0 {
            state.collapsed_repeats = state.collapsed_repeats.saturating_add(collapsed);
        }
    }
    let requests = batch.into_iter().map(|work| work.into_request()).collect();
    let results = runtime.block_on(audit_log.append_batch_with_principal(requests));
    let mut persisted = 0_u64;
    let mut failed = 0_u64;
    let mut last_error = None;
    for result in results {
        if result.is_ok() {
            persisted = persisted.saturating_add(1);
        } else if let Err(error) = result {
            failed = failed.saturating_add(1);
            last_error = Some(error.to_string());
        }
    }
    if let Ok(mut state) = health.lock() {
        state.persisted = state.persisted.saturating_add(persisted);
        state.failed = state.failed.saturating_add(failed);
        if let Some(error) = last_error {
            state.last_error = Some(error);
        }
    }
}

fn audit_writer(
    audit_log: &Arc<AuditLog>,
    receiver: &Receiver<()>,
    pending: &Mutex<HashMap<String, Box<AuditWork>>>,
    health: &Arc<Mutex<AuditHealthState>>,
    policy: HostAuditPolicy,
) {
    if let Ok(mut state) = health.lock() {
        state.worker_alive = true;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let reason = format!("failed to create audit writer runtime: {error}");
            while receiver.recv().is_ok() {}
            let _ = take_pending(pending, usize::MAX);
            if let Ok(mut state) = health.lock() {
                state.failed = state.failed.saturating_add(1);
                state.worker_alive = false;
                state.last_error = Some(reason);
            }
            return;
        },
    };

    loop {
        if receiver.recv().is_err() {
            let rest = take_pending(pending, policy.max_batch);
            if !rest.is_empty() {
                persist_batch(&runtime, audit_log, health, rest);
                continue;
            }
            break;
        }
        let deadline = Instant::now()
            .checked_add(policy.coalesce)
            .unwrap_or_else(Instant::now);
        loop {
            let timeout = deadline.saturating_duration_since(Instant::now());
            if timeout.is_zero() {
                break;
            }
            match receiver.recv_timeout(timeout) {
                Ok(()) | Err(RecvTimeoutError::Timeout) => {},
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        let batch = take_pending(pending, policy.max_batch.min(16));
        if !batch.is_empty() {
            persist_batch(&runtime, audit_log, health, batch);
        }
    }
    if let Ok(mut state) = health.lock() {
        state.worker_alive = false;
    }
}

/// Truncate a guest-controlled string to at most [`MAX_AUDIT_STR_BYTES`],
/// snapping to a UTF-8 char boundary so the stored value is always valid UTF-8.
///
/// See the [`MAX_AUDIT_STR_BYTES`] amplification threat: guest strings are
/// unbounded and are signed+persisted per call, so they must be bounded at this
/// sink boundary before `to_owned`.
fn truncate_guest_str(s: &str) -> String {
    if s.len() <= MAX_AUDIT_STR_BYTES {
        return s.to_owned();
    }
    // Snap down to the largest char boundary at or below the cap so slicing
    // never splits a multi-byte code point (which would panic). Index 0 is
    // always a boundary, so the search always yields.
    let end = (0..=MAX_AUDIT_STR_BYTES)
        .rev()
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(0);
    s[..end].to_owned()
}

/// Persists capsule per-action host calls onto the kernel's signed audit
/// chain.
///
/// Moved into a `dyn HostAuditSink` handed to every capsule engine at load. One
/// per kernel boot, bound to the kernel's single `session_id`.
#[derive(Clone)]
pub struct KernelAuditSink {
    /// The kernel session every entry is chained under.
    session_id: SessionId,
    /// Bounded writer queue. Producers never block on a full queue.
    queue: Arc<AuditQueue>,
    policy: HostAuditPolicy,
}

impl KernelAuditSink {
    /// Construct a sink over the kernel's audit log + session using default
    /// [`HostAuditPolicy`].
    #[must_use]
    pub fn new(audit_log: impl Into<Arc<AuditLog>>, session_id: impl Into<SessionId>) -> Self {
        Self::with_policy(audit_log, session_id, HostAuditPolicy::default())
    }

    /// Construct a sink with an operator policy from [`AuditConfig`].
    #[must_use]
    pub fn with_policy(
        audit_log: impl Into<Arc<AuditLog>>,
        session_id: impl Into<SessionId>,
        policy: HostAuditPolicy,
    ) -> Self {
        let audit_log = audit_log.into();
        Self {
            session_id: session_id.into(),
            queue: AuditQueue::new(audit_log, policy),
            policy,
        }
    }

    /// Return operator-visible queue and persistence health.
    #[must_use]
    pub fn health(&self) -> AuditSinkHealth {
        self.queue.health()
    }

    /// Stop the bounded writer after draining all accepted events.
    pub fn shutdown(&self) {
        self.queue.shutdown();
    }

    /// Map a neutral host event onto the internal audit action.
    ///
    /// `FileWrite` content hashing is not captured at this per-action seam
    /// yet (the host fn reports the path, not the written bytes); a
    /// zero hash is recorded as a documented placeholder pending a
    /// content-addressed follow-up.
    fn to_action(event: HostAuditEvent<'_>) -> AuditAction {
        // Every guest-controlled string is bounded here (see
        // `truncate_guest_str` / `MAX_AUDIT_STR_BYTES`) before it is signed and
        // persisted, closing the disk/CPU amplification path.
        match event {
            HostAuditEvent::FileRead { path } | HostAuditEvent::FileProbe { path } => {
                AuditAction::FileRead {
                    path: truncate_guest_str(path),
                }
            },
            HostAuditEvent::FileWrite { path } => AuditAction::FileWrite {
                path: truncate_guest_str(path),
                // Content hash not captured at the per-action seam yet.
                content_hash: ContentHash::zero(),
            },
            HostAuditEvent::FileDelete { path } => AuditAction::FileDelete {
                path: truncate_guest_str(path),
            },
            HostAuditEvent::NetConnect { host, port } => AuditAction::NetConnect {
                host: truncate_guest_str(host),
                port,
            },
            HostAuditEvent::NetBind { addr } => AuditAction::NetBind {
                addr: truncate_guest_str(addr),
            },
            HostAuditEvent::ProcessSpawn { command } => AuditAction::ProcessSpawn {
                command: truncate_guest_str(command),
            },
            HostAuditEvent::NetAccept {
                local_addr,
                peer_addr,
            } => AuditAction::NetAccept {
                local_addr: truncate_guest_str(local_addr),
                peer_addr: truncate_guest_str(peer_addr),
            },
        }
    }

    fn record_action(
        &self,
        principal: &PrincipalId,
        action: AuditAction,
        outcome: HostAuditOutcome<'_>,
    ) {
        let (proof, audit_outcome) = Self::to_proof_outcome(outcome);
        let work = Box::new(AuditWork {
            session_id: self.session_id.clone(),
            principal: principal.clone(),
            action,
            authorization: proof,
            outcome: audit_outcome,
            repeats: 1,
        });
        if self.queue.submit(work).is_err() {
            self.queue
                .record_failure("audit writer unavailable".to_owned());
            warn!(
                security_event = true,
                %principal,
                "Failed to enqueue per-action audit entry"
            );
        }
    }

    /// Build the authorization proof + outcome pair for an outcome.
    fn to_proof_outcome(outcome: HostAuditOutcome<'_>) -> (AuthorizationProof, AuditOutcome) {
        match outcome {
            HostAuditOutcome::Allowed => (
                AuthorizationProof::System {
                    reason: MANIFEST_GATED_REASON.into(),
                },
                AuditOutcome::success(),
            ),
            HostAuditOutcome::Failed(e) => (
                AuthorizationProof::System {
                    reason: MANIFEST_GATED_REASON.into(),
                },
                AuditOutcome::failure(e),
            ),
            HostAuditOutcome::Denied(r) => (
                AuthorizationProof::Denied {
                    reason: r.to_owned(),
                },
                AuditOutcome::failure(r),
            ),
        }
    }
}

impl HostAuditSink for KernelAuditSink {
    fn record(
        &self,
        principal: &PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    ) {
        if matches!(event, HostAuditEvent::FileProbe { .. })
            && matches!(outcome, HostAuditOutcome::Allowed)
            && !self.policy.persist_path_probes
        {
            self.queue.omit_path_probe();
            return;
        }
        let action = Self::to_action(event);
        self.record_action(principal, action, outcome);
    }
}

#[cfg(test)]
mod tests;
