//! Kernel implementation of the capsule host-audit sink.
//!
//! The WASM host engine (`astrid-capsule`) reports sensitive per-action host
//! calls — fs read/write/delete, net connect/bind/accept, process spawn — to
//! the [`HostAuditSink`](astrid_capsule::HostAuditSink) trait. The kernel
//! holds both the durable audit log and the runtime ed25519 signing key, so
//! it is the side that can map those neutral events onto a signed,
//! hash-chained [`AuditEntry`](astrid_audit::AuditEntry).
//!
//! # Ordered, loss-accounted lane
//!
//! A host call is placed in its principal chain's FIFO (see [`lane`]) and the
//! host call returns. A dedicated writer (see [`writer`]) appends the FIFO in
//! order, so a chain's entries are in call order. Consecutive calls share one
//! entry that counts them and commits to each of them through a fold
//! ([`astrid_audit::host_call`]). A call that meets a full queue is counted
//! in a signed loss entry at its place in the chain, and a lane run that
//! stops without draining leaves a signed gap entry at the next start (see
//! [`marker`]). Producers never block on the queue.
//!
//! # Fail-closed classes
//!
//! For host-call classes in `audit.host_fail_closed`, [`HostAuditSink::admit`]
//! queues a write-ahead entry and waits until it is durable before the effect
//! runs; if it cannot be recorded, the call is refused and the refusal is
//! recorded as a denial.

mod lane;
mod marker;
mod writer;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use astrid_audit::host_call::{HOST_CALL_CLASSES, HostCallOutcome};
use astrid_audit::{AuditAction, AuditLog, AuditOutcome, AuthorizationProof, CapsuleActor};
use astrid_capsule::{
    HostAuditActor, HostAuditEvent, HostAuditOutcome, HostAuditReceipt, HostAuditRefusal,
    HostAuditSink,
};
use astrid_config::types::AuditConfig;
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_crypto::ContentHash;
use astrid_storage::ScopedKvStore;
use tracing::warn;

use lane::{AdmitTicket, Call, Lanes, Lifecycle, Pushed};
use writer::{HealthState, Shared, WriterConfig};
mod coverage;

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

/// How long a fail-closed host call waits for its write-ahead entry.
const FAIL_CLOSED_WAIT: Duration = Duration::from_secs(10);

/// Operator policy for the host-audit writer. Built from [`AuditConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAuditPolicy {
    coalesce: Duration,
    max_batch: usize,
    queue_capacity: usize,
    persist_path_probes: bool,
    /// Bit `i` set: class `HOST_CALL_CLASSES[i]` fails closed.
    fail_closed: u8,
}

impl Default for HostAuditPolicy {
    fn default() -> Self {
        Self::from(&AuditConfig::default())
    }
}

impl From<&AuditConfig> for HostAuditPolicy {
    fn from(config: &AuditConfig) -> Self {
        let fail_closed = HOST_CALL_CLASSES
            .iter()
            .enumerate()
            .filter(|(_, class)| config.host_fail_closed.iter().any(|name| name == *class))
            .fold(0_u8, |bits, (index, _)| bits | (1 << index));
        Self {
            coalesce: Duration::from_millis(config.host_coalesce_ms),
            max_batch: usize::try_from(config.host_batch_max)
                .unwrap_or(128)
                .clamp(8, 128),
            queue_capacity: usize::try_from(config.host_queue_capacity)
                .unwrap_or(4096)
                .clamp(64, 65_536),
            persist_path_probes: config.host_path_probes,
            fail_closed,
        }
    }
}

impl HostAuditPolicy {
    /// Whether `event` must be admitted through a durable write-ahead entry.
    fn fails_closed(&self, event: &HostAuditEvent<'_>) -> bool {
        let index = match event {
            HostAuditEvent::FileRead { .. } => 0,
            HostAuditEvent::FileWrite { .. } => 1,
            HostAuditEvent::FileDelete { .. } => 2,
            HostAuditEvent::NetConnect { .. } => 3,
            HostAuditEvent::NetBind { .. } => 4,
            HostAuditEvent::NetAccept { .. } => 5,
            HostAuditEvent::ProcessSpawn { .. } => 6,
            HostAuditEvent::FileProbe { .. }
            | HostAuditEvent::HttpRequest(_)
            | HostAuditEvent::HttpResponse(_)
            | HostAuditEvent::ToolCall { .. }
            | HostAuditEvent::ApprovalRequested { .. }
            | HostAuditEvent::ApprovalDecided(_) => return false,
        };
        self.fail_closed & (1 << index) != 0
    }
}

/// Operator-visible health of the host-audit lane.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditSinkHealth {
    /// Calls accepted by the lane (recorded, queued, or loss-accounted).
    pub accepted: u64,
    /// Calls whose entry (single or run) is durable.
    pub persisted: u64,
    /// Calls counted by durable loss entries instead of their own entry.
    pub lost: u64,
    /// Failed durable append attempts (each is retried).
    pub failed: u64,
    /// Calls that met a full queue and went into a loss entry.
    pub queue_full: u64,
    /// Calls accepted but not yet counted by a durable entry.
    pub queue_depth: u64,
    /// Calls folded into a run entry after its first call.
    pub collapsed_repeats: u64,
    /// Allowed path probes omitted from the signed chain.
    pub omitted_path_probes: u64,
    /// Durable gap entries for lane runs that stopped without draining.
    pub gaps_recorded: u64,
    /// Fail-closed calls refused because their write-ahead entry was not
    /// durable.
    pub fail_closed_refused: u64,
    /// Calls reported after the writer stopped; they reach no entry.
    pub dropped_after_shutdown: u64,
    /// Whether the dedicated writer thread is alive.
    pub worker_alive: bool,
    /// Whether a failure or dead writer has degraded ingestion.
    pub degraded: bool,
    /// Most recent persistence/worker error, if degraded.
    pub last_error: Option<String>,
}

struct AuditQueue {
    shared: Arc<Shared>,
    omitted_path_probes: AtomicU64,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl AuditQueue {
    fn new(
        audit_log: Arc<AuditLog>,
        session: SessionId,
        policy: HostAuditPolicy,
        marker: Option<ScopedKvStore>,
    ) -> Arc<Self> {
        let shared = Arc::new(Shared {
            lanes: Mutex::new(Lanes::new(policy.queue_capacity, marker.is_some())),
            wake: Condvar::new(),
            health: Mutex::new(HealthState::default()),
        });
        let config = WriterConfig {
            audit_log,
            session,
            policy,
            marker,
        };
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("astrid-audit-writer".to_owned())
            .spawn(move || writer::run(&worker_shared, &config))
            .ok();
        if worker.is_none() {
            shared.health().last_error = Some("failed to spawn host-audit writer".to_owned());
            shared.lanes().lifecycle = Lifecycle::Closed;
        }
        Arc::new(Self {
            shared,
            omitted_path_probes: AtomicU64::new(0),
            worker: Mutex::new(worker),
        })
    }

    fn health(&self) -> AuditSinkHealth {
        let (accepted, queue_depth, queue_full) = {
            let lanes = self.shared.lanes();
            (lanes.accepted, lanes.queued_calls, lanes.queue_full)
        };
        let health = self.shared.health();
        AuditSinkHealth {
            accepted,
            persisted: health.persisted,
            lost: health.lost,
            failed: health.failed,
            queue_full,
            queue_depth,
            collapsed_repeats: health.collapsed_repeats,
            omitted_path_probes: self.omitted_path_probes.load(Ordering::Relaxed),
            gaps_recorded: health.gaps_recorded,
            fail_closed_refused: health.fail_closed_refused,
            dropped_after_shutdown: health.dropped_after_shutdown,
            worker_alive: health.worker_alive,
            degraded: health.failed > 0 || health.marker_errors > 0 || !health.worker_alive,
            last_error: health.last_error.clone(),
        }
    }

    /// Ask the writer to drain everything and stop, then wait for it.
    fn shutdown(&self) {
        {
            let mut lanes = self.shared.lanes();
            if lanes.lifecycle == Lifecycle::Open {
                lanes.lifecycle = Lifecycle::Draining;
            }
        }
        self.shared.wake.notify_all();
        self.join();
    }

    fn join(&self) {
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(worker) = worker {
            let _ = worker.join();
        }
    }

    /// Stop the writer without draining or closing the lane marker, the way
    /// a crash would.
    #[cfg(test)]
    fn abandon(&self) {
        self.shared.lanes().lifecycle = Lifecycle::Abandoned;
        self.shared.wake.notify_all();
        self.join();
    }
}

impl Drop for AuditQueue {
    fn drop(&mut self) {
        self.shutdown();
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

/// Run a blocking wait without stalling a tokio worker thread.
fn wait_blocking<T>(wait: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) =>
        {
            tokio::task::block_in_place(wait)
        },
        _ => wait(),
    }
}

/// Persists capsule per-action host calls onto the kernel's signed audit
/// chain.
///
/// Moved into a `dyn HostAuditSink` handed to every capsule engine at load. One
/// per kernel boot, bound to the kernel's single `session_id`.
#[derive(Clone)]
pub struct KernelAuditSink {
    session_id: SessionId,
    /// Ordered lane and its writer. Producers never block on a full queue.
    queue: Arc<AuditQueue>,
    policy: HostAuditPolicy,
    /// Capsule code identity stamped on every entry this handle writes.
    /// `None` on the kernel's own handle; set on the per-capsule handles the
    /// engine obtains through [`HostAuditSink::attributed`].
    actor: Option<Arc<CapsuleActor>>,
    /// The audit log, for records that must be durable before the host call
    /// proceeds ([`HostAuditSink::commit`]).
    audit_log: Arc<AuditLog>,
    /// Per-principal HTTP request numbers for this kernel run, shared by
    /// every handle so the sequence spans all capsules of a principal.
    http_sequences: Arc<Mutex<HashMap<PrincipalId, u64>>>,
    /// Identifier of this kernel run, recorded with every HTTP entry. The
    /// sequences restart with each run, so a verifier checks for gaps per run.
    run_id: Arc<str>,
}

impl KernelAuditSink {
    /// Construct a sink over the kernel's audit log + session using default
    /// [`HostAuditPolicy`].
    #[must_use]
    pub fn new(audit_log: impl Into<Arc<AuditLog>>, session_id: impl Into<SessionId>) -> Self {
        Self::with_policy(audit_log, session_id, HostAuditPolicy::default())
    }

    /// Construct a sink with an operator policy from [`AuditConfig`].
    ///
    /// Without a lane marker, a lane run that stops without draining leaves
    /// no gap entry; use [`with_lane_marker`](Self::with_lane_marker) for a
    /// durable kernel.
    #[must_use]
    pub fn with_policy(
        audit_log: impl Into<Arc<AuditLog>>,
        session_id: impl Into<SessionId>,
        policy: HostAuditPolicy,
    ) -> Self {
        Self::build(audit_log.into(), session_id.into(), policy, None)
    }

    /// Construct a sink that keeps its lane marker in `marker`, a
    /// kernel-owned control projection, so the next start records a gap
    /// entry when this lane run stops without draining.
    #[must_use]
    pub fn with_lane_marker(
        audit_log: impl Into<Arc<AuditLog>>,
        session_id: impl Into<SessionId>,
        policy: HostAuditPolicy,
        marker: ScopedKvStore,
    ) -> Self {
        Self::build(audit_log.into(), session_id.into(), policy, Some(marker))
    }

    fn build(
        audit_log: Arc<AuditLog>,
        session_id: SessionId,
        policy: HostAuditPolicy,
        marker: Option<ScopedKvStore>,
    ) -> Self {
        Self {
            session_id: session_id.clone(),
            queue: AuditQueue::new(Arc::clone(&audit_log), session_id, policy, marker),
            policy,
            actor: None,
            audit_log,
            http_sequences: Arc::default(),
            run_id: Arc::from(uuid::Uuid::new_v4().to_string()),
        }
    }

    /// Return operator-visible queue and persistence health.
    #[must_use]
    pub fn health(&self) -> AuditSinkHealth {
        self.queue.health()
    }

    /// Stop the writer after draining every accepted call, then mark the
    /// lane run closed.
    pub fn shutdown(&self) {
        self.queue.shutdown();
    }

    /// Map a neutral host event onto the internal audit action, stamped with
    /// `actor`.
    ///
    /// `FileWrite` carries the BLAKE3 of the written bytes when the host call
    /// wrote content; a directory creation or a write denied before content
    /// was accepted records the zero hash.
    fn to_action(event: HostAuditEvent<'_>, actor: Option<CapsuleActor>) -> AuditAction {
        // Every guest-controlled string is bounded here (see
        // `truncate_guest_str` / `MAX_AUDIT_STR_BYTES`) before it is signed and
        // persisted, closing the disk/CPU amplification path.
        match event {
            HostAuditEvent::FileRead { path } | HostAuditEvent::FileProbe { path } => {
                AuditAction::FileRead {
                    path: truncate_guest_str(path),
                    actor,
                }
            },
            HostAuditEvent::FileWrite { path, content_hash } => AuditAction::FileWrite {
                path: truncate_guest_str(path),
                content_hash: content_hash.unwrap_or_else(ContentHash::zero),
                actor,
            },
            HostAuditEvent::FileDelete { path } => AuditAction::FileDelete {
                path: truncate_guest_str(path),
                actor,
            },
            HostAuditEvent::NetConnect { host, port } => AuditAction::NetConnect {
                host: truncate_guest_str(host),
                port,
                actor,
            },
            HostAuditEvent::NetBind { addr } => AuditAction::NetBind {
                addr: truncate_guest_str(addr),
                actor,
            },
            HostAuditEvent::ProcessSpawn { command } => AuditAction::ProcessSpawn {
                command: truncate_guest_str(command),
                actor,
            },
            HostAuditEvent::NetAccept {
                local_addr,
                peer_addr,
            } => AuditAction::NetAccept {
                local_addr: truncate_guest_str(local_addr),
                peer_addr: truncate_guest_str(peer_addr),
                actor,
            },
            HostAuditEvent::HttpRequest(request) => coverage::http_request_action(&request, actor),
            HostAuditEvent::HttpResponse(response) => {
                coverage::http_response_action(&response, actor)
            },
            HostAuditEvent::ToolCall {
                capsule_id,
                tool,
                call_id,
                args_hash,
                result_hash,
            } => {
                coverage::tool_call_action(capsule_id, tool, call_id, args_hash, result_hash, actor)
            },
            HostAuditEvent::ApprovalRequested {
                request_id,
                action,
                resource,
            } => coverage::approval_requested_action(request_id, action, resource, actor),
            HostAuditEvent::ApprovalDecided(decision) => {
                coverage::approval_decision_action(&decision, actor)
            },
        }
    }

    /// Split a neutral outcome into the lane's outcome kind and detail.
    fn classify(outcome: HostAuditOutcome<'_>) -> (HostCallOutcome, String) {
        match outcome {
            HostAuditOutcome::Allowed => (HostCallOutcome::Ok, String::new()),
            HostAuditOutcome::Failed(error) => (HostCallOutcome::Failed, truncate_guest_str(error)),
            HostAuditOutcome::Denied(reason) => {
                (HostCallOutcome::Denied, truncate_guest_str(reason))
            },
        }
    }

    fn to_proof_outcome(outcome: HostAuditOutcome<'_>) -> (AuthorizationProof, AuditOutcome) {
        match outcome {
            HostAuditOutcome::Allowed => (
                AuthorizationProof::System {
                    reason: MANIFEST_GATED_REASON.into(),
                },
                AuditOutcome::success(),
            ),
            HostAuditOutcome::Failed(error) => (
                AuthorizationProof::System {
                    reason: MANIFEST_GATED_REASON.into(),
                },
                AuditOutcome::failure(truncate_guest_str(error)),
            ),
            HostAuditOutcome::Denied(reason) => (
                AuthorizationProof::Denied {
                    reason: truncate_guest_str(reason),
                },
                AuditOutcome::failure(truncate_guest_str(reason)),
            ),
        }
    }

    /// Queue one call behind everything already queued for its chain.
    fn enqueue(&self, principal: &PrincipalId, call: Call) {
        let pushed = self
            .queue
            .shared
            .lanes()
            .push_call(principal, call, Instant::now());
        match pushed {
            Pushed::Folded => {},
            Pushed::Queued | Pushed::Lost => self.queue.shared.wake.notify_one(),
            Pushed::Closed => {
                {
                    let mut health = self.queue.shared.health();
                    health.dropped_after_shutdown = health.dropped_after_shutdown.saturating_add(1);
                }
                warn!(
                    security_event = true,
                    %principal,
                    "host call reported after the audit writer stopped; not recorded"
                );
            },
        }
    }

    fn record_at(
        &self,
        principal: &PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
        at: Timestamp,
    ) {
        if matches!(event, HostAuditEvent::FileProbe { .. })
            && matches!(outcome, HostAuditOutcome::Allowed)
            && !self.policy.persist_path_probes
        {
            self.queue
                .omitted_path_probes
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut action = Self::to_action(event, self.actor.as_deref().cloned());
        self.stamp_http_sequence(principal, &mut action);
        let (outcome, detail) = Self::classify(outcome);
        self.enqueue(
            principal,
            Call {
                action,
                outcome,
                detail,
                at,
            },
        );
    }

    /// Queue a write-ahead entry and wait until it is durable.
    fn admit_durably(&self, principal: &PrincipalId, action: AuditAction) -> Result<(), String> {
        let ticket = Arc::new(AdmitTicket::new());
        let queued = self.queue.shared.lanes().push_admit(
            principal,
            action,
            Arc::clone(&ticket),
            Instant::now(),
        );
        if !queued {
            return Err("audit writer stopped".to_owned());
        }
        self.queue.shared.wake.notify_one();
        wait_blocking(|| ticket.wait(FAIL_CLOSED_WAIT))
    }

    /// Stop the writer as a crash would: nothing more is drained and the lane
    /// marker stays open.
    #[cfg(test)]
    fn abandon_for_test(&self) {
        self.queue.abandon();
    }
}

impl HostAuditSink for KernelAuditSink {
    fn record(
        &self,
        principal: &PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    ) {
        self.record_at(principal, event, outcome, Timestamp::now());
    }

    fn admit(
        &self,
        principal: &PrincipalId,
        event: HostAuditEvent<'_>,
    ) -> Result<(), HostAuditRefusal> {
        if !self.policy.fails_closed(&event) {
            return Ok(());
        }
        let action = Self::to_action(event, self.actor.as_deref().cloned());
        let Err(reason) = self.admit_durably(principal, action.clone()) else {
            return Ok(());
        };
        {
            let mut health = self.queue.shared.health();
            health.fail_closed_refused = health.fail_closed_refused.saturating_add(1);
        }
        warn!(
            security_event = true,
            %principal,
            %reason,
            "fail-closed host call refused: write-ahead audit entry not durable"
        );
        self.enqueue(
            principal,
            Call {
                action,
                outcome: HostCallOutcome::Denied,
                detail: truncate_guest_str(&format!("fail-closed audit unavailable: {reason}")),
                at: Timestamp::now(),
            },
        );
        Err(HostAuditRefusal::new(reason))
    }

    fn attributed(&self, actor: HostAuditActor) -> Option<Arc<dyn HostAuditSink>> {
        Some(Arc::new(Self {
            actor: Some(Arc::new(coverage::to_capsule_actor(&actor))),
            ..self.clone()
        }))
    }

    fn commit<'a>(
        &'a self,
        principal: &'a PrincipalId,
        event: HostAuditEvent<'a>,
        outcome: HostAuditOutcome<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostAuditReceipt> + Send + 'a>> {
        Box::pin(self.commit_direct(principal, event, outcome))
    }
}

#[cfg(test)]
mod attribution_tests;
#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tool_approval_tests;
