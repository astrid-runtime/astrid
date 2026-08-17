//! Kernel implementation of the capsule host-audit sink.
//!
//! The WASM host engine (`astrid-capsule`) reports sensitive per-action host
//! calls — fs read/write/delete, net connect/bind, process spawn — to the
//! [`HostAuditSink`](astrid_capsule::HostAuditSink) trait. The kernel holds
//! both the durable audit log and the runtime ed25519 signing key, so it is
//! the side that can map those neutral events onto a signed, hash-chained
//! [`AuditEntry`](astrid_audit::AuditEntry). A bounded writer coalesces
//! concurrent reports; host calls return after enqueue and durability is
//! exposed through [`AuditSinkHealth`]. Queue saturation supplies explicit
//! backpressure rather than dropping audit evidence.

use std::sync::{
    Arc, Mutex,
    mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
};
use std::thread::{self, JoinHandle};

use astrid_audit::{AuditAction, AuditLog, AuditOutcome, AuthorizationProof};
use astrid_capsule::{HostAuditEvent, HostAuditOutcome, HostAuditSink};
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

const AUDIT_QUEUE_CAPACITY: usize = 1024;
const AUDIT_MAX_BATCH: usize = 64;

struct AuditWork {
    session_id: SessionId,
    principal: PrincipalId,
    action: AuditAction,
    authorization: AuthorizationProof,
    outcome: AuditOutcome,
}

#[derive(Default)]
struct AuditHealthState {
    accepted: u64,
    persisted: u64,
    failed: u64,
    queue_full: u64,
    queued: u64,
    worker_alive: bool,
    last_error: Option<String>,
}

/// Operator-visible health for the bounded host-audit ingestion queue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditSinkHealth {
    /// Events accepted into the bounded queue.
    pub accepted: u64,
    /// Events acknowledged after durable append.
    pub persisted: u64,
    /// Events whose durable append failed.
    pub failed: u64,
    /// Number of times producers observed a full queue.
    pub queue_full: u64,
    /// Events accepted but not yet removed from the writer queue.
    pub queue_depth: u64,
    /// Whether the dedicated writer thread is alive.
    pub worker_alive: bool,
    /// Whether a failure or dead writer has degraded ingestion.
    pub degraded: bool,
    /// Most recent persistence/worker error, if degraded.
    pub last_error: Option<String>,
}

struct AuditQueue {
    sender: Mutex<Option<SyncSender<Box<AuditWork>>>>,
    health: Arc<Mutex<AuditHealthState>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl AuditQueue {
    fn new(audit_log: Arc<AuditLog>) -> Arc<Self> {
        let (sender, receiver) = sync_channel(AUDIT_QUEUE_CAPACITY);
        let health = Arc::new(Mutex::new(AuditHealthState::default()));
        let worker_health = Arc::clone(&health);
        let worker = thread::Builder::new()
            .name("astrid-audit-writer".to_owned())
            .spawn(move || audit_writer(&audit_log, &receiver, &worker_health))
            .ok();
        let queue = Arc::new(Self {
            sender: Mutex::new(Some(sender)),
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
        match sender.try_send(work) {
            Ok(()) => {
                if let Ok(mut health) = self.health.lock() {
                    health.accepted = health.accepted.saturating_add(1);
                    health.queued = health.queued.saturating_add(1);
                }
                Ok(())
            },
            Err(TrySendError::Full(work)) => {
                self.mark_queue_full();
                match sender.send(work) {
                    Ok(()) => {
                        if let Ok(mut health) = self.health.lock() {
                            health.accepted = health.accepted.saturating_add(1);
                            health.queued = health.queued.saturating_add(1);
                        }
                        Ok(())
                    },
                    Err(error) => Err(error.0),
                }
            },
            Err(TrySendError::Disconnected(work)) => Err(work),
        }
    }

    fn record_failure(&self, error: String) {
        if let Ok(mut health) = self.health.lock() {
            health.failed = health.failed.saturating_add(1);
            health.worker_alive = false;
            health.last_error = Some(error);
        }
    }

    fn mark_queue_full(&self) {
        if let Ok(mut health) = self.health.lock() {
            health.queue_full = health.queue_full.saturating_add(1);
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

fn audit_writer(
    audit_log: &Arc<AuditLog>,
    receiver: &Receiver<Box<AuditWork>>,
    health: &Arc<Mutex<AuditHealthState>>,
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
            if let Ok(mut state) = health.lock() {
                state.failed = state.failed.saturating_add(1);
                state.worker_alive = false;
                state.last_error = Some(reason);
            }
            return;
        },
    };

    while let Ok(first) = receiver.recv() {
        if let Ok(mut state) = health.lock() {
            state.queued = state.queued.saturating_sub(1);
        }
        let mut batch = Vec::with_capacity(AUDIT_MAX_BATCH);
        batch.push(first);
        while batch.len() < AUDIT_MAX_BATCH {
            match receiver.try_recv() {
                Ok(work) => {
                    if let Ok(mut state) = health.lock() {
                        state.queued = state.queued.saturating_sub(1);
                    }
                    batch.push(work);
                },
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        let requests = batch
            .iter()
            .map(|work| {
                (
                    work.session_id.clone(),
                    work.principal.clone(),
                    work.action.clone(),
                    work.authorization.clone(),
                    work.outcome.clone(),
                )
            })
            .collect();
        let results = runtime.block_on(audit_log.append_batch_with_principal(requests));
        for result in results {
            if result.is_ok() {
                if let Ok(mut state) = health.lock() {
                    state.persisted = state.persisted.saturating_add(1);
                }
            } else if let Err(error) = &result
                && let Ok(mut state) = health.lock()
            {
                state.failed = state.failed.saturating_add(1);
                state.last_error = Some(error.to_string());
            }
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
    /// Bounded writer queue. Producers wait only when capacity is exhausted;
    /// durable acknowledgement is reported through [`AuditSinkHealth`].
    queue: Arc<AuditQueue>,
}

impl KernelAuditSink {
    /// Construct a sink over the kernel's audit log + session.
    ///
    /// Generic over the inputs (mirroring [`AuditLog::in_memory`]): accepts
    /// either an owned [`AuditLog`] or a shared `Arc<AuditLog>`, and any
    /// `Into<SessionId>`.
    #[must_use]
    pub fn new(audit_log: impl Into<Arc<AuditLog>>, session_id: impl Into<SessionId>) -> Self {
        let audit_log = audit_log.into();
        Self {
            session_id: session_id.into(),
            queue: AuditQueue::new(audit_log),
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
            HostAuditEvent::FileRead { path } => AuditAction::FileRead {
                path: truncate_guest_str(path),
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
        // The writer owns signing/storage latency. A full bounded queue blocks
        // here (explicit backpressure); a healthy enqueue is not reported as a
        // durable commit until the writer increments `persisted`.
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
        let action = Self::to_action(event);
        self.record_action(principal, action, outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use astrid_crypto::KeyPair;

    fn principal() -> PrincipalId {
        PrincipalId::new("alice").expect("valid principal")
    }

    fn record_event_kinds(sink: &KernelAuditSink, principal: &PrincipalId) {
        sink.record(
            principal,
            HostAuditEvent::FileRead { path: "/w/r" },
            HostAuditOutcome::Allowed,
        );
        sink.record(
            principal,
            HostAuditEvent::FileWrite { path: "/w/w" },
            HostAuditOutcome::Failed("disk full"),
        );
        sink.record(
            principal,
            HostAuditEvent::FileDelete { path: "/w/d" },
            HostAuditOutcome::Allowed,
        );
        sink.record(
            principal,
            HostAuditEvent::NetConnect {
                host: "example.com",
                port: 443,
            },
            HostAuditOutcome::Allowed,
        );
        sink.record(
            principal,
            HostAuditEvent::NetBind {
                addr: "127.0.0.1:0",
            },
            HostAuditOutcome::Allowed,
        );
        sink.record(
            principal,
            HostAuditEvent::NetAccept {
                local_addr: "127.0.0.1:8788",
                peer_addr: "127.0.0.1:49152",
            },
            HostAuditOutcome::Allowed,
        );
        sink.record(
            principal,
            HostAuditEvent::ProcessSpawn { command: "ls" },
            HostAuditOutcome::Denied("not in host_process allowlist"),
        );
    }

    /// Every event kind, including a denial, lands a principal-stamped,
    /// correctly-mapped entry, and the resulting chain still verifies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn records_each_event_kind_onto_the_signed_chain() {
        let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
        // Fixed, non-nil session id (nil is reserved for system/daemon
        // messages); deterministic so the test stays reproducible.
        let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0994));
        let sink = KernelAuditSink::new(Arc::clone(&log), session.clone());
        let p = principal();

        record_event_kinds(&sink, &p);
        sink.shutdown();

        let entries = log
            .get_principal_entries(&session, Some(&p))
            .await
            .expect("read principal entries");
        assert_eq!(entries.len(), 7, "all seven events must persist");

        // Every entry is stamped with the acting principal.
        for e in &entries {
            assert_eq!(e.principal.as_ref(), Some(&p), "principal must be stamped");
        }

        // FileRead → success.
        assert!(matches!(
            (&entries[0].action, &entries[0].outcome),
            (AuditAction::FileRead { path }, AuditOutcome::Success { .. }) if path == "/w/r"
        ));
        // FileWrite Failed → Failure + zero content hash placeholder.
        assert!(matches!(
            (&entries[1].action, &entries[1].outcome),
            (AuditAction::FileWrite { path, content_hash }, AuditOutcome::Failure { .. })
                if path == "/w/w" && *content_hash == ContentHash::zero()
        ));
        // FileDelete → success.
        assert!(matches!(
            &entries[2].action,
            AuditAction::FileDelete { path } if path == "/w/d"
        ));
        // NetConnect → success with host + port.
        assert!(matches!(
            &entries[3].action,
            AuditAction::NetConnect { host, port } if host == "example.com" && *port == 443
        ));
        // NetBind → success with addr.
        assert!(matches!(
            &entries[4].action,
            AuditAction::NetBind { addr } if addr == "127.0.0.1:0"
        ));
        // NetAccept → success with host-observed endpoints.
        assert!(matches!(
            &entries[5].action,
            AuditAction::NetAccept {
                local_addr,
                peer_addr,
            } if local_addr == "127.0.0.1:8788" && peer_addr == "127.0.0.1:49152"
        ));
        // ProcessSpawn Denied → Failure + Denied proof.
        assert!(matches!(
            (
                &entries[6].action,
                &entries[6].authorization,
                &entries[6].outcome
            ),
            (
                AuditAction::ProcessSpawn { command },
                AuthorizationProof::Denied { .. },
                AuditOutcome::Failure { .. }
            ) if command == "ls"
        ));

        // The signed hash chain remains valid after the high-frequency
        // appends.
        let verification = log.verify_chain(&session).await.expect("verify chain");
        assert!(
            verification.valid,
            "chain must remain valid: {verification:?}"
        );
    }

    /// A multi-megabyte guest string is capped to [`MAX_AUDIT_STR_BYTES`] before
    /// it is signed and persisted, and the stored form is still valid UTF-8.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_guest_strings_are_truncated_at_the_sink() {
        let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
        let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0995));
        let sink = KernelAuditSink::new(Arc::clone(&log), session.clone());
        let p = principal();

        // 4 MiB of a multi-byte code point: exercises both the size cap and the
        // char-boundary snap (the naive byte cut could land mid-'é').
        let huge = "é".repeat(4 * 1024 * 1024);
        assert!(huge.len() > MAX_AUDIT_STR_BYTES);

        sink.record(
            &p,
            HostAuditEvent::ProcessSpawn { command: &huge },
            // Even a denied call from a zero-capability capsule must not persist
            // the unbounded string — that is the amplification vector.
            HostAuditOutcome::Denied("not in host_process allowlist"),
        );
        sink.record(
            &p,
            HostAuditEvent::FileRead { path: &huge },
            HostAuditOutcome::Allowed,
        );
        sink.shutdown();

        let entries = log
            .get_principal_entries(&session, Some(&p))
            .await
            .expect("read principal entries");
        assert_eq!(entries.len(), 2);

        for e in &entries {
            let stored = match &e.action {
                AuditAction::ProcessSpawn { command } => command,
                AuditAction::FileRead { path } => path,
                other => panic!("unexpected action: {other:?}"),
            };
            assert!(
                stored.len() <= MAX_AUDIT_STR_BYTES,
                "stored string must be capped: {} bytes",
                stored.len()
            );
            // `str` is UTF-8 by construction; assert the snap preserved whole
            // code points (no trailing partial 'é').
            assert!(
                stored.chars().all(|c| c == 'é'),
                "truncation must not split a multi-byte code point"
            );
        }

        // Bounding the field must not break the signed chain.
        let verification = log.verify_chain(&session).await.expect("verify chain");
        assert!(
            verification.valid,
            "chain must remain valid: {verification:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn host_record_is_enqueue_only_and_shutdown_is_the_durable_barrier() {
        let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
        let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0997));
        let sink = KernelAuditSink::new(Arc::clone(&log), session.clone());
        let p = principal();
        let started = std::time::Instant::now();
        sink.record(
            &p,
            HostAuditEvent::FileRead { path: "/enqueue" },
            HostAuditOutcome::Allowed,
        );
        // This call must not wait for the writer's append/fync path. The
        // bounded queue records acceptance immediately; shutdown below is the
        // explicit point at which a caller asks for durable completion.
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        assert_eq!(sink.health().accepted, 1);
        sink.shutdown();
        assert_eq!(sink.health().persisted, 1);
        assert_eq!(log.count_session(&session).await.unwrap_or_default(), 1);
    }

    /// The truncation helper snaps to a char boundary and is a no-op under the
    /// cap.
    #[test]
    fn truncate_guest_str_snaps_to_char_boundary() {
        // Under the cap: identity.
        assert_eq!(truncate_guest_str("hello"), "hello");

        // 'é' is 2 bytes; a string that ends exactly one byte past the cap must
        // snap DOWN to the last whole code point, never mid-'é'.
        let s = "é".repeat(MAX_AUDIT_STR_BYTES); // 2 * cap bytes
        let out = truncate_guest_str(&s);
        assert!(out.len() <= MAX_AUDIT_STR_BYTES);
        assert!(out.is_char_boundary(out.len()));
        assert!(out.chars().all(|c| c == 'é'));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bounded_writer_durably_acks_concurrent_reports() {
        let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
        let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0996));
        let sink = Arc::new(KernelAuditSink::new(Arc::clone(&log), session.clone()));
        let p = principal();
        let mut threads = Vec::new();
        for worker in 0..4 {
            let sink = Arc::clone(&sink);
            let p = p.clone();
            threads.push(std::thread::spawn(move || {
                for index in 0..64 {
                    let path = format!("/bounded/{worker}/{index}");
                    sink.record(
                        &p,
                        HostAuditEvent::FileRead { path: &path },
                        HostAuditOutcome::Allowed,
                    );
                }
            }));
        }
        for thread in threads {
            thread.join().expect("reporting thread");
        }
        sink.shutdown();
        let health = sink.health();
        assert_eq!(health.accepted, 256);
        assert_eq!(health.persisted, 256);
        assert_eq!(health.failed, 0);
        assert_eq!(log.count_session(&session).await.unwrap(), 256);
        assert!(log.verify_chain(&session).await.unwrap().valid);
    }
}
