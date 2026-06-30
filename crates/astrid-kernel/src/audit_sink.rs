//! Kernel implementation of the capsule host-audit sink.
//!
//! The WASM host engine (`astrid-capsule`) reports sensitive per-action host
//! calls — fs read/write/delete, net connect/bind, process spawn — to the
//! [`HostAuditSink`](astrid_capsule::HostAuditSink) trait. The kernel holds
//! both the durable audit log and the runtime ed25519 signing key, so it is
//! the side that can map those neutral events onto a signed, hash-chained
//! [`AuditEntry`](astrid_audit::AuditEntry) and append it synchronously.
//!
//! This mirrors `kernel_router::record_admin_audit`: persistence failures are
//! logged and swallowed (audit degrades to "continue + alert"), never panic
//! or block the host call.

use std::sync::Arc;

use astrid_audit::{AuditAction, AuditLog, AuditOutcome, AuthorizationProof};
use astrid_capsule::{HostAuditEvent, HostAuditOutcome, HostAuditSink};
use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::ContentHash;
use tracing::warn;

/// Authorization reason stamped on an allowed or failed manifest-gated host
/// call — the capsule's declared manifest allowlist is what authorized the
/// effect (there is no per-call user/capability token at this seam).
const MANIFEST_GATED_REASON: &str = "manifest-gated host call";

/// Persists capsule per-action host calls onto the kernel's signed audit
/// chain.
///
/// Cloned (cheap — `Arc` + `SessionId`) into a `dyn HostAuditSink` handed to
/// every capsule engine at load. One per kernel boot, bound to the kernel's
/// single `session_id`.
pub struct KernelAuditSink {
    /// The kernel's durable, signed audit log (shared `Arc`).
    audit_log: Arc<AuditLog>,
    /// The kernel session every entry is chained under.
    session_id: SessionId,
}

impl KernelAuditSink {
    /// Construct a sink over the kernel's audit log + session.
    ///
    /// Generic over the inputs (mirroring [`AuditLog::in_memory`]): accepts
    /// either an owned [`AuditLog`] or a shared `Arc<AuditLog>`, and any
    /// `Into<SessionId>`.
    #[must_use]
    pub fn new(audit_log: impl Into<Arc<AuditLog>>, session_id: impl Into<SessionId>) -> Self {
        Self {
            audit_log: audit_log.into(),
            session_id: session_id.into(),
        }
    }

    /// Map a neutral host event onto the internal audit action.
    ///
    /// `FileWrite` content hashing is not captured at this per-action seam
    /// yet (the host fn reports the path, not the written bytes); a
    /// zero hash is recorded as a documented placeholder pending a
    /// content-addressed follow-up.
    fn to_action(event: HostAuditEvent<'_>) -> AuditAction {
        match event {
            HostAuditEvent::FileRead { path } => AuditAction::FileRead {
                path: path.to_owned(),
            },
            HostAuditEvent::FileWrite { path } => AuditAction::FileWrite {
                path: path.to_owned(),
                // Content hash not captured at the per-action seam yet.
                content_hash: ContentHash::zero(),
            },
            HostAuditEvent::FileDelete { path } => AuditAction::FileDelete {
                path: path.to_owned(),
            },
            HostAuditEvent::NetConnect { host, port } => AuditAction::NetConnect {
                host: host.to_owned(),
                port,
            },
            HostAuditEvent::NetBind { addr } => AuditAction::NetBind {
                addr: addr.to_owned(),
            },
            HostAuditEvent::ProcessSpawn { command } => AuditAction::ProcessSpawn {
                command: command.to_owned(),
            },
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
        let action = Self::to_action(event);
        let (proof, audit_outcome) = Self::to_proof_outcome(outcome);
        if let Err(e) = self.audit_log.append_with_principal(
            self.session_id.clone(),
            principal.clone(),
            action,
            proof,
            audit_outcome,
        ) {
            warn!(
                security_event = true,
                %principal,
                error = %e,
                "Failed to persist per-action audit entry — continuing"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use astrid_crypto::KeyPair;

    fn principal() -> PrincipalId {
        PrincipalId::new("alice").expect("valid principal")
    }

    /// Every event kind, including a denial, lands a principal-stamped,
    /// correctly-mapped entry, and the resulting chain still verifies.
    #[test]
    fn records_each_event_kind_onto_the_signed_chain() {
        let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
        // Fixed, non-nil session id (nil is reserved for system/daemon
        // messages); deterministic so the test stays reproducible.
        let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0994));
        let sink = KernelAuditSink::new(Arc::clone(&log), session.clone());
        let p = principal();

        sink.record(
            &p,
            HostAuditEvent::FileRead { path: "/w/r" },
            HostAuditOutcome::Allowed,
        );
        sink.record(
            &p,
            HostAuditEvent::FileWrite { path: "/w/w" },
            HostAuditOutcome::Failed("disk full"),
        );
        sink.record(
            &p,
            HostAuditEvent::FileDelete { path: "/w/d" },
            HostAuditOutcome::Allowed,
        );
        sink.record(
            &p,
            HostAuditEvent::NetConnect {
                host: "example.com",
                port: 443,
            },
            HostAuditOutcome::Allowed,
        );
        sink.record(
            &p,
            HostAuditEvent::NetBind {
                addr: "127.0.0.1:0",
            },
            HostAuditOutcome::Allowed,
        );
        sink.record(
            &p,
            HostAuditEvent::ProcessSpawn { command: "ls" },
            HostAuditOutcome::Denied("not in host_process allowlist"),
        );

        let entries = log
            .get_principal_entries(&session, Some(&p))
            .expect("read principal entries");
        assert_eq!(entries.len(), 6, "all six events must persist");

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
        // ProcessSpawn Denied → Failure + Denied proof.
        assert!(matches!(
            (
                &entries[5].action,
                &entries[5].authorization,
                &entries[5].outcome
            ),
            (
                AuditAction::ProcessSpawn { command },
                AuthorizationProof::Denied { .. },
                AuditOutcome::Failure { .. }
            ) if command == "ls"
        ));

        // The signed hash chain remains valid after the high-frequency
        // appends.
        let verification = log.verify_chain(&session).expect("verify chain");
        assert!(
            verification.valid,
            "chain must remain valid: {verification:?}"
        );
    }
}
