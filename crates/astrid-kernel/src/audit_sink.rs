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
    // never splits a multi-byte code point (which would panic).
    let mut end = MAX_AUDIT_STR_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

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

    /// A multi-megabyte guest string is capped to [`MAX_AUDIT_STR_BYTES`] before
    /// it is signed and persisted, and the stored form is still valid UTF-8.
    #[test]
    fn oversized_guest_strings_are_truncated_at_the_sink() {
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

        let entries = log
            .get_principal_entries(&session, Some(&p))
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
        let verification = log.verify_chain(&session).expect("verify chain");
        assert!(
            verification.valid,
            "chain must remain valid: {verification:?}"
        );
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
}
