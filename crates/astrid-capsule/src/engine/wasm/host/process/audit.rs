//! Audit envelopes for the `astrid:process` host fns.
//!
//! Split out of `process/mod.rs` so the spawn/handle host-fn surface and its
//! audit instrumentation stay legible as separate concerns. Every helper
//! emits the off-by-default `astrid.audit.process` observability line; the
//! spawn helpers additionally report a typed
//! [`ProcessSpawn`](crate::audit_sink::HostAuditEvent::ProcessSpawn)
//! onto the kernel's signed audit chain (the sensitive exec seam).

use crate::audit_sink::{HostAuditEvent, HostAuditOutcome};
use crate::engine::wasm::host_state::HostState;

/// True for the sensitive exec seams — `spawn`, `spawn-background`,
/// `spawn-persistent` — whose ops mint a fresh child onto the signed audit
/// chain. Lifecycle/handle ops (`wait`, `kill`, `status`, …) act on an
/// already-audited child and return false. Matches on the trailing verb so a
/// fully-qualified WIT op (`astrid:process/host.spawn-background`) and a bare
/// verb classify identically.
fn is_spawn_op(op: &str) -> bool {
    let verb = op.rsplit('.').next().unwrap_or(op);
    verb == "spawn" || verb.starts_with("spawn-")
}

/// Audit a process host fn invocation.
///
/// Emits the off-by-default `astrid.audit.process` observability line for
/// every op, and additionally reports a typed
/// [`ProcessSpawn`](HostAuditEvent::ProcessSpawn) event to the per-action
/// audit sink for SPAWN ops (the sensitive exec seam). Lifecycle/handle ops
/// (`wait`, `kill`, `status`, …) keep the tracing line but do not land a
/// per-action chain entry — they act on an already-audited child, not a fresh
/// exec.
pub(crate) fn audit_process<T, E: std::fmt::Debug>(
    state: &HostState,
    op: &str,
    cmd: &str,
    result: &Result<T, E>,
) {
    let capsule_id = state.capsule_id.as_str();
    let principal = state.effective_principal();
    match result {
        Ok(_) => tracing::debug!(
            target: "astrid.audit.process",
            %capsule_id,
            %principal,
            fn = op,
            cmd,
            "audit",
        ),
        Err(e) => tracing::debug!(
            target: "astrid.audit.process",
            %capsule_id,
            %principal,
            fn = op,
            cmd,
            error = ?e,
            "audit",
        ),
    }

    // Only spawn ops (incl. spawn-background / spawn-persistent) mint a fresh
    // sensitive exec onto the audit chain.
    if !is_spawn_op(op) {
        return;
    }
    let Some(sink) = state.audit_sink.as_ref() else {
        return;
    };
    let err_buf;
    let outcome = match result {
        Ok(_) => HostAuditOutcome::Allowed,
        Err(e) => {
            err_buf = format!("{e:?}");
            HostAuditOutcome::Failed(&err_buf)
        },
    };
    sink.record(
        &principal,
        HostAuditEvent::ProcessSpawn { command: cmd },
        outcome,
    );
}

/// Audit a spawn that carried read-only file injections. Emits the same
/// `astrid.audit.process` line as [`audit_process`] plus an `injections` field
/// = a formatted `"<target>=<blake3hex>"` list. Only the target paths and
/// content hashes are logged — never the source path's parent, the bytes, or
/// any token (consistent with the existing audit discipline).
pub(crate) fn audit_process_injections<T, E: std::fmt::Debug>(
    state: &HostState,
    op: &'static str,
    cmd: &str,
    audit: &[(String, String)],
    result: &Result<T, E>,
) {
    let injections = audit
        .iter()
        .map(|(target, hash)| format!("{target}={hash}"))
        .collect::<Vec<_>>()
        .join(",");
    let capsule_id = state.capsule_id.as_str();
    let principal = state.effective_principal();
    match result {
        Ok(_) => tracing::debug!(
            target: "astrid.audit.process",
            %capsule_id,
            %principal,
            fn = op,
            cmd,
            injections = %injections,
            "audit",
        ),
        Err(e) => tracing::debug!(
            target: "astrid.audit.process",
            %capsule_id,
            %principal,
            fn = op,
            cmd,
            injections = %injections,
            error = ?e,
            "audit",
        ),
    }

    // A spawn-with-injections is still a sensitive exec: report it onto the
    // signed audit chain exactly as the no-injection path does. The injected
    // file targets/hashes stay in the observability line only (the chain
    // entry records the command, per the per-action seam's current fidelity).
    if is_spawn_op(op)
        && let Some(sink) = state.audit_sink.as_ref()
    {
        let err_buf;
        let outcome = match result {
            Ok(_) => HostAuditOutcome::Allowed,
            Err(e) => {
                err_buf = format!("{e:?}");
                HostAuditOutcome::Failed(&err_buf)
            },
        };
        sink.record(
            &principal,
            HostAuditEvent::ProcessSpawn { command: cmd },
            outcome,
        );
    }
}

/// Audit a spawn RESULT, routing through the injection-aware envelope when the
/// spawn carried read-only file injections and the plain envelope otherwise.
///
/// Used by BOTH the success path and the early-return error arms (a failed
/// `prepare_sandboxed_command`, a failed `spawn`, or a `resource_table` push
/// failure after a child has already forked) so that every exit from a spawn
/// host fn lands exactly one chain entry — the `?`-shortcut arms used to return
/// before any audit, leaving a fork or a fork-failure with no trace.
pub(crate) fn audit_spawn_result<T, E: std::fmt::Debug>(
    state: &HostState,
    op: &'static str,
    cmd: &str,
    injections: &[(String, String)],
    result: &Result<T, E>,
) {
    if injections.is_empty() {
        audit_process(state, op, cmd, result);
    } else {
        audit_process_injections(state, op, cmd, injections, result);
    }
}

/// Emit the `astrid.audit.process` tracing line for a denied spawn AND
/// report the typed `ProcessSpawn` + `Denied` event to the per-action audit
/// sink. Used on the spawn gate-denial branches in place of the success-path
/// [`audit_process`] so the chain entry carries a `Denied` outcome (not a
/// generic `Failed`) and the denial is recorded exactly once.
pub(crate) fn record_process_denied(state: &HostState, op: &str, command: &str, reason: &str) {
    let result: Result<(), &str> = Err(reason);
    // Observability line (mirrors what audit_process would have emitted on
    // the Err path) — kept so the tracing surface is unchanged.
    tracing::debug!(
        target: "astrid.audit.process",
        capsule_id = %state.capsule_id.as_str(),
        principal = %state.effective_principal(),
        fn = op,
        cmd = command,
        error = ?result,
        "audit",
    );
    if let Some(sink) = state.audit_sink.as_ref() {
        sink.record(
            &state.effective_principal(),
            HostAuditEvent::ProcessSpawn { command },
            HostAuditOutcome::Denied(reason),
        );
    }
}

/// Audit an id-keyed persistent-process op. Logs a short, non-reversible
/// hash of the `process-id` — never the raw token, per the WIT ("never the
/// raw id") — plus the op, principal, and capsule.
pub(crate) fn audit_process_id<T, E: std::fmt::Debug>(
    state: &HostState,
    op: &'static str,
    id: &str,
    result: &Result<T, E>,
) {
    let id_hash = blake3::hash(id.as_bytes()).to_hex();
    let id = &id_hash[..16];
    let capsule_id = state.capsule_id.as_str();
    let principal = state.effective_principal();
    match result {
        Ok(_) => tracing::debug!(
            target: "astrid.audit.process",
            %capsule_id,
            %principal,
            fn = op,
            id,
            "audit",
        ),
        Err(e) => tracing::debug!(
            target: "astrid.audit.process",
            %capsule_id,
            %principal,
            fn = op,
            id,
            error = ?e,
            "audit",
        ),
    }
}
