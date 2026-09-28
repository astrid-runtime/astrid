//! Mapping helpers for the audit-coverage records: the capsule actor stamped
//! on host-call entries.

use astrid_audit::{AuditAction, CapsuleActor};
use astrid_capsule::HostAuditActor;

use super::truncate_guest_str;

/// Convert the engine's load-time actor into the signed audit form.
pub(super) fn to_capsule_actor(actor: &HostAuditActor) -> CapsuleActor {
    CapsuleActor {
        capsule_id: truncate_guest_str(&actor.capsule_id),
        wasm_hash: actor.wasm_hash,
    }
}

/// The capsule a host-observed action is attributed to, if any.
pub(super) fn action_actor(action: &AuditAction) -> Option<&CapsuleActor> {
    match action {
        AuditAction::FileRead { actor, .. }
        | AuditAction::FileWrite { actor, .. }
        | AuditAction::FileDelete { actor, .. }
        | AuditAction::NetConnect { actor, .. }
        | AuditAction::NetBind { actor, .. }
        | AuditAction::NetAccept { actor, .. }
        | AuditAction::ProcessSpawn { actor, .. } => actor.as_ref(),
        _ => None,
    }
}
