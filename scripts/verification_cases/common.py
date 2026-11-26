"""Verified inputs, proof items and exact source edits."""

from pathlib import Path

ENTRY = Path("verification/hosted_authority.rs")
MODEL = Path("verification/hosted_authority_model.rs")
AUTHORITY = Path("crates/astrid-capabilities/src/store/authority.rs")
GUEST_AUTHORITY = Path("crates/astrid-storage/src/principal_state/guest_authority.rs")
KV_ENCODING = Path("crates/astrid-storage/src/kv/encoding.rs")
OVERLAY = Path("crates/astrid-storage/src/kv/tree/overlay/traversal.rs")
OVERLAY_UPDATE = Path("crates/astrid-storage/src/kv/tree/overlay/update.rs")
PRINCIPAL_SCOPE = Path("crates/astrid-kernel/src/kernel_router/principal_scope.rs")
BINDING = Path("crates/astrid-storage/src/principal_directory/binding.rs")
CACHE_ADDRESS = Path("crates/astrid-kernel/src/capsule_materialization/cache_address.rs")
GENERATION = Path("crates/astrid-capsule/src/registry/generation.rs")
VIEW_OWNER = Path("crates/astrid-capsule/src/registry/view_owner.rs")
ORDERED_DISPATCH = Path("crates/astrid-events/src/ordered_dispatch.rs")
DELIVERY_COMMIT = Path("crates/astrid-events/src/admission/commit.rs")
ROUTE_GATE = Path("crates/astrid-events/src/route/gate/state.rs")
ROUTE_SCOPE = Path("crates/astrid-events/src/route/scope.rs")
PRINCIPAL_SYNTAX = Path("crates/astrid-core/src/principal/syntax.rs")
INGRESS_FRAME = Path("crates/astrid-capsule/src/engine/wasm/host/net/ingress_frame.rs")
DEVICE_ADMISSION = Path("crates/astrid-core/src/profile/device_admission.rs")
CONSENT_IDENTITY = Path("crates/astrid-capsule/src/engine/wasm/host/consent_identity.rs")
NATIVE_TOPIC = Path("crates/astrid-uplink/src/native/topic_policy.rs")
NATIVE_RECIPIENT = Path("crates/astrid-uplink/src/native/recipient.rs")
NATIVE_QUEUE = Path("crates/astrid-uplink/src/native/delivery_queue.rs")
NATIVE_REPLY = Path("crates/astrid-uplink/src/native/reply_claim.rs")
NATIVE_FRAME = Path("crates/astrid-uplink/src/native/frame_segments.rs")
DEVICE_SESSIONS = Path("crates/astrid-core/src/profile/device_sessions/phase.rs")
DEVICE_REGISTRATION = Path("crates/astrid-core/src/profile/device_registration.rs")
DEVICE_CHALLENGE = Path("crates/astrid-core/src/profile/device_challenge.rs")
REGISTERED_BEARER = Path("crates/astrid-core/src/session_token/registered_bearer.rs")
PRIVATE_RESPONDER = Path("crates/astrid-capsule/src/elicitation/responder.rs")
PAIR_DENIES = Path("crates/astrid-kernel/src/kernel_router/admin/pair_device_handlers/deny_patterns.rs")
RECEIPT = Path("crates/astrid-kernel/src/kernel_router/resume_receipt/validation.rs")
UID_TEXT = Path("crates/astrid-core/src/identity/principal/text.rs")
FILESYSTEM_PATH = Path("crates/astrid-storage/src/filesystem/path_validation.rs")
STORAGE_HANDLES = Path("crates/astrid-capsule/src/engine/wasm/storage_handles.rs")
STORAGE_FILE = Path("crates/astrid-capsule/src/engine/wasm/storage_file.rs")
LEASE_RESERVATION = Path("crates/astrid-kernel/src/storage_mount/lease_authority/reservation.rs")
LEASE_SUBTREE = Path("crates/astrid-kernel/src/storage_mount/lease_authority/subtree.rs")
LEASE_CALLBACK = Path("crates/astrid-kernel/src/storage_mount/lease_authority/callback.rs")
LEASE_REQUESTER = Path("crates/astrid-kernel/src/storage_mount/lease_authority/requester.rs")
INVOCATION_OWNER = Path("crates/astrid-capsule/src/engine/wasm/invocation_owner/admission.rs")
MOUNT = Path("crates/astrid-capsule/src/engine/wasm/mount_selection.rs")
PAIR_RESULT = Path("crates/astrid-kernel/src/kernel_router/admin/pair_issue_result.rs")
INPUTS = [
    UID_TEXT,
    FILESYSTEM_PATH,
    STORAGE_HANDLES,
    STORAGE_FILE,
    PAIR_RESULT,
    LEASE_CALLBACK,
    Path("crates/astrid-capsule/src/engine/wasm/guest_kv.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/guest_uplink.rs"),
    Path("crates/astrid-capsule/src/security/identity.rs"),
    Path("crates/astrid-kernel/src/storage_mount/lease_authority/destination.rs"),
    Path("crates/astrid-kernel/src/storage_mount/lease_authority/worker.rs"),
    LEASE_SUBTREE,
    LEASE_RESERVATION,
    Path("verification/hosted_lease_model.rs"),
    Path("verification/hosted_wal_physical_model.rs"),
    Path("verification/hosted_wal_binding.rs"),
    Path("verification/hosted_wal_stream.rs"),
    Path("verification/hosted_wal_writer_trace.rs"),
    Path("verification/hosted_uplink_model.rs"),
    Path("verification/hosted_kv_model.rs"),
    Path("verification/hosted_wal_model.rs"),
    Path("crates/astrid-core/src/storage_filesystem/operation.rs"),
    LEASE_REQUESTER,
    INVOCATION_OWNER,
    MOUNT,
    RECEIPT,
    PAIR_DENIES,
    PRIVATE_RESPONDER,
    REGISTERED_BEARER,
    ORDERED_DISPATCH,
    DELIVERY_COMMIT,
    DEVICE_CHALLENGE,
    DEVICE_REGISTRATION,
    DEVICE_SESSIONS,
    NATIVE_FRAME,
    NATIVE_REPLY,
    NATIVE_QUEUE,
    NATIVE_TOPIC,
    NATIVE_RECIPIENT,
    CONSENT_IDENTITY,
    DEVICE_ADMISSION,
    INGRESS_FRAME,
    PRINCIPAL_SYNTAX,
    ROUTE_SCOPE,
    ROUTE_GATE,
    VIEW_OWNER,
    GENERATION,
    CACHE_ADDRESS,
    BINDING,
    PRINCIPAL_SCOPE,
    OVERLAY_UPDATE,
    OVERLAY,
    KV_ENCODING,
    GUEST_AUTHORITY,
    Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/measured_record.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/measurement.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/interior.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/commit_wire.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/transaction.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/read_buffer.rs"),
    Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
    Path("crates/astrid-storage/src/principal_state/owner_codec.rs"),
    Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/root_history.rs"),
    ENTRY,
    MODEL,
    AUTHORITY,
    Path("crates/astrid-capsule-types/src/fuel_ledger/arithmetic.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/principal_tracker/state.rs"),
    Path("crates/astrid-core/src/capability_grammar/matcher.rs"),
]
PROOF_ITEMS = [
    "theorem_acknowledged_revocation_keeps_grant_revoked",
    "acknowledged_revocation_denies_reusable_admission",
    "theorem_single_use_grant_admits_one_consumption",
    "theorem_acknowledged_consumption_keeps_grant_used",
    "acknowledged_consumption_survives_a_later_revocation",
    "acknowledged_consumption_is_used_at_index",
    "theorem_revocation_keeps_grant_revoked_until_recovery",
    "revocation_denies_reusable_admission_until_recovery",
    "witness_unacknowledged_revocation_reopens_at_recovery",
    "theorem_retirement_admits_no_operation",
    "retirement_closes_after_an_earlier_resume",
    "witness_earlier_resume_does_not_reopen_retirement",
    "theorem_committed_fuel_is_budget_plus_charged_excess",
    "theorem_committed_fuel_stays_within_budget",
    "witness_charged_excess_is_the_only_overshoot",
]
def replace_once(text: str, old: str, new: str) -> str:
    """Replace the one occurrence of `old` in `text`."""
    if text.count(old) != 1:
        raise ValueError(f"expected one occurrence of {old!r}, found {text.count(old)}")
    return text.replace(old, new, 1)


def item(text: str, function: str) -> tuple[int, int]:
    """Locate a top-level proof item, from its signature to its closing brace.

    The scope includes the requires and ensures clauses.
    """
    start = text.index(f"fn {function}(")
    closing = text.index("\n}\n", start) + 1
    return start, closing


def edit_function(text: str, function: str, old: str, new: str) -> str:
    """Replace the one occurrence of `old` in a top-level proof item."""
    start, closing = item(text, function)
    item_text = text[start:closing]
    return text[:start] + replace_once(item_text, old, new) + text[closing:]


def contradict_function(text: str, function: str) -> str:
    """Put a false assertion first in the body of a proof item."""
    signature = text.index(f"proof fn {function}(")
    opening = text.index("{\n", signature) + 2
    return text[:opening] + "    assert(false);\n" + text[opening:]
