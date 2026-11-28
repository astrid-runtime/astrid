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
NATIVE_FRAME = Path("crates/astrid-uplink/src/frame_segments.rs")
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
    Path("crates/astrid-mcp/src/server/peer_selection.rs"),
    Path("crates/astrid-mcp/src/server/tool_call.rs"),
    Path("crates/astrid-workspace/src/sandbox/prefix_policy.rs"),
    Path("crates/astrid-workspace/src/sandbox/path_literal.rs"),
    Path("crates/astrid-workspace/src/sandbox/seatbelt_profile.rs"),
    Path("crates/astrid-workspace/src/sandbox/bwrap_flags.rs"),
    Path("verification/hosted_mcp_peer.rs"),
    Path("crates/astrid-capsule/src/engine/mcp/network.rs"),
    Path("crates/astrid-mcp/src/server/stdio_policy.rs"),
    Path("crates/astrid-cli/src/commands/mcp/mrtr_context.rs"),
    Path("verification/hosted_mrtr_context.rs"),
    Path("crates/astrid-cli/src/commands/mcp/server/invocation.rs"),
    Path("crates/astrid-cli/src/commands/mcp/mrtr_redemption.rs"),
    Path("crates/astrid-capsule/src/engine/mcp_cleanup.rs"),
    Path("crates/astrid-capsule/src/engine/mcp_registration.rs"),
    Path("verification/hosted_batch_slots.rs"),
    Path("verification/hosted_journal_history.rs"),
    Path("crates/astrid-storage/src/engine/durable/batch_slots.rs"),
    Path("verification/hosted_chunk_tree_range.rs"),
    Path("crates/astrid-storage/src/content_dag/child_range.rs"),
    Path("crates/astrid-storage/src/content_dag/chunk_range.rs"),
    Path("crates/astrid-storage/src/byte_order.rs"),
    Path("crates/astrid-storage/src/storage_words.rs"),
    Path("crates/astrid-storage/src/storage_fields.rs"),
    Path("crates/astrid-storage/src/content_dag/file_wire.rs"),
    Path("verification/hosted_file_descriptor.rs"),
    Path("crates/astrid-storage/src/content/catalog/summary.rs"),
    Path("verification/hosted_catalog_charge.rs"),
    Path("crates/astrid-storage/src/content/store/quota_transition.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/io/splice.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/io/dispatch.rs"),
    Path("verification/hosted_io_splice.rs"),
    Path("verification/hosted_io_disposal.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/io/disposal.rs"),
    Path("verification/hosted_tcp_destinations.rs"),
    Path("crates/astrid-core/src/principal/retirement.rs"),
    Path("crates/astrid-storage/src/ownership/pending.rs"),
    Path("crates/astrid-storage/src/ownership/recovery.rs"),
    Path("verification/hosted_retirement_recovery.rs"),
    Path("verification/hosted_runtime_residency.rs"),
    Path("crates/astrid-kernel/src/runtime_residency.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/net/reservation.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/net/bind_target.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/net/destinations.rs"),
    Path("verification/hosted_pool_return.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/pool/return_policy.rs"),
    Path("verification/hosted_http_hop.rs"),
    Path("verification/hosted_http_slots.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/http/slots.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/http/body.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/http/hop.rs"),
    Path("verification/hosted_egress_reply.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/egress_reply.rs"),
    Path("crates/astrid-capsule/src/profile_cache/command.rs"),
    Path("verification/hosted_process_command.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/process/command.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/process/spawn_admission.rs"),
    UID_TEXT,
    FILESYSTEM_PATH,
    Path("crates/astrid-storage/src/filesystem/replacement.rs"),
    Path("crates/astrid-storage/src/content/name.rs"),
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
    Path("verification/hosted_closure_model.rs"),
    Path("verification/hosted_record_model.rs"),
    Path("crates/astrid-storage/src/engine/durable_cache/resident.rs"),
    Path("crates/astrid-storage/src/engine/durable/format/recovered_record.rs"),
    Path("crates/astrid-storage/src/engine/durable/read_admission.rs"),
    Path("verification/hosted_arena_placement.rs"),
    Path("verification/hosted_arena_append.rs"),
    Path("verification/hosted_recovery_barrier.rs"),
    Path("verification/hosted_checkpoint_recovery.rs"),
    Path("verification/hosted_duplicate_recovery.rs"),
    Path("verification/hosted_record_roundtrip.rs"),
    Path("crates/astrid-storage/src/engine/durable/arena_index.rs"),
    Path("crates/astrid-storage/src/engine/durable/index/key.rs"),
    Path("crates/astrid-storage/src/engine/durable/index/admission.rs"),
    Path("crates/astrid-storage/src/engine/durable/index/rebuild.rs"),
    Path("crates/astrid-storage/src/engine/durable/format/checkpoint_reader.rs"),
    Path("crates/astrid-storage/src/engine/durable/format/duplicates.rs"),
    Path("crates/astrid-storage/src/engine/durable/arena_frame.rs"),
    Path("crates/astrid-storage/src/engine/durable/frame_repair.rs"),
    Path("crates/astrid-storage/src/engine/durable/recovery_barrier.rs"),
    Path("crates/astrid-storage/src/engine/durable/recovered_closure.rs"),
    Path("crates/astrid-storage/src/engine/durable/arena_vectors.rs"),
    Path("crates/astrid-storage/src/engine/durable/direct_placement.rs"),
    Path("crates/astrid-storage/src/engine/durable/format/arena_span.rs"),
    Path("crates/astrid-storage/src/engine/durable/format/positional_read.rs"),
    Path("crates/astrid-storage/src/engine/durable/format/verified_record.rs"),
    Path("crates/astrid-storage/src/storage_model/object_codes.rs"),
    Path("crates/astrid-storage/src/storage_model/reference_kind.rs"),
    Path("crates/astrid-storage/src/storage_model/object_reference.rs"),
    Path("crates/astrid-storage/src/storage_model/root_state.rs"),
    Path("crates/astrid-storage/src/storage_model/object_record.rs"),
    Path("verification/hosted_uplink_model.rs"),
    Path("verification/hosted_kv_model.rs"),
    Path("verification/hosted_wal_model.rs"),
    Path("crates/astrid-core/src/storage_filesystem/operation.rs"),
    LEASE_REQUESTER,
    INVOCATION_OWNER,
    MOUNT,
    Path("crates/astrid-vfs/src/open_options.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/fs/access.rs"),
    Path("verification/hosted_file_open.rs"),
    Path("crates/astrid-vfs/src/host_address.rs"),
    Path("verification/hosted_vfs_address.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/fs/physical.rs"),
    Path("verification/hosted_physical_path.rs"),
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
    Path("crates/astrid-capsule/src/engine/wasm/host/consent_reply.rs"),
    Path("verification/hosted_consent_reply.rs"),
    Path("verification/hosted_device_profile.rs"),
    DEVICE_ADMISSION,
    INGRESS_FRAME,
    PRINCIPAL_SYNTAX,
    ROUTE_SCOPE,
    Path("verification/hosted_registry_lookup.rs"),
    Path("verification/hosted_source_lookup.rs"),
    Path("verification/hosted_process_selection.rs"),
    Path("crates/astrid-storage/src/content/store/commit_candidate.rs"),
    Path("crates/astrid-storage/src/engine/kv/ready_root.rs"),
    Path("crates/astrid-storage/src/kv/tree/hot_snapshot.rs"),
    Path("crates/astrid-storage/src/kv/tree/hot_lookup.rs"),
    Path("crates/astrid-storage/src/content/store/header_cache.rs"),
    Path("crates/astrid-storage/src/kv/tree/memo_admission.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/native_logs/dispatch.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/native_logs/admission.rs"),
    Path("verification/hosted_native_log.rs"),
    Path("crates/astrid-core/src/platform_fs/windows/projection_session/append/confirmation.rs"),
    Path("crates/astrid-core/src/platform_fs/private_projection/unix/append/selection.rs"),
    Path("crates/astrid-storage/src/content/store/header_graph.rs"),
    Path("crates/astrid-storage/src/storage_model/reference_lookup.rs"),
    Path("crates/astrid-storage/src/content/store/components.rs"),
    Path("crates/astrid-storage/src/content/component_labels.rs"),
    Path("crates/astrid-storage/src/content/store/workspace/retry.rs"),
    Path("crates/astrid-storage/src/content/store/workspace/reference_transition.rs"),
    Path("verification/hosted_workspace_commit.rs"),
    Path("verification/hosted_workspace_references.rs"),
    Path("verification/hosted_header_components.rs"),
    Path("crates/astrid-capsule/src/context/workspace_commit.rs"),
    Path("verification/hosted_ephemeral_process.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/process/process_batch.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/process/persistent/publication.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/process/persistent/reap.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/process/persistent/signal_target.rs"),
    Path("crates/astrid-capsule/src/registry_keys.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/process/tracker_registry.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/process/persistent/cleanup.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/process/persistent/retirement.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/host/process/persistent/selection.rs"),
    Path("crates/astrid-capsule/src/registry/source_lookup.rs"),
    Path("crates/astrid-capsule/src/registry/view_lookup.rs"),
    Path("crates/astrid-capsule/src/registry/generation_replacement.rs"),
    Path("crates/astrid-capsule/src/registry/uplink_index.rs"),
    Path("crates/astrid-capsule/src/registry/registration.rs"),
    Path("crates/astrid-capsule/src/registry/viewers.rs"),
    Path("crates/astrid-capsule/src/registry/dependent_views.rs"),
    Path("crates/astrid-capsule/src/registry/instance_swap.rs"),
    Path("crates/astrid-capsule/src/registry/runtime_scope.rs"),
    ROUTE_GATE,
    Path("verification/hosted_route_retirement.rs"),
    VIEW_OWNER,
    GENERATION,
    CACHE_ADDRESS,
    BINDING,
    PRINCIPAL_SCOPE,
    OVERLAY_UPDATE,
    OVERLAY,
    KV_ENCODING,
    GUEST_AUTHORITY,
    Path("crates/astrid-storage/src/engine/durable/group/receipt.rs"),
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
    Path("crates/astrid-storage/src/engine/durable/journal_history.rs"),
    Path("crates/astrid-storage/src/engine/durable/journal_snapshot.rs"),
    Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
    Path("crates/astrid-storage/src/engine/durable/closure_walk.rs"),
    Path("crates/astrid-storage/src/engine/durable/closure_load.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/overlay_object.rs"),
    Path("crates/astrid-storage/src/engine/transaction_records.rs"),
    Path("crates/astrid-storage/src/engine/root_declaration.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/root_history.rs"),
    ENTRY,
    MODEL,
    AUTHORITY,
    Path("verification/hosted_overlay_range.rs"),
    Path("crates/astrid-storage/src/kv/tree/overlay/range.rs"),
    Path("verification/hosted_key_projection.rs"),
    Path("verification/hosted_checkpoint_range.rs"),
    Path("verification/hosted_checkpoint_leaf.rs"),
    Path("verification/hosted_checkpoint_page.rs"),
    Path("verification/hosted_checkpoint_reference.rs"),
    Path("verification/hosted_checkpoint_totals.rs"),
    Path("verification/hosted_checkpoint_key_field.rs"),
    Path("verification/hosted_checkpoint_child.rs"),
    Path("verification/hosted_checkpoint_branch.rs"),
    Path("verification/hosted_checkpoint_summary.rs"),
    Path("verification/hosted_checkpoint_header.rs"),
    Path("verification/hosted_checkpoint_value.rs"),
    Path("verification/hosted_delta_mutation.rs"),
    Path("verification/hosted_checkpoint_entries.rs"),
    Path("verification/hosted_checkpoint_leaf_record.rs"),
    Path("verification/hosted_checkpoint_record.rs"),
    Path("verification/hosted_checkpoint_walk.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_progress.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_walk.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_leaf.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_page.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_reference.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_totals.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_key_field.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_child.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_branch.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_summary.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_header.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_value.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_entries.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_leaf_summary.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_leaf_record.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_record.rs"),
    Path("crates/astrid-storage/src/kv/tree/checkpoint_range.rs"),
    Path("crates/astrid-storage/src/kv/tree/context/replacement.rs"),
    Path("crates/astrid-storage/src/kv/tree/delta_mutation.rs"),
    Path("crates/astrid-storage/src/kv/tree/delta_batch.rs"),
    Path("crates/astrid-storage/src/kv/tree/key_projection.rs"),
    Path("verification/hosted_token_recovery.rs"),
    Path("crates/astrid-capabilities/src/store/marker_batch.rs"),
    Path("crates/astrid-capabilities/src/store/marker_key.rs"),
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
