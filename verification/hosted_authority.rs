// Verus entry point for transitions used by hosted Astrid.

extern crate self as astrid_core;
#[path = "../crates/astrid-storage/src/content_dag/file_wire.rs"]
mod file_wire;
#[path = "../crates/astrid-storage/src/content_dag/chunk_range.rs"]
mod chunk_range;
#[path = "../crates/astrid-storage/src/content_dag/child_range.rs"]
mod child_range;
#[path = "../crates/astrid-storage/src/engine/durable/batch_slots.rs"]
mod batch_slots;
#[path = "../crates/astrid-storage/src/engine/durable/read_admission.rs"]
mod read_admission;
#[path = "../crates/astrid-storage/src/engine/durable_cache/resident.rs"]
mod resident;
#[path = "../crates/astrid-storage/src/engine/kv/ready_root.rs"]
mod ready_root;
#[path = "../crates/astrid-storage/src/kv/tree/hot_snapshot.rs"]
mod hot_snapshot;
#[path = "../crates/astrid-storage/src/kv/tree/hot_lookup.rs"]
mod hot_lookup;
#[path = "../crates/astrid-storage/src/kv/tree/memo_admission.rs"]
mod memo_admission;
#[path = "../crates/astrid-capsule/src/engine/wasm/native_logs/admission.rs"]
mod native_log_admission;
#[path = "../crates/astrid-capsule/src/engine/wasm/native_logs/dispatch.rs"]
mod native_log_dispatch;
#[path = "../crates/astrid-core/src/platform_fs/private_projection/unix/append/selection.rs"]
mod private_append_leaf;
#[path = "../crates/astrid-core/src/platform_fs/windows/projection_session/append/confirmation.rs"]
mod windows_append_confirmation;
mod hosted_native_log;
mod hosted_batch_slots;
mod hosted_chunk_tree_range;
#[path = "../crates/astrid-storage/src/byte_order.rs"]
mod byte_order;
#[path = "../crates/astrid-storage/src/storage_words.rs"]
mod storage_words;
#[path = "../crates/astrid-storage/src/storage_fields.rs"]
mod storage_fields;
mod hosted_file_descriptor;
#[path = "../crates/astrid-storage/src/content/catalog/summary.rs"]
mod catalog_summary;
mod hosted_catalog_charge;
#[path = "../crates/astrid-storage/src/content/store/quota_transition.rs"]
mod quota_transition;
#[path = "../crates/astrid-storage/src/content/store/workspace/reference_transition.rs"]
mod workspace_references;
#[path = "../crates/astrid-storage/src/content/store/workspace/retry.rs"]
mod workspace_retry;
#[path = "../crates/astrid-storage/src/content/store/commit_candidate.rs"]
mod commit_candidate;
#[path = "../crates/astrid-storage/src/content/store/header_cache.rs"]
mod header_cache;
#[path = "../crates/astrid-storage/src/content/store/header_graph.rs"]
mod header_graph;
#[path = "../crates/astrid-storage/src/content/store/components.rs"]
mod header_components;
#[path = "../crates/astrid-storage/src/content/component_labels.rs"]
mod component_labels;
mod hosted_header_components;
mod hosted_workspace_references;
#[path = "../crates/astrid-capsule/src/context/workspace_commit.rs"]
mod workspace_commit;
mod hosted_workspace_commit;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/spawn_admission.rs"]
mod spawn_admission;
#[path = "../crates/astrid-capsule/src/registry_keys.rs"]
mod registry_keys;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/process_batch.rs"]
mod process_batch;
mod hosted_ephemeral_process;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/tracker_registry.rs"]
mod tracker_registry;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/command.rs"]
mod process_command;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/persistent/selection.rs"]
mod process_selection;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/persistent/cleanup.rs"]
mod process_cleanup;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/persistent/retirement.rs"]
mod process_retirement;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/persistent/publication.rs"]
mod process_publication;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/persistent/reap.rs"]
mod process_reap;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/persistent/signal_target.rs"]
mod signal_target;
mod hosted_process_selection;
#[path = "../crates/astrid-capsule/src/profile_cache/command.rs"]
mod profile_command;
mod hosted_process_command;
#[path = "../crates/astrid-capsule/src/engine/wasm/guest_kv.rs"]
mod guest_kv_dispatch;
#[path = "../crates/astrid-capsule/src/engine/wasm/guest_uplink.rs"]
mod guest_uplink;
mod hosted_uplink_model;
mod hosted_wal_model;

#[path = "hosted_kv_model.rs"]
mod guest_kv_model;
#[path = "../crates/astrid-capsule/src/security/identity.rs"]
mod manifest_identity;
#[path = "../crates/astrid-kernel/src/storage_mount/lease_authority/worker.rs"]
mod worker;
#[path = "../crates/astrid-kernel/src/storage_mount/lease_authority/reservation.rs"]
mod mount_reservation;

#[path = "../crates/astrid-kernel/src/storage_mount/lease_authority/subtree.rs"]
mod storage_subtree;

#[path = "../crates/astrid-core/src/storage_filesystem/operation.rs"]
pub mod storage_filesystem;

#[path = "../crates/astrid-kernel/src/storage_mount/lease_authority/callback.rs"]
mod storage_callback;
use storage_callback as callback;
use storage_subtree as subtree;
#[path = "../crates/astrid-kernel/src/storage_mount/lease_authority/destination.rs"]
mod mount_destination;

#[path = "../crates/astrid-kernel/src/storage_mount/lease_authority/requester.rs"]
mod storage_lease_requester;
use storage_lease_requester as requester;

#[path = "../crates/astrid-capsule/src/engine/wasm/invocation_owner/admission.rs"]
mod invocation_owner_admission;

#[path = "../crates/astrid-kernel/src/kernel_router/admin/pair_issue_result.rs"]
mod pair_issue_result;

#[path = "../crates/astrid-capsule/src/engine/wasm/storage_file.rs"]
mod storage_file;

#[path = "../crates/astrid-capsule/src/engine/wasm/storage_handles.rs"]
mod storage_handles;

#[path = "../crates/astrid-storage/src/filesystem/replacement.rs"]
mod replacement;
#[path = "../crates/astrid-storage/src/content/name.rs"]
mod content_name;
pub use content_name::ContentName;
#[path = "../crates/astrid-storage/src/filesystem/path_validation.rs"]
mod path_validation;

#[path = "../crates/astrid-core/src/identity/principal/text.rs"]
mod principal_uid_text;

#[path = "../crates/astrid-capsule/src/engine/wasm/mount_selection.rs"]
mod mount_selection;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/fs/physical.rs"]
mod physical;
mod hosted_physical_path;
#[path = "../crates/astrid-vfs/src/host_address.rs"]
mod host_address;
mod hosted_vfs_address;
#[path = "../crates/astrid-vfs/src/open_options.rs"]
mod open_options;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/fs/access.rs"]
mod file_access;
mod hosted_file_open;

#[path = "../crates/astrid-kernel/src/kernel_router/resume_receipt/validation.rs"]
mod receipt_validation;

#[path = "../crates/astrid-kernel/src/kernel_router/admin/pair_device_handlers/deny_patterns.rs"]
mod pair_deny_patterns;

#[path = "../crates/astrid-capsule/src/elicitation/responder.rs"]
mod private_responder;

#[path = "../crates/astrid-capsule-types/src/fuel_ledger/arithmetic.rs"]
mod arithmetic;

#[path = "../crates/astrid-capsule/src/engine/wasm/principal_tracker/state.rs"]
mod principal_invocation_state;

#[path = "../crates/astrid-core/src/capability_grammar/matcher.rs"]
mod matcher;

#[path = "../crates/astrid-capabilities/src/store/marker_key.rs"]
mod marker_key;

#[path = "../crates/astrid-capabilities/src/store/authority.rs"]
mod token_authority;
use token_authority as authority;
#[path = "../crates/astrid-capabilities/src/store/marker_batch.rs"]
mod marker_batch;
mod hosted_token_recovery;

#[path = "hosted_authority_model.rs"]
mod model;

#[path = "hosted_lease_model.rs"]
mod lease_model;

#[path = "../crates/astrid-storage/src/principal_state/guest_authority.rs"]
mod guest_authority;

#[path = "../crates/astrid-storage/src/principal_state/owner_codec.rs"]
mod owner_codec;

#[path = "../crates/astrid-storage/src/engine/durable/journal_history.rs"]
mod journal_history;
#[path = "../crates/astrid-storage/src/engine/durable/journal_snapshot.rs"]
mod journal_snapshot;
mod hosted_journal_history;
#[path = "../crates/astrid-storage/src/engine/durable/root_transition.rs"]
mod root_transition;
#[path = "../crates/astrid-storage/src/engine/durable/wal/root_history.rs"]
mod wal_root_history;
#[path = "../crates/astrid-storage/src/engine/durable/closure_load.rs"]
mod closure_load;
#[path = "../crates/astrid-storage/src/engine/durable/wal/overlay_object.rs"]
mod overlay_object;
#[path = "../crates/astrid-storage/src/engine/transaction_records.rs"]
mod transaction_records;
#[path = "../crates/astrid-storage/src/engine/root_declaration.rs"]
mod root_declaration;
#[path = "../crates/astrid-storage/src/engine/durable/closure_walk.rs"]
mod closure_walk;
#[path = "../crates/astrid-storage/src/storage_model/object_codes.rs"]
mod object_codes;
use object_codes::{ObjectClass, ObjectKind};
#[path = "../crates/astrid-storage/src/storage_model/reference_kind.rs"]
mod reference_kind;
use reference_kind::ReferenceKind;
#[path = "../crates/astrid-storage/src/storage_model/object_reference.rs"]
mod object_reference;
#[path = "../crates/astrid-storage/src/storage_model/reference_lookup.rs"]
mod reference_lookup;
#[path = "../crates/astrid-storage/src/storage_model/root_state.rs"]
mod root_state;
use root_state::{RootGeneration, RootState};
#[path = "../crates/astrid-storage/src/storage_model/object_record.rs"]
mod object_record;
use object_record::{ObjectRecord,ObjectFormatVersion};
use object_reference::{ObjectId, ObjectReference, ReferenceLabel};
#[path = "../crates/astrid-storage/src/engine/durable/format/arena_span.rs"]
mod arena_span;
#[path = "../crates/astrid-storage/src/engine/durable/arena_index.rs"]
mod arena_index;
#[path = "../crates/astrid-storage/src/engine/durable/index/key.rs"]
mod checkpoint_key;
#[path = "../crates/astrid-storage/src/engine/durable/format/checkpoint_reader.rs"]
mod checkpoint_reader;
#[path = "../crates/astrid-storage/src/engine/durable/format/duplicates.rs"]
mod duplicates;
#[path = "../crates/astrid-storage/src/engine/durable/index/rebuild.rs"]
mod checkpoint_rebuild;
#[path = "../crates/astrid-storage/src/engine/durable/index/admission.rs"]
mod checkpoint_admission;
#[path = "../crates/astrid-storage/src/engine/durable/arena_frame.rs"]
mod arena_frame;
#[path = "../crates/astrid-storage/src/engine/durable/frame_repair.rs"]
mod frame_repair;
#[path = "../crates/astrid-storage/src/engine/durable/recovery_barrier.rs"]
mod recovery_barrier;
#[path = "../crates/astrid-storage/src/engine/durable/recovered_closure.rs"]
mod recovered_closure;
use arena_frame::ArenaLocation;
#[path = "../crates/astrid-storage/src/engine/durable/arena_vectors.rs"]
mod arena_vectors;
#[path = "../crates/astrid-storage/src/engine/durable/direct_placement.rs"]
mod direct_placement;
#[path = "../crates/astrid-storage/src/engine/durable/format/positional_read.rs"]
mod positional_read;
#[path = "../crates/astrid-storage/src/engine/durable/format/verified_record.rs"]
mod verified_record;
#[path = "../crates/astrid-storage/src/engine/durable/format/recovered_record.rs"]
mod recovered_record;
mod hosted_record_model;
mod hosted_arena_placement;
mod hosted_arena_append;
mod hosted_recovery_barrier;
mod hosted_checkpoint_recovery;
mod hosted_duplicate_recovery;
mod hosted_record_roundtrip;
mod hosted_closure_model;

#[path = "../crates/astrid-storage/src/engine/durable/group/receipt.rs"]
mod group_receipt;
#[path = "../crates/astrid-storage/src/engine/durable/frontier.rs"]
mod group_frontier;
#[path = "../crates/astrid-storage/src/engine/durable/wal/commit_wire.rs"]
mod commit_wire;
#[path = "../crates/astrid-storage/src/engine/durable/wal/transaction.rs"]
mod wal_transaction;
#[path = "../crates/astrid-storage/src/engine/durable/wal/record_wire.rs"]
mod wal_record_wire;
#[path = "../crates/astrid-storage/src/engine/durable/wal/read_buffer.rs"]
mod wal_read_buffer;
use wal_record_wire as record_wire;
#[path = "../crates/astrid-storage/src/engine/durable/wal/measurement.rs"]
mod wal_measurement;
use wal_measurement as measurement;
use wal_physical_wire as physical_wire;
#[path = "../crates/astrid-storage/src/engine/durable/wal/measured_record.rs"]
mod wal_measured_record;
#[path = "../crates/astrid-storage/src/engine/durable/wal/physical_wire.rs"]
mod wal_physical_wire;
#[path = "../crates/astrid-storage/src/engine/durable/wal/interior.rs"]
mod wal_interior;
mod hosted_wal_physical_model;
mod hosted_wal_binding;
mod hosted_wal_stream;
#[path = "../crates/astrid-storage/src/engine/durable/root_wire.rs"]
mod root_wire;

#[path = "../crates/astrid-storage/src/kv/encoding.rs"]
mod encoding;
#[path = "../crates/astrid-storage/src/kv/tree/context/replacement.rs"]
mod kv_replacement;
#[path = "../crates/astrid-storage/src/kv/tree/key_projection.rs"]
mod key_projection;
mod hosted_key_projection;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_range.rs"]
mod checkpoint_range;
mod hosted_checkpoint_range;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_leaf.rs"]
mod checkpoint_leaf;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_page.rs"]
mod checkpoint_page;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_point.rs"]
mod checkpoint_point;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_record.rs"]
mod checkpoint_record;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_reference.rs"]
mod checkpoint_reference;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_totals.rs"]
mod checkpoint_totals;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_key_field.rs"]
mod checkpoint_key_field;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_child.rs"]
mod checkpoint_child;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_branch.rs"]
mod checkpoint_branch;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_summary.rs"]
mod checkpoint_summary;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_header.rs"]
mod checkpoint_header;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_value.rs"]
mod checkpoint_value;
#[path = "../crates/astrid-storage/src/kv/tree/delta_mutation.rs"]
mod delta_mutation;
#[path = "../crates/astrid-storage/src/kv/tree/delta_recovery.rs"]
mod delta_recovery;
#[path = "../crates/astrid-storage/src/kv/tree/delta_replay.rs"]
mod delta_replay;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_replay.rs"]
mod checkpoint_replay;
#[path = "../crates/astrid-storage/src/kv/tree/delta_totals.rs"]
mod delta_totals;
#[path = "../crates/astrid-storage/src/kv/tree/spill_record.rs"]
mod spill_record;
#[path = "../crates/astrid-storage/src/kv/tree/projection_record.rs"]
mod projection_record;
#[path = "../crates/astrid-storage/src/kv/tree/replay_values.rs"]
mod replay_values;
mod hosted_projection_record;
mod hosted_checkpoint_point;
mod hosted_spill_record;
#[path = "../crates/astrid-storage/src/kv/tree/delta_batch.rs"]
mod delta_batch;
#[path = "../crates/astrid-storage/src/kv/tree/delta_chain.rs"]
mod delta_chain;
mod hosted_delta_chain;
mod hosted_delta_replay;
#[path = "../crates/astrid-storage/src/kv/tree/delta_header.rs"]
mod delta_header;
mod hosted_delta_mutation;
mod hosted_replay_values;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_entries.rs"]
mod checkpoint_entries;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_leaf_summary.rs"]
mod checkpoint_leaf_summary;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_leaf_record.rs"]
mod checkpoint_leaf_record;
mod hosted_checkpoint_leaf_record;
mod hosted_checkpoint_record;
mod hosted_checkpoint_entries;
mod hosted_checkpoint_value;
mod hosted_checkpoint_header;
mod hosted_checkpoint_summary;
mod hosted_checkpoint_branch;
mod hosted_checkpoint_child;
mod hosted_checkpoint_key_field;
mod hosted_checkpoint_totals;
mod hosted_checkpoint_reference;
mod hosted_checkpoint_page;
mod hosted_checkpoint_leaf;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_progress.rs"]
mod checkpoint_progress;
#[path = "../crates/astrid-storage/src/kv/tree/checkpoint_walk.rs"]
mod checkpoint_walk;
mod hosted_checkpoint_walk;

#[path = "../crates/astrid-storage/src/kv/tree/overlay/traversal.rs"]
mod traversal;
#[path = "../crates/astrid-storage/src/kv/tree/overlay/range.rs"]
mod overlay_range;
mod hosted_overlay_range;

#[path = "../crates/astrid-storage/src/kv/tree/overlay/update.rs"]
mod overlay_update;

#[path = "../crates/astrid-kernel/src/kernel_router/principal_scope.rs"]
mod principal_scope;

#[path = "../crates/astrid-storage/src/principal_directory/binding.rs"]
mod principal_binding;

#[path = "../crates/astrid-kernel/src/capsule_materialization/cache_address.rs"]
mod cache_address;

// The scope operation only moves and compares the admitted opaque UID.
type PrincipalUid = u64;
#[path = "../crates/astrid-capsule/src/registry/runtime_scope.rs"]
mod runtime_scope;
use runtime_scope::RuntimeScope;

#[path = "../crates/astrid-capsule/src/registry/generation.rs"]
mod runtime_generation;
use runtime_generation as generation;
#[path = "../crates/astrid-capsule/src/registry/generation_replacement.rs"]
mod generation_replacement;
#[path = "../crates/astrid-capsule/src/registry/instance_swap.rs"]
mod instance_swap;
#[path = "../crates/astrid-capsule/src/registry/source_lookup.rs"]
mod source_lookup;
mod hosted_source_lookup;
#[path = "../crates/astrid-capsule/src/registry/view_lookup.rs"]
mod view_lookup;
#[path = "../crates/astrid-capsule/src/registry/registration.rs"]
mod registration;
mod hosted_registry_lookup;
#[path = "../crates/astrid-capsule/src/registry/uplink_index.rs"]
mod uplink_index;
#[path = "../crates/astrid-capsule/src/registry/viewers.rs"]
mod viewers;
#[path = "../crates/astrid-capsule/src/registry/dependent_views.rs"]
mod dependent_views;

#[path = "../crates/astrid-capsule/src/registry/view_owner.rs"]
mod view_owner;

#[path = "../crates/astrid-events/src/route/gate/state.rs"]
mod route_gate;
mod hosted_route_retirement;

#[path = "../crates/astrid-events/src/route/scope.rs"]
mod route_scope;

#[path = "../crates/astrid-core/src/principal/syntax.rs"]
mod principal_syntax;

#[path = "../crates/astrid-capsule/src/engine/wasm/host/net/ingress_frame.rs"]
mod ingress_frame;

#[path = "../crates/astrid-core/src/profile/device_registration.rs"]
mod device_registration;
#[path = "../crates/astrid-core/src/profile/device_sessions/phase.rs"]
mod device_session_phase;
#[path = "../crates/astrid-core/src/profile/device_challenge.rs"]
mod device_challenge;
#[path = "../crates/astrid-core/src/profile/device_admission.rs"]
mod device_admission;

#[path = "../crates/astrid-capsule/src/engine/wasm/host/consent_identity.rs"]
mod consent_identity;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/consent_reply.rs"]
mod consent_reply;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/egress_reply.rs"]
mod egress_reply;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/http/hop.rs"]
mod http_hop;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/http/body.rs"]
mod http_body;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/http/slots.rs"]
mod http_slots;
mod hosted_http_slots;
mod hosted_http_hop;
mod hosted_egress_reply;
mod hosted_consent_reply;
mod hosted_device_profile;

#[path = "../crates/astrid-uplink/src/native/recipient.rs"]
mod native_recipient;

#[path = "../crates/astrid-uplink/src/native/topic_policy.rs"]
mod native_topic_policy;

#[path = "../crates/astrid-uplink/src/frame_segments.rs"]
mod native_frame_segments;
#[path = "../crates/astrid-uplink/src/native/delivery_queue.rs"]
mod native_delivery_queue;

#[path = "../crates/astrid-uplink/src/native/reply_claim.rs"]
mod native_reply_claim;

#[path = "../crates/astrid-events/src/admission/commit.rs"]
mod delivery_commit;

#[path = "../crates/astrid-events/src/ordered_dispatch.rs"]
mod ordered_dispatch;

#[path = "../crates/astrid-core/src/session_token/registered_bearer.rs"]
mod registered_bearer;

#[path = "../crates/astrid-capsule/src/engine/wasm/pool/return_policy.rs"]
mod pool_return;
mod hosted_pool_return;

#[path = "../crates/astrid-capsule/src/engine/wasm/host/io/splice.rs"]
mod io_splice;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/io/dispatch.rs"]
mod io_dispatch;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/io/disposal.rs"]
mod io_disposal;
mod hosted_io_disposal;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/net/destinations.rs"]
mod tcp_destinations;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/net/bind_target.rs"]
mod tcp_bind_target;
#[path = "../crates/astrid-capsule/src/engine/wasm/host/net/reservation.rs"]
mod net_reservation;
mod hosted_tcp_destinations;
mod hosted_io_splice;

#[path = "../crates/astrid-kernel/src/runtime_residency.rs"]
mod runtime_residency;
mod hosted_runtime_residency;

#[path = "../crates/astrid-core/src/principal/retirement.rs"]
mod principal_fences;

#[path = "../crates/astrid-storage/src/ownership/pending.rs"]
mod pending_deletions;
use pending_deletions as pending;
use principal_binding::recovery_aliases;
#[path = "../crates/astrid-storage/src/ownership/recovery.rs"]
mod recovery;
mod hosted_retirement_recovery;

#[path = "../crates/astrid-mcp/src/server/peer_selection.rs"]
mod peer_selection;
#[path = "../crates/astrid-mcp/src/server/tool_call.rs"]
mod tool_call;
#[path = "../crates/astrid-capsule/src/engine/mcp_registration.rs"]
mod mcp_registration;
use runtime_generation::RuntimeId as RegistryId;
#[path = "../crates/astrid-capsule/src/engine/mcp_cleanup.rs"]
mod mcp_cleanup;
#[path = "../crates/astrid-capsule/src/engine/mcp/network.rs"]
mod capsule_stdio_network;
#[path = "../crates/astrid-mcp/src/server/stdio_policy.rs"]
mod stdio_policy;
#[path = "../crates/astrid-workspace/src/sandbox/prefix_policy.rs"]
mod prefix_policy;
#[path = "../crates/astrid-workspace/src/sandbox/path_literal.rs"]
mod path_literal;
#[path = "../crates/astrid-workspace/src/sandbox/seatbelt_profile.rs"]
mod seatbelt_profile;
#[path = "../crates/astrid-workspace/src/sandbox/bwrap_flags.rs"]
mod bwrap_flags;
mod hosted_mcp_peer;
#[path = "../crates/astrid-cli/src/commands/mcp/mrtr_context.rs"]
mod mrtr_context;
#[path = "../crates/astrid-cli/src/commands/mcp/mrtr_redemption.rs"]
mod mrtr_redemption;
mod hosted_mrtr_context;
#[path = "../crates/astrid-cli/src/commands/mcp/server/invocation.rs"]
mod invocation;
