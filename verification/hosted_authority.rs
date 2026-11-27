// Verus entry point for transitions used by hosted Astrid.

extern crate self as astrid_core;
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
#[path = "../crates/astrid-capsule/src/engine/wasm/host/process/registry_keys.rs"]
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

#[path = "../crates/astrid-storage/src/filesystem/path_validation.rs"]
mod path_validation;

#[path = "../crates/astrid-core/src/identity/principal/text.rs"]
mod principal_uid_text;

#[path = "../crates/astrid-capsule/src/engine/wasm/mount_selection.rs"]
mod mount_selection;

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

#[path = "../crates/astrid-capabilities/src/store/authority.rs"]
mod token_authority;

#[path = "hosted_authority_model.rs"]
mod model;

#[path = "hosted_lease_model.rs"]
mod lease_model;

#[path = "../crates/astrid-storage/src/principal_state/guest_authority.rs"]
mod guest_authority;

#[path = "../crates/astrid-storage/src/principal_state/owner_codec.rs"]
mod owner_codec;

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
#[path = "../crates/astrid-storage/src/storage_model/root_state.rs"]
mod root_state;
use root_state::RootState;
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
use arena_frame::ArenaLocation;
#[path = "../crates/astrid-storage/src/engine/durable/arena_vectors.rs"]
mod arena_vectors;
#[path = "../crates/astrid-storage/src/engine/durable/direct_placement.rs"]
mod direct_placement;
#[path = "../crates/astrid-storage/src/engine/durable/format/positional_read.rs"]
mod positional_read;
#[path = "../crates/astrid-storage/src/engine/durable/format/verified_record.rs"]
mod verified_record;
mod hosted_record_model;
mod hosted_arena_placement;
mod hosted_arena_append;
mod hosted_checkpoint_recovery;
mod hosted_duplicate_recovery;
mod hosted_record_roundtrip;
mod hosted_closure_model;

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

#[path = "../crates/astrid-storage/src/kv/tree/overlay/traversal.rs"]
mod traversal;

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

#[path = "../crates/astrid-capsule/src/registry/generation.rs"]
mod runtime_generation;
use runtime_generation as generation;
#[path = "../crates/astrid-capsule/src/registry/instance_swap.rs"]
mod instance_swap;
#[path = "../crates/astrid-capsule/src/registry/source_lookup.rs"]
mod source_lookup;
mod hosted_source_lookup;
#[path = "../crates/astrid-capsule/src/registry/view_lookup.rs"]
mod view_lookup;
mod hosted_registry_lookup;
#[path = "../crates/astrid-capsule/src/registry/viewers.rs"]
mod viewers;

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

#[path = "../crates/astrid-uplink/src/native/frame_segments.rs"]
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
