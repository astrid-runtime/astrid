// Verus entry point for transitions used by hosted Astrid.

extern crate self as astrid_core;
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

#[path = "../crates/astrid-capsule/src/registry/generation.rs"]
mod runtime_generation;

#[path = "../crates/astrid-capsule/src/registry/view_owner.rs"]
mod view_owner;

#[path = "../crates/astrid-events/src/route/gate/state.rs"]
mod route_gate;

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
