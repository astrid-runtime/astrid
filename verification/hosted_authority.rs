// Verus entry point for transitions used by hosted Astrid.

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

#[path = "../crates/astrid-storage/src/principal_state/guest_authority.rs"]
mod guest_authority;

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
