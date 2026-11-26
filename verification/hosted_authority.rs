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
