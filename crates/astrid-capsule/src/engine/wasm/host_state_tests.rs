//! Tests for `host_state.rs`. Split to keep `host_state.rs` under the
//! 1000-line CI threshold. Included via `#[path]` from its sibling.
//!
//! Every HostState in this module is built via
//! [`test_fixtures::minimal_host_state`]. Tests mutate only the fields
//! they actually exercise; the fixture handles the 40-field ceremony.

use std::sync::Arc;

use super::super::test_fixtures::{minimal_host_state, open_log};
use super::*;

#[test]
fn host_state_debug_format() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let state = minimal_host_state(rt.handle().clone());

    let debug = format!("{state:?}");
    assert!(debug.contains("test"));
    assert!(debug.contains("has_security"));
    assert!(debug.contains("has_inbound_tx"));
    assert!(debug.contains("registered_uplinks"));
}

#[test]
fn register_uplink_accumulates() {
    use astrid_core::uplink::{UplinkCapabilities, UplinkProfile, UplinkSource};

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    state.has_uplink_capability = true;

    assert!(state.uplinks().is_empty());

    let desc = UplinkDescriptor::builder("test-conn", "discord")
        .source(UplinkSource::Wasm {
            capsule_id: "test".into(),
        })
        .capabilities(UplinkCapabilities::receive_only())
        .profile(UplinkProfile::Chat)
        .build();
    state.register_uplink(desc).unwrap();

    assert_eq!(state.uplinks().len(), 1);
    assert_eq!(state.uplinks()[0].name, "test-conn");
}

#[test]
fn set_inbound_tx_stores_sender() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());

    assert!(state.inbound_tx.is_none());

    let (tx, _rx) = mpsc::channel(256);
    state.set_inbound_tx(tx);

    assert!(state.inbound_tx.is_some());
}

#[test]
fn register_uplink_rejects_at_limit() {
    use astrid_core::uplink::{UplinkCapabilities, UplinkProfile, UplinkSource};

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    state.has_uplink_capability = true;

    for i in 0..MAX_UPLINKS_PER_CAPSULE {
        let desc = UplinkDescriptor::builder(format!("conn-{i}"), "discord")
            .source(UplinkSource::Wasm {
                capsule_id: "test".into(),
            })
            .capabilities(UplinkCapabilities::receive_only())
            .profile(UplinkProfile::Chat)
            .build();
        assert!(state.register_uplink(desc).is_ok());
    }

    assert_eq!(state.uplinks().len(), MAX_UPLINKS_PER_CAPSULE);

    let extra = UplinkDescriptor::builder("over-limit", "discord")
        .source(UplinkSource::Wasm {
            capsule_id: "test".into(),
        })
        .capabilities(UplinkCapabilities::receive_only())
        .profile(UplinkProfile::Chat)
        .build();
    assert!(state.register_uplink(extra).is_err());
    assert_eq!(state.uplinks().len(), MAX_UPLINKS_PER_CAPSULE);
}

#[test]
fn register_uplink_rejects_duplicate_name_and_platform() {
    use astrid_core::uplink::{UplinkCapabilities, UplinkProfile, UplinkSource};

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    state.has_uplink_capability = true;

    let desc1 = UplinkDescriptor::builder("my-conn", "discord")
        .source(UplinkSource::Wasm {
            capsule_id: "test".into(),
        })
        .capabilities(UplinkCapabilities::receive_only())
        .profile(UplinkProfile::Chat)
        .build();
    assert!(state.register_uplink(desc1).is_ok());

    let desc2 = UplinkDescriptor::builder("my-conn", "discord")
        .source(UplinkSource::Wasm {
            capsule_id: "test".into(),
        })
        .capabilities(UplinkCapabilities::receive_only())
        .profile(UplinkProfile::Chat)
        .build();
    let err = state.register_uplink(desc2).unwrap_err();
    assert!(err.contains("duplicate"), "expected duplicate error: {err}");

    let desc3 = UplinkDescriptor::builder("my-conn", "telegram")
        .source(UplinkSource::Wasm {
            capsule_id: "test".into(),
        })
        .capabilities(UplinkCapabilities::receive_only())
        .profile(UplinkProfile::Chat)
        .build();
    assert!(state.register_uplink(desc3).is_ok());
    assert_eq!(state.uplinks().len(), 2);
}

// ---------------------------------------------------------------------
// effective_* accessor precedence (#661)
// ---------------------------------------------------------------------
//
// Chain tests in host/sys.rs and host/elicit.rs cover the end-to-end
// wiring for `log` and `has_secret`. These direct unit tests pin the
// accessor contract itself so it survives future chain-test refactors:
// when an invocation value is installed, the accessor returns it; when
// it's cleared, the accessor falls back to the load-time value.

#[test]
fn effective_secret_store_prefers_invocation_over_load_time() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());

    // Load-time store pointer (snapshotted as raw `*const` for identity
    // comparison — `Arc::ptr_eq` would require an identical `Arc`).
    let owner_ptr = Arc::as_ptr(&state.secret_store);
    assert!(
        std::ptr::eq(Arc::as_ptr(state.effective_secret_store()), owner_ptr),
        "with no invocation store installed, effective_* returns the load-time store"
    );

    // Install a distinct invocation store; accessor must switch.
    let alice_kv = ScopedKvStore::new(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        "capsule:alice",
    )
    .unwrap();
    let alice_store: Arc<dyn SecretStore> = Arc::new(astrid_storage::KvSecretStore::new(
        alice_kv,
        state.runtime_handle.clone(),
    ));
    let alice_ptr = Arc::as_ptr(&alice_store);
    state.invocation_secret_store = Some(alice_store);

    assert!(
        std::ptr::eq(Arc::as_ptr(state.effective_secret_store()), alice_ptr),
        "with invocation store installed, accessor returns the invocation store"
    );
    assert!(
        !std::ptr::eq(Arc::as_ptr(state.effective_secret_store()), owner_ptr),
        "owner's store must not be returned while invocation is installed"
    );

    // Clear; falls back.
    state.invocation_secret_store = None;
    assert!(
        std::ptr::eq(Arc::as_ptr(state.effective_secret_store()), owner_ptr),
        "after clear, accessor falls back to the load-time store"
    );
}

#[test]
fn effective_capsule_log_prefers_invocation_over_load_time() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let owner_log = open_log(&tmp.path().join("owner.log"));
    let alice_log = open_log(&tmp.path().join("alice.log"));

    let mut state = minimal_host_state(rt.handle().clone());

    // No logs installed → None.
    assert!(state.effective_capsule_log().is_none());

    // Only load-time installed → returns load-time.
    state.capsule_log = Some(Arc::clone(&owner_log));
    assert!(
        Arc::ptr_eq(state.effective_capsule_log().unwrap(), &owner_log),
        "only load-time log installed"
    );

    // Both installed → returns invocation.
    state.invocation_capsule_log = Some(Arc::clone(&alice_log));
    assert!(
        Arc::ptr_eq(state.effective_capsule_log().unwrap(), &alice_log),
        "invocation wins when both are installed"
    );

    // Clear invocation → falls back to load-time.
    state.invocation_capsule_log = None;
    assert!(
        Arc::ptr_eq(state.effective_capsule_log().unwrap(), &owner_log),
        "falls back to load-time after invocation clear"
    );
}

// ── Layer 3 quota plumbing (#666) ────────────────────────────────────────

#[test]
fn effective_profile_falls_back_to_default_when_unset() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let state = minimal_host_state(rt.handle().clone());

    // No invocation_profile set → process-global `default_ref()` returned.
    let p = state.effective_profile();
    assert!(std::ptr::eq(
        p,
        astrid_core::profile::PrincipalProfile::default_ref()
    ));
    assert_eq!(
        p.quotas.max_memory_bytes,
        astrid_core::profile::DEFAULT_MAX_MEMORY_BYTES
    );
}

#[test]
fn effective_profile_prefers_invocation_over_default() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());

    let mut custom = astrid_core::profile::PrincipalProfile::default();
    custom.quotas.max_memory_bytes = 16 * 1024 * 1024;
    custom.quotas.max_timeout_secs = 7;
    let custom_arc = Arc::new(custom);
    state.invocation_profile = Some(Arc::clone(&custom_arc));

    let p = state.effective_profile();
    assert_eq!(p.quotas.max_memory_bytes, 16 * 1024 * 1024);
    assert_eq!(p.quotas.max_timeout_secs, 7);
    // And crucially, it is NOT the default-ref.
    assert!(!std::ptr::eq(
        p,
        astrid_core::profile::PrincipalProfile::default_ref()
    ));
}

#[test]
fn effective_principal_prefers_caller_over_owner() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    let owner = astrid_core::PrincipalId::new("owner").expect("valid owner");
    state.principal = owner.clone();

    // No caller → falls back to owner.
    assert_eq!(state.effective_principal(), owner);

    // Caller with a different principal → wins.
    let alice = astrid_core::PrincipalId::new("alice").expect("valid alice");
    let msg = astrid_events::ipc::IpcMessage::new(
        "test",
        astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::new_v4(),
    )
    .with_principal(alice.to_string());
    state.caller_context = Some(msg);
    assert_eq!(state.effective_principal(), alice);

    // Unparseable caller principal → falls back to owner (defensive).
    if let Some(m) = state.caller_context.as_mut() {
        m.principal = Some(String::new());
    }
    assert_eq!(state.effective_principal(), owner);
}

/// Regression for the prompt-pipeline stall investigated under
/// the v0.7 smoke test: nested `ipc::recv` inside an interceptor
/// (e.g. prompt-builder waiting on plugin hook responses) used to
/// reinstall the outer caller from whatever the recv drained,
/// silently flipping the orchestration chain
/// (react → prompt-builder → router → provider) to the inner
/// publisher's principal mid-flow. The fix marks the invocation as
/// `interceptor_active` and short-circuits
/// `install_recv_invocation_context` — the interceptor's caller is
/// owned by the dispatcher, not by recv. The companion empty-recv
/// clear path is removed at the call site (see `host/ipc.rs::poll`
/// and `recv`): empty drains keep the prior caller context so
/// follow-up publishes between recvs stamp the correct principal.
#[test]
fn install_recv_invocation_context_preserves_outer_caller_inside_interceptor() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    let alice = astrid_core::PrincipalId::new("alice").expect("valid alice");
    let bob = astrid_core::PrincipalId::new("bob").expect("valid bob");

    // Interceptor was dispatched under alice; mid-execution it polls
    // a subscription and gets back a message published by bob. The
    // outer caller (alice) owns outbound stamping for this
    // invocation — bob's message must not overwrite it.
    let outer = astrid_events::ipc::IpcMessage::new(
        "user.v1.prompt",
        astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::new_v4(),
    )
    .with_principal(alice.to_string());
    state.caller_context = Some(outer);
    state.interceptor_active = true;

    let inner = astrid_events::ipc::IpcMessage::new(
        "some.v1.event",
        astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::new_v4(),
    )
    .with_principal(bob.to_string());

    state.install_recv_invocation_context(&inner);

    assert_eq!(
        state
            .caller_context
            .as_ref()
            .and_then(|c| c.principal.clone())
            .as_deref(),
        Some("alice"),
        "Nested recv inside interceptor must not rewrite the outer caller"
    );
}

/// The guest-pulled `recv` path resolves the invoking principal's quota
/// profile, so per-principal ceilings (here `max_background_processes`)
/// apply to run+recv capsules instead of silently using the default
/// profile — the gap this fix closes. Previously `invocation_profile` was
/// only ever set on the dispatcher-driven interceptor path.
#[test]
fn install_recv_invocation_context_resolves_invoking_principal_profile() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());

    // Seed on-disk profiles for `alice` (max_background_processes = 3) and the
    // capsule owner / `default` principal (= 7), behind a tempdir-rooted cache.
    // Both differ from the process-global default (8) so the recv path can be
    // shown to apply the *publisher's* configured quota in every case —
    // including when the publisher is the capsule owner.
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let alice = astrid_core::PrincipalId::new("alice").expect("valid alice");
    std::fs::create_dir_all(home.profiles_dir()).expect("mkdir etc/profiles");
    let write_profile = |principal: &astrid_core::PrincipalId, max_bg: u32| {
        std::fs::write(
            home.profile_path(principal),
            format!(
                "profile_version = {}\n[quotas]\nmax_background_processes = {max_bg}\n",
                astrid_core::profile::CURRENT_PROFILE_VERSION
            ),
        )
        .expect("write profile");
    };
    write_profile(&alice, 3);
    write_profile(&state.principal, 7);
    // Guard the fixture's premise: the seeded quotas must be distinct from the
    // process-global default, or the assertions below couldn't tell the
    // publisher's profile apart from the fall-back.
    assert_ne!(astrid_core::profile::DEFAULT_MAX_BACKGROUND_PROCESSES, 3);
    assert_ne!(astrid_core::profile::DEFAULT_MAX_BACKGROUND_PROCESSES, 7);
    state.profile_cache = Some(Arc::new(
        crate::profile_cache::PrincipalProfileCache::with_home(home),
    ));

    // No caller yet → no override → the process-global default quota.
    assert!(state.invocation_profile.is_none());
    assert_eq!(
        state.effective_profile().quotas.max_background_processes,
        astrid_core::profile::DEFAULT_MAX_BACKGROUND_PROCESSES
    );

    // A recv message from alice installs HER profile → her quota applies.
    let msg = astrid_events::ipc::IpcMessage::new(
        "some.v1.event",
        astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::new_v4(),
    )
    .with_principal(alice.to_string());
    state.install_recv_invocation_context(&msg);

    assert_eq!(
        state.effective_profile().quotas.max_background_processes,
        3,
        "recv path must apply the invoking principal's quota, not the default"
    );

    // A subsequent recv from the owner/default principal applies the OWNER's
    // configured profile — NOT the process-global default and NOT a leak of
    // alice's quota. `effective_profile()`'s fall-back is the global default,
    // never the owner's on-disk profile, so the recv path must resolve the
    // owner explicitly (as the interceptor path always has). Asserting on the
    // effective quota value keeps the test off the `Option`'s internal
    // representation.
    let owner_msg = astrid_events::ipc::IpcMessage::new(
        "some.v1.event",
        astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::new_v4(),
    )
    .with_principal(state.principal.to_string());
    state.install_recv_invocation_context(&owner_msg);

    assert_eq!(
        state.effective_profile().quotas.max_background_processes,
        7,
        "owner-principal recv must apply the owner's configured profile, not the default or alice's"
    );
}
