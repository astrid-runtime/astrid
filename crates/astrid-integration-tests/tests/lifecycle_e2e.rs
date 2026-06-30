//! End-to-end tests for capsule lifecycle dispatch (install/upgrade hooks).
//!
//! Tests that don't require lifecycle exports in the fixture (skip path, invalid
//! WASM) run against the current fixture. Tests that exercise actual lifecycle
//! hooks self-skip unless a fixture exporting `#[astrid::install]` /
//! `#[astrid::upgrade]` is present.

use std::path::PathBuf;
use std::sync::Arc;

use astrid_capsule::capsule::CapsuleId;
use astrid_capsule::engine::wasm::host_state::LifecyclePhase;
use astrid_capsule::engine::wasm::{LifecycleConfig, run_lifecycle};
use astrid_events::AstridEvent;
use astrid_events::EventBus;
use astrid_events::ipc::{IpcMessage, IpcPayload, OnboardingFieldType, Topic};
use astrid_storage::{MemoryKvStore, ScopedKvStore};
use uuid::Uuid;

fn fixture_path() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test-all-endpoints.wasm");

    if !path.exists() {
        eprintln!("Skipping test: Fixture not found at {}", path.display());
        return None;
    }
    Some(path)
}

fn make_lifecycle_config(wasm_bytes: Vec<u8>) -> (LifecycleConfig, ScopedKvStore) {
    let kv_store = Arc::new(MemoryKvStore::new());
    let kv = ScopedKvStore::new(kv_store, "plugin:test-lifecycle").unwrap();
    let event_bus = EventBus::with_capacity(128);
    let workspace = std::env::temp_dir().join("astrid-lifecycle-test");
    let _ = std::fs::create_dir_all(&workspace);

    let secret_store = astrid_storage::build_secret_store(
        "test-lifecycle",
        kv.clone(),
        tokio::runtime::Handle::current(),
    );
    let cfg = LifecycleConfig {
        wasm_bytes,
        capsule_id: CapsuleId::new("test-lifecycle").unwrap(),
        workspace_root: workspace,
        home_root: None,
        kv: kv.clone(),
        event_bus,
        config: std::collections::HashMap::new(),
        secret_store,
        http_limits: astrid_capsule::HttpLimits::default(),
        audit_sink: None,
    };
    (cfg, kv)
}

fn lifecycle_answer_for(field_type: &OnboardingFieldType) -> (Option<String>, Option<Vec<String>>) {
    match field_type {
        OnboardingFieldType::Secret => (Some("test-secret-value".to_string()), None),
        OnboardingFieldType::Array => (None, Some(vec!["item1".into(), "item2".into()])),
        _ => (Some("test-value".to_string()), None),
    }
}

fn publish_lifecycle_response(
    bus: &EventBus,
    request_id: Uuid,
    principal: Option<&str>,
    value: Option<String>,
    values: Option<Vec<String>>,
) {
    let response = IpcPayload::ElicitResponse {
        request_id,
        value,
        values,
    };
    let mut msg = IpcMessage::new(
        Topic::elicit_response(request_id),
        response,
        uuid::Uuid::nil(),
    );
    if let Some(principal) = principal {
        msg = msg.with_principal(principal);
    }
    bus.publish(AstridEvent::Ipc {
        message: msg,
        metadata: astrid_events::EventMetadata::default(),
    });
}

fn publish_lifecycle_noise(bus: &EventBus, request_id: Uuid) {
    publish_lifecycle_response(
        bus,
        Uuid::new_v4(),
        Some("agent-alice"),
        Some("stale-unknown".to_string()),
        None,
    );
    publish_lifecycle_response(
        bus,
        request_id,
        Some("agent-bob"),
        Some("wrong-principal".to_string()),
        None,
    );
}

async fn answer_lifecycle_elicit_requests(
    mut receiver: astrid_events::EventReceiver,
    bus: EventBus,
) {
    while let Some(event) = receiver.recv().await {
        let AstridEvent::Ipc { message, .. } = &*event else {
            continue;
        };
        let IpcPayload::ElicitRequest {
            request_id, field, ..
        } = &message.payload
        else {
            continue;
        };
        let request_id = *request_id;
        publish_lifecycle_noise(&bus, request_id);

        let (value, values) = lifecycle_answer_for(&field.field_type);
        publish_lifecycle_response(
            &bus,
            request_id,
            message.principal.as_deref(),
            value,
            values,
        );
    }
}

/// When the WASM binary does not export `astrid_install`, `run_lifecycle` should
/// return `Ok(())` silently instead of failing.
#[tokio::test(flavor = "multi_thread")]
async fn test_lifecycle_skips_when_no_install_export() {
    let Some(path) = fixture_path() else {
        return;
    };
    let wasm_bytes = std::fs::read(&path).unwrap();
    let (cfg, _kv) = make_lifecycle_config(wasm_bytes);

    let result = run_lifecycle(cfg, LifecyclePhase::Install, None).await;
    assert!(
        result.is_ok(),
        "expected Ok when export is missing, got: {result:?}"
    );
}

/// Same as above but for upgrade phase.
#[tokio::test(flavor = "multi_thread")]
async fn test_lifecycle_skips_when_no_upgrade_export() {
    let Some(path) = fixture_path() else {
        return;
    };
    let wasm_bytes = std::fs::read(&path).unwrap();
    let (cfg, _kv) = make_lifecycle_config(wasm_bytes);

    let result = run_lifecycle(cfg, LifecyclePhase::Upgrade, Some("0.1.0")).await;
    assert!(
        result.is_ok(),
        "expected Ok when export is missing, got: {result:?}"
    );
}

/// Invalid WASM bytes should produce a build error, not a panic.
#[tokio::test(flavor = "multi_thread")]
async fn test_lifecycle_rejects_invalid_wasm() {
    let (cfg, _kv) = make_lifecycle_config(b"not a wasm binary".to_vec());

    let result = run_lifecycle(cfg, LifecyclePhase::Install, None).await;
    assert!(result.is_err(), "expected error for invalid WASM bytes");
}

/// When the fixture is rebuilt with lifecycle exports, this test exercises the
/// full install lifecycle with elicit. A background task responds to elicit
/// requests so the host function unblocks.
///
/// Self-skips unless a fixture exporting `#[astrid::install]` is present.
#[tokio::test(flavor = "multi_thread")]
async fn test_lifecycle_install_with_elicit() {
    let Some(path) = fixture_path() else {
        return;
    };
    let wasm_bytes = std::fs::read(&path).unwrap();
    let (cfg, kv) = make_lifecycle_config(wasm_bytes);
    let event_bus = cfg.event_bus.clone();

    let elicit_receiver = event_bus.subscribe_topic("astrid.v1.elicit");
    let responder_bus = event_bus.clone();
    let responder = tokio::spawn(async move {
        answer_lifecycle_elicit_requests(elicit_receiver, responder_bus).await;
    });

    let result = run_lifecycle(cfg, LifecyclePhase::Install, None).await;

    responder.abort();

    // If the fixture doesn't have astrid_install yet, run_lifecycle returns Ok
    // (skip path). Only assert KV writes if the hook actually ran.
    if result.is_ok() {
        if let Some(app_name) = kv.get("install_app_name").await.unwrap() {
            assert_eq!(
                app_name, b"test-value",
                "install hook should have stored the elicited app_name"
            );

            let secret_exists = kv.exists("__secret:api_key").await.unwrap();
            assert!(
                secret_exists,
                "secret should have been persisted to KV by the host function"
            );
        }
        // If install_app_name is None, the fixture didn't have the export - that's fine
    } else {
        panic!("lifecycle install failed: {result:?}");
    }
}

/// Upgrade lifecycle with no elicit calls - verifies the hook runs and writes KV.
#[tokio::test(flavor = "multi_thread")]
async fn test_lifecycle_upgrade_records_kv() {
    let Some(path) = fixture_path() else {
        return;
    };
    let wasm_bytes = std::fs::read(&path).unwrap();
    let (cfg, kv) = make_lifecycle_config(wasm_bytes);

    let result = run_lifecycle(cfg, LifecyclePhase::Upgrade, Some("0.1.0")).await;

    assert!(result.is_ok(), "lifecycle upgrade failed: {result:?}");

    // If the fixture has the upgrade export, verify it wrote to KV.
    // Otherwise the skip path returns Ok and KV is empty - both are valid.
    if let Some(upgrade_ran) = kv.get("upgrade_ran").await.unwrap() {
        assert_eq!(
            upgrade_ran, b"true",
            "upgrade hook should have recorded that it ran"
        );
    }
}
