//! Regression tests for revocation durability.
//!
//! A successful delete must remain an authentication fence after a gateway
//! restart.  These tests inject a KV CAS failure while the audit watcher
//! handles the delete, then hydrate a fresh gateway from the same backend.
//! The durable path falls back to a maximum-epoch tombstone, so the same
//! backend can hydrate a fresh gateway without resurrecting the bearer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use astrid_core::PrincipalId;
use astrid_events::{AstridEvent, EventBus, EventMetadata};
use astrid_gateway::GatewayConfig;
use astrid_gateway::auth::{mint_bearer, mint_bearer_scoped, verify_bearer};
use astrid_gateway::routes;
use astrid_gateway::routes::distribution::{DistributionInfo, OnboardingFields};
use astrid_gateway::state::{GatewayState, SigningMaterial};
use astrid_storage::{KvStore, MemoryKvStore, StorageError, StorageResult};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// A durable backend whose compare-and-swap path can be failed on demand.
/// Revocation writes use CAS/max semantics, so failing only CAS exercises the
/// exact persistence boundary without disturbing hydration reads.
#[derive(Debug, Default)]
struct FailingCasStore {
    inner: MemoryKvStore,
    fail_cas: AtomicBool,
}

#[async_trait]
impl KvStore for FailingCasStore {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(namespace, key).await
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        self.inner.set(namespace, key, value).await
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.delete(namespace, key).await
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys(namespace).await
    }

    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        if self.fail_cas.load(Ordering::Acquire) {
            return Err(StorageError::Internal(
                "injected revocation CAS failure".to_owned(),
            ));
        }
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
}

fn state_with(
    signing: SigningMaterial,
    store: Arc<FailingCasStore>,
    revoked_at: Arc<RwLock<HashMap<PrincipalId, u64>>>,
    revoked_key_ids: Arc<RwLock<HashMap<String, u64>>>,
) -> Arc<GatewayState> {
    Arc::new(GatewayState {
        config: GatewayConfig::default(),
        storage_kv: Some(store as Arc<dyn KvStore>),
        signing,
        distribution: Arc::new(DistributionInfo::single_tenant()),
        onboarding: Arc::new(OnboardingFields::default()),
        redeem_limiter: tokio::sync::Mutex::default(),
        metrics_handle: astrid_gateway::metrics::install_recorder().expect("recorder"),
        event_bus: None,
        revoked_at,
        revoked_key_ids,
        audit_log: None,
        session_id: None,
        gateway_route_uuid: uuid::Uuid::new_v4(),
        readiness_probe: None,
        topic_probe: None,
        registry_timeout: None,
    })
}

fn clone_signing(signing: &SigningMaterial) -> SigningMaterial {
    SigningMaterial {
        signer: signing.signer.clone(),
        verifier: signing.verifier,
    }
}

fn publish_audit(bus: &EventBus, value: serde_json::Value) {
    let message = astrid_events::ipc::IpcMessage::new(
        astrid_events::ipc::Topic::from_raw(astrid_gateway::routes::events::AUDIT_TOPIC),
        astrid_events::ipc::IpcPayload::RawJson(value),
        uuid::Uuid::nil(),
    )
    .with_principal("admin".to_owned());
    let _ = bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("revocation-red-test"),
        message,
    });
}

async fn assert_refresh_is_unauthorized(state: Arc<GatewayState>, bearer: &str) {
    let router = routes::build(state);
    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/refresh")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .expect("refresh request");
    let response = router.oneshot(request).await.expect("refresh response");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a bearer revoked before restart must not refresh after hydration"
    );
}

#[tokio::test]
async fn principal_delete_cas_failure_does_not_resurrect_bearer_after_restart() {
    let store = Arc::new(FailingCasStore::default());
    store.fail_cas.store(true, Ordering::Release);
    let signing = SigningMaterial::fresh();
    let principal = PrincipalId::new("alice").expect("principal");
    let first = state_with(
        clone_signing(&signing),
        Arc::clone(&store),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(RwLock::new(HashMap::new())),
    );
    let bearer = mint_bearer(&signing.signer, &principal, 3600);
    let issued_at = verify_bearer(&first, &bearer)
        .expect("bearer is valid before deletion")
        .issued_at_epoch;

    let bus = Arc::new(EventBus::new());
    astrid_gateway::revocations::spawn_watcher(
        Arc::clone(&bus),
        Arc::clone(&first.revoked_at),
        Some(Arc::clone(&store) as Arc<dyn KvStore>),
    );
    tokio::task::yield_now().await;
    publish_audit(
        &bus,
        serde_json::json!({
            "ts_epoch": issued_at.saturating_add(1),
            "method": "admin.agent.delete",
            "target_principal": principal.as_str(),
            "outcome": "success",
        }),
    );

    for _ in 0..100 {
        if first
            .revoked_at
            .read()
            .expect("revocation map")
            .contains_key(&principal)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        verify_bearer(&first, &bearer).is_err(),
        "live in-memory revocation should reject the old bearer even while KV is failing"
    );
    let (persisted_principals, _) = astrid_gateway::revocations::load_from_store(&*store)
        .await
        .expect("read tombstone");
    assert_eq!(
        persisted_principals.get(&principal),
        Some(&u64::MAX),
        "CAS failure must persist a fail-closed principal tombstone"
    );

    // Simulate a fresh gateway process: no in-memory map is carried across,
    // and hydration is the only source of the revocation fence.
    let restarted = state_with(
        clone_signing(&signing),
        Arc::clone(&store),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(RwLock::new(HashMap::new())),
    );
    restarted
        .hydrate_revocations()
        .await
        .expect("restart hydration");
    assert!(
        verify_bearer(&restarted, &bearer).is_err(),
        "principal deletion must remain durable when the watcher CAS fails"
    );
    assert_refresh_is_unauthorized(restarted, &bearer).await;
}

#[tokio::test]
async fn device_delete_cas_failure_does_not_resurrect_scoped_bearer_after_restart() {
    let store = Arc::new(FailingCasStore::default());
    store.fail_cas.store(true, Ordering::Release);
    let signing = SigningMaterial::fresh();
    let principal = PrincipalId::new("alice").expect("principal");
    let key_id = "deadbeefcafe0001";
    let first = state_with(
        clone_signing(&signing),
        Arc::clone(&store),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(RwLock::new(HashMap::new())),
    );
    let bearer = mint_bearer_scoped(&signing.signer, &principal, key_id, 3600);
    let issued_at = verify_bearer(&first, &bearer)
        .expect("scoped bearer is valid before deletion")
        .issued_at_epoch;

    let bus = Arc::new(EventBus::new());
    astrid_gateway::revocations::spawn_key_revocation_watcher(
        Arc::clone(&bus),
        Arc::clone(&first.revoked_key_ids),
        Some(Arc::clone(&store) as Arc<dyn KvStore>),
    );
    tokio::task::yield_now().await;
    publish_audit(
        &bus,
        serde_json::json!({
            "ts_epoch": issued_at.saturating_add(1),
            "method": "admin.auth.pair.revoke",
            "outcome": "success",
            "params": { "params": { "key_id": key_id } },
        }),
    );

    for _ in 0..100 {
        if first
            .revoked_key_ids
            .read()
            .expect("revoked key map")
            .contains_key(key_id)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        verify_bearer(&first, &bearer).is_err(),
        "live in-memory device revocation should reject the old scoped bearer"
    );
    let (_, persisted_devices) = astrid_gateway::revocations::load_from_store(&*store)
        .await
        .expect("read tombstone");
    assert_eq!(
        persisted_devices.get(key_id),
        Some(&u64::MAX),
        "CAS failure must persist a fail-closed device tombstone"
    );

    let restarted = state_with(
        clone_signing(&signing),
        Arc::clone(&store),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(RwLock::new(HashMap::new())),
    );
    restarted
        .hydrate_revocations()
        .await
        .expect("restart hydration");
    assert!(
        verify_bearer(&restarted, &bearer).is_err(),
        "device deletion must remain durable when the watcher CAS fails"
    );
    assert_refresh_is_unauthorized(restarted, &bearer).await;
}
