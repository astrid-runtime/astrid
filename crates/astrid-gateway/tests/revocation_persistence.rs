//! Regression tests for revocation durability.
//!
//! A successful delete must remain an authentication fence after a gateway
//! restart.  These tests inject a KV CAS failure while the audit watcher
//! handles the delete, then hydrate a fresh gateway from the same backend.
//! The durable path falls back to a maximum-epoch tombstone, so the same
//! backend can hydrate a fresh gateway without resurrecting the bearer. A
//! dual write failure is covered separately: the live process is fenced, but
//! an empty healthy backend cannot reconstruct that in-memory-only fence.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use astrid_core::PrincipalId;
use astrid_events::{AstridEvent, EventBus, EventMetadata};
use astrid_gateway::GatewayConfig;
use astrid_gateway::auth::{mint_bearer, mint_bearer_scoped, verify_bearer};
use astrid_gateway::error::GatewayError;
use astrid_gateway::routes;
use astrid_gateway::routes::distribution::{DistributionInfo, OnboardingFields};
use astrid_gateway::state::{GatewayState, SigningMaterial};
use astrid_storage::{KvStore, MemoryKvStore, StorageError, StorageResult};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use tower::ServiceExt;

/// A durable backend whose write and read paths can be failed independently.
/// Revocation writes use CAS/max semantics, so failing only CAS exercises the
/// fallback tombstone path while leaving hydration reads available. Failing
/// both writes exercises the boundary where only the live process can retain
/// a fail-closed fence; failing reads then proves startup aborts closed.
#[derive(Debug, Default)]
struct FailingCasStore {
    inner: MemoryKvStore,
    fail_cas: AtomicBool,
    fail_set: AtomicBool,
    fail_reads: AtomicBool,
}

#[async_trait]
impl KvStore for FailingCasStore {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        if self.fail_reads.load(Ordering::Acquire) {
            return Err(StorageError::Connection(
                "injected revocation read failure".to_owned(),
            ));
        }
        self.inner.get(namespace, key).await
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        if self.fail_set.load(Ordering::Acquire) {
            return Err(StorageError::Internal(
                "injected revocation set failure".to_owned(),
            ));
        }
        self.inner.set(namespace, key, value).await
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.delete(namespace, key).await
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        if self.fail_reads.load(Ordering::Acquire) {
            return Err(StorageError::Connection(
                "injected revocation list failure".to_owned(),
            ));
        }
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

fn scoped_bearer_at(
    signer: &SigningKey,
    principal: &PrincipalId,
    key_id: &str,
    issued_at_epoch: u64,
    lifetime_secs: u64,
) -> String {
    let expires_at_epoch = issued_at_epoch.saturating_add(lifetime_secs);
    let message = format!("{principal}:{issued_at_epoch}:{expires_at_epoch}:{key_id}");
    let signature = signer.sign(message.as_bytes());
    let principal_segment =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(principal.as_str());
    let issued_segment =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(issued_at_epoch.to_string());
    let expires_segment =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expires_at_epoch.to_string());
    let key_segment = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_id);
    format!(
        "{principal_segment}.{issued_segment}.{expires_segment}.{key_segment}.{}",
        hex::encode(signature.to_bytes())
    )
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

async fn assert_auth_me_status(state: Arc<GatewayState>, bearer: &str, expected: StatusCode) {
    let router = routes::build(state);
    let request = Request::builder()
        .method("GET")
        .uri("/api/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .expect("auth/me request");
    let response = router.oneshot(request).await.expect("auth/me response");
    assert_eq!(
        response.status(),
        expected,
        "GET /api/auth/me should expose the revocation fence"
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
async fn http_revoke_204_linearizes_before_watcher() {
    let store = Arc::new(FailingCasStore::default());
    let signing = SigningMaterial::fresh();
    let principal = PrincipalId::new("alice").expect("principal");
    let key_id = "deadbeefcafe0001";
    let first = state_with(
        clone_signing(&signing),
        Arc::clone(&store),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(RwLock::new(HashMap::new())),
    );

    // Keep all claims in the past/current second and choose the fence
    // explicitly. This proves the at-or-before rule without relying on a
    // scheduler delay or the audit watcher.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after UNIX_EPOCH")
        .as_secs();
    let fence = now.saturating_sub(1);
    let old_bearer = scoped_bearer_at(
        &signing.signer,
        &principal,
        key_id,
        fence.saturating_sub(1),
        3600,
    );
    let refreshed_bearer = scoped_bearer_at(&signing.signer, &principal, key_id, fence, 3600);
    assert!(verify_bearer(&first, &old_bearer).is_ok());
    assert!(verify_bearer(&first, &refreshed_bearer).is_ok());

    // This is the HTTP handler's fence publication, with no audit event and
    // no watcher task running. A 204-equivalent helper call must publish both
    // durable and live state before its future resolves.
    let published = astrid_gateway::routes::principals::acknowledge_device_revocation(
        first.as_ref(),
        key_id,
        fence,
    )
    .await
    .expect("device revocation fence persists");
    assert_eq!(published, StatusCode::NO_CONTENT);
    assert!(verify_bearer(&first, &old_bearer).is_err());
    assert!(verify_bearer(&first, &refreshed_bearer).is_err());
    assert_auth_me_status(Arc::clone(&first), &old_bearer, StatusCode::UNAUTHORIZED).await;
    assert_auth_me_status(
        Arc::clone(&first),
        &refreshed_bearer,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_refresh_is_unauthorized(Arc::clone(&first), &old_bearer).await;
    assert_refresh_is_unauthorized(Arc::clone(&first), &refreshed_bearer).await;

    // A legitimate re-pair has a strictly newer issuance epoch and remains
    // valid even though it uses the same deterministic key_id.
    let repaired_bearer = scoped_bearer_at(
        &signing.signer,
        &principal,
        key_id,
        fence.saturating_add(1),
        3600,
    );
    assert!(verify_bearer(&first, &repaired_bearer).is_ok());
    assert_auth_me_status(Arc::clone(&first), &repaired_bearer, StatusCode::OK).await;

    // A fresh gateway process must hydrate the same durable fence and keep
    // rejecting both pre-fence bearers without any watcher activity.
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
    assert!(verify_bearer(&restarted, &old_bearer).is_err());
    assert!(verify_bearer(&restarted, &refreshed_bearer).is_err());
    assert!(verify_bearer(&restarted, &repaired_bearer).is_ok());
    assert_auth_me_status(
        Arc::clone(&restarted),
        &old_bearer,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_auth_me_status(
        Arc::clone(&restarted),
        &refreshed_bearer,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_auth_me_status(Arc::clone(&restarted), &repaired_bearer, StatusCode::OK).await;
    assert_refresh_is_unauthorized(Arc::clone(&restarted), &old_bearer).await;
    assert_refresh_is_unauthorized(restarted, &refreshed_bearer).await;
}

#[tokio::test]
async fn http_revoke_persist_failure_is_not_204_and_stays_fail_closed() {
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after UNIX_EPOCH")
        .as_secs();
    let fence = now.saturating_sub(1);
    let old_bearer = scoped_bearer_at(
        &signing.signer,
        &principal,
        key_id,
        fence.saturating_sub(1),
        3600,
    );
    let refreshed_bearer = scoped_bearer_at(&signing.signer, &principal, key_id, fence, 3600);
    let newer_bearer = scoped_bearer_at(
        &signing.signer,
        &principal,
        key_id,
        fence.saturating_add(1),
        3600,
    );
    assert!(verify_bearer(&first, &old_bearer).is_ok());
    assert!(verify_bearer(&first, &refreshed_bearer).is_ok());
    assert!(verify_bearer(&first, &newer_bearer).is_ok());

    // The kernel has already acknowledged PairDeviceRevoked, but the
    // gateway must not translate a failed durable fence publication into
    // HTTP 204. The fallback MAX tombstone is live and durable instead.
    let result = astrid_gateway::routes::principals::acknowledge_device_revocation(
        first.as_ref(),
        key_id,
        fence,
    )
    .await;
    assert!(matches!(&result, Err(GatewayError::Internal(_))));
    let error = result.expect_err("CAS failure must prevent a 204 acknowledgement");
    assert_eq!(
        error.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        first
            .revoked_key_ids
            .read()
            .expect("revoked key map")
            .get(key_id),
        Some(&u64::MAX),
        "CAS failure must install a live fail-closed fence"
    );
    let (_, persisted_devices) = astrid_gateway::revocations::load_from_store(&*store)
        .await
        .expect("read MAX tombstone");
    assert_eq!(persisted_devices.get(key_id), Some(&u64::MAX));
    for bearer in [&old_bearer, &refreshed_bearer, &newer_bearer] {
        assert_auth_me_status(Arc::clone(&first), bearer, StatusCode::UNAUTHORIZED).await;
    }

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
    for bearer in [&old_bearer, &refreshed_bearer, &newer_bearer] {
        assert_auth_me_status(Arc::clone(&restarted), bearer, StatusCode::UNAUTHORIZED).await;
    }
}

#[tokio::test]
async fn http_revoke_double_persist_failure_aborts_restart_hydration() {
    let store = Arc::new(FailingCasStore::default());
    store.fail_cas.store(true, Ordering::Release);
    store.fail_set.store(true, Ordering::Release);
    let signing = SigningMaterial::fresh();
    let key_id = "deadbeefcafe0001";
    let first = state_with(
        clone_signing(&signing),
        Arc::clone(&store),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(RwLock::new(HashMap::new())),
    );

    // Both durable publication attempts fail. The HTTP edge must surface
    // that loss instead of acknowledging the kernel's successful revoke.
    let result = astrid_gateway::routes::principals::acknowledge_device_revocation(
        first.as_ref(),
        key_id,
        1_700_000_500,
    )
    .await;
    assert!(matches!(&result, Err(GatewayError::Internal(_))));
    let error = result.expect_err("dual persistence failure must prevent 204");
    assert_eq!(
        error.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        first
            .revoked_key_ids
            .read()
            .expect("revoked key map")
            .get(key_id),
        Some(&u64::MAX),
        "dual persistence failure must install a live fail-closed fence"
    );

    // The failed set() left the backend empty; the live map above is not
    // durable evidence. Reads still work for this explicit empty-store check.
    let (_, persisted_devices) = astrid_gateway::revocations::load_from_store(&*store)
        .await
        .expect("empty backend remains readable");
    assert_eq!(
        persisted_devices.get(key_id),
        None,
        "dual persistence failure must not claim a durable tombstone"
    );

    // A restart has fresh maps and must refuse to hydrate while the backend
    // is unavailable/corrupt, rather than exposing an unfenced listener.
    store.fail_reads.store(true, Ordering::Release);
    let restarted = state_with(
        clone_signing(&signing),
        Arc::clone(&store),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(RwLock::new(HashMap::new())),
    );
    assert!(
        restarted.hydrate_revocations().await.is_err(),
        "restart hydration must abort when revocation KV reads fail"
    );
    assert!(
        restarted
            .revoked_key_ids
            .read()
            .expect("fresh revoked key map")
            .is_empty(),
        "restart evidence must come from hydration, not the first process map"
    );
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
