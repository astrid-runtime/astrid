use super::*;
use crate::pattern::ResourcePattern;
use crate::token::{AuditEntryId, TokenScope};
use astrid_crypto::KeyPair;
use astrid_storage::MemoryKvStore;

fn test_keypair() -> KeyPair {
    KeyPair::generate()
}

fn default_principal() -> PrincipalId {
    PrincipalId::default()
}

fn alice() -> PrincipalId {
    PrincipalId::new("alice").expect("valid")
}

fn bob() -> PrincipalId {
    PrincipalId::new("bob").expect("valid")
}

#[tokio::test]
async fn test_in_memory_store() {
    let store = CapabilityStore::in_memory();
    let keypair = test_keypair();

    let token = CapabilityToken::create(
        ResourcePattern::exact("mcp://test:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Session,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        default_principal(),
    );

    let token_id = token.id.clone();

    store.add(token).await.unwrap();
    assert!(
        store
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );
    assert!(store.get(&token_id).await.unwrap().is_some());
}

#[tokio::test]
async fn test_revoke() {
    let store = CapabilityStore::in_memory();
    let keypair = test_keypair();

    let token = CapabilityToken::create(
        ResourcePattern::exact("mcp://test:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Session,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        default_principal(),
    );

    let token_id = token.id.clone();

    store.add(token).await.unwrap();
    assert!(
        store
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );

    store.revoke(&token_id).await.unwrap();
    assert!(
        !store
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );
    assert!(matches!(
        store.get(&token_id).await,
        Err(CapabilityError::TokenRevoked { .. })
    ));
}

#[tokio::test]
async fn test_clear_session() {
    let store = CapabilityStore::in_memory();
    let keypair = test_keypair();

    let token = CapabilityToken::create(
        ResourcePattern::exact("mcp://test:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Session,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        default_principal(),
    );

    store.add(token).await.unwrap();
    assert!(
        store
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );

    store.clear_session().unwrap();
    assert!(
        !store
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );
}

#[tokio::test]
async fn test_find_capability() {
    let store = CapabilityStore::in_memory();
    let keypair = test_keypair();

    let token = CapabilityToken::create(
        ResourcePattern::new("mcp://filesystem:*").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Session,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        default_principal(),
    );

    store.add(token).await.unwrap();

    let found = store
        .find_capability(
            &default_principal(),
            "mcp://filesystem:read_file",
            Permission::Invoke,
        )
        .await;
    assert!(found.is_some());

    let not_found = store
        .find_capability(
            &default_principal(),
            "mcp://memory:read",
            Permission::Invoke,
        )
        .await;
    assert!(not_found.is_none());
}

#[tokio::test]
async fn test_find_capability_cross_principal_rejection() {
    // Bob-minted token cannot authorise Alice. Fail-closed even when the
    // resource and permission match.
    let store = CapabilityStore::in_memory();
    let keypair = test_keypair();

    let token = CapabilityToken::create(
        ResourcePattern::exact("mcp://test:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Session,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        bob(),
    );
    store.add(token).await.unwrap();

    assert!(
        store
            .find_capability(&bob(), "mcp://test:tool", Permission::Invoke)
            .await
            .is_some()
    );
    assert!(
        store
            .find_capability(&alice(), "mcp://test:tool", Permission::Invoke)
            .await
            .is_none()
    );
    assert!(
        !store
            .has_capability(&alice(), "mcp://test:tool", Permission::Invoke)
            .await
    );
}

#[tokio::test]
async fn test_clear_session_for_scoped_to_principal() {
    let store = CapabilityStore::in_memory();
    let keypair = test_keypair();

    for p in [alice(), bob()] {
        let token = CapabilityToken::create(
            ResourcePattern::exact("mcp://test:tool").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Session,
            keypair.key_id(),
            AuditEntryId::new(),
            &keypair,
            None,
            p,
        );
        store.add(token).await.unwrap();
    }

    store.clear_session_for(&alice()).unwrap();

    assert!(
        !store
            .has_capability(&alice(), "mcp://test:tool", Permission::Invoke)
            .await
    );
    assert!(
        store
            .has_capability(&bob(), "mcp://test:tool", Permission::Invoke)
            .await
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_persistent_store() {
    // Use an in-memory KvStore for testing (avoids filesystem issues).
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let store = CapabilityStore::with_kv_store(Arc::clone(&kv))
        .await
        .unwrap();
    let keypair = test_keypair();

    let token = CapabilityToken::create(
        ResourcePattern::exact("mcp://test:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Persistent,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        default_principal(),
    );

    let token_id = token.id.clone();

    store.add(token).await.unwrap();

    // Reload store to verify persistence (same backing store).
    drop(store);
    let store2 = CapabilityStore::with_kv_store(kv).await.unwrap();
    assert!(store2.get(&token_id).await.unwrap().is_some());
    // Verify find_capability (the production lookup path) also works after reload.
    assert!(
        store2
            .find_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
            .is_some()
    );

    // Also test disk-backed store can open and store/retrieve.
    let temp_dir = tempfile::tempdir().unwrap();
    let disk_store = CapabilityStore::with_persistence(temp_dir.path().join("caps"))
        .await
        .unwrap();
    let token2 = CapabilityToken::create(
        ResourcePattern::exact("mcp://test:tool2").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Persistent,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        default_principal(),
    );
    let other_token_id = token2.id.clone();
    disk_store.add(token2).await.unwrap();
    assert!(disk_store.get(&other_token_id).await.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_revocation_survives_restart() {
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let store = CapabilityStore::with_kv_store(Arc::clone(&kv))
        .await
        .unwrap();
    let keypair = test_keypair();

    let token = CapabilityToken::create(
        ResourcePattern::exact("mcp://test:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Persistent,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        default_principal(),
    );

    let token_id = token.id.clone();
    store.add(token).await.unwrap();
    store.revoke(&token_id).await.unwrap();

    // Reload - revocation must survive.
    drop(store);
    let store2 = CapabilityStore::with_kv_store(kv).await.unwrap();
    assert!(matches!(
        store2.get(&token_id).await,
        Err(CapabilityError::TokenRevoked { .. })
    ));
    assert!(
        !store2
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mark_used_survives_restart() {
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let store = CapabilityStore::with_kv_store(Arc::clone(&kv))
        .await
        .unwrap();
    let keypair = test_keypair();

    let token = CapabilityToken::create_with_options(
        ResourcePattern::exact("mcp://test:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Persistent,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        true,
        default_principal(),
    );

    let token_id = token.id.clone();
    store.add(token).await.unwrap();
    store.mark_used(&token_id).await.unwrap();

    // Reload - used state must survive.
    drop(store);
    let store2 = CapabilityStore::with_kv_store(kv).await.unwrap();
    assert!(store2.is_used(&token_id).await);
    assert!(
        !store2
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );
}

#[tokio::test]
async fn test_find_capability_excludes_used_single_use() {
    let store = CapabilityStore::in_memory();
    let keypair = test_keypair();

    let token = CapabilityToken::create_with_options(
        ResourcePattern::exact("mcp://test:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Session,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        true,
        default_principal(),
    );

    let token_id = token.id.clone();
    store.add(token).await.unwrap();

    // Before marking used: both find_capability and has_capability return the token
    assert!(
        store
            .find_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
            .is_some()
    );
    assert!(
        store
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );

    // Mark the single-use token as consumed
    store.mark_used(&token_id).await.unwrap();

    // After marking used: both must exclude the consumed token
    assert!(
        store
            .find_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
            .is_none()
    );
    assert!(
        !store
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );
}

/// Helper: create a valid persistent token, serialize it, tamper a field,
/// and write the corrupted bytes directly to the KV store (bypassing
/// `CapabilityStore::add` which validates). Returns the token ID.
async fn inject_tampered_persistent_token(kv: &Arc<dyn KvStore>, keypair: &KeyPair) -> TokenId {
    let principal = default_principal();
    let token = CapabilityToken::create(
        ResourcePattern::exact("mcp://tampered:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Persistent,
        keypair.key_id(),
        AuditEntryId::new(),
        keypair,
        None,
        principal.clone(),
    );
    let token_id = token.id.clone();

    // Serialize, tamper a field (add an extra permission), re-serialize.
    let mut value: serde_json::Value = serde_json::to_value(&token).unwrap();
    value["permissions"] = serde_json::json!(["invoke", "read", "write"]);
    let tampered_bytes = serde_json::to_vec(&value).unwrap();

    kv.set(NS_TOKENS, &token_key(&principal, &token_id), tampered_bytes)
        .await
        .unwrap();
    // Mirror what `CapabilityStore::add` does: populate the `token_id →
    // principal` index so `get()` can still route to the tampered bytes.
    // Without this the injection path would only be reachable via the
    // legacy v1 probe, which is a different code path than this test is
    // trying to exercise.
    kv.set(
        NS_TOKEN_INDEX,
        &token_id.0.to_string(),
        principal.as_str().as_bytes().to_vec(),
    )
    .await
    .unwrap();
    token_id
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_rejects_tampered_persistent_token() {
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let store = CapabilityStore::with_kv_store(Arc::clone(&kv))
        .await
        .unwrap();
    let keypair = test_keypair();

    let token_id = inject_tampered_persistent_token(&kv, &keypair).await;

    // get() should return an error for tampered tokens
    let result = store.get(&token_id).await;
    assert!(
        matches!(result, Err(CapabilityError::InvalidSignature)),
        "expected InvalidSignature, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_find_capability_skips_tampered_persistent_token() {
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let store = CapabilityStore::with_kv_store(Arc::clone(&kv))
        .await
        .unwrap();
    let keypair = test_keypair();

    let _token_id = inject_tampered_persistent_token(&kv, &keypair).await;

    assert!(
        store
            .find_capability(
                &default_principal(),
                "mcp://tampered:tool",
                Permission::Invoke
            )
            .await
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_has_capability_skips_tampered_persistent_token() {
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let store = CapabilityStore::with_kv_store(Arc::clone(&kv))
        .await
        .unwrap();
    let keypair = test_keypair();

    let _token_id = inject_tampered_persistent_token(&kv, &keypair).await;

    assert!(
        !store
            .has_capability(
                &default_principal(),
                "mcp://tampered:tool",
                Permission::Invoke
            )
            .await
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_find_capability_excludes_used_single_use_persistent() {
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let store = CapabilityStore::with_kv_store(Arc::clone(&kv))
        .await
        .unwrap();
    let keypair = test_keypair();

    let token = CapabilityToken::create_with_options(
        ResourcePattern::exact("mcp://test:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Persistent,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        true,
        default_principal(),
    );

    let token_id = token.id.clone();
    store.add(token).await.unwrap();

    assert!(
        store
            .find_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
            .is_some()
    );
    assert!(
        store
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );

    store.mark_used(&token_id).await.unwrap();

    assert!(
        store
            .find_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
            .is_none()
    );
    assert!(
        !store
            .has_capability(&default_principal(), "mcp://test:tool", Permission::Invoke)
            .await
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_persistent_v1_token_rejected_after_upgrade() {
    // Simulate a v1 token on disk: write raw JSON under the legacy
    // `caps:tokens/{id}` path (flat, pre-Layer-4). The v2 verifier must
    // refuse it with InvalidSignature — no silent upgrade.
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let store = CapabilityStore::with_kv_store(Arc::clone(&kv))
        .await
        .unwrap();
    let keypair = test_keypair();

    // Build a token with a dummy principal, then re-sign it against the v1
    // payload so its signature is "valid for v1" but fails under v2.
    let mut token = CapabilityToken::create(
        ResourcePattern::exact("mcp://test:tool").unwrap(),
        vec![Permission::Invoke],
        TokenScope::Persistent,
        keypair.key_id(),
        AuditEntryId::new(),
        &keypair,
        None,
        default_principal(),
    );
    let v2_payload = token.signing_data();
    let principal_suffix_len = 4usize + default_principal().as_str().len();
    let v1_payload = &v2_payload[..v2_payload.len() - principal_suffix_len];
    token.signature = keypair.sign(v1_payload);

    let bytes = serde_json::to_vec(&token).unwrap();
    // Legacy flat path.
    kv.set(NS_TOKENS, &token.id.0.to_string(), bytes)
        .await
        .unwrap();

    let result = store.get(&token.id).await;
    assert!(
        matches!(result, Err(CapabilityError::InvalidSignature)),
        "v1 tokens must be rejected with InvalidSignature; got {result:?}"
    );
}
