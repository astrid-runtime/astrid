//! Tests for `secret.rs`. Split out to keep `secret.rs` under the 1000-line CI
//! threshold. Included via `#[path]` from its sibling.

use std::sync::Arc;

use super::{
    DenySecretStore, FileSecretStore, KvSecretStore, ReadThroughSecretStore, ScopedKvStore,
    SecretStore, SecretStoreError, build_secret_store,
};
use crate::MemoryKvStore;

#[test]
fn deny_secret_store_holds_nothing_and_denies_writes() {
    // The neutral fail-closed placeholder used as a shared runtime's load-time
    // secret store (#1069): exposes NOTHING and grants NOTHING.
    let store = DenySecretStore::new();
    // Reads report "no such secret" — never another principal's data.
    assert!(!store.exists("api_key").unwrap());
    assert_eq!(store.get("api_key").unwrap(), None);
    // Writes and deletes are rejected outright.
    assert!(matches!(
        store.set("api_key", "sk-secret"),
        Err(SecretStoreError::NoAccess(_))
    ));
    assert!(matches!(
        store.delete("api_key"),
        Err(SecretStoreError::NoAccess(_))
    ));
    // Still nothing after the rejected write.
    assert!(!store.exists("api_key").unwrap());
}

/// Build a `KvSecretStore` backed by an in-memory KV. Returns a dedicated
/// tokio runtime that the store uses internally for `block_on`.
fn make_kv_store() -> (KvSecretStore, ScopedKvStore, tokio::runtime::Runtime) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let store = Arc::new(MemoryKvStore::new());
    let kv = ScopedKvStore::new(store, "plugin:test-capsule").unwrap();
    let secret_store = KvSecretStore::new(kv.clone(), rt.handle().clone());
    (secret_store, kv, rt)
}

#[test]
fn kv_set_and_exists() {
    let (store, _kv, _rt) = make_kv_store();
    assert!(!store.exists("api_key").unwrap());
    store.set("api_key", "sk-12345").unwrap();
    assert!(store.exists("api_key").unwrap());
}

#[test]
fn kv_set_and_get() {
    let (store, _kv, _rt) = make_kv_store();
    assert_eq!(store.get("api_key").unwrap(), None);
    store.set("api_key", "sk-12345").unwrap();
    assert_eq!(store.get("api_key").unwrap(), Some("sk-12345".into()));
}

#[test]
fn kv_delete_existing() {
    let (store, _kv, _rt) = make_kv_store();
    store.set("api_key", "sk-12345").unwrap();
    assert!(store.delete("api_key").unwrap());
    assert!(!store.exists("api_key").unwrap());
}

#[test]
fn kv_delete_nonexistent() {
    let (store, _kv, _rt) = make_kv_store();
    assert!(!store.delete("missing").unwrap());
}

#[test]
fn kv_empty_key_rejected() {
    let (store, _kv, _rt) = make_kv_store();
    assert!(matches!(
        store.set("", "value"),
        Err(SecretStoreError::Invalid(_))
    ));
    assert!(matches!(
        store.exists(""),
        Err(SecretStoreError::Invalid(_))
    ));
    assert!(matches!(store.get(""), Err(SecretStoreError::Invalid(_))));
    assert!(matches!(
        store.delete(""),
        Err(SecretStoreError::Invalid(_))
    ));
}

#[test]
fn kv_overwrite_secret() {
    let (store, _kv, _rt) = make_kv_store();
    store.set("key", "v1").unwrap();
    store.set("key", "v2").unwrap();
    assert_eq!(store.get("key").unwrap(), Some("v2".into()));
}

#[test]
fn kv_isolation_between_keys() {
    let (store, _kv, _rt) = make_kv_store();
    store.set("key_a", "a").unwrap();
    store.set("key_b", "b").unwrap();
    assert_eq!(store.get("key_a").unwrap(), Some("a".into()));
    assert_eq!(store.get("key_b").unwrap(), Some("b".into()));
    assert!(!store.exists("key_c").unwrap());
}

#[test]
fn kv_prefixed_key_format() {
    let (store, kv, rt) = make_kv_store();
    store.set("my_secret", "value").unwrap();
    // Verify the underlying KV uses the __secret: prefix
    let raw = rt.block_on(kv.get("__secret:my_secret")).unwrap();
    assert_eq!(raw, Some(b"value".to_vec()));
}

#[test]
fn read_through_exists_migrates_legacy_value() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let backing = Arc::new(MemoryKvStore::new());
    let primary_kv = ScopedKvStore::new(backing.clone(), "primary").unwrap();
    let legacy_kv = ScopedKvStore::new(backing, "legacy").unwrap();
    let primary: Arc<dyn SecretStore> =
        Arc::new(KvSecretStore::new(primary_kv.clone(), rt.handle().clone()));
    let legacy: Arc<dyn SecretStore> =
        Arc::new(KvSecretStore::new(legacy_kv.clone(), rt.handle().clone()));
    legacy.set("old", "legacy-value").unwrap();
    let store = ReadThroughSecretStore::new(primary.clone(), legacy.clone());

    assert!(store.exists("old").unwrap());
    assert_eq!(
        primary.get("old").unwrap().as_deref(),
        Some("legacy-value"),
        "observing a legacy value through exists copies it into the primary scope"
    );
}

#[test]
fn read_through_get_migrates_legacy_value_but_writes_only_primary() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let backing = Arc::new(MemoryKvStore::new());
    let primary: Arc<dyn SecretStore> = Arc::new(KvSecretStore::new(
        ScopedKvStore::new(backing.clone(), "primary").unwrap(),
        rt.handle().clone(),
    ));
    let legacy: Arc<dyn SecretStore> = Arc::new(KvSecretStore::new(
        ScopedKvStore::new(backing, "legacy").unwrap(),
        rt.handle().clone(),
    ));
    legacy.set("old", "legacy-value").unwrap();
    let store = ReadThroughSecretStore::new(primary.clone(), legacy.clone());

    assert_eq!(store.get("old").unwrap().as_deref(), Some("legacy-value"));
    assert_eq!(
        primary.get("old").unwrap().as_deref(),
        Some("legacy-value"),
        "reading a legacy value copies it into the primary scope"
    );

    store.set("new", "primary-value").unwrap();
    assert_eq!(
        primary.get("new").unwrap().as_deref(),
        Some("primary-value")
    );
    assert_eq!(
        legacy.get("new").unwrap(),
        None,
        "new writes must never flow back into the legacy scope"
    );
}

#[test]
fn read_through_delete_prevents_legacy_value_resurrection() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let backing = Arc::new(MemoryKvStore::new());
    let primary: Arc<dyn SecretStore> = Arc::new(KvSecretStore::new(
        ScopedKvStore::new(backing.clone(), "primary").unwrap(),
        rt.handle().clone(),
    ));
    let legacy: Arc<dyn SecretStore> = Arc::new(KvSecretStore::new(
        ScopedKvStore::new(backing, "legacy").unwrap(),
        rt.handle().clone(),
    ));
    legacy.set("old", "legacy-value").unwrap();
    let store = ReadThroughSecretStore::new(primary, legacy.clone());

    assert!(store.delete("old").unwrap());
    assert_eq!(store.get("old").unwrap(), None);
    assert_eq!(legacy.get("old").unwrap(), None);
}

#[test]
fn build_secret_store_returns_arc() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let store = Arc::new(MemoryKvStore::new());
    let kv = ScopedKvStore::new(store, "plugin:test").unwrap();
    let secret_store = build_secret_store("test", kv, rt.handle().clone());
    assert!(!secret_store.exists("nonexistent").unwrap());
}

// -----------------------------------------------------------------------
// FallbackSecretStore tests (keychain feature)
// -----------------------------------------------------------------------

#[cfg(feature = "keychain")]
mod fallback_tests {
    use std::sync::Arc;

    use crate::MemoryKvStore;
    use crate::kv::ScopedKvStore;
    use crate::secret::{FallbackSecretStore, KeychainSecretStore, KvSecretStore, SecretStore};

    fn make_fallback_kv_only() -> FallbackSecretStore {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let store = Arc::new(MemoryKvStore::new());
        let kv = ScopedKvStore::new(store, "plugin:fallback-test").unwrap();
        let kv_store = KvSecretStore::new(kv, rt.handle().clone());
        let keychain = KeychainSecretStore::new("fallback-test");
        // Force KV-only mode to test the degradation path
        FallbackSecretStore::new_kv_only(keychain, kv_store)
    }

    #[test]
    fn fallback_kv_only_reports_not_using_keychain() {
        let store = make_fallback_kv_only();
        assert!(!store.is_using_keychain());
    }

    #[test]
    fn fallback_kv_only_set_and_exists() {
        let store = make_fallback_kv_only();
        assert!(!store.exists("api_key").unwrap());
        store.set("api_key", "sk-12345").unwrap();
        assert!(store.exists("api_key").unwrap());
    }

    #[test]
    fn fallback_kv_only_set_and_get() {
        let store = make_fallback_kv_only();
        store.set("api_key", "sk-12345").unwrap();
        assert_eq!(store.get("api_key").unwrap(), Some("sk-12345".into()));
    }

    #[test]
    fn fallback_kv_only_delete() {
        let store = make_fallback_kv_only();
        store.set("api_key", "sk-12345").unwrap();
        assert!(store.delete("api_key").unwrap());
        assert!(!store.exists("api_key").unwrap());
    }

    #[test]
    fn fallback_kv_only_delete_nonexistent() {
        let store = make_fallback_kv_only();
        assert!(!store.delete("missing").unwrap());
    }

    #[test]
    fn fallback_kv_only_rejects_empty_value() {
        let store = make_fallback_kv_only();
        assert!(store.set("key", "").is_err());
    }

    #[test]
    fn fallback_kv_only_rejects_colon_key() {
        let store = make_fallback_kv_only();
        assert!(store.set("ns:key", "val").is_err());
    }
}

#[test]
fn kv_empty_value_rejected() {
    let (store, _kv, _rt) = make_kv_store();
    assert!(matches!(
        store.set("api_key", ""),
        Err(SecretStoreError::Invalid(_))
    ));
}

#[test]
fn kv_key_with_colon_rejected() {
    let (store, _kv, _rt) = make_kv_store();
    assert!(matches!(
        store.set("ns:key", "value"),
        Err(SecretStoreError::Invalid(_))
    ));
    assert!(matches!(
        store.exists("ns:key"),
        Err(SecretStoreError::Invalid(_))
    ));
    assert!(matches!(
        store.get("ns:key"),
        Err(SecretStoreError::Invalid(_))
    ));
    assert!(matches!(
        store.delete("ns:key"),
        Err(SecretStoreError::Invalid(_))
    ));
}

// ── FileSecretStore defence-in-depth tests ─────────────────────

#[test]
fn file_key_with_null_byte_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileSecretStore::new(dir.path());
    // validate_key catches the null byte at the API boundary
    // (returns Invalid); even if it didn't, key_path would.
    assert!(matches!(
        store.set("bad\0key", "x"),
        Err(SecretStoreError::Invalid(_))
    ));
}

#[test]
fn file_get_rejects_oversized_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileSecretStore::new(dir.path());
    store.ensure_root().unwrap();
    // Plant a 128 KiB file under the store — twice the cap.
    let big = vec![b'x'; 128 * 1024];
    std::fs::write(dir.path().join("OVERSIZED"), &big).unwrap();
    let err = store.get("OVERSIZED").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("exceeds") && msg.contains("65536"),
        "expected size-cap rejection, got: {msg}"
    );
}

#[test]
fn file_get_within_cap_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileSecretStore::new(dir.path());
    store.set("OK", "value").unwrap();
    assert_eq!(store.get("OK").unwrap().as_deref(), Some("value"));
}
