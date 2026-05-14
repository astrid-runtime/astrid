//! Secure secret storage abstraction for capsule credentials.
//!
//! Provides a [`SecretStore`] trait with two implementations:
//!
//! - **[`KeychainSecretStore`]** (behind the `keychain` feature): Uses the OS
//!   keychain (macOS Keychain, Linux secret-service) via the `keyring` crate.
//! - **[`KvSecretStore`]**: Falls back to the existing [`ScopedKvStore`] with a
//!   `__secret:` key prefix. Suitable for headless/CI environments.
//!
//! Production code should use [`FallbackSecretStore`], which tries the keychain
//! first and degrades to KV storage when the keychain is unavailable.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use crate::kv::ScopedKvStore;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from secret storage operations.
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    /// The platform keychain is not accessible (headless, locked, no daemon).
    #[error("keychain not accessible: {0}")]
    NoAccess(String),

    /// The key or value was invalid for the backend.
    #[error("invalid secret key or value: {0}")]
    Invalid(String),

    /// An internal or platform error occurred.
    #[error("secret store error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Secure secret storage for capsule credentials.
///
/// Implementations must be `Send + Sync` for use in WASM host function
/// `UserData<HostState>`. All methods are synchronous because they are called
/// from synchronous Extism host functions that bridge to async via
/// `runtime_handle.block_on()`.
pub trait SecretStore: Send + Sync + fmt::Debug {
    /// Store a secret value for the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is empty, the backend rejects the value,
    /// or a platform error occurs.
    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError>;

    /// Check whether a secret exists for the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is empty or a platform error occurs.
    fn exists(&self, key: &str) -> Result<bool, SecretStoreError>;

    /// Retrieve a secret value. Returns `None` if not found.
    ///
    /// Currently not exposed as a WASM host function (capsules use `exists()`
    /// to check for secrets and receive values through elicitation). Kept as
    /// part of the trait for CLI tooling and future `astrid_get_secret` host
    /// function support.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is empty or a platform error occurs.
    fn get(&self, key: &str) -> Result<Option<String>, SecretStoreError>;

    /// Delete a secret. Returns `true` if it existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is empty or a platform error occurs.
    fn delete(&self, key: &str) -> Result<bool, SecretStoreError>;
}

/// Validate that a secret key is non-empty and does not contain the `:`
/// separator character (used internally for namespace isolation).
fn validate_key(key: &str) -> Result<(), SecretStoreError> {
    if key.is_empty() {
        return Err(SecretStoreError::Invalid(
            "secret key must not be empty".into(),
        ));
    }
    if key.contains(':') {
        return Err(SecretStoreError::Invalid(
            "secret key must not contain ':'".into(),
        ));
    }
    Ok(())
}

/// Validate that a secret value is non-empty. Empty secrets are ambiguous
/// with "not set" and should be rejected at the boundary.
fn validate_value(value: &str) -> Result<(), SecretStoreError> {
    if value.is_empty() {
        return Err(SecretStoreError::Invalid(
            "secret value must not be empty".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// KV-backed implementation (always available)
// ---------------------------------------------------------------------------

/// KV-backed secret store using the `__secret:` key prefix convention.
///
/// This is the fallback for environments where the OS keychain is unavailable
/// (CI, headless servers, containers). Secrets are stored in the same
/// [`ScopedKvStore`] as other plugin data, namespaced to
/// `plugin:{capsule_id}:__secret:{key}`.
///
/// Less secure than the OS keychain (secrets at rest in the KV database
/// without OS-level encryption) but functional everywhere.
pub struct KvSecretStore {
    kv: ScopedKvStore,
    runtime_handle: tokio::runtime::Handle,
}

impl fmt::Debug for KvSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvSecretStore")
            .field("namespace", &self.kv.namespace())
            .finish_non_exhaustive()
    }
}

impl KvSecretStore {
    /// Create a new KV-backed secret store.
    #[must_use]
    pub fn new(kv: ScopedKvStore, runtime_handle: tokio::runtime::Handle) -> Self {
        Self { kv, runtime_handle }
    }

    /// The prefixed key used in the underlying KV store.
    fn prefixed_key(key: &str) -> String {
        format!("__secret:{key}")
    }
}

impl SecretStore for KvSecretStore {
    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError> {
        validate_key(key)?;
        validate_value(value)?;
        let prefixed = Self::prefixed_key(key);
        self.runtime_handle
            .block_on(self.kv.set(&prefixed, value.as_bytes().to_vec()))
            .map_err(|e| SecretStoreError::Internal(format!("KV set failed: {e}")))
    }

    fn exists(&self, key: &str) -> Result<bool, SecretStoreError> {
        validate_key(key)?;
        let prefixed = Self::prefixed_key(key);
        self.runtime_handle
            .block_on(self.kv.exists(&prefixed))
            .map_err(|e| SecretStoreError::Internal(format!("KV exists failed: {e}")))
    }

    fn get(&self, key: &str) -> Result<Option<String>, SecretStoreError> {
        validate_key(key)?;
        let prefixed = Self::prefixed_key(key);
        let bytes = self
            .runtime_handle
            .block_on(self.kv.get(&prefixed))
            .map_err(|e| SecretStoreError::Internal(format!("KV get failed: {e}")))?;
        match bytes {
            Some(b) => {
                let s = String::from_utf8(b)
                    .map_err(|e| SecretStoreError::Internal(format!("bad UTF-8 in secret: {e}")))?;
                Ok(Some(s))
            },
            None => Ok(None),
        }
    }

    fn delete(&self, key: &str) -> Result<bool, SecretStoreError> {
        validate_key(key)?;
        let prefixed = Self::prefixed_key(key);
        self.runtime_handle
            .block_on(self.kv.delete(&prefixed))
            .map_err(|e| SecretStoreError::Internal(format!("KV delete failed: {e}")))
    }
}

// ---------------------------------------------------------------------------
// File-backed implementation (default for the CLI tool model)
// ---------------------------------------------------------------------------

/// File-per-secret store rooted at a directory, one file per key.
///
/// Layout (one absolute path per secret):
/// ```text
/// <root>/<key>            file: 0o600, contents: the raw secret value
/// ```
///
/// `<root>` is supplied by the caller — typically
/// `~/.astrid/secrets/<scope>/<capsule>/`, where `<scope>` is either
/// an agent principal name or `__host__`. The caller is responsible
/// for tucking the path together; this store is naive about
/// `(principal, capsule)` semantics so it stays composable with the
/// existing keychain/KV constructors.
///
/// Design rationale (pivoted from keychain default):
/// - **No prompts** — the OS doesn't gate access on code signature.
///   Survives every `cargo build` / `cargo install` / `brew install`
///   identity change without operator interaction.
/// - **Matches CLI tool norm** — `gh`, `aws`, `kubectl`, `npm`,
///   `docker` (default credential helper) all store credentials in
///   `~/.config` / `~/.aws` / etc. with `0o600`. The OS user account
///   is the trust boundary.
/// - **One file per secret** — eliminates the corrupt-all-on-partial-
///   -write failure mode of a single JSON blob, and avoids JSON
///   serialization for what's already an opaque string value.
/// - **Permissions enforced on write** — `0o600` on the file,
///   `0o700` on the parent (set when creating). Existing files
///   created with looser perms get re-stamped on next `set`.
pub struct FileSecretStore {
    /// The directory all keys for this `(scope, capsule)` live in.
    root: PathBuf,
}

impl fmt::Debug for FileSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSecretStore")
            .field("root", &self.root)
            .finish()
    }
}

impl FileSecretStore {
    /// Create a new file-backed store rooted at `root`. The directory
    /// is created lazily on `set`; reads against a missing root
    /// return `None` / `false` as if no entries existed.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve a key to its on-disk path. Rejects keys that contain
    /// path separators, null bytes, or otherwise escape the root —
    /// defense in depth against caller bugs since `validate_key`
    /// already excludes `:`, but doesn't filter `/`, `\\`, or `\0`.
    fn key_path(&self, key: &str) -> Result<PathBuf, SecretStoreError> {
        if key.contains('/') || key.contains(std::path::MAIN_SEPARATOR) || key.contains('\0') {
            return Err(SecretStoreError::Invalid(
                "secret key must not contain path separators or null bytes".into(),
            ));
        }
        Ok(self.root.join(key))
    }

    /// Ensure `root` exists with `0700` permissions on Unix. No-op
    /// on platforms without Unix permissions.
    fn ensure_root(&self) -> Result<(), SecretStoreError> {
        std::fs::create_dir_all(&self.root)
            .map_err(|e| SecretStoreError::Internal(format!("create secrets dir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            // Best-effort; if the dir already had perms we tolerate it.
            let _ = std::fs::set_permissions(&self.root, perms);
        }
        Ok(())
    }
}

impl SecretStore for FileSecretStore {
    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError> {
        validate_key(key)?;
        validate_value(value)?;
        self.ensure_root()?;
        let path = self.key_path(key)?;

        // Atomic write: write to a sibling tempfile then rename. Avoids
        // a half-written secret on crash/power-loss between open and
        // close. The tempfile inherits 0600 via OpenOptions on Unix.
        let tmp = self.root.join(format!(".{key}.tmp"));
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts
                .open(&tmp)
                .map_err(|e| SecretStoreError::Internal(format!("open secret tempfile: {e}")))?;
            f.write_all(value.as_bytes())
                .map_err(|e| SecretStoreError::Internal(format!("write secret: {e}")))?;
            f.sync_all()
                .map_err(|e| SecretStoreError::Internal(format!("sync secret: {e}")))?;
        }
        // Final perm stamp on the tempfile in case the platform
        // ignored OpenOptionsExt::mode (rare, but cheap to enforce).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&tmp, perms);
        }
        std::fs::rename(&tmp, &path)
            .map_err(|e| SecretStoreError::Internal(format!("rename secret: {e}")))?;
        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool, SecretStoreError> {
        validate_key(key)?;
        let path = self.key_path(key)?;
        Ok(path.exists())
    }

    fn get(&self, key: &str) -> Result<Option<String>, SecretStoreError> {
        // Size-cap the read so a stray oversized file (corrupted,
        // attacker-planted, or operator-typo) can't OOM the daemon
        // when a capsule asks for the secret. 64 KiB is well above
        // any plausible secret (API keys, OAuth tokens, signing
        // material) but small enough to be a useful guard.
        const MAX_SECRET_BYTES: u64 = 64 * 1024;
        validate_key(key)?;
        let path = self.key_path(key)?;
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(SecretStoreError::Internal(format!("stat secret: {e}"))),
        };
        if meta.len() > MAX_SECRET_BYTES {
            return Err(SecretStoreError::Internal(format!(
                "secret file exceeds {MAX_SECRET_BYTES}-byte cap ({} bytes)",
                meta.len()
            )));
        }
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SecretStoreError::Internal(format!("read secret: {e}"))),
        }
    }

    fn delete(&self, key: &str) -> Result<bool, SecretStoreError> {
        validate_key(key)?;
        let path = self.key_path(key)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(SecretStoreError::Internal(format!("delete secret: {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Keychain-backed implementation (behind `keychain` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "keychain")]
mod keychain_impl {
    use super::{SecretStore, SecretStoreError, validate_key, validate_value};

    /// OS keychain-backed secret store using the `keyring` crate.
    ///
    /// Each secret is stored as a keyring entry with:
    /// - **service**: `"astrid:{capsule_id}"`
    /// - **user**: the secret key name (e.g. `"api_key"`)
    ///
    /// This provides per-capsule isolation at the OS level. Different capsules
    /// use different service names and cannot read each other's secrets.
    #[derive(Debug)]
    pub struct KeychainSecretStore {
        /// The keyring service name, typically `"astrid:{capsule_id}"`.
        service: String,
    }

    impl KeychainSecretStore {
        /// Create a new keychain-backed secret store for a capsule.
        ///
        /// The `capsule_id` is used to scope all secrets under the service
        /// name `"astrid:{capsule_id}"`.
        #[must_use]
        pub fn new(capsule_id: &str) -> Self {
            Self {
                service: format!("astrid:{capsule_id}"),
            }
        }

        /// Build a keyring `Entry` for the given key.
        fn entry(&self, key: &str) -> Result<keyring::Entry, SecretStoreError> {
            keyring::Entry::new(&self.service, key).map_err(|e| match e {
                keyring::Error::Invalid(attr, reason) => {
                    SecretStoreError::Invalid(format!("{attr}: {reason}"))
                },
                keyring::Error::TooLong(attr, max) => {
                    SecretStoreError::Invalid(format!("{attr} exceeds max length {max}"))
                },
                other => SecretStoreError::Internal(other.to_string()),
            })
        }
    }

    /// Map a keyring error to a `SecretStoreError`, treating `NoEntry` as a
    /// non-error condition (returns the provided default instead).
    fn map_keyring_error(e: keyring::Error) -> SecretStoreError {
        match e {
            keyring::Error::NoStorageAccess(inner) => SecretStoreError::NoAccess(inner.to_string()),
            keyring::Error::PlatformFailure(inner) => {
                SecretStoreError::NoAccess(format!("platform failure: {inner}"))
            },
            keyring::Error::Invalid(attr, reason) => {
                SecretStoreError::Invalid(format!("{attr}: {reason}"))
            },
            keyring::Error::TooLong(attr, max) => {
                SecretStoreError::Invalid(format!("{attr} exceeds max length {max}"))
            },
            keyring::Error::BadEncoding(bytes) => {
                SecretStoreError::Internal(format!("bad encoding: {} bytes", bytes.len()))
            },
            keyring::Error::Ambiguous(entries) => SecretStoreError::Internal(format!(
                "ambiguous: {} matching credentials",
                entries.len()
            )),
            // NoEntry is handled by callers, not mapped here
            keyring::Error::NoEntry => SecretStoreError::Internal("unexpected NoEntry".into()),
            // keyring::Error is #[non_exhaustive]
            other => SecretStoreError::Internal(other.to_string()),
        }
    }

    impl SecretStore for KeychainSecretStore {
        fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError> {
            validate_key(key)?;
            validate_value(value)?;
            let entry = self.entry(key)?;
            entry.set_password(value).map_err(map_keyring_error)
        }

        fn exists(&self, key: &str) -> Result<bool, SecretStoreError> {
            validate_key(key)?;
            let entry = self.entry(key)?;
            match entry.get_password() {
                Ok(_) => Ok(true),
                Err(keyring::Error::NoEntry) => Ok(false),
                Err(e) => Err(map_keyring_error(e)),
            }
        }

        fn get(&self, key: &str) -> Result<Option<String>, SecretStoreError> {
            validate_key(key)?;
            let entry = self.entry(key)?;
            match entry.get_password() {
                Ok(password) => Ok(Some(password)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(map_keyring_error(e)),
            }
        }

        fn delete(&self, key: &str) -> Result<bool, SecretStoreError> {
            validate_key(key)?;
            let entry = self.entry(key)?;
            match entry.delete_credential() {
                Ok(()) => Ok(true),
                Err(keyring::Error::NoEntry) => Ok(false),
                Err(e) => Err(map_keyring_error(e)),
            }
        }
    }
}

#[cfg(feature = "keychain")]
pub use keychain_impl::KeychainSecretStore;

// ---------------------------------------------------------------------------
// Fallback: keychain with KV degradation
// ---------------------------------------------------------------------------

#[cfg(feature = "keychain")]
mod fallback_impl {
    use std::fmt;

    use super::{KeychainSecretStore, KvSecretStore, SecretStore, SecretStoreError};

    /// Composite secret store that probes the OS keychain at creation time and
    /// commits to a single backend for the lifetime of the store.
    ///
    /// This avoids split-brain: if the keychain is unavailable at construction,
    /// all operations go to KV. If available, all go to keychain. No per-operation
    /// fallback that could scatter secrets across both backends.
    pub struct FallbackSecretStore {
        keychain: KeychainSecretStore,
        kv: KvSecretStore,
        use_keychain: bool,
    }

    impl fmt::Debug for FallbackSecretStore {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("FallbackSecretStore")
                .field("keychain", &self.keychain)
                .field("kv", &self.kv)
                .field("use_keychain", &self.use_keychain)
                .finish_non_exhaustive()
        }
    }

    impl FallbackSecretStore {
        /// Create a new fallback secret store.
        ///
        /// Probes the keychain with a dummy `exists()` call. If that succeeds,
        /// all future operations go to the keychain. If it fails with
        /// `NoAccess`, all operations go to KV and a warning is logged once.
        pub fn new(keychain: KeychainSecretStore, kv: KvSecretStore) -> Self {
            let use_keychain = match keychain.exists("__probe") {
                Ok(_) | Err(SecretStoreError::Invalid(_)) => true,
                Err(SecretStoreError::NoAccess(reason)) => {
                    tracing::warn!(
                        %reason,
                        "OS keychain unavailable at startup, using KV secret storage"
                    );
                    false
                },
                Err(SecretStoreError::Internal(reason)) => {
                    tracing::warn!(
                        %reason,
                        "OS keychain probe failed, using KV secret storage"
                    );
                    false
                },
            };
            Self {
                keychain,
                kv,
                use_keychain,
            }
        }

        /// Whether this store is using the OS keychain backend.
        #[must_use]
        pub fn is_using_keychain(&self) -> bool {
            self.use_keychain
        }

        /// Force the KV backend regardless of keychain availability.
        /// Used in tests to exercise the degradation path.
        #[cfg(test)]
        pub(crate) fn new_kv_only(keychain: KeychainSecretStore, kv: KvSecretStore) -> Self {
            Self {
                keychain,
                kv,
                use_keychain: false,
            }
        }
    }

    impl SecretStore for FallbackSecretStore {
        fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError> {
            if self.use_keychain {
                self.keychain.set(key, value)
            } else {
                self.kv.set(key, value)
            }
        }

        fn exists(&self, key: &str) -> Result<bool, SecretStoreError> {
            if self.use_keychain {
                self.keychain.exists(key)
            } else {
                self.kv.exists(key)
            }
        }

        fn get(&self, key: &str) -> Result<Option<String>, SecretStoreError> {
            if self.use_keychain {
                self.keychain.get(key)
            } else {
                self.kv.get(key)
            }
        }

        fn delete(&self, key: &str) -> Result<bool, SecretStoreError> {
            if self.use_keychain {
                self.keychain.delete(key)
            } else {
                self.kv.delete(key)
            }
        }
    }
}

#[cfg(feature = "keychain")]
pub use fallback_impl::FallbackSecretStore;

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// Create the best available [`SecretStore`] for production use.
///
/// With the `keychain` feature enabled, returns a [`FallbackSecretStore`] that
/// tries the OS keychain first. Without the feature, returns a [`KvSecretStore`].
#[must_use]
pub fn build_secret_store(
    capsule_id: &str,
    kv: ScopedKvStore,
    runtime_handle: tokio::runtime::Handle,
) -> Arc<dyn SecretStore> {
    // capsule_id scopes the keychain service name when the keychain feature is
    // enabled. Without the feature it is unused, but we keep the parameter for
    // a consistent API surface.
    #[cfg(not(feature = "keychain"))]
    let _ = capsule_id;
    let kv_store = KvSecretStore::new(kv, runtime_handle);

    #[cfg(feature = "keychain")]
    {
        let keychain = KeychainSecretStore::new(capsule_id);
        Arc::new(FallbackSecretStore::new(keychain, kv_store))
    }

    #[cfg(not(feature = "keychain"))]
    {
        Arc::new(kv_store)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        FileSecretStore, KvSecretStore, ScopedKvStore, SecretStore, SecretStoreError,
        build_secret_store,
    };
    use crate::MemoryKvStore;

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
}
