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
#[non_exhaustive]
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
// Neutral fail-closed implementation
// ---------------------------------------------------------------------------

/// A secret store that holds no data and denies every operation.
///
/// This is the **neutral, fail-closed placeholder** used as the load-time
/// secret store of a content-addressed capsule runtime that is SHARED across
/// principals (issue #1069). Such a runtime is loaded under no real principal's
/// identity; a per-invocation [`SecretStore`] scoped to the *invoking* principal
/// is installed on every call that carries a principal. This placeholder is
/// therefore only ever reached by principal-less / load-time contexts (system
/// and lifecycle events, load-time host calls). It must expose **nothing** and
/// grant **nothing** — never another principal's secrets.
///
/// `exists` and `get` report "no such secret" (`false` / `None`); `set` and
/// `delete` are rejected outright. A capsule that reaches this store on a real
/// invocation is a bug — the correct behaviour is to deny, not to silently fall
/// back to some principal's real secrets.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenySecretStore;

impl DenySecretStore {
    /// Construct the neutral, deny-all secret store.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SecretStore for DenySecretStore {
    fn set(&self, _key: &str, _value: &str) -> Result<(), SecretStoreError> {
        Err(SecretStoreError::NoAccess(
            "no principal in scope: secret writes are denied on the neutral store".into(),
        ))
    }

    fn exists(&self, _key: &str) -> Result<bool, SecretStoreError> {
        Ok(false)
    }

    fn get(&self, _key: &str) -> Result<Option<String>, SecretStoreError> {
        Ok(None)
    }

    fn delete(&self, _key: &str) -> Result<bool, SecretStoreError> {
        Err(SecretStoreError::NoAccess(
            "no principal in scope: secret deletes are denied on the neutral store".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Read-through migration
// ---------------------------------------------------------------------------

/// Secret-store compatibility bridge that reads a legacy scope only when the
/// primary scope has no value.
///
/// Writes always go to `primary`. A legacy value observed through
/// [`exists`](Self::exists) or [`get`](Self::get) is copied into `primary` on a
/// best-effort basis, while the legacy copy is retained for older binaries.
/// Deletes target both stores so a removed legacy value cannot reappear on the
/// next read.
///
/// This type does not decide which principals may use a legacy scope. Callers
/// must construct it only at the compatibility boundary that owns that policy.
#[derive(Debug)]
pub struct ReadThroughSecretStore {
    primary: Arc<dyn SecretStore>,
    legacy: Arc<dyn SecretStore>,
}

impl ReadThroughSecretStore {
    /// Create a read-through bridge from `legacy` into `primary`.
    #[must_use]
    pub fn new(primary: Arc<dyn SecretStore>, legacy: Arc<dyn SecretStore>) -> Self {
        Self { primary, legacy }
    }
}

impl SecretStore for ReadThroughSecretStore {
    fn set(&self, key: &str, value: &str) -> Result<(), SecretStoreError> {
        self.primary.set(key, value)
    }

    fn exists(&self, key: &str) -> Result<bool, SecretStoreError> {
        if self.primary.exists(key)? {
            return Ok(true);
        }
        let Some(value) = self.legacy.get(key)? else {
            return Ok(false);
        };
        if let Err(error) = self.primary.set(key, &value) {
            tracing::warn!(
                %error,
                "legacy secret existed but could not be copied into the primary scope"
            );
        }
        Ok(true)
    }

    fn get(&self, key: &str) -> Result<Option<String>, SecretStoreError> {
        if let Some(value) = self.primary.get(key)? {
            return Ok(Some(value));
        }
        let Some(value) = self.legacy.get(key)? else {
            return Ok(None);
        };
        if let Err(error) = self.primary.set(key, &value) {
            tracing::warn!(
                %error,
                "legacy secret was readable but could not be copied into the primary scope"
            );
        }
        Ok(Some(value))
    }

    fn delete(&self, key: &str) -> Result<bool, SecretStoreError> {
        let primary_deleted = self.primary.delete(key)?;
        let legacy_deleted = self.legacy.delete(key)?;
        Ok(primary_deleted || legacy_deleted)
    }
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
#[non_exhaustive]
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
#[non_exhaustive]
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

    /// Write a keychain entry via `security add-generic-password -A` so
    /// the entry's ACL grants access to any application on the local
    /// machine. Without `-A` the OS prompts the operator each time the
    /// reading binary's code signature changes — which is every
    /// `cargo build` in a dev workflow.
    ///
    /// Deletes any existing entry with the same `(service, account)` first
    /// because `security add-generic-password` errors on `errSecDuplicateItem`
    /// rather than overwriting. The delete is best-effort — a missing
    /// entry returns non-zero, which we ignore.
    ///
    /// Worth flagging: `-A` makes the entry readable by **any** app on
    /// the machine, not just Astrid. That's acceptable for local
    /// single-operator dev/use because the keychain is already
    /// per-OS-user. A production hardening step would code-sign the
    /// astrid binary with a stable identity and revert to the
    /// `kSecAttrAccessControl`-restricted ACL; tracked separately.
    #[cfg(target_os = "macos")]
    pub(super) fn macos_set_with_any_app_access(
        service: &str,
        account: &str,
        password: &str,
    ) -> Result<(), SecretStoreError> {
        use std::process::Command;
        // Best-effort delete; ignore exit status because "entry not
        // found" is the common path on first write.
        let _ = Command::new("security")
            .args(["delete-generic-password", "-a", account, "-s", service])
            .output();

        let out = Command::new("security")
            .args([
                "add-generic-password",
                "-a",
                account,
                "-s",
                service,
                "-w",
                password,
                "-A",
                "-U",
            ])
            .output()
            .map_err(|e| {
                SecretStoreError::NoAccess(format!("security CLI invocation failed: {e}"))
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(SecretStoreError::Internal(format!(
                "security add-generic-password failed: {}",
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// OS keychain-backed secret store using the `keyring` crate.
    ///
    /// Each secret is stored as a keyring entry with:
    /// - **service**: `"astrid:{capsule_id}"`
    /// - **user**: the secret key name (e.g. `"api_key"`)
    ///
    /// This provides per-capsule isolation at the OS level. Different capsules
    /// use different service names and cannot read each other's secrets.
    #[derive(Debug)]
    #[non_exhaustive]
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
            // On macOS the default ACL on a fresh keychain entry only
            // grants access to the binary that created it — and the
            // signature of a dev `cargo build` changes on every rebuild,
            // so every restart of the daemon would re-prompt the
            // operator to unlock the entry. Bypass the prompt by using
            // the `security` CLI with `-A` (any-app access) on macOS.
            // The non-macOS keyring path keeps its native semantics.
            #[cfg(target_os = "macos")]
            {
                macos_set_with_any_app_access(&self.service, key, value)
            }
            #[cfg(not(target_os = "macos"))]
            {
                let entry = self.entry(key)?;
                entry.set_password(value).map_err(map_keyring_error)
            }
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
    #[non_exhaustive]
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
#[path = "secret_tests.rs"]
mod tests;
