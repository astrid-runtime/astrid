//! Capability token storage.
//!
//! Provides both in-memory (session) and persistent (`SurrealKV`) storage
//! for capability tokens.

use astrid_core::principal::PrincipalId;
use astrid_core::{Permission, TokenId};
use astrid_storage::{KvStore, SurrealKvStore};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::error::{CapabilityError, CapabilityResult};
use crate::token::CapabilityToken;

// -- Namespace constants --

/// Namespace for persistent capability tokens. Keys under this namespace
/// are `{principal}/{token_id}` — the per-principal prefix keeps
/// `list_keys_with_prefix` scans cheap per principal (Layer 4, issue #668).
const NS_TOKENS: &str = "caps:tokens";
/// Secondary index: `{token_id}` → `{principal}`. Lets [`CapabilityStore::get`]
/// and [`CapabilityStore::revoke`] locate a token by id in `O(1)` even
/// though the primary layout is principal-prefixed. Kept in sync with
/// [`NS_TOKENS`] by `add`/`revoke`/`cleanup_expired`.
const NS_TOKEN_INDEX: &str = "caps:token_index";
const NS_REVOKED: &str = "caps:revoked";
const NS_USED: &str = "caps:used";

/// Build the persistent-token key for a given principal and token id.
fn token_key(principal: &PrincipalId, token_id: &TokenId) -> String {
    format!("{principal}/{}", token_id.0)
}

/// Prefix used to scan a principal's persistent tokens via
/// [`KvStore::list_keys_with_prefix`].
fn token_key_prefix(principal: &PrincipalId) -> String {
    format!("{principal}/")
}

/// Tombstone value for presence-only KV entries (revoked/used markers).
const PRESENCE_MARKER: &[u8] = &[1];

/// Run an async future synchronously.
///
/// Handles three cases:
/// - Inside an async context: uses a scoped thread to avoid the
///   "cannot `block_on` from within a runtime" panic.
/// - Outside a runtime: creates a temporary runtime.
fn block_on<F>(f: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => std::thread::scope(|s| {
            s.spawn(|| handle.block_on(f))
                .join()
                .expect("async thread panicked")
        }),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime")
            .block_on(f),
    }
}

/// Capability store with both session and persistent storage.
///
/// As of Layer 4 (issue #668), session tokens are keyed per-principal; the
/// persistent layout stores keys as `{principal}/{token_id}` under the
/// single [`NS_TOKENS`] namespace, so
/// [`list_keys_with_prefix`](KvStore::list_keys_with_prefix) scans for a
/// given principal are cheap. A secondary [`NS_TOKEN_INDEX`] maps
/// `{token_id}` → `{principal}` so [`get`](Self::get) and
/// [`revoke`](Self::revoke) stay `O(1)` even though they accept only a
/// `TokenId`. Revocation and single-use consumption remain global (they
/// are about the token's identity, not the caller): revoking a token
/// revokes it for every principal that happened to hold it.
pub struct CapabilityStore {
    /// Session tokens (in-memory, cleared on session end), keyed per-principal.
    session_tokens: RwLock<HashMap<PrincipalId, HashMap<TokenId, CapabilityToken>>>,
    /// Persistent tokens (`KvStore` backed).
    persistent_store: Option<Arc<dyn KvStore>>,
    /// Revoked token IDs (quick lookup). Global — cross-principal.
    revoked: RwLock<std::collections::HashSet<TokenId>>,
    /// Used single-use token IDs (replay protection). Global — cross-principal.
    used_tokens: RwLock<std::collections::HashSet<TokenId>>,
}

impl CapabilityStore {
    /// Create an in-memory only store (no persistence).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            session_tokens: RwLock::new(HashMap::new()),
            persistent_store: None,
            revoked: RwLock::new(std::collections::HashSet::new()),
            used_tokens: RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Create a store with persistence.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or read.
    pub fn with_persistence(path: impl AsRef<Path>) -> CapabilityResult<Self> {
        let store =
            SurrealKvStore::open(path).map_err(|e| CapabilityError::StorageError(e.to_string()))?;
        let kv: Arc<dyn KvStore> = Arc::new(store);

        let mut cap_store = Self {
            session_tokens: RwLock::new(HashMap::new()),
            persistent_store: Some(kv),
            revoked: RwLock::new(std::collections::HashSet::new()),
            used_tokens: RwLock::new(std::collections::HashSet::new()),
        };

        // Load revoked and used tokens
        cap_store.load_revoked()?;
        cap_store.load_used_tokens()?;

        Ok(cap_store)
    }

    /// Create a store backed by an existing `KvStore` (for shared stores).
    ///
    /// # Errors
    ///
    /// Returns an error if loading existing revoked/used tokens fails.
    pub fn with_kv_store(store: Arc<dyn KvStore>) -> CapabilityResult<Self> {
        let mut cap_store = Self {
            session_tokens: RwLock::new(HashMap::new()),
            persistent_store: Some(store),
            revoked: RwLock::new(std::collections::HashSet::new()),
            used_tokens: RwLock::new(std::collections::HashSet::new()),
        };

        cap_store.load_revoked()?;
        cap_store.load_used_tokens()?;

        Ok(cap_store)
    }

    /// Load revoked token IDs from persistent storage.
    fn load_revoked(&mut self) -> CapabilityResult<()> {
        let Some(store) = &self.persistent_store else {
            return Ok(());
        };

        let keys = block_on(store.list_keys(NS_REVOKED))
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?;

        let mut revoked = self
            .revoked
            .write()
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?;

        for key in keys {
            if let Ok(uuid) = uuid::Uuid::parse_str(&key) {
                revoked.insert(TokenId::from_uuid(uuid));
            }
        }

        Ok(())
    }

    /// Load used single-use token IDs from persistent storage.
    fn load_used_tokens(&mut self) -> CapabilityResult<()> {
        let Some(store) = &self.persistent_store else {
            return Ok(());
        };

        let keys = block_on(store.list_keys(NS_USED))
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?;

        let mut used = self
            .used_tokens
            .write()
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?;

        for key in keys {
            if let Ok(uuid) = uuid::Uuid::parse_str(&key) {
                used.insert(TokenId::from_uuid(uuid));
            }
        }

        Ok(())
    }

    /// Add a capability token.
    ///
    /// The token is inserted under its own [`CapabilityToken::principal`] —
    /// that is the only source of truth for principal assignment. Callers
    /// cannot override it.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid or storage fails.
    pub fn add(&self, token: CapabilityToken) -> CapabilityResult<()> {
        // Validate the token first
        token.validate()?;

        let principal = token.principal.clone();
        match token.scope {
            crate::token::TokenScope::Session => {
                let mut tokens = self
                    .session_tokens
                    .write()
                    .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
                tokens
                    .entry(principal)
                    .or_default()
                    .insert(token.id.clone(), token);
            },
            crate::token::TokenScope::Persistent => {
                if let Some(store) = &self.persistent_store {
                    let serialized = serde_json::to_vec(&token)
                        .map_err(|e| CapabilityError::SerializationError(e.to_string()))?;

                    let key = token_key(&principal, &token.id);
                    block_on(store.set(NS_TOKENS, &key, serialized))
                        .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
                    // Maintain the `token_id → principal` index so `get`
                    // and `revoke` stay O(1).
                    block_on(store.set(
                        NS_TOKEN_INDEX,
                        &token.id.0.to_string(),
                        principal.as_str().as_bytes().to_vec(),
                    ))
                    .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
                } else {
                    // Fall back to session storage if no persistence
                    let mut tokens = self
                        .session_tokens
                        .write()
                        .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
                    tokens
                        .entry(principal)
                        .or_default()
                        .insert(token.id.clone(), token);
                }
            },
        }

        Ok(())
    }

    /// Get a token by ID, searching across every principal.
    ///
    /// `get` is a token-identity lookup, not a grant check — the principal
    /// filter is applied by [`has_capability`](Self::has_capability) /
    /// [`find_capability`](Self::find_capability) and by the validator. This
    /// method returns the token regardless of principal so callers can
    /// audit or display a specific token by ID.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::TokenRevoked`] if the token has been
    /// revoked, [`CapabilityError::InvalidSignature`] if a persistent payload
    /// fails verification (including v1 tokens still on disk after upgrade
    /// to v2 signing), or a storage error if reading fails.
    pub fn get(&self, token_id: &TokenId) -> CapabilityResult<Option<CapabilityToken>> {
        // Check if revoked
        {
            let revoked = self
                .revoked
                .read()
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            if revoked.contains(token_id) {
                return Err(CapabilityError::TokenRevoked {
                    token_id: token_id.to_string(),
                });
            }
        }

        // Check session tokens first (scan across principals — token id is unique).
        {
            let tokens = self
                .session_tokens
                .read()
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            for principal_map in tokens.values() {
                if let Some(token) = principal_map.get(token_id) {
                    return Ok(Some(token.clone()));
                }
            }
        }

        // Check persistent storage. We don't know which principal's prefix
        // to scan, so iterate top-level namespaces. In practice the set is
        // small (one entry per active principal) and this runs far less
        // often than the hot lookup paths.
        if let Some(store) = &self.persistent_store
            && let Some(token) = Self::read_persistent_token_any_principal(store, token_id)?
        {
            return Ok(Some(token));
        }

        Ok(None)
    }

    /// Persistent read for the given token id across every principal.
    ///
    /// Uses the [`NS_TOKEN_INDEX`] secondary index (`token_id` →
    /// `principal`) to locate the primary entry in `O(1)`. Falls back to
    /// the legacy flat key `caps:tokens/{token_id}` so v1 tokens on disk
    /// after upgrade still surface as `InvalidSignature` with a re-mint
    /// hint, rather than silently disappearing.
    fn read_persistent_token_any_principal(
        store: &Arc<dyn KvStore>,
        token_id: &TokenId,
    ) -> CapabilityResult<Option<CapabilityToken>> {
        let token_id_str = token_id.0.to_string();

        // Primary path: secondary index → principal → primary key.
        if let Some(principal_bytes) = block_on(store.get(NS_TOKEN_INDEX, &token_id_str))
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?
        {
            let principal_str = std::str::from_utf8(&principal_bytes).map_err(|e| {
                CapabilityError::StorageError(format!(
                    "corrupt token index entry for {token_id_str}: {e}"
                ))
            })?;
            let principal = PrincipalId::new(principal_str).map_err(|e| {
                CapabilityError::StorageError(format!(
                    "invalid principal '{principal_str}' in token index for {token_id_str}: {e}"
                ))
            })?;
            let key = token_key(&principal, token_id);
            if let Some(bytes) = block_on(store.get(NS_TOKENS, &key))
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?
            {
                let token: CapabilityToken = serde_json::from_slice(&bytes)
                    .map_err(|e| CapabilityError::SerializationError(e.to_string()))?;
                token.validate()?;
                return Ok(Some(token));
            }
            // Index pointed at a missing primary entry — stale index row.
            // Delete the orphan and fall through (may still hit the v1
            // legacy probe below).
            let _ = block_on(store.delete(NS_TOKEN_INDEX, &token_id_str));
        }

        // Legacy v1 flat key (no principal prefix). Surface the re-mint
        // hint and let `validate()` reject it as InvalidSignature (v1
        // payload vs v2 verifier).
        if let Some(bytes) = block_on(store.get(NS_TOKENS, &token_id_str))
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?
        {
            tracing::error!(
                %token_id,
                "v1 capability token on disk at caps:tokens/{token_id_str}; \
                 v2 signing rejects it — operator must re-mint"
            );
            let token: CapabilityToken = serde_json::from_slice(&bytes)
                .map_err(|e| CapabilityError::SerializationError(e.to_string()))?;
            token.validate()?;
            return Ok(Some(token));
        }

        Ok(None)
    }

    /// Check if a single-use token has already been consumed.
    ///
    /// Returns `Ok(true)` if the token is single-use and already consumed.
    /// Returns `Ok(false)` if the token is not single-use or has not been used.
    /// Returns `Err(())` on lock poisoning, to support fail-closed callers.
    fn is_consumed_single_use(&self, token: &CapabilityToken) -> Result<bool, ()> {
        if !token.is_single_use() {
            return Ok(false);
        }
        let used = self.used_tokens.read().map_err(|_| ())?;
        Ok(used.contains(&token.id))
    }

    /// Check if `principal` holds a capability for `(resource, permission)`.
    ///
    /// Fail-closed on cross-principal mismatch: a token whose
    /// `CapabilityToken::principal` does not match the caller's `principal`
    /// is rejected up front, even if the resource pattern matches. Layer 4
    /// of multi-tenancy (issue #668).
    pub fn has_capability(
        &self,
        principal: &PrincipalId,
        resource: &str,
        permission: Permission,
    ) -> bool {
        self.find_capability(principal, resource, permission)
            .is_some()
    }

    /// Find a token owned by `principal` that grants the given capability.
    ///
    /// Scans session tokens under `principal` first, then the persistent
    /// store's `caps:tokens:{principal}` prefix. Tokens whose `principal`
    /// field does not match the caller are skipped — revocation stays
    /// global but grants are always principal-filtered.
    pub fn find_capability(
        &self,
        principal: &PrincipalId,
        resource: &str,
        permission: Permission,
    ) -> Option<CapabilityToken> {
        // Check session tokens (this principal's inner map only).
        if let Ok(tokens) = self.session_tokens.read()
            && let Some(principal_map) = tokens.get(principal)
        {
            for token in principal_map.values() {
                if token.principal != *principal {
                    // Defense-in-depth: refuse to consider a token that
                    // slipped into the wrong principal's inner map.
                    continue;
                }
                if !token.is_expired() && token.grants(resource, permission) {
                    match self.is_consumed_single_use(token) {
                        Ok(true) => {},
                        Ok(false) => return Some(token.clone()),
                        Err(()) => return None,
                    }
                }
            }
        }

        // Check persistent tokens for this principal.
        if let Some(store) = &self.persistent_store {
            let prefix = token_key_prefix(principal);
            if let Ok(keys) = block_on(store.list_keys_with_prefix(NS_TOKENS, &prefix)) {
                for key in keys {
                    let Ok(Some(data)) = block_on(store.get(NS_TOKENS, &key)) else {
                        continue;
                    };
                    let Ok(token) = serde_json::from_slice::<CapabilityToken>(&data) else {
                        continue;
                    };
                    // Defense in depth: validate persistent tokens (expiry +
                    // signature). v1-signed tokens will fail here.
                    if let Err(e) = token.validate() {
                        if matches!(e, CapabilityError::TokenExpired { .. }) {
                            tracing::debug!(token_id = %token.id, "skipping expired persistent token");
                        } else {
                            tracing::error!(
                                token_id = %token.id,
                                error = %e,
                                "persistent capability token failed v2 verification — \
                                 operator must re-mint (pre-Layer-4 tokens no longer verify)"
                            );
                        }
                        continue;
                    }
                    // Cross-principal mismatch: skip (token bytes were under
                    // the wrong prefix on disk, or principal was tampered —
                    // signature already caught that case).
                    if token.principal != *principal {
                        continue;
                    }
                    // Revocation is global.
                    if let Ok(revoked) = self.revoked.read()
                        && revoked.contains(&token.id)
                    {
                        continue;
                    }
                    if token.grants(resource, permission) {
                        match self.is_consumed_single_use(&token) {
                            Ok(true) => {},
                            Ok(false) => return Some(token),
                            Err(()) => return None,
                        }
                    }
                }
            }
        }

        None
    }

    /// Revoke a token (global — all principals).
    ///
    /// Revocation is a property of the token's identity, not the caller.
    /// Once revoked, a token stays revoked for every principal that might
    /// hold it — the mark is written to the global revoked set and the
    /// persistent token bytes are deleted from every known principal
    /// namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if storage operations fail.
    pub fn revoke(&self, token_id: &TokenId) -> CapabilityResult<()> {
        // Persist revocation first so KV is the ground truth. If the daemon
        // crashes after this point, `load_revoked()` will still see it on
        // restart.
        if let Some(store) = &self.persistent_store {
            let token_id_str = token_id.0.to_string();

            block_on(store.set(NS_REVOKED, &token_id_str, PRESENCE_MARKER.to_vec()))
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;

            // Look up the principal via the secondary index (O(1)) and
            // delete the single primary entry.
            if let Ok(Some(principal_bytes)) = block_on(store.get(NS_TOKEN_INDEX, &token_id_str))
                && let Ok(principal_str) = std::str::from_utf8(&principal_bytes)
                && let Ok(principal) = PrincipalId::new(principal_str)
            {
                let key = token_key(&principal, token_id);
                if let Err(e) = block_on(store.delete(NS_TOKENS, &key)) {
                    tracing::debug!(%token_id_str, "revoke: delete miss under {key}: {e}");
                }
            }
            // Drop the index row regardless.
            let _ = block_on(store.delete(NS_TOKEN_INDEX, &token_id_str));
            // Legacy sweep: a v1 token still at the flat `caps:tokens/{id}`
            // key from before the Layer 4 migration.
            let _ = block_on(store.delete(NS_TOKENS, &token_id_str));
        }

        // Update in-memory state (rebuilt from KV on restart regardless).
        {
            let mut revoked = self
                .revoked
                .write()
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            revoked.insert(token_id.clone());
        }

        {
            let mut tokens = self
                .session_tokens
                .write()
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            for principal_map in tokens.values_mut() {
                principal_map.remove(token_id);
            }
            tokens.retain(|_, m| !m.is_empty());
        }

        Ok(())
    }

    /// Clear all session tokens, across every principal.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock cannot be acquired.
    pub fn clear_session(&self) -> CapabilityResult<()> {
        let mut tokens = self
            .session_tokens
            .write()
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
        tokens.clear();
        Ok(())
    }

    /// Clear session tokens owned by `principal` only.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock cannot be acquired.
    pub fn clear_session_for(&self, principal: &PrincipalId) -> CapabilityResult<()> {
        let mut tokens = self
            .session_tokens
            .write()
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
        tokens.remove(principal);
        Ok(())
    }

    /// Mark a single-use token as used.
    ///
    /// This should be called after successfully using a single-use token
    /// to prevent replay attacks.
    ///
    /// # Errors
    ///
    /// Returns an error if the token was already used or storage fails.
    pub fn mark_used(&self, token_id: &TokenId) -> CapabilityResult<()> {
        // Hold a single write lock across check, persist, and insert to
        // prevent TOCTOU races where two concurrent callers both pass
        // the "already used?" check before either inserts.
        let mut used = self
            .used_tokens
            .write()
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?;

        if used.contains(token_id) {
            return Err(CapabilityError::TokenAlreadyUsed {
                token_id: token_id.to_string(),
            });
        }

        // Persist first so KV is the ground truth. If the daemon crashes
        // after this point, `load_used_tokens()` will still see it on
        // restart. Holding the write lock across `block_on` is safe
        // because `block_on` spawns an OS thread and does not re-acquire
        // any lock on this store.
        if let Some(store) = &self.persistent_store {
            block_on(store.set(NS_USED, &token_id.0.to_string(), PRESENCE_MARKER.to_vec()))
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
        }

        used.insert(token_id.clone());
        Ok(())
    }

    /// Check if a single-use token has been used.
    pub fn is_used(&self, token_id: &TokenId) -> bool {
        self.used_tokens
            .read()
            .is_ok_and(|used| used.contains(token_id))
    }

    /// Validate and optionally consume a token.
    ///
    /// For single-use tokens, this marks them as used.
    /// For regular tokens, this just validates them.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, expired, revoked, or already used.
    pub fn use_token(&self, token_id: &TokenId) -> CapabilityResult<CapabilityToken> {
        let token = self
            .get(token_id)?
            .ok_or_else(|| CapabilityError::TokenNotFound {
                token_id: token_id.to_string(),
            })?;

        // Validate the token
        token.validate()?;

        // For single-use tokens, mark as used
        if token.is_single_use() {
            self.mark_used(token_id)?;
        }

        Ok(token)
    }

    /// List all valid tokens across every principal.
    ///
    /// # Errors
    ///
    /// Returns an error if storage operations fail.
    pub fn list_tokens(&self) -> CapabilityResult<Vec<CapabilityToken>> {
        let mut tokens = Vec::new();

        // Session tokens
        {
            let session = self
                .session_tokens
                .read()
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            for principal_map in session.values() {
                for token in principal_map.values() {
                    if !token.is_expired() {
                        tokens.push(token.clone());
                    }
                }
            }
        }

        // Persistent tokens — iterate every `{principal}/{token_id}` key.
        if let Some(store) = &self.persistent_store {
            let revoked = self
                .revoked
                .read()
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;

            let keys = block_on(store.list_keys(NS_TOKENS))
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            for key in keys {
                let Ok(data) = block_on(store.get(NS_TOKENS, &key)) else {
                    continue;
                };
                if let Some(bytes) = data
                    && let Ok(token) = serde_json::from_slice::<CapabilityToken>(&bytes)
                    && !revoked.contains(&token.id)
                    && !token.is_expired()
                {
                    tokens.push(token);
                }
            }
        }

        Ok(tokens)
    }

    /// Cleanup expired tokens from persistent storage across every principal.
    ///
    /// # Errors
    ///
    /// Returns an error if storage operations fail.
    pub fn cleanup_expired(&self) -> CapabilityResult<usize> {
        let mut removed: usize = 0;

        if let Some(store) = &self.persistent_store {
            let keys = block_on(store.list_keys(NS_TOKENS))
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            for key in keys {
                let Ok(data) = block_on(store.get(NS_TOKENS, &key)) else {
                    continue;
                };
                if let Some(bytes) = data
                    && let Ok(token) = serde_json::from_slice::<CapabilityToken>(&bytes)
                    && token.is_expired()
                {
                    let _ = block_on(store.delete(NS_TOKENS, &key));
                    // Keep the secondary index in lock-step with the
                    // primary data so stale index rows don't accumulate.
                    let _ = block_on(store.delete(NS_TOKEN_INDEX, &token.id.0.to_string()));
                    removed = removed.saturating_add(1);
                }
            }
        }

        Ok(removed)
    }
}

impl Default for CapabilityStore {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl std::fmt::Debug for CapabilityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (session_principals, session_count) = self.session_tokens.read().map_or((0, 0), |t| {
            (t.len(), t.values().map(HashMap::len).sum::<usize>())
        });
        let revoked_count = self.revoked.read().map_or(0, |r| r.len());
        let used_count = self.used_tokens.read().map_or(0, |u| u.len());
        let has_persistence = self.persistent_store.is_some();

        f.debug_struct("CapabilityStore")
            .field("session_principals", &session_principals)
            .field("session_tokens", &session_count)
            .field("revoked_count", &revoked_count)
            .field("used_count", &used_count)
            .field("has_persistence", &has_persistence)
            .finish()
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
