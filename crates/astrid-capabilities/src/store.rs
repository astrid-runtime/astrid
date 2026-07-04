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
    ///
    /// This is a `tokio::sync::RwLock` (unlike the other fields) because
    /// [`mark_used`](Self::mark_used) must hold the write guard **across the
    /// persistent KV write** to close the check-then-persist TOCTOU replay
    /// window — a `std` guard cannot legally live across an `.await`.
    used_tokens: tokio::sync::RwLock<std::collections::HashSet<TokenId>>,
}

impl CapabilityStore {
    /// Create an in-memory only store (no persistence).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            session_tokens: RwLock::new(HashMap::new()),
            persistent_store: None,
            revoked: RwLock::new(std::collections::HashSet::new()),
            used_tokens: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Create a store with persistence.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or read.
    pub async fn with_persistence(path: impl AsRef<Path>) -> CapabilityResult<Self> {
        let store =
            SurrealKvStore::open(path).map_err(|e| CapabilityError::StorageError(e.to_string()))?;
        let kv: Arc<dyn KvStore> = Arc::new(store);

        let mut cap_store = Self {
            session_tokens: RwLock::new(HashMap::new()),
            persistent_store: Some(kv),
            revoked: RwLock::new(std::collections::HashSet::new()),
            used_tokens: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        };

        // Load revoked and used tokens
        cap_store.load_revoked().await?;
        cap_store.load_used_tokens().await?;

        Ok(cap_store)
    }

    /// Create a store backed by an existing `KvStore` (for shared stores).
    ///
    /// # Errors
    ///
    /// Returns an error if loading existing revoked/used tokens fails.
    pub async fn with_kv_store(store: Arc<dyn KvStore>) -> CapabilityResult<Self> {
        let mut cap_store = Self {
            session_tokens: RwLock::new(HashMap::new()),
            persistent_store: Some(store),
            revoked: RwLock::new(std::collections::HashSet::new()),
            used_tokens: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        };

        cap_store.load_revoked().await?;
        cap_store.load_used_tokens().await?;

        Ok(cap_store)
    }

    /// Load revoked token IDs from persistent storage.
    async fn load_revoked(&mut self) -> CapabilityResult<()> {
        let Some(store) = &self.persistent_store else {
            return Ok(());
        };

        let keys = store
            .list_keys(NS_REVOKED)
            .await
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
    async fn load_used_tokens(&mut self) -> CapabilityResult<()> {
        let Some(store) = &self.persistent_store else {
            return Ok(());
        };

        let keys = store
            .list_keys(NS_USED)
            .await
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?;

        let mut used = self.used_tokens.write().await;

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
    pub async fn add(&self, token: CapabilityToken) -> CapabilityResult<()> {
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
                    store
                        .set(NS_TOKENS, &key, serialized)
                        .await
                        .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
                    // Maintain the `token_id → principal` index so `get`
                    // and `revoke` stay O(1).
                    store
                        .set(
                            NS_TOKEN_INDEX,
                            &token.id.0.to_string(),
                            principal.as_str().as_bytes().to_vec(),
                        )
                        .await
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
    pub async fn get(&self, token_id: &TokenId) -> CapabilityResult<Option<CapabilityToken>> {
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
            && let Some(token) = Self::read_persistent_token_any_principal(store, token_id).await?
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
    async fn read_persistent_token_any_principal(
        store: &Arc<dyn KvStore>,
        token_id: &TokenId,
    ) -> CapabilityResult<Option<CapabilityToken>> {
        let token_id_str = token_id.0.to_string();

        // Primary path: secondary index → principal → primary key.
        if let Some(principal_bytes) = store
            .get(NS_TOKEN_INDEX, &token_id_str)
            .await
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
            if let Some(bytes) = store
                .get(NS_TOKENS, &key)
                .await
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
            let _ = store.delete(NS_TOKEN_INDEX, &token_id_str).await;
        }

        // Legacy v1 flat key (no principal prefix). Surface the re-mint
        // hint and let `validate()` reject it as InvalidSignature (v1
        // payload vs v2 verifier).
        if let Some(bytes) = store
            .get(NS_TOKENS, &token_id_str)
            .await
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
    /// Returns `true` only if the token is single-use and already consumed.
    async fn is_consumed_single_use(&self, token: &CapabilityToken) -> bool {
        if !token.is_single_use() {
            return false;
        }
        self.used_tokens.read().await.contains(&token.id)
    }

    /// Check if `principal` holds a capability for `(resource, permission)`.
    ///
    /// Fail-closed on cross-principal mismatch: a token whose
    /// `CapabilityToken::principal` does not match the caller's `principal`
    /// is rejected up front, even if the resource pattern matches. Layer 4
    /// of multi-tenancy (issue #668).
    pub async fn has_capability(
        &self,
        principal: &PrincipalId,
        resource: &str,
        permission: Permission,
    ) -> bool {
        self.find_capability(principal, resource, permission)
            .await
            .is_some()
    }

    /// Find a token owned by `principal` that grants the given capability.
    ///
    /// Scans session tokens under `principal` first, then the persistent
    /// store's `caps:tokens:{principal}` prefix. Tokens whose `principal`
    /// field does not match the caller are skipped — revocation stays
    /// global but grants are always principal-filtered.
    pub async fn find_capability(
        &self,
        principal: &PrincipalId,
        resource: &str,
        permission: Permission,
    ) -> Option<CapabilityToken> {
        // Check session tokens (this principal's inner map only). Matching
        // candidates are cloned out first — the `std` read guard must not be
        // held across the consumed-check await below.
        let session_candidates: Vec<CapabilityToken> = match self.session_tokens.read() {
            Ok(tokens) => tokens
                .get(principal)
                .map_or_else(Vec::new, |principal_map| {
                    principal_map
                        .values()
                        .filter(|token| {
                            // Defense-in-depth: refuse to consider a token that
                            // slipped into the wrong principal's inner map.
                            token.principal == *principal
                                && !token.is_expired()
                                && token.grants(resource, permission)
                        })
                        .cloned()
                        .collect()
                }),
            Err(_) => Vec::new(),
        };
        for token in session_candidates {
            if !self.is_consumed_single_use(&token).await {
                return Some(token);
            }
        }

        // Check persistent tokens for this principal.
        if let Some(store) = &self.persistent_store {
            let prefix = token_key_prefix(principal);
            if let Ok(keys) = store.list_keys_with_prefix(NS_TOKENS, &prefix).await {
                for key in keys {
                    let Ok(Some(data)) = store.get(NS_TOKENS, &key).await else {
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
                    if token.grants(resource, permission)
                        && !self.is_consumed_single_use(&token).await
                    {
                        return Some(token);
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
    pub async fn revoke(&self, token_id: &TokenId) -> CapabilityResult<()> {
        // Persist revocation first so KV is the ground truth. If the daemon
        // crashes after this point, `load_revoked()` will still see it on
        // restart.
        if let Some(store) = &self.persistent_store {
            let token_id_str = token_id.0.to_string();

            store
                .set(NS_REVOKED, &token_id_str, PRESENCE_MARKER.to_vec())
                .await
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;

            // Look up the principal via the secondary index (O(1)) and
            // delete the single primary entry.
            if let Ok(Some(principal_bytes)) = store.get(NS_TOKEN_INDEX, &token_id_str).await
                && let Ok(principal_str) = std::str::from_utf8(&principal_bytes)
                && let Ok(principal) = PrincipalId::new(principal_str)
            {
                let key = token_key(&principal, token_id);
                if let Err(e) = store.delete(NS_TOKENS, &key).await {
                    tracing::debug!(%token_id_str, "revoke: delete miss under {key}: {e}");
                }
            }
            // Drop the index row regardless.
            let _ = store.delete(NS_TOKEN_INDEX, &token_id_str).await;
            // Legacy sweep: a v1 token still at the flat `caps:tokens/{id}`
            // key from before the Layer 4 migration.
            let _ = store.delete(NS_TOKENS, &token_id_str).await;
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
    pub async fn mark_used(&self, token_id: &TokenId) -> CapabilityResult<()> {
        // Hold a single write lock across check, persist, and insert to
        // prevent TOCTOU races where two concurrent callers both pass
        // the "already used?" check before either inserts.
        let mut used = self.used_tokens.write().await;

        if used.contains(token_id) {
            return Err(CapabilityError::TokenAlreadyUsed {
                token_id: token_id.to_string(),
            });
        }

        // Persist first so KV is the ground truth. If the daemon crashes
        // after this point, `load_used_tokens()` will still see it on
        // restart. The write guard is a `tokio::sync` guard precisely so it
        // can be held across this await — dropping it before the persist
        // would reopen the TOCTOU replay window.
        if let Some(store) = &self.persistent_store {
            store
                .set(NS_USED, &token_id.0.to_string(), PRESENCE_MARKER.to_vec())
                .await
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
        }

        used.insert(token_id.clone());
        Ok(())
    }

    /// Check if a single-use token has been used.
    pub async fn is_used(&self, token_id: &TokenId) -> bool {
        self.used_tokens.read().await.contains(token_id)
    }

    /// Validate and optionally consume a token.
    ///
    /// For single-use tokens, this marks them as used.
    /// For regular tokens, this just validates them.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, expired, revoked, or already used.
    pub async fn use_token(&self, token_id: &TokenId) -> CapabilityResult<CapabilityToken> {
        let token = self
            .get(token_id)
            .await?
            .ok_or_else(|| CapabilityError::TokenNotFound {
                token_id: token_id.to_string(),
            })?;

        // Validate the token
        token.validate()?;

        // For single-use tokens, mark as used
        if token.is_single_use() {
            self.mark_used(token_id).await?;
        }

        Ok(token)
    }

    /// List all valid tokens across every principal.
    ///
    /// # Errors
    ///
    /// Returns an error if storage operations fail.
    pub async fn list_tokens(&self) -> CapabilityResult<Vec<CapabilityToken>> {
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
            // Snapshot the revoked set — a `std` read guard cannot be
            // held across the KV awaits below.
            let revoked = self
                .revoked
                .read()
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?
                .clone();

            let keys = store
                .list_keys(NS_TOKENS)
                .await
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            for key in keys {
                let Ok(data) = store.get(NS_TOKENS, &key).await else {
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
    pub async fn cleanup_expired(&self) -> CapabilityResult<usize> {
        let mut removed: usize = 0;

        if let Some(store) = &self.persistent_store {
            let keys = store
                .list_keys(NS_TOKENS)
                .await
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            for key in keys {
                let Ok(data) = store.get(NS_TOKENS, &key).await else {
                    continue;
                };
                if let Some(bytes) = data
                    && let Ok(token) = serde_json::from_slice::<CapabilityToken>(&bytes)
                    && token.is_expired()
                {
                    let _ = store.delete(NS_TOKENS, &key).await;
                    // Keep the secondary index in lock-step with the
                    // primary data so stale index rows don't accumulate.
                    let _ = store.delete(NS_TOKEN_INDEX, &token.id.0.to_string()).await;
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
        let used_count = self.used_tokens.try_read().map_or(0, |u| u.len());
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
