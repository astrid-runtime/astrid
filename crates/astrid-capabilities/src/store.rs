//! Capability token storage.
//!
//! Provides in-memory session storage and persistent storage through an
//! injected [`KvStore`]. The native kernel injects its authoritative principal
//! store. [`CapabilityStore::with_persistence`] retains the old standalone
//! `SurrealKV` constructor for compatibility during the migration window.

use astrid_core::principal::PrincipalId;
use astrid_core::{Permission, TokenId};
use astrid_storage::{KvStore, SurrealKvStore};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

mod authority;
use authority::{Admission, Marker, TokenStatus};

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
    /// Principals undergoing durable deletion. The async lock is held for the
    /// full token add/read transaction so retirement is a real authority
    /// fence rather than a check-then-act race.
    retiring_principals: tokio::sync::RwLock<std::collections::HashSet<PrincipalId>>,
    /// Session tokens (in-memory, cleared on session end), keyed per-principal.
    session_tokens: RwLock<HashMap<PrincipalId, HashMap<TokenId, CapabilityToken>>>,
    /// Persistent tokens (`KvStore` backed).
    persistent_store: Option<Arc<dyn KvStore>>,
    /// Orders token admission, revocation and consumption in this daemon.
    /// The write guard spans the authority-changing durable operation.
    authority: tokio::sync::RwLock<HashMap<TokenId, TokenStatus>>,
}

impl CapabilityStore {
    /// Create an in-memory only store (no persistence).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            retiring_principals: tokio::sync::RwLock::new(std::collections::HashSet::new()),
            session_tokens: RwLock::new(HashMap::new()),
            persistent_store: None,
            authority: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Create a store with legacy standalone `SurrealKV` persistence.
    ///
    /// Native Astrid composition should inject the authoritative store through
    /// [`Self::with_kv_store`]. This constructor remains for callers that own a
    /// standalone legacy store path.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or read.
    pub async fn with_persistence(path: impl AsRef<Path>) -> CapabilityResult<Self> {
        let store =
            SurrealKvStore::open(path).map_err(|e| CapabilityError::StorageError(e.to_string()))?;
        let kv: Arc<dyn KvStore> = Arc::new(store);

        Self::with_kv_store(kv).await
    }

    /// Create a store backed by an existing `KvStore` (for shared stores).
    ///
    /// # Errors
    ///
    /// Returns an error if loading existing revoked/used tokens fails.
    pub async fn with_kv_store(store: Arc<dyn KvStore>) -> CapabilityResult<Self> {
        let mut recorded: HashMap<TokenId, Vec<Marker>> = HashMap::new();
        for (namespace, marker) in [(NS_REVOKED, Marker::Revoked), (NS_USED, Marker::Consumed)] {
            for key in store
                .list_keys(namespace)
                .await
                .map_err(|error| CapabilityError::StorageError(error.to_string()))?
            {
                let id = uuid::Uuid::parse_str(&key)
                    .map(TokenId::from_uuid)
                    .map_err(|error| {
                        CapabilityError::StorageError(format!(
                            "invalid token marker in {namespace}: {error}"
                        ))
                    })?;
                recorded.entry(id).or_default().push(marker);
            }
        }
        // Each token's live authority is replayed from the markers the store
        // reports for it, as `TokenStatus::recover_markers` verifies.
        let authority = recorded
            .into_iter()
            .map(|(id, markers)| (id, TokenStatus::recover_markers(&markers)))
            .collect();
        Ok(Self {
            persistent_store: Some(store),
            authority: tokio::sync::RwLock::new(authority),
            ..Self::in_memory()
        })
    }

    fn status(authority: &HashMap<TokenId, TokenStatus>, id: &TokenId) -> TokenStatus {
        authority
            .get(id)
            .copied()
            .unwrap_or_else(|| TokenStatus::recover(false, false))
    }

    fn ensure_admission(
        status: TokenStatus,
        id: &TokenId,
        single_use: bool,
    ) -> CapabilityResult<()> {
        match status.admit(single_use) {
            Admission::Revoked => Err(CapabilityError::TokenRevoked {
                token_id: id.to_string(),
            }),
            Admission::AlreadyUsed => Err(CapabilityError::TokenAlreadyUsed {
                token_id: id.to_string(),
            }),
            Admission::Allowed => Ok(()),
        }
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
        let retirement = self.retiring_principals.read().await;
        if retirement.contains(&token.principal) {
            return Err(CapabilityError::StorageError(format!(
                "principal {} is retiring",
                token.principal
            )));
        }
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
        let retirement = self.retiring_principals.read().await;
        let authority = self.authority.read().await;
        Self::ensure_admission(Self::status(&authority, token_id), token_id, false)?;
        self.lookup(token_id, &retirement).await
    }

    async fn lookup(
        &self,
        token_id: &TokenId,
        retirement: &std::collections::HashSet<PrincipalId>,
    ) -> CapabilityResult<Option<CapabilityToken>> {
        // Check session tokens first (scan across principals — token id is unique).
        {
            let tokens = self
                .session_tokens
                .read()
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            for principal_map in tokens.values() {
                if let Some(token) = principal_map.get(token_id) {
                    if retirement.contains(&token.principal) {
                        return Ok(None);
                    }
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
            if retirement.contains(&token.principal) {
                return Ok(None);
            }
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
                if token.id != *token_id || token.principal != principal {
                    return Err(CapabilityError::InvalidSignature);
                }
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
            if token.id != *token_id {
                return Err(CapabilityError::InvalidSignature);
            }
            return Ok(Some(token));
        }

        Ok(None)
    }

    async fn is_available(&self, token: &CapabilityToken) -> bool {
        let authority = self.authority.read().await;
        matches!(
            Self::status(&authority, &token.id).admit(token.is_single_use()),
            Admission::Allowed
        )
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
        let retirement = self.retiring_principals.read().await;
        if retirement.contains(principal) {
            return None;
        }
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
            if self.is_available(&token).await {
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
                    if token.grants(resource, permission) && self.is_available(&token).await {
                        return Some(token);
                    }
                }
            }
        }

        None
    }

    /// Fence all token creation and authorization for a retiring principal.
    ///
    /// An add already in progress holds the read side of this lock until its
    /// storage transaction completes. Therefore, once this method returns,
    /// the subsequent purge observes every earlier add and every later add is
    /// rejected.
    pub async fn begin_principal_retirement(&self, principal: PrincipalId) {
        self.retiring_principals.write().await.insert(principal);
    }

    /// Return whether new authority for `principal` is currently fenced.
    ///
    /// Lifecycle code uses this at other admission edges, such as capsule
    /// loading, so an on-disk profile retained temporarily for reclamation
    /// policy cannot make a retiring principal live again.
    pub async fn is_principal_retiring(&self, principal: &PrincipalId) -> bool {
        self.retiring_principals.read().await.contains(principal)
    }

    /// Release an in-process retirement fence after durable reclamation.
    pub async fn finish_principal_retirement(&self, principal: &PrincipalId) {
        self.retiring_principals.write().await.remove(principal);
    }

    /// Revoke a token (global — all principals).
    ///
    /// Revocation is a property of the token's identity, not the caller.
    /// Once revoked, a token stays revoked for every principal that might
    /// hold it. The marker is authoritative even when cleanup of the token
    /// payload or index is incomplete.
    ///
    /// # Errors
    ///
    /// Returns an error if storage operations fail.
    pub async fn revoke(&self, token_id: &TokenId) -> CapabilityResult<()> {
        // Close live admission before the durable write. If the future is
        // canceled or storage reports an error, retain the in-memory fence.
        // Only a successful durable write provides the restart guarantee.
        {
            let mut authority = self.authority.write().await;
            authority
                .entry(token_id.clone())
                .or_insert_with(|| TokenStatus::recover(false, false))
                .record_revocation();
            if let Some(store) = &self.persistent_store {
                store
                    .set(
                        NS_REVOKED,
                        &token_id.0.to_string(),
                        PRESENCE_MARKER.to_vec(),
                    )
                    .await
                    .map_err(|error| CapabilityError::StorageError(error.to_string()))?;
            }
        }
        if let Some(store) = &self.persistent_store {
            let token_id_str = token_id.0.to_string();
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

    /// Permanently remove every capability token owned by `principal`.
    ///
    /// This is stronger than session cleanup and is intended for identity
    /// deletion. Primary rows and secondary indexes are removed so a later
    /// identity that reuses the same human-readable alias cannot inherit the
    /// old generation's authority. Revocation and replay tombstones are kept:
    /// they are cheap, globally unique, and must remain fail-closed if deleting
    /// a primary row fails.
    ///
    /// # Errors
    ///
    /// Returns a storage error after attempting every cleanup operation. The
    /// in-memory session state is cleared even when durable cleanup fails.
    pub async fn purge_principal(&self, principal: &PrincipalId) -> CapabilityResult<()> {
        self.clear_session_for(principal)?;
        let Some(store) = &self.persistent_store else {
            return Ok(());
        };

        let prefix = token_key_prefix(principal);
        let primary_keys = store
            .list_keys_with_prefix(NS_TOKENS, &prefix)
            .await
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
        let mut token_ids = std::collections::HashSet::new();
        for key in &primary_keys {
            if let Some(raw_id) = key.strip_prefix(&prefix)
                && let Ok(id) = uuid::Uuid::parse_str(raw_id)
            {
                token_ids.insert(TokenId::from_uuid(id));
            }
        }

        // Include index-only remnants from an interrupted earlier purge.
        let index_keys = store
            .list_keys(NS_TOKEN_INDEX)
            .await
            .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
        for raw_id in index_keys {
            let owner = store
                .get(NS_TOKEN_INDEX, &raw_id)
                .await
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            if owner.as_deref() == Some(principal.as_str().as_bytes())
                && let Ok(id) = uuid::Uuid::parse_str(&raw_id)
            {
                token_ids.insert(TokenId::from_uuid(id));
            }
        }

        let mut failures = Vec::new();
        for key in primary_keys {
            if let Err(error) = store.delete(NS_TOKENS, &key).await {
                failures.push(format!("delete token {key}: {error}"));
            }
        }
        for token_id in &token_ids {
            let raw_id = token_id.0.to_string();
            if let Err(error) = store.delete(NS_TOKEN_INDEX, &raw_id).await {
                failures.push(format!("delete {NS_TOKEN_INDEX}/{raw_id}: {error}"));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(CapabilityError::StorageError(failures.join("; ")))
        }
    }

    /// Mark a single-use token as used.
    ///
    /// Admission records consumption before allowing an operation to use
    /// the grant. Use [`Self::use_token`] to validate and consume together.
    ///
    /// # Errors
    ///
    /// Returns an error if the token was revoked, already used, or storage fails.
    pub async fn mark_used(&self, token_id: &TokenId) -> CapabilityResult<()> {
        let mut authority = self.authority.write().await;
        self.consume(&mut authority, token_id).await
    }

    async fn consume(
        &self,
        authority: &mut HashMap<TokenId, TokenStatus>,
        token_id: &TokenId,
    ) -> CapabilityResult<()> {
        let mut status = Self::status(authority, token_id);
        Self::ensure_admission(status, token_id, true)?;

        // A canceled or ambiguous write can have committed. Requiring
        // durable absence atomically prevents a retry from winning twice.
        let won = if let Some(store) = &self.persistent_store {
            store
                .compare_and_swap(
                    NS_USED,
                    &token_id.0.to_string(),
                    None,
                    PRESENCE_MARKER.to_vec(),
                )
                .await
                .map_err(|error| CapabilityError::StorageError(error.to_string()))?
        } else {
            true
        };
        let admitted = status.confirm_consumption(won);
        authority.insert(token_id.clone(), status);
        if !admitted {
            return Err(CapabilityError::TokenAlreadyUsed {
                token_id: token_id.to_string(),
            });
        }
        Ok(())
    }

    /// Check if a single-use token has been used.
    pub async fn is_used(&self, token_id: &TokenId) -> bool {
        Self::status(&*self.authority.read().await, token_id).is_used()
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
        self.use_checked(token_id, |_| Ok(())).await
    }

    pub(crate) async fn use_checked(
        &self,
        token_id: &TokenId,
        check: impl FnOnce(&CapabilityToken) -> CapabilityResult<()> + Send,
    ) -> CapabilityResult<CapabilityToken> {
        let retirement = self.retiring_principals.read().await;
        {
            let authority = self.authority.read().await;
            Self::ensure_admission(Self::status(&authority, token_id), token_id, false)?;
        }
        let token = self.lookup(token_id, &retirement).await?.ok_or_else(|| {
            CapabilityError::TokenNotFound {
                token_id: token_id.to_string(),
            }
        })?;
        if token.id != *token_id {
            return Err(CapabilityError::InvalidSignature);
        }
        token.validate()?;
        check(&token)?;

        if token.is_single_use() {
            let mut authority = self.authority.write().await;
            token.check_admission_expiry()?;
            self.consume(&mut authority, token_id).await?;
        } else {
            let authority = self.authority.read().await;
            token.check_admission_expiry()?;
            Self::ensure_admission(Self::status(&authority, token_id), token_id, false)?;
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
        let authority = self.authority.read().await;

        // Session tokens
        {
            let session = self
                .session_tokens
                .read()
                .map_err(|e| CapabilityError::StorageError(e.to_string()))?;
            for principal_map in session.values() {
                for token in principal_map.values() {
                    if !token.is_expired() && !Self::status(&authority, &token.id).is_revoked() {
                        tokens.push(token.clone());
                    }
                }
            }
        }

        // Persistent tokens — iterate every `{principal}/{token_id}` key.
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
                    && !Self::status(&authority, &token.id).is_revoked()
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
        let (revoked_count, used_count) = self.authority.try_read().map_or((0, 0), |authority| {
            (
                authority
                    .values()
                    .filter(|status| status.is_revoked())
                    .count(),
                authority.values().filter(|status| status.is_used()).count(),
            )
        });
        let retiring_count = self
            .retiring_principals
            .try_read()
            .map_or(0, |principals| principals.len());
        let has_persistence = self.persistent_store.is_some();

        f.debug_struct("CapabilityStore")
            .field("session_principals", &session_principals)
            .field("session_tokens", &session_count)
            .field("revoked_count", &revoked_count)
            .field("used_count", &used_count)
            .field("retiring_principals", &retiring_count)
            .field("has_persistence", &has_persistence)
            .finish()
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
