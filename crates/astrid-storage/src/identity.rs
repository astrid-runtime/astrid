//! Identity store for managing users and platform links.
//!
//! Provides an [`IdentityStore`] trait with a KV-backed implementation
//! ([`KvIdentityStore`]) that stores user records and platform links
//! in a [`ScopedKvStore`] with namespace `system:identity`.
//!
//! ## KV Key Scheme
//!
//! Keys use `/` as the separator. Both `platform` and `platform_user_id`
//! are validated to reject `/` and `\0` before key construction:
//!
//! - `user/{uuid}` - JSON-serialized [`AstridUserId`]
//! - `link/{platform}/{platform_user_id}` - JSON-serialized [`FrontendLink`]
//! - `name/{display_name}` - UUID string (name-to-UUID index for config resolution)

use std::fmt;

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use astrid_core::identity::types::{AstridUserId, FrontendLink, normalize_platform};
use astrid_core::identity::{PrincipalGenesis, PrincipalIdentity, PrincipalUid};
use astrid_core::principal::PrincipalId;

use crate::PrincipalDirectory;
use crate::kv::ScopedKvStore;

mod persistence;
use persistence::PersistedUser;

// Keep these established public items nominally in `identity` while their
// physical source remains independently reviewable under the repository's
// source-file cap.
include!("identity/contract.rs");

#[derive(Debug)]
enum DirectoryMutation {
    Unchanged,
    Registered {
        alias: PrincipalId,
        uid: PrincipalUid,
    },
    Renamed {
        uid: PrincipalUid,
        previous: PrincipalId,
        current: PrincipalId,
    },
}

// ---------------------------------------------------------------------------
// KV-backed implementation
// ---------------------------------------------------------------------------

/// KV-backed identity store.
///
/// Uses a [`ScopedKvStore`] (typically namespace `system:identity`) to persist
/// user records and platform links. All data is JSON-serialized.
#[derive(Clone)]
pub struct KvIdentityStore {
    kv: ScopedKvStore,
    principals: Option<PrincipalDirectory>,
}

impl fmt::Debug for KvIdentityStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvIdentityStore")
            .field("namespace", &self.kv.namespace())
            .field(
                "principal_directory",
                &self.principals.as_ref().map(|_| "attached"),
            )
            .finish()
    }
}

impl KvIdentityStore {
    /// Create a new KV-backed identity store.
    #[must_use]
    pub fn new(kv: ScopedKvStore) -> Self {
        Self {
            kv,
            principals: None,
        }
    }

    /// Create a KV-backed identity store bound to the runtime's live
    /// principal directory.
    #[must_use]
    pub fn with_principal_directory(kv: ScopedKvStore, principals: PrincipalDirectory) -> Self {
        Self {
            kv,
            principals: Some(principals),
        }
    }

    /// Build the KV key for a user record.
    fn user_key(id: Uuid) -> String {
        format!("user/{id}")
    }

    /// Build the KV key for a platform link.
    fn link_key(platform: &str, platform_user_id: &str) -> String {
        format!("link/{platform}/{platform_user_id}")
    }

    /// Build the KV key for a name-to-UUID index entry.
    fn name_key(name: &str) -> String {
        format!("name/{name}")
    }

    fn bind_directory(
        &self,
        previous_alias: Option<&PrincipalId>,
        principal: &PrincipalId,
        uid: PrincipalUid,
    ) -> Result<DirectoryMutation, IdentityError> {
        let Some(directory) = &self.principals else {
            return Ok(DirectoryMutation::Unchanged);
        };
        match directory.alias_for(uid) {
            Ok(existing) if existing == *principal => Ok(DirectoryMutation::Unchanged),
            Ok(existing) if previous_alias == Some(&existing) => {
                directory
                    .rename(uid, &existing, principal.clone())
                    .map_err(|error| IdentityError::InvalidInput(error.to_string()))?;
                Ok(DirectoryMutation::Renamed {
                    uid,
                    previous: existing,
                    current: principal.clone(),
                })
            },
            Ok(existing) => Err(IdentityError::InvalidInput(format!(
                "principal uid {uid} is already bound to alias {existing}"
            ))),
            Err(_) => {
                if let Some(previous) = previous_alias
                    && let Ok(existing) = directory.uid_for(previous)
                {
                    return Err(IdentityError::InvalidInput(format!(
                        "principal alias {previous} is bound to a different uid {existing}"
                    )));
                }
                directory
                    .register(principal.clone(), uid)
                    .map_err(|error| {
                        IdentityError::InvalidInput(format!(
                            "principal identity collision: {error}"
                        ))
                    })?;
                Ok(DirectoryMutation::Registered {
                    alias: principal.clone(),
                    uid,
                })
            },
        }
    }

    fn rollback_directory(&self, mutation: DirectoryMutation) -> Result<(), IdentityError> {
        let Some(directory) = &self.principals else {
            return Ok(());
        };
        match mutation {
            DirectoryMutation::Unchanged => Ok(()),
            DirectoryMutation::Registered { alias, uid } => {
                directory.unregister(&alias, uid);
                Ok(())
            },
            DirectoryMutation::Renamed {
                uid,
                previous,
                current,
            } => directory
                .rename(uid, &current, previous)
                .map_err(|error| IdentityError::Storage(format!("directory rollback: {error}"))),
        }
    }

    /// Read the immutable principal identity bound to one user record.
    ///
    /// Frontend-only users legitimately return `None`.
    ///
    /// # Errors
    ///
    /// Returns an identity or storage error if the persisted record is
    /// malformed.
    pub async fn get_principal_identity(
        &self,
        id: Uuid,
    ) -> Result<Option<PrincipalIdentity>, IdentityError> {
        let identity = self
            .load_user_record(id)
            .await?
            .and_then(|record| record.principal_identity);
        if let Some(identity) = &identity {
            identity
                .validate()
                .map_err(|error| IdentityError::InvalidInput(error.to_string()))?;
        }
        Ok(identity)
    }

    /// Validate that a string is non-empty.
    fn validate_non_empty(value: &str, field: &str) -> Result<(), IdentityError> {
        if value.trim().is_empty() {
            return Err(IdentityError::InvalidInput(format!(
                "{field} must not be empty"
            )));
        }
        Ok(())
    }

    /// Validate that a platform name is safe for use as a KV key component.
    ///
    /// Rejects empty strings and strings containing `/` or `\0`, which would
    /// allow key-path injection in the `link/{platform}/{platform_user_id}` scheme.
    fn validate_platform(value: &str) -> Result<(), IdentityError> {
        Self::validate_non_empty(value, "platform")?;
        if value.contains('/') || value.contains('\0') {
            return Err(IdentityError::InvalidInput(
                "platform must not contain '/' or null bytes".into(),
            ));
        }
        Ok(())
    }

    /// Validate that a platform user ID is safe for use as a KV key component.
    ///
    /// Rejects empty strings and strings containing `/` or `\0`, which would
    /// allow key-path injection in the `link/{platform}/{platform_user_id}` scheme.
    fn validate_platform_user_id(value: &str) -> Result<(), IdentityError> {
        Self::validate_non_empty(value, "platform_user_id")?;
        if value.contains('/') || value.contains('\0') {
            return Err(IdentityError::InvalidInput(
                "platform_user_id must not contain '/' or null bytes".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl IdentityStore for KvIdentityStore {
    async fn create_user(&self, display_name: Option<&str>) -> Result<AstridUserId, IdentityError> {
        let mut user = AstridUserId::new();
        if let Some(name) = display_name {
            if name.contains('/') || name.contains('\0') {
                return Err(IdentityError::InvalidInput(
                    "display_name must not contain '/' or null bytes".into(),
                ));
            }
            user = user.with_display_name(name);
        }

        self.persist_user(&user).await?;

        // Index by display name if provided.
        // Note: this overwrites any existing name index entry. The name index is
        // a best-effort lookup for config resolution, not a uniqueness constraint.
        // Last writer wins - the most recently created user with a given name
        // will be found by `get_user_by_name`.
        self.index_display_name(&user).await?;

        Ok(user)
    }

    async fn create_principal(
        &self,
        principal: PrincipalId,
        initial_public_key: [u8; 32],
    ) -> Result<AstridUserId, IdentityError> {
        for user in self.list_users().await? {
            if user.principal == principal && self.get_principal_identity(user.id).await?.is_some()
            {
                return Err(IdentityError::InvalidInput(format!(
                    "principal alias {principal} already has an identity"
                )));
            }
        }
        let user = AstridUserId::new()
            .with_principal(principal.clone())
            .with_display_name(principal.as_str());
        let identity = PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
            user.id,
            user.created_at,
            initial_public_key,
        ))
        .map_err(|error| IdentityError::InvalidInput(error.to_string()))?;
        let directory_mutation = self.bind_directory(None, &principal, identity.uid)?;
        if let Err(error) = self
            .persist_user_record(&user, Some(identity.clone()))
            .await
        {
            self.rollback_directory(directory_mutation)?;
            return Err(error);
        }
        if let Err(error) = self.index_display_name(&user).await {
            let _ = self.kv.delete(&Self::user_key(user.id)).await;
            self.rollback_directory(directory_mutation)?;
            return Err(error);
        }
        Ok(user)
    }

    async fn bind_principal_identity(
        &self,
        id: Uuid,
        principal: PrincipalId,
        initial_public_key: [u8; 32],
    ) -> Result<PrincipalIdentity, IdentityError> {
        let mut user = self
            .load_user_record(id)
            .await?
            .ok_or(IdentityError::UserNotFound(id))?;
        let previous_alias = user.user.principal.clone();
        user.user.principal = principal.clone();
        let identity = match user.principal_identity {
            Some(identity) => {
                identity
                    .validate()
                    .map_err(|error| IdentityError::InvalidInput(error.to_string()))?;
                identity
            },
            None => PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
                user.user.id,
                user.user.created_at,
                initial_public_key,
            ))
            .map_err(|error| IdentityError::InvalidInput(error.to_string()))?,
        };
        let directory_mutation =
            self.bind_directory(Some(&previous_alias), &principal, identity.uid)?;
        if let Err(error) = self
            .persist_user_record(&user.user, Some(identity.clone()))
            .await
        {
            self.rollback_directory(directory_mutation)?;
            return Err(error);
        }
        Ok(identity)
    }

    async fn load_principal_directory(&self) -> Result<(), IdentityError> {
        let keys = self
            .kv
            .list_keys_with_prefix("user/")
            .await
            .map_err(|error| IdentityError::Storage(error.to_string()))?;
        let mut bindings = Vec::new();
        for key in keys {
            if let Some(user) = self
                .kv
                .get_json::<PersistedUser>(&key)
                .await
                .map_err(|error| IdentityError::Storage(error.to_string()))?
                && let Some(identity) = user.principal_identity
            {
                identity
                    .validate()
                    .map_err(|error| IdentityError::InvalidInput(error.to_string()))?;
                bindings.push((user.user.principal, identity.uid));
            }
        }
        if let Some(directory) = &self.principals {
            directory.replace_all(bindings).map_err(|error| {
                IdentityError::InvalidInput(format!("principal directory: {error}"))
            })?;
        }
        Ok(())
    }

    async fn get_user(&self, id: Uuid) -> Result<Option<AstridUserId>, IdentityError> {
        self.load_user_record(id)
            .await
            .map(|record| record.map(|record| record.user))
    }

    async fn resolve(
        &self,
        platform: &str,
        platform_user_id: &str,
    ) -> Result<Option<AstridUserId>, IdentityError> {
        Self::validate_platform(platform)?;
        Self::validate_platform_user_id(platform_user_id)?;

        let normalized = normalize_platform(platform);
        let key = Self::link_key(&normalized, platform_user_id);

        let link: Option<FrontendLink> = self
            .kv
            .get_json(&key)
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))?;

        match link {
            Some(l) => self.get_user(l.astrid_user_id).await,
            None => Ok(None),
        }
    }

    async fn link(
        &self,
        platform: &str,
        platform_user_id: &str,
        astrid_user_id: Uuid,
        method: &str,
    ) -> Result<FrontendLink, IdentityError> {
        Self::validate_platform(platform)?;
        Self::validate_platform_user_id(platform_user_id)?;
        Self::validate_non_empty(method, "method")?;

        // Verify the target user exists.
        let user = self.get_user(astrid_user_id).await?;
        if user.is_none() {
            return Err(IdentityError::UserNotFound(astrid_user_id));
        }

        let normalized = normalize_platform(platform);
        let link = FrontendLink {
            platform: normalized.clone(),
            platform_user_id: platform_user_id.to_string(),
            astrid_user_id,
            linked_at: Utc::now(),
            method: method.to_string(),
        };

        let key = Self::link_key(&normalized, platform_user_id);
        self.kv
            .set_json(&key, &link)
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))?;

        Ok(link)
    }

    async fn unlink(&self, platform: &str, platform_user_id: &str) -> Result<bool, IdentityError> {
        Self::validate_platform(platform)?;
        Self::validate_platform_user_id(platform_user_id)?;

        let normalized = normalize_platform(platform);
        let key = Self::link_key(&normalized, platform_user_id);

        self.kv
            .delete(&key)
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))
    }

    async fn list_links(&self, astrid_user_id: Uuid) -> Result<Vec<FrontendLink>, IdentityError> {
        let keys = self
            .kv
            .list_keys_with_prefix("link/")
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))?;

        let mut links = Vec::new();
        for key in keys {
            if let Some(link) = self
                .kv
                .get_json::<FrontendLink>(&key)
                .await
                .map_err(|e| IdentityError::Storage(e.to_string()))?
                && link.astrid_user_id == astrid_user_id
            {
                links.push(link);
            }
        }
        Ok(links)
    }

    async fn get_user_by_name(&self, name: &str) -> Result<Option<AstridUserId>, IdentityError> {
        let key = Self::name_key(name.trim());
        let uuid_bytes = self
            .kv
            .get(&key)
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))?;

        match uuid_bytes {
            Some(bytes) => {
                let uuid_str = String::from_utf8(bytes)
                    .map_err(|e| IdentityError::Storage(format!("invalid UUID bytes: {e}")))?;
                let id = Uuid::parse_str(&uuid_str)
                    .map_err(|e| IdentityError::Storage(format!("invalid UUID: {e}")))?;
                self.get_user(id).await
            },
            None => Ok(None),
        }
    }

    async fn delete_user(&self, id: Uuid) -> Result<bool, IdentityError> {
        let Some(record) = self.load_user_record(id).await? else {
            return Ok(false);
        };
        let user = record.user;

        // Drop every link that points at this user. We scan `link/` and
        // delete matches — O(links) per delete, but the link table is
        // small (one row per (platform, platform_user) pair).
        let link_keys = self
            .kv
            .list_keys_with_prefix("link/")
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))?;
        for key in link_keys {
            if let Some(link) = self
                .kv
                .get_json::<FrontendLink>(&key)
                .await
                .map_err(|e| IdentityError::Storage(e.to_string()))?
                && link.astrid_user_id == id
            {
                self.kv
                    .delete(&key)
                    .await
                    .map_err(|e| IdentityError::Storage(e.to_string()))?;
            }
        }

        // Drop the name index entry, but only if it still points at this
        // UUID — `get_user_by_name` is best-effort and two users can
        // share a display name if created in sequence.
        if let Some(name) = user.display_name.as_deref() {
            let key = Self::name_key(name.trim());
            if let Some(bytes) = self
                .kv
                .get(&key)
                .await
                .map_err(|e| IdentityError::Storage(e.to_string()))?
                && String::from_utf8(bytes).ok().as_deref() == Some(id.to_string().as_str())
            {
                self.kv
                    .delete(&key)
                    .await
                    .map_err(|e| IdentityError::Storage(e.to_string()))?;
            }
        }

        // Finally drop the user record itself.
        self.kv
            .delete(&Self::user_key(id))
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))?;
        if let (Some(directory), Some(identity)) = (&self.principals, record.principal_identity) {
            directory.unregister(&user.principal, identity.uid);
        }
        Ok(true)
    }

    async fn list_users(&self) -> Result<Vec<AstridUserId>, IdentityError> {
        let keys = self
            .kv
            .list_keys_with_prefix("user/")
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))?;
        let mut users = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(user) = self
                .kv
                .get_json::<AstridUserId>(&key)
                .await
                .map_err(|e| IdentityError::Storage(e.to_string()))?
            {
                users.push(user);
            }
        }
        Ok(users)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod failure_tests;
#[cfg(test)]
mod principal_tests;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::MemoryKvStore;

    fn make_store() -> KvIdentityStore {
        let kv_backend = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(kv_backend, "system:identity").unwrap();
        KvIdentityStore::new(scoped)
    }

    #[tokio::test]
    async fn create_and_get_user() {
        let store = make_store();

        let user = store.create_user(Some("Alice")).await.unwrap();
        assert_eq!(user.display_name.as_deref(), Some("Alice"));

        let fetched = store.get_user(user.id).await.unwrap();
        assert_eq!(fetched, Some(user));
    }

    #[tokio::test]
    async fn create_user_no_name() {
        let store = make_store();
        let user = store.create_user(None).await.unwrap();
        assert!(user.display_name.is_none());
    }

    #[tokio::test]
    async fn get_nonexistent_user() {
        let store = make_store();
        let result = store.get_user(Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolve_linked_user() {
        let store = make_store();
        let user = store.create_user(Some("Bob")).await.unwrap();

        store
            .link("Discord", "12345", user.id, "admin")
            .await
            .unwrap();

        let resolved = store.resolve("discord", "12345").await.unwrap();
        assert_eq!(resolved.unwrap().id, user.id);
    }

    #[tokio::test]
    async fn resolve_unlinked_returns_none() {
        let store = make_store();
        let result = store.resolve("discord", "99999").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolve_normalizes_platform() {
        let store = make_store();
        let user = store.create_user(None).await.unwrap();

        store
            .link("  DISCORD  ", "abc", user.id, "admin")
            .await
            .unwrap();

        // Different casing/whitespace should still resolve.
        let resolved = store.resolve("Discord", "abc").await.unwrap();
        assert_eq!(resolved.unwrap().id, user.id);
    }

    #[tokio::test]
    async fn link_requires_existing_user() {
        let store = make_store();
        let fake_id = Uuid::new_v4();

        let err = store
            .link("discord", "123", fake_id, "admin")
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::UserNotFound(_)));
    }

    #[tokio::test]
    async fn link_upsert_semantics() {
        let store = make_store();
        let user1 = store.create_user(Some("Alice")).await.unwrap();
        let user2 = store.create_user(Some("Bob")).await.unwrap();

        store
            .link("discord", "123", user1.id, "admin")
            .await
            .unwrap();
        // Re-link to a different user (upsert).
        store
            .link("discord", "123", user2.id, "admin")
            .await
            .unwrap();

        let resolved = store.resolve("discord", "123").await.unwrap();
        assert_eq!(resolved.unwrap().id, user2.id);
    }

    #[tokio::test]
    async fn unlink_removes_link() {
        let store = make_store();
        let user = store.create_user(None).await.unwrap();

        store
            .link("telegram", "789", user.id, "admin")
            .await
            .unwrap();
        let removed = store.unlink("telegram", "789").await.unwrap();
        assert!(removed);

        let resolved = store.resolve("telegram", "789").await.unwrap();
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn unlink_nonexistent_returns_false() {
        let store = make_store();
        let removed = store.unlink("discord", "nonexistent").await.unwrap();
        assert!(!removed);
    }

    #[tokio::test]
    async fn list_links_filters_by_user() {
        let store = make_store();
        let alice = store.create_user(Some("Alice")).await.unwrap();
        let bob = store.create_user(Some("Bob")).await.unwrap();

        store
            .link("discord", "a1", alice.id, "admin")
            .await
            .unwrap();
        store
            .link("telegram", "a2", alice.id, "admin")
            .await
            .unwrap();
        store.link("discord", "b1", bob.id, "admin").await.unwrap();

        let alice_links = store.list_links(alice.id).await.unwrap();
        assert_eq!(alice_links.len(), 2);
        assert!(alice_links.iter().all(|l| l.astrid_user_id == alice.id));

        let bob_links = store.list_links(bob.id).await.unwrap();
        assert_eq!(bob_links.len(), 1);
    }

    #[tokio::test]
    async fn list_links_empty_for_unknown_user() {
        let store = make_store();
        let links = store.list_links(Uuid::new_v4()).await.unwrap();
        assert!(links.is_empty());
    }

    #[tokio::test]
    async fn get_user_by_name_works() {
        let store = make_store();
        let user = store.create_user(Some("Charlie")).await.unwrap();

        let found = store.get_user_by_name("Charlie").await.unwrap();
        assert_eq!(found.unwrap().id, user.id);
    }

    #[tokio::test]
    async fn get_user_by_name_not_found() {
        let store = make_store();
        let found = store.get_user_by_name("nobody").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn empty_platform_rejected() {
        let store = make_store();
        let err = store.resolve("", "123").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn empty_platform_user_id_rejected() {
        let store = make_store();
        let err = store.resolve("discord", "  ").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn link_empty_method_rejected() {
        let store = make_store();
        let user = store.create_user(None).await.unwrap();
        let err = store.link("discord", "123", user.id, "").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn platform_user_id_with_slash_rejected() {
        let store = make_store();
        let user = store.create_user(None).await.unwrap();

        // link rejects slash
        let err = store
            .link("discord", "123/../../user/456", user.id, "admin")
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));

        // resolve rejects slash
        let err = store.resolve("discord", "a/b").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));

        // unlink rejects slash
        let err = store.unlink("discord", "x/y").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn platform_user_id_with_null_rejected() {
        let store = make_store();
        let err = store.resolve("discord", "abc\0def").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn create_user_with_slash_in_name_rejected() {
        let store = make_store();
        let err = store.create_user(Some("admin/root")).await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn platform_with_slash_rejected() {
        let store = make_store();
        let user = store.create_user(None).await.unwrap();

        let err = store
            .link("a/b", "123", user.id, "admin")
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));

        let err = store.resolve("x/y", "123").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));

        let err = store.unlink("m/n", "123").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn platform_with_null_rejected() {
        let store = make_store();
        let err = store.resolve("disc\0rd", "123").await.unwrap_err();
        assert!(matches!(err, IdentityError::InvalidInput(_)));
    }

    // ── delete_user / list_users (issue #672) ────────────────────────

    #[tokio::test]
    async fn delete_user_removes_record_and_links() {
        let store = make_store();
        let alice = store.create_user(Some("Alice")).await.unwrap();
        store
            .link("discord", "a1", alice.id, "admin")
            .await
            .unwrap();
        store
            .link("telegram", "a2", alice.id, "admin")
            .await
            .unwrap();

        assert!(store.delete_user(alice.id).await.unwrap());
        assert!(store.get_user(alice.id).await.unwrap().is_none());
        // Links must not resolve after delete.
        assert!(store.resolve("discord", "a1").await.unwrap().is_none());
        assert!(store.resolve("telegram", "a2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_user_idempotent_for_missing_uuid() {
        let store = make_store();
        assert!(!store.delete_user(Uuid::new_v4()).await.unwrap());
    }

    #[tokio::test]
    async fn delete_user_preserves_other_users_links() {
        let store = make_store();
        let alice = store.create_user(Some("Alice")).await.unwrap();
        let bob = store.create_user(Some("Bob")).await.unwrap();
        store
            .link("discord", "a1", alice.id, "admin")
            .await
            .unwrap();
        store.link("discord", "b1", bob.id, "admin").await.unwrap();

        assert!(store.delete_user(alice.id).await.unwrap());
        // Bob's link is intact.
        let resolved = store.resolve("discord", "b1").await.unwrap();
        assert_eq!(resolved.unwrap().id, bob.id);
    }

    #[tokio::test]
    async fn delete_user_clears_name_index_when_unique() {
        let store = make_store();
        let user = store.create_user(Some("Unique")).await.unwrap();
        assert!(store.delete_user(user.id).await.unwrap());
        assert!(store.get_user_by_name("Unique").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_user_leaves_name_index_when_it_points_to_a_different_uuid() {
        // Name index is last-writer-wins (best-effort). After User B shares
        // a display name with User A, the index points to B. Deleting A
        // must not blow away B's index entry.
        let store = make_store();
        let a = store.create_user(Some("Shared")).await.unwrap();
        let b = store.create_user(Some("Shared")).await.unwrap();
        assert!(store.delete_user(a.id).await.unwrap());
        let found = store.get_user_by_name("Shared").await.unwrap();
        assert_eq!(found.unwrap().id, b.id);
    }

    #[tokio::test]
    async fn list_users_returns_every_created_user() {
        let store = make_store();
        let a = store.create_user(Some("a")).await.unwrap();
        let b = store.create_user(Some("b")).await.unwrap();
        let c = store.create_user(None).await.unwrap();

        let mut users = store.list_users().await.unwrap();
        users.sort_by_key(|u| u.id);
        let mut expected = vec![a, b, c];
        expected.sort_by_key(|u| u.id);
        assert_eq!(users, expected);
    }

    #[tokio::test]
    async fn list_users_after_delete_excludes_deleted() {
        let store = make_store();
        let a = store.create_user(Some("a")).await.unwrap();
        let b = store.create_user(Some("b")).await.unwrap();
        store.delete_user(a.id).await.unwrap();

        let users = store.list_users().await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].id, b.id);
    }
}
