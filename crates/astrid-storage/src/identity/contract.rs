// Public identity-store contract and typed failures.

/// Errors from identity store operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The specified user was not found.
    #[error("user not found: {0}")]
    UserNotFound(Uuid),

    /// The underlying storage operation failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// Input validation failed.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Identity store for managing users and platform links.
///
/// All operations are async because the backing store is async.
#[async_trait]
pub trait IdentityStore: Send + Sync + fmt::Debug {
    /// Create a new [`AstridUserId`]. Returns the created user.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Storage`] if persistence fails.
    async fn create_user(&self, display_name: Option<&str>) -> Result<AstridUserId, IdentityError>;

    /// Create the authoritative identity record for one new principal.
    ///
    /// Unlike a frontend-only user, this record carries immutable genesis
    /// identity and registers its mutable alias in the live principal
    /// directory.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidInput`] for an alias collision or
    /// invalid genesis identity, and [`IdentityError::Storage`] if persistence
    /// fails.
    async fn create_principal(
        &self,
        principal: PrincipalId,
        initial_public_key: [u8; 32],
    ) -> Result<AstridUserId, IdentityError> {
        let _ = (principal, initial_public_key);
        Err(IdentityError::InvalidInput(
            "this identity store does not support durable principal identities".to_owned(),
        ))
    }

    /// Backfill or validate stable identity for an existing principal user.
    ///
    /// Existing UUID and creation time are reused, so a retry with the same
    /// initial key derives the same UID.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::UserNotFound`] when `id` is absent,
    /// [`IdentityError::InvalidInput`] for conflicting identity, and
    /// [`IdentityError::Storage`] if persistence fails.
    async fn bind_principal_identity(
        &self,
        id: Uuid,
        principal: PrincipalId,
        initial_public_key: [u8; 32],
    ) -> Result<PrincipalIdentity, IdentityError> {
        let _ = (id, principal, initial_public_key);
        Err(IdentityError::InvalidInput(
            "this identity store does not support durable principal identities".to_owned(),
        ))
    }

    /// Validate every persisted principal identity and populate the live
    /// alias directory.
    ///
    /// # Errors
    ///
    /// Returns an identity or storage error without admitting a partial
    /// conflicting mapping.
    async fn load_principal_directory(&self) -> Result<(), IdentityError> {
        Ok(())
    }

    /// Look up a user by UUID. Returns `None` if not found.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Storage`] if the read fails.
    async fn get_user(&self, id: Uuid) -> Result<Option<AstridUserId>, IdentityError>;

    /// Resolve a platform identity to an [`AstridUserId`].
    /// Returns `None` if no link exists for this platform + `user_id` pair.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Storage`] if the read fails.
    /// Returns [`IdentityError::InvalidInput`] if platform or `user_id` is empty.
    async fn resolve(
        &self,
        platform: &str,
        platform_user_id: &str,
    ) -> Result<Option<AstridUserId>, IdentityError>;

    /// Link a platform identity to an existing [`AstridUserId`].
    ///
    /// Uses upsert semantics: if a link already exists for this
    /// platform + `user_id`, it is updated to point to the new user.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::UserNotFound`] if the target user doesn't exist.
    /// Returns [`IdentityError::InvalidInput`] if any input is empty.
    /// Returns [`IdentityError::Storage`] if persistence fails.
    async fn link(
        &self,
        platform: &str,
        platform_user_id: &str,
        astrid_user_id: Uuid,
        method: &str,
    ) -> Result<FrontendLink, IdentityError>;

    /// Remove a platform link. Returns `true` if the link existed.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidInput`] if platform or `user_id` is empty.
    /// Returns [`IdentityError::Storage`] if the delete fails.
    async fn unlink(&self, platform: &str, platform_user_id: &str) -> Result<bool, IdentityError>;

    /// List all links for a given [`AstridUserId`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Storage`] if the scan fails.
    async fn list_links(&self, astrid_user_id: Uuid) -> Result<Vec<FrontendLink>, IdentityError>;

    /// Look up a user by display name. Returns `None` if not found.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Storage`] if the read fails.
    async fn get_user_by_name(&self, name: &str) -> Result<Option<AstridUserId>, IdentityError>;

    /// Remove a user record, every link pointing at it, and the display
    /// name index. Returns `true` if the user existed (and was deleted),
    /// `false` if the UUID was already absent (idempotent).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Storage`] if any underlying read, scan,
    /// or delete fails.
    async fn delete_user(&self, id: Uuid) -> Result<bool, IdentityError>;

    /// List every user record currently in the store.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Storage`] if the scan or any read fails.
    async fn list_users(&self) -> Result<Vec<AstridUserId>, IdentityError>;
}
