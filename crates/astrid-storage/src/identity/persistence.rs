//! Storage-private identity envelope and atomic user-record helpers.

use astrid_core::identity::PrincipalIdentity;
use astrid_core::identity::types::AstridUserId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{IdentityError, KvIdentityStore};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PersistedUser {
    #[serde(flatten)]
    pub(super) user: AstridUserId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) principal_identity: Option<PrincipalIdentity>,
}

impl KvIdentityStore {
    pub(super) async fn persist_user(&self, user: &AstridUserId) -> Result<(), IdentityError> {
        self.persist_user_record(user, None).await
    }

    pub(super) async fn persist_user_record(
        &self,
        user: &AstridUserId,
        principal_identity: Option<PrincipalIdentity>,
    ) -> Result<(), IdentityError> {
        self.kv
            .set_json(
                &Self::user_key(user.id),
                &PersistedUser {
                    user: user.clone(),
                    principal_identity,
                },
            )
            .await
            .map_err(|error| IdentityError::Storage(error.to_string()))
    }

    pub(super) async fn load_user_record(
        &self,
        id: Uuid,
    ) -> Result<Option<PersistedUser>, IdentityError> {
        self.kv
            .get_json(&Self::user_key(id))
            .await
            .map_err(|error| IdentityError::Storage(error.to_string()))
    }

    pub(super) async fn index_display_name(
        &self,
        user: &AstridUserId,
    ) -> Result<(), IdentityError> {
        if let Some(name) = user
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            self.kv
                .set(&Self::name_key(name), user.id.to_string().into_bytes())
                .await
                .map_err(|error| IdentityError::Storage(error.to_string()))?;
        }
        Ok(())
    }
}
