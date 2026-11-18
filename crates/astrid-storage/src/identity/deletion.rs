//! Cleanup uses the bytes whose owner was checked, never a later name binding.

use super::{FrontendLink, IdentityError, KvIdentityStore, Uuid};

impl KvIdentityStore {
    pub(super) async fn delete_user_records(&self, id: Uuid) -> Result<bool, IdentityError> {
        let Some(record) = self.load_user_record(id).await? else {
            return Ok(false);
        };
        let user = record.user;

        for (key, _) in self.scan_user_links(id).await? {
            self.delete_link_if_owned(&key, id).await?;
        }
        if let Some(name) = user.display_name.as_deref() {
            self.delete_name_if_owned(name.trim(), id).await?;
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

    async fn delete_link_if_owned(&self, key: &str, user: Uuid) -> Result<(), IdentityError> {
        loop {
            let Some(bytes) = self
                .kv
                .get(key)
                .await
                .map_err(|ref error| storage_error(error))?
            else {
                return Ok(());
            };
            // Validate the current record, including non-canonical legacy JSON,
            // but retain its exact observed bytes for the backend comparison.
            let owner = serde_json::from_slice::<FrontendLink>(&bytes)
                .map_err(|error| IdentityError::Storage(error.to_string()))?
                .astrid_user_id;
            if owner != user
                || self
                    .kv
                    .compare_and_delete(key, bytes)
                    .await
                    .map_err(|ref error| storage_error(error))?
            {
                return Ok(());
            }
            // A same-owner refresh still needs cleanup. Recheck ownership after
            // a failed comparison instead of leaving a link to the deleted user.
        }
    }

    async fn delete_name_if_owned(&self, name: &str, user: Uuid) -> Result<(), IdentityError> {
        let key = Self::name_key(name);
        if let Some(bytes) = self
            .kv
            .get(&key)
            .await
            .map_err(|ref error| storage_error(error))?
            && bytes == user.to_string().as_bytes()
        {
            self.kv
                .compare_and_delete(&key, bytes)
                .await
                .map_err(|ref error| storage_error(error))?;
        }
        Ok(())
    }
}

fn storage_error(error: &crate::StorageError) -> IdentityError {
    IdentityError::Storage(error.to_string())
}
