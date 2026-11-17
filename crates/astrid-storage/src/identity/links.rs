//! Read link candidates through the backing store's namespace range traversal.

use super::{FrontendLink, IdentityError, KvIdentityStore, Uuid};

impl KvIdentityStore {
    pub(super) async fn scan_user_links(
        &self,
        user: Uuid,
    ) -> Result<Vec<(String, FrontendLink)>, IdentityError> {
        let entries = self
            .kv
            .list_entries_with_prefix("link/")
            .await
            .map_err(|error| IdentityError::Storage(error.to_string()))?;
        let mut links = Vec::new();
        for entry in entries {
            if entry.namespace != self.kv.namespace() || !entry.key.starts_with("link/") {
                return Err(IdentityError::Storage(
                    "identity link scan escaped its namespace or prefix".to_owned(),
                ));
            }
            let link: FrontendLink = serde_json::from_slice(&entry.value).map_err(|error| {
                IdentityError::Storage(format!(
                    "invalid stored frontend link {}: {error}",
                    entry.key
                ))
            })?;
            if link.astrid_user_id == user {
                links.push((entry.key, link));
            }
        }
        Ok(links)
    }
}
