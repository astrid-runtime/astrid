//! Read link candidates through the backing store's namespace range traversal.

use parking_lot::Mutex;
use std::sync::Arc;

use super::{FrontendLink, IdentityError, KvIdentityStore, Uuid};
use crate::StorageError;

impl KvIdentityStore {
    pub(super) async fn scan_user_links(
        &self,
        user: Uuid,
    ) -> Result<Vec<(String, FrontendLink)>, IdentityError> {
        let links = Arc::new(Mutex::new(Vec::new()));
        let selected = Arc::clone(&links);
        let expected_namespace = self.kv.namespace().to_owned();
        self.kv
            .visit_entries_with_prefix(
                "link/",
                Box::new(move |namespace, key, value| {
                    // Only the waiting caller and this callback own the result.
                    // A dropped caller cannot consume further decoded rows.
                    if Arc::strong_count(&selected) == 1 {
                        return Err(StorageError::Internal(
                            "identity link scan caller was dropped".to_owned(),
                        ));
                    }
                    if namespace != expected_namespace || !key.starts_with("link/") {
                        return Err(StorageError::Internal(
                            "identity link scan escaped its namespace or prefix".to_owned(),
                        ));
                    }
                    // Validate every row, including foreign users' links. Only the
                    // requested result survives the callback; raw values are borrowed.
                    let link: FrontendLink = serde_json::from_slice(value).map_err(|error| {
                        StorageError::Serialization(format!(
                            "invalid stored frontend link {key}: {error}"
                        ))
                    })?;
                    if link.astrid_user_id == user {
                        selected.lock().push((key.to_owned(), link));
                    }
                    Ok(())
                }),
            )
            .await
            .map_err(|error| IdentityError::Storage(error.to_string()))?;
        let mut links = Arc::into_inner(links)
            .ok_or_else(|| {
                IdentityError::Storage(
                    "identity link visitor outlived its completed scan".to_owned(),
                )
            })?
            .into_inner();
        // Preserve native lexical results even when the checkpoint and overlay
        // were visited independently. Unrelated keys never enter this vector.
        links.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        Ok(links)
    }
}
