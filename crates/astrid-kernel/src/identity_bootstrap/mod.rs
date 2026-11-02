//! Bind the kernel identity store over `system:identity`.
//!
//! Native boot opens a runtime principal store first; assemble already
//! populated the shared [`PrincipalDirectory`] from every durable `user/`
//! record. Portable [`crate::Kernel::with_resources`] injects KV without that
//! store and must still load and validate once. Wasm has no runtime principal
//! store.

use std::io;
use std::sync::Arc;

use astrid_storage::{IdentityStore, KvIdentityStore, KvStore, PrincipalDirectory, ScopedKvStore};

#[cfg(not(target_family = "wasm"))]
use astrid_storage::RuntimePrincipalStore;

/// Construct the kernel identity store and load durable identities when the
/// caller did not already assemble a runtime principal store.
///
/// `principal_store = Some` is the native ownership token that assemble already
/// ran [`IdentityStore::load_principal_directory`] on this shared directory.
/// Skipping that second walk does not skip `identity.validate()` on the first
/// load, nor identity construction used by later CLI-root bootstrap.
pub(crate) async fn bind_identity_store(
    kv: &Arc<dyn KvStore>,
    principal_directory: PrincipalDirectory,
    #[cfg(not(target_family = "wasm"))] principal_store: Option<&RuntimePrincipalStore>,
) -> io::Result<Arc<dyn IdentityStore>> {
    let identity_kv = ScopedKvStore::new(Arc::clone(kv), "system:identity")
        .map_err(|error| io::Error::other(format!("Failed to create identity KV: {error}")))?;
    let identity_store: Arc<dyn IdentityStore> = Arc::new(
        KvIdentityStore::with_principal_directory(identity_kv, principal_directory),
    );
    if should_load_principal_directory(
        #[cfg(not(target_family = "wasm"))]
        principal_store,
    ) {
        identity_store
            .load_principal_directory()
            .await
            .map_err(|error| {
                io::Error::other(format!(
                    "Failed to load durable principal identities: {error}"
                ))
            })?;
    }
    Ok(identity_store)
}

fn should_load_principal_directory(
    #[cfg(not(target_family = "wasm"))] principal_store: Option<&RuntimePrincipalStore>,
) -> bool {
    #[cfg(not(target_family = "wasm"))]
    {
        principal_store.is_none()
    }
    #[cfg(target_family = "wasm")]
    {
        true
    }
}

#[cfg(test)]
mod tests;
