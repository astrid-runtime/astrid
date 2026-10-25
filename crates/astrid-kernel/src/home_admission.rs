//! Distinguish ordinary home admission from authenticated retirement recovery.

use std::io;

use astrid_core::dirs::AstridHome;

pub(crate) enum HomeAdmission {
    Ordinary,
    Retiring,
}

impl HomeAdmission {
    pub(crate) async fn open_store(
        self,
        home: &AstridHome,
        quota: std::sync::Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>>,
        principals: astrid_storage::PrincipalDirectory,
    ) -> Result<astrid_storage::RuntimePrincipalStore, astrid_storage::StorageError> {
        match self {
            Self::Ordinary => {
                astrid_storage::open_runtime_principal_store_with_directory(home, quota, principals)
                    .await
            },
            Self::Retiring => {
                let store = astrid_storage::open_runtime_principal_store_from_retiring_projection(
                    home, quota, principals,
                )
                .await?;
                // The sentinel was absent when boot captured its origin.
                // Restoring existing v2 authority must not let a missing
                // migration ledger initialize as a fresh home afterwards.
                crate::legacy_migration_barrier::reject_incomplete_layout_v2(home)
                    .map_err(|error| astrid_storage::StorageError::Connection(error.to_string()))?;
                Ok(store)
            },
        }
    }
}

pub(crate) fn validate(home: &AstridHome) -> io::Result<HomeAdmission> {
    match home.ensure() {
        Ok(()) => Ok(HomeAdmission::Ordinary),
        Err(admission_error) => {
            home.validate_volume_recovery_candidate().map_err(|recovery_error| {
                io::Error::other(format!("Failed to validate Astrid home layout: {admission_error}; volume recovery preflight: {recovery_error}"))
            })?;
            // Structure permits only opening media. Storage must verify the
            // same-root RETIRING inventory before consuming any host authority.
            Ok(HomeAdmission::Retiring)
        },
    }
}

#[cfg(test)]
mod tests;
