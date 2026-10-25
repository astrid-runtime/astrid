//! Distinguish ordinary home admission from authenticated retirement recovery.

use std::io;

use astrid_core::dirs::AstridHome;

pub(crate) enum HomeAdmission {
    Ordinary,
    FreshRetry,
    Unsentinelled,
}

impl HomeAdmission {
    pub(crate) async fn open_store(
        self,
        home: &AstridHome,
        quota: std::sync::Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>>,
        principals: astrid_storage::PrincipalDirectory,
    ) -> Result<
        (
            astrid_storage::RuntimePrincipalStore,
            Option<crate::legacy_migration_barrier::LayoutOrigin>,
        ),
        astrid_storage::StorageError,
    > {
        use crate::legacy_migration_barrier::LayoutOrigin;
        match self {
            Self::Unsentinelled => {
                let (store, origin) =
                    astrid_storage::open_runtime_principal_store_from_unsentinelled_projection(
                        home, quota, principals,
                    )
                    .await?;
                let origin = match origin {
                    astrid_storage::RecoveredProjectionOrigin::FreshAdmission => {
                        LayoutOrigin::Fresh
                    },
                    astrid_storage::RecoveredProjectionOrigin::Existing => {
                        crate::legacy_migration_barrier::reject_incomplete_layout_v2(home)
                            .map_err(|error| {
                                astrid_storage::StorageError::Connection(error.to_string())
                            })?;
                        LayoutOrigin::ExistingV2
                    },
                };
                Ok((store, Some(origin)))
            },
            Self::FreshRetry => {
                if !matches!(
                    std::fs::symlink_metadata(crate::legacy_migration_barrier::ledger_path(home)),
                    Err(error) if error.kind() == io::ErrorKind::NotFound
                ) {
                    return Err(astrid_storage::StorageError::Connection(
                        "fresh admission ledger appeared before singleton acquisition".to_owned(),
                    ));
                }
                astrid_storage::open_runtime_principal_store_from_fresh_admission(
                    home, quota, principals,
                )
                .await
                .map(|store| (store, Some(LayoutOrigin::Fresh)))
            },
            Self::Ordinary => {
                astrid_storage::open_runtime_principal_store_with_directory(home, quota, principals)
                    .await
                    .map(|store| (store, None))
            },
        }
    }
}

#[cfg(test)]
mod tests;

/// A missing ledger is recoverable only after storage proves that this is an
/// abandoned bootstrap, never merely because the volume was originally fresh.
pub(crate) fn validate_boot(home: &AstridHome) -> io::Result<HomeAdmission> {
    match crate::legacy_migration_barrier::reject_incomplete_layout_v2(home) {
        Ok(()) => {
            if home.layout_version()?.is_none() && canonical_volume_present(home)? {
                home.validate_volume_recovery_candidate()?;
                Ok(HomeAdmission::Unsentinelled)
            } else {
                home.ensure()?;
                Ok(HomeAdmission::Ordinary)
            }
        },
        Err(error) => {
            let ledger = crate::legacy_migration_barrier::ledger_path(home);
            let ledger_missing = match std::fs::symlink_metadata(ledger) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                Ok(_) => false,
                Err(error) => return Err(error),
            };
            if !ledger_missing || !canonical_volume_present(home)? {
                return Err(error);
            }
            home.validate_fresh_admission_candidate()?;
            Ok(HomeAdmission::FreshRetry)
        },
    }
}

fn canonical_volume_present(home: &AstridHome) -> io::Result<bool> {
    match std::fs::symlink_metadata(home.storage_volume_path()) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical storage volume is redirected or not a regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
