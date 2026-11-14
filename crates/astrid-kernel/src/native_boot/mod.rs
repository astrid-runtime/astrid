//! Singleton-owned native storage acquisition with authenticated retry.

use std::{io, sync::Arc};

use astrid_core::dirs::AstridHome;
use astrid_storage::{KvQuotaResolver, PrincipalDirectory, RuntimePrincipalStore, StateOwner};

use crate::legacy_migration_barrier::{self, StartupLayout};

/// Home-bound singleton custody retained through recovery and assembly.
pub(crate) struct NativeBootAdmission {
    home: AstridHome,
    layout: StartupLayout,
    singleton_lock: std::fs::File,
}

impl NativeBootAdmission {
    pub(crate) fn acquire(home: &AstridHome) -> io::Result<Self> {
        let layout = legacy_migration_barrier::classify_startup(home)?;
        prepare_home(home, layout)?;
        let singleton_lock = crate::socket::acquire_boot_singleton_lock(home)?;
        if matches!(layout, StartupLayout::Ordinary(_)) {
            prepare_ordinary_storage(home)?;
        }
        Ok(Self {
            home: home.clone(),
            layout,
            singleton_lock,
        })
    }

    pub(crate) async fn open(
        self,
        quota: Arc<dyn KvQuotaResolver<StateOwner>>,
        principals: PrincipalDirectory,
    ) -> io::Result<(
        RuntimePrincipalStore,
        std::fs::File,
        legacy_migration_barrier::LayoutOrigin,
    )> {
        let store = open_state(&self.home, quota, principals, self.layout).await?;
        Ok((store, self.singleton_lock, self.layout.origin()))
    }
}

fn prepare_home(home: &AstridHome, layout: StartupLayout) -> io::Result<()> {
    home.validate_run_dir()?;
    match layout {
        StartupLayout::Ordinary(_) => home.ensure(),
        StartupLayout::RecoverRetiring => {
            // Only singleton namespace acquisition may precede the content
            // guard. Existing run paths must not redirect that acquisition.
            if home.run_dir().try_exists()? {
                astrid_core::platform_fs::validate_private_directory(&home.run_dir())?;
                let lock = home.run_dir().join("system.lock");
                if lock.try_exists()? {
                    astrid_core::platform_fs::validate_private_file(&lock)?;
                }
            }
            Ok(())
        },
    }
}

fn prepare_ordinary_storage(home: &AstridHome) -> io::Result<()> {
    home.clear_runtime_principal_scratch()?;
    if home.layout_version()?.as_deref() == Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION) {
        let target = astrid_core::dirs::LayoutMigrationTarget::for_current_executable(
            astrid_storage::RUNTIME_STORE_FORMAT_ID,
        )?;
        home.begin_layout_v2_migration(&target)?;
    }
    Ok(())
}

async fn open_state(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
    principals: PrincipalDirectory,
    layout: StartupLayout,
) -> io::Result<RuntimePrincipalStore> {
    let store = match layout {
        StartupLayout::Ordinary(_) => {
            astrid_storage::open_runtime_principal_store_with_directory(home, quota, principals)
                .await
        },
        StartupLayout::RecoverRetiring => {
            astrid_storage::open_runtime_principal_store_recovering_projection(
                home,
                quota,
                principals,
                |view| legacy_migration_barrier::validate_recovery(home, view),
            )
            .await
        },
    }
    .map_err(|error| io::Error::other(format!("Failed to open principal store: {error}")))?;
    if layout == StartupLayout::RecoverRetiring {
        // The interrupted subset has now been restored from authenticated
        // volume authority. Ordinary validation remains the serving boundary.
        legacy_migration_barrier::reject_incomplete_layout_v2(home)?;
        home.ensure()?;
        prepare_ordinary_storage(home)?;
    }
    Ok(store)
}

#[cfg(test)]
mod tests;
