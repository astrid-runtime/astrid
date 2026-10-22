//! Explicit instance-local dependencies for callback-only/provider-fault tests.

use std::{path::PathBuf, sync::OnceLock};

use astrid_core::storage_provider::StorageMountId;

#[derive(Default)]
pub(crate) struct CallbackTestResolver {
    dependency: OnceLock<Result<tempfile::TempDir, String>>,
}

impl CallbackTestResolver {
    /// Own real private sockets without pretending to register an `FSKit` extension.
    pub(crate) fn use_private_callbacks(&self) {
        let directory = tempfile::Builder::new()
            .prefix("astrid-cb-")
            .tempdir_in("/private/tmp")
            .expect("private callback fixture directory");
        astrid_core::platform_fs::ensure_private_directory(directory.path())
            .expect("callback fixture directory is private");
        assert!(self.dependency.set(Ok(directory)).is_ok());
    }

    /// Real-provider lanes must still resolve the registered extension container.
    pub(crate) fn use_callbacks_for_controlled_provider(&self, native_lane: bool) {
        if !native_lane {
            self.use_private_callbacks();
        }
    }

    pub(super) fn refuse_for_test(&self) {
        assert!(
            self.dependency
                .set(Err(
                    "FSKIT_EXTENSION_UNAVAILABLE: controlled missing container".to_owned()
                ))
                .is_ok()
        );
    }

    pub(super) fn resolve(&self, mount_id: StorageMountId) -> Option<Result<PathBuf, String>> {
        self.dependency.get().map(|dependency| {
            dependency
                .as_ref()
                .map(|directory| directory.path().join(mount_id.to_string()))
                .map_err(Clone::clone)
        })
    }
}
