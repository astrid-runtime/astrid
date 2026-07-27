//! Test-only filesystem fixtures.

use std::path::{Path, PathBuf};

/// A temporary directory whose Windows path satisfies Astrid's private ACL
/// boundary instead of inheriting the shared system-temp permissions.
pub(crate) struct PrivateTempDir {
    path: PathBuf,
    #[cfg(not(windows))]
    _temporary: tempfile::TempDir,
}

impl PrivateTempDir {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(windows)]
impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn private_tempdir() -> PrivateTempDir {
    #[cfg(windows)]
    {
        let runtime_root = astrid_core::platform_fs::default_astrid_home_root()
            .expect("resolve Windows LocalAppData");
        let local_app_data = runtime_root
            .parent()
            .and_then(Path::parent)
            .expect("Astrid runtime root is below Windows LocalAppData");
        let path = local_app_data.join(format!("AstridTest-{}", uuid::Uuid::new_v4().simple()));
        astrid_core::platform_fs::ensure_private_directory(&path)
            .expect("create a private Windows test directory");
        PrivateTempDir { path }
    }

    #[cfg(not(windows))]
    {
        let temporary = tempfile::tempdir().expect("create test directory");
        PrivateTempDir {
            path: temporary.path().to_path_buf(),
            _temporary: temporary,
        }
    }
}
