//! Private, uniquely owned native fixtures, outside any Astrid daemon home.

use std::io;
use std::path::{Path, PathBuf};

pub(super) struct TestDirectory(PathBuf);

impl TestDirectory {
    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        // The constructor owns this exclusive random name. Never clean up a
        // shared parent, default runtime home, or a caller-supplied path.
        if let Err(error) = std::fs::remove_dir_all(&self.0)
            && error.kind() != io::ErrorKind::NotFound
        {
            eprintln!("remove owned audit fixture {}: {error}", self.0.display());
        }
    }
}

pub(super) fn temporary() -> io::Result<TestDirectory> {
    #[cfg(windows)]
    {
        let base = directories::BaseDirs::new()
            .ok_or_else(|| io::Error::other("LocalAppData is unavailable"))?;
        let path = base
            .data_local_dir()
            .join(format!("astrid-audit-test-{}", uuid::Uuid::new_v4()));
        astrid_core::platform_fs::create_private_directory(&path)?;
        Ok(TestDirectory(path))
    }
    #[cfg(not(windows))]
    {
        Ok(TestDirectory(tempfile::tempdir()?.keep()))
    }
}
