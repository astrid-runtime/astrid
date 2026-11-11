//! Windows rooted projection via captured `TrustedPathGuard` sessions.

use std::io::{self, Read, Write};

use super::RelativePath;
use crate::platform_fs::StagingScope;
use crate::platform_fs::windows::{ProjectionInspection as NativeInspection, ProjectionRoot};

pub(super) struct Projection {
    inner: ProjectionRoot,
}

impl Projection {
    pub(super) fn open(root: &std::path::Path) -> io::Result<Self> {
        Ok(Self {
            inner: ProjectionRoot::open_writer(root, None)?,
        })
    }

    pub(super) fn open_with_staging(
        root: &std::path::Path,
        scope: StagingScope,
    ) -> io::Result<Self> {
        Ok(Self {
            inner: ProjectionRoot::open_writer(root, Some(scope))?,
        })
    }

    pub(super) fn snapshot_to(
        &self,
        relative: &RelativePath,
        output: &mut dyn Write,
    ) -> io::Result<Option<u64>> {
        self.inner.snapshot_to(&relative.0, output)
    }

    pub(super) fn write(&self, relative: &RelativePath, bytes: &[u8]) -> io::Result<()> {
        self.inner.write(&relative.0, bytes)
    }

    pub(super) fn write_from(
        &self,
        relative: &RelativePath,
        reader: &mut dyn Read,
        exact_len: u64,
    ) -> io::Result<()> {
        self.inner.write_from(&relative.0, reader, exact_len)
    }

    pub(super) fn remove(&self, relative: &RelativePath) -> io::Result<()> {
        self.inner.remove(&relative.0)
    }

    pub(super) fn remove_staging(
        &self,
        relative: &RelativePath,
        scope: StagingScope,
    ) -> io::Result<()> {
        self.inner.remove_staging(&relative.0, scope)
    }

    pub(super) fn remove_authorized_private_leaf(&self, relative: &RelativePath) -> io::Result<()> {
        self.inner.remove_authorized_private_leaf(&relative.0)
    }

    pub(super) fn ensure_directory(&self, relative: &RelativePath) -> io::Result<()> {
        self.inner.ensure_directory(&relative.0)
    }

    pub(super) fn sync(&self) -> io::Result<()> {
        self.inner.sync()
    }
}

pub(super) struct Inspection {
    inner: NativeInspection,
}

impl Inspection {
    pub(super) fn try_open(root: &std::path::Path) -> io::Result<Self> {
        Ok(Self {
            inner: NativeInspection::try_open(root)?,
        })
    }

    pub(super) fn matches_private_directory(&self, relative: &RelativePath) -> io::Result<bool> {
        self.inner.matches_private_directory(&relative.0)
    }

    pub(super) fn matches_private_file(
        &self,
        relative: &RelativePath,
        expected: &[u8],
    ) -> io::Result<bool> {
        self.inner.matches_private_file(&relative.0, expected)
    }

    pub(super) fn confirm_absolute_root(&self) -> io::Result<()> {
        self.inner.confirm_absolute_root()
    }
}
