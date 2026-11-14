//! Windows rooted projection via captured `TrustedPathGuard` sessions.

use std::io::{self, Read, Write};

use super::RelativePath;
use crate::platform_fs::StagingScope;
use crate::platform_fs::windows::{ProjectionInspection as NativeInspection, ProjectionRoot};
pub(super) use crate::platform_fs::windows::{
    ProjectionPublication as FileIdentity, ProjectionReplacement as Replacement,
};

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

    pub(super) fn capture_replacement<'a>(
        &'a self,
        relative: &RelativePath,
        sink: &mut dyn Write,
    ) -> io::Result<(Replacement<'a>, Option<u64>)> {
        self.inner.capture_replacement(&relative.0, sink)
    }
    pub(super) fn rollback_publication(
        &self,
        relative: &RelativePath,
        identity: FileIdentity,
        prior: Option<(&mut dyn Read, u64)>,
    ) -> io::Result<()> {
        self.inner
            .rollback_publication(&relative.0, identity, prior)
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

pub(super) struct AppendRoot {
    inner: crate::platform_fs::windows::ProjectionAppendRoot,
}

impl AppendRoot {
    pub(super) fn open_private_append(&self, relative: &RelativePath) -> io::Result<std::fs::File> {
        self.inner.open_private_append(&relative.0)
    }
}

pub(super) struct Inspection {
    inner: NativeInspection,
}

impl Inspection {
    pub(super) fn capture_append_root(&self) -> io::Result<AppendRoot> {
        Ok(AppendRoot {
            inner: self.inner.capture_append_root()?,
        })
    }

    pub(super) fn try_open(root: &std::path::Path) -> io::Result<Self> {
        Ok(Self {
            inner: NativeInspection::try_open(root)?,
        })
    }

    pub(super) fn open_writer(&self) -> io::Result<Projection> {
        Ok(Projection {
            inner: self.inner.open_writer()?,
        })
    }

    pub(super) fn matches_private_directory(&self, relative: &RelativePath) -> io::Result<bool> {
        self.inner.matches_private_directory(&relative.0)
    }

    pub(super) fn matches_private_file_from(
        &self,
        relative: &RelativePath,
        length: u64,
        expected: &mut dyn Read,
    ) -> io::Result<bool> {
        self.inner
            .matches_private_file_from(&relative.0, length, expected)
    }

    pub(super) fn confirm_absolute_root(&self) -> io::Result<()> {
        self.inner.confirm_absolute_root()
    }
}
