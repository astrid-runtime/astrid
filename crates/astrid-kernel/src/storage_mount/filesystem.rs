use super::*;

pub(super) trait CallbackFilesystem {
    fn stat(&self, path: &FilesystemPath) -> Result<FilesystemEntry, FilesystemError>;
    fn read_dir(&self, path: &FilesystemPath) -> Result<Vec<FilesystemEntry>, FilesystemError>;
    fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FilesystemError>;
    fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), FilesystemError>;
    fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError>;
    fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError>;
    fn rename(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
        replace: bool,
    ) -> Result<(), FilesystemError>;
    fn sync(&self) -> Result<(), FilesystemError>;
}

impl<P, E> CallbackFilesystem for AstridFilesystem<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: astrid_storage::engine::PrincipalProjectionEngine<P>,
{
    fn stat(&self, path: &FilesystemPath) -> Result<FilesystemEntry, FilesystemError> {
        AstridFilesystem::stat(self, path)
    }

    fn read_dir(&self, path: &FilesystemPath) -> Result<Vec<FilesystemEntry>, FilesystemError> {
        AstridFilesystem::read_dir(self, path)
    }

    fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FilesystemError> {
        AstridFilesystem::read(self, path, offset, length)
    }

    fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        AstridFilesystem::write(self, path, bytes)
    }

    fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        AstridFilesystem::create_dir(self, path)
    }

    fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        AstridFilesystem::remove(self, path)
    }

    fn rename(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
        replace: bool,
    ) -> Result<(), FilesystemError> {
        if replace {
            AstridFilesystem::rename_replacing(self, from, to)
        } else {
            AstridFilesystem::rename(self, from, to)
        }
    }

    fn sync(&self) -> Result<(), FilesystemError> {
        AstridFilesystem::sync(self)
    }
}

impl<P, E> CallbackFilesystem for astrid_storage::WorkspaceFilesystem<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: astrid_storage::engine::PrincipalProjectionEngine<P>,
{
    fn stat(&self, path: &FilesystemPath) -> Result<FilesystemEntry, FilesystemError> {
        self.stat(path).map_err(map_workspace_error)
    }

    fn read_dir(&self, path: &FilesystemPath) -> Result<Vec<FilesystemEntry>, FilesystemError> {
        self.read_dir(path).map_err(map_workspace_error)
    }

    fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FilesystemError> {
        self.read(path, offset, length).map_err(map_workspace_error)
    }

    fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        self.write(path, bytes).map_err(map_workspace_error)
    }

    fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.create_dir(path).map_err(map_workspace_error)
    }

    fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.remove(path).map_err(map_workspace_error)
    }

    fn rename(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
        replace: bool,
    ) -> Result<(), FilesystemError> {
        if replace {
            astrid_storage::WorkspaceFilesystem::rename_replacing(self, from, to)
                .map_err(map_workspace_error)
        } else {
            astrid_storage::WorkspaceFilesystem::rename(self, from, to).map_err(map_workspace_error)
        }
    }

    fn sync(&self) -> Result<(), FilesystemError> {
        astrid_storage::WorkspaceFilesystem::sync(self).map_err(map_workspace_error)
    }
}

impl<P, E> CallbackFilesystem for OwnerSubtreeFilesystem<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: astrid_storage::engine::PrincipalProjectionEngine<P>,
{
    fn stat(&self, path: &FilesystemPath) -> Result<FilesystemEntry, FilesystemError> {
        OwnerSubtreeFilesystem::stat(self, path)
    }

    fn read_dir(&self, path: &FilesystemPath) -> Result<Vec<FilesystemEntry>, FilesystemError> {
        OwnerSubtreeFilesystem::read_dir(self, path)
    }

    fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FilesystemError> {
        OwnerSubtreeFilesystem::read(self, path, offset, length)
    }

    fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        OwnerSubtreeFilesystem::write(self, path, bytes)
    }

    fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        OwnerSubtreeFilesystem::create_dir(self, path)
    }

    fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        OwnerSubtreeFilesystem::remove(self, path)
    }

    fn rename(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
        replace: bool,
    ) -> Result<(), FilesystemError> {
        if replace {
            OwnerSubtreeFilesystem::rename_replacing(self, from, to)
        } else {
            OwnerSubtreeFilesystem::rename(self, from, to)
        }
    }

    fn sync(&self) -> Result<(), FilesystemError> {
        OwnerSubtreeFilesystem::sync(self)
    }
}

/// Restrict an owner filesystem to one kernel-selected logical subtree.
/// Callback paths remain relative to the subtree root; the caller cannot
/// escape it by selecting a different prefix in an operation.
pub(super) struct PrefixedFilesystem<F> {
    pub(super) inner: F,
    pub(super) prefix: String,
}

impl<F> PrefixedFilesystem<F> {
    fn path(&self, path: &FilesystemPath) -> Result<FilesystemPath, FilesystemError> {
        let full = if path.as_str().is_empty() {
            self.prefix.clone()
        } else {
            format!("{}/{}", self.prefix, path.as_str())
        };
        FilesystemPath::new(full)
    }
}

impl<F: CallbackFilesystem> CallbackFilesystem for PrefixedFilesystem<F> {
    fn stat(&self, path: &FilesystemPath) -> Result<FilesystemEntry, FilesystemError> {
        self.inner.stat(&self.path(path)?)
    }

    fn read_dir(&self, path: &FilesystemPath) -> Result<Vec<FilesystemEntry>, FilesystemError> {
        self.inner.read_dir(&self.path(path)?)
    }

    fn read(
        &self,
        path: &FilesystemPath,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FilesystemError> {
        self.inner.read(&self.path(path)?, offset, length)
    }

    fn write(&self, path: &FilesystemPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        self.inner.write(&self.path(path)?, bytes)
    }

    fn create_dir(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.inner.create_dir(&self.path(path)?)
    }

    fn remove(&self, path: &FilesystemPath) -> Result<(), FilesystemError> {
        self.inner.remove(&self.path(path)?)
    }

    fn rename(
        &self,
        from: &FilesystemPath,
        to: &FilesystemPath,
        replace: bool,
    ) -> Result<(), FilesystemError> {
        self.inner
            .rename(&self.path(from)?, &self.path(to)?, replace)
    }

    fn sync(&self) -> Result<(), FilesystemError> {
        self.inner.sync()
    }
}

pub(super) fn execute_blocking(
    filesystem: &impl CallbackFilesystem,
    operation: StorageFilesystemOperationV1,
) -> Result<StorageFilesystemSuccessV1, FilesystemError> {
    match operation {
        StorageFilesystemOperationV1::Stat { path } => {
            let path = FilesystemPath::new(path)?;
            Ok(StorageFilesystemSuccessV1::Entry(entry(
                &filesystem.stat(&path)?,
            )))
        },
        StorageFilesystemOperationV1::ReadDirectory { path } => {
            let path = FilesystemPath::new(path)?;
            Ok(StorageFilesystemSuccessV1::Entries(
                filesystem.read_dir(&path)?.iter().map(entry).collect(),
            ))
        },
        StorageFilesystemOperationV1::Read {
            path,
            offset,
            length,
        } => {
            if length > STORAGE_FILESYSTEM_MAX_IO_BYTES {
                return Err(FilesystemError::InvalidPath(path));
            }
            let path = FilesystemPath::new(path)?;
            let stat = filesystem.stat(&path)?;
            let available = stat.logical_bytes().saturating_sub(offset);
            let length = length.min(available);
            Ok(StorageFilesystemSuccessV1::Data(
                filesystem.read(&path, offset, length)?,
            ))
        },
        StorageFilesystemOperationV1::Write { path, offset, data } => {
            write_range(filesystem, path, offset, &data)
        },
        StorageFilesystemOperationV1::SetLength { path, length } => {
            let path = FilesystemPath::new(path)?;
            let current_length = require_file(filesystem, &path)?;
            if current_length == length {
                return Ok(StorageFilesystemSuccessV1::Written(length));
            }
            let mut bytes = filesystem.read(&path, 0, current_length)?;
            let target = usize::try_from(length)
                .map_err(|_| FilesystemError::InvalidPath(path.as_str().to_owned()))?;
            bytes.resize(target, 0);
            filesystem.write(&path, &bytes)?;
            Ok(StorageFilesystemSuccessV1::Written(length))
        },
        StorageFilesystemOperationV1::Create { path, kind } => {
            let path = FilesystemPath::new(path)?;
            match kind {
                StorageFilesystemEntryKindV1::File => {
                    match filesystem.stat(&path) {
                        Ok(_) => return Err(FilesystemError::AlreadyExists(path)),
                        Err(FilesystemError::NotFound(_)) => {},
                        Err(error) => return Err(error),
                    }
                    filesystem.write(&path, &[])?;
                },
                StorageFilesystemEntryKindV1::Directory => filesystem.create_dir(&path)?,
            }
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Remove { path } => {
            filesystem.remove(&FilesystemPath::new(path)?)?;
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Rename { from, to, replace } => {
            let from = FilesystemPath::new(from)?;
            let to = FilesystemPath::new(to)?;
            filesystem.rename(&from, &to, replace)?;
            Ok(StorageFilesystemSuccessV1::Done)
        },
        StorageFilesystemOperationV1::Sync => {
            filesystem.sync()?;
            Ok(StorageFilesystemSuccessV1::Done)
        },
    }
}

fn write_range(
    filesystem: &impl CallbackFilesystem,
    path: String,
    offset: u64,
    data: &[u8],
) -> Result<StorageFilesystemSuccessV1, FilesystemError> {
    let data_length = u64::try_from(data.len()).unwrap_or(u64::MAX);
    if data_length > STORAGE_FILESYSTEM_MAX_IO_BYTES {
        return Err(FilesystemError::InvalidPath(path));
    }
    let path = FilesystemPath::new(path)?;
    let current_length = require_file(filesystem, &path)?;
    if data.is_empty() {
        return Ok(StorageFilesystemSuccessV1::Written(current_length));
    }
    let end_offset = offset
        .checked_add(data_length)
        .ok_or_else(|| FilesystemError::InvalidPath(path.as_str().to_owned()))?;
    let mut bytes = filesystem.read(&path, 0, current_length)?;
    let start = usize::try_from(offset)
        .map_err(|_| FilesystemError::InvalidPath(path.as_str().to_owned()))?;
    let end = start
        .checked_add(data.len())
        .ok_or_else(|| FilesystemError::InvalidPath(path.as_str().to_owned()))?;
    if end > bytes.len() {
        bytes.resize(end, 0);
    }
    bytes[start..end].copy_from_slice(data);
    filesystem.write(&path, &bytes)?;
    Ok(StorageFilesystemSuccessV1::Written(
        current_length.max(end_offset),
    ))
}

fn require_file(
    filesystem: &impl CallbackFilesystem,
    path: &FilesystemPath,
) -> Result<u64, FilesystemError> {
    let stat = filesystem.stat(path)?;
    if stat.kind() != FilesystemEntryKind::File {
        return Err(FilesystemError::IsDirectory(path.clone()));
    }
    Ok(stat.logical_bytes())
}

fn map_workspace_error(error: astrid_storage::WorkspaceBranchError) -> FilesystemError {
    match error {
        astrid_storage::WorkspaceBranchError::Filesystem(error) => error,
        other => FilesystemError::Staging(other.to_string()),
    }
}
