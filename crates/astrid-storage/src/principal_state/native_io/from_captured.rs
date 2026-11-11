//! Construct a private directory capability from an already-owned directory file.

use super::PrivateDirectory;
#[cfg(windows)]
use crate::StorageResult;
#[cfg(windows)]
use cap_std::fs::Dir;
#[cfg(windows)]
use std::fs::File;
#[cfg(windows)]
use std::path::PathBuf;

impl PrivateDirectory {
    pub(super) fn confirm_path_binding(&self) -> crate::StorageResult<()> {
        #[cfg(windows)]
        let identity = {
            use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
                FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            // cap-std's ambient directory opens deny delete sharing. That
            // conflicts with a captured DELETE owner even for an identity
            // check. This attribute-only, no-follow observation grants no
            // traversal or mutation authority and closes before we continue.
            let file = std::fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&self.path)
                .map_err(|error| super::connection(format!("confirm captured path: {error}")))?;
            let metadata = file
                .metadata()
                .map_err(|error| super::connection(format!("inspect captured path: {error}")))?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(super::connection(
                    "captured path became a redirect".to_owned(),
                ));
            }
            super::private_directory_file_identity(&file)?
        };
        #[cfg(not(windows))]
        let identity = Self::open(&self.path)?.identity;
        if identity != self.identity {
            return Err(super::connection(
                "captured retirement path changed during validation".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    pub(in crate::principal_state) fn raw_identity(&self) -> (u64, u64) {
        (self.identity.volume.0, self.identity.directory.0)
    }

    /// Wrap a directory file that already names the captured object.
    ///
    /// This does not reopen a path and does not restore pathname authority if
    /// ancestors later move. The file is consumed as the capability handle.
    #[cfg(windows)]
    pub(in crate::principal_state) fn from_std_directory_file(
        file: File,
        path: PathBuf,
    ) -> StorageResult<Self> {
        Self::from_std_directory_file_with_flush(file, path, None)
    }

    /// Construct a captured capability with an explicit paired flush authority.
    ///
    /// Ordinary readonly `from_std_directory_file` keeps `flush = None` so
    /// `sync` fails closed without ambient reopen. Mutating callers such as
    /// `empty_moved_tree` supply a flusher from
    /// `CapturedDirectory::open_paired_flush` (relative parent+name, 128-bit match).
    #[cfg(windows)]
    pub(in crate::principal_state) fn from_std_directory_file_with_flush(
        file: File,
        path: PathBuf,
        flush: Option<astrid_core::platform_fs::directory_capability::DirectoryFlushCapability>,
    ) -> StorageResult<Self> {
        let identity = super::private_directory_file_identity(&file)?;
        if let Some(capability) = flush.as_ref() {
            let flush_identity = super::private_directory_file_identity(capability.file())?;
            if flush_identity != identity {
                return Err(super::connection(
                    "captured flush handle does not name the same directory".to_owned(),
                ));
            }
        }
        let directory = Dir::from_std_file(file);
        Ok(Self {
            directory,
            path,
            identity,
            flush,
        })
    }
}
