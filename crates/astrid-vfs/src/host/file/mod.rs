//! Native descriptor ownership and positional operations.

use std::io::{self, Write};
use std::sync::Arc;

use astrid_capabilities::DirHandle;
use async_trait::async_trait;
use tokio::sync::OwnedSemaphorePermit;

use crate::file::{FileLength, FileOffset, FileOperationGuard, OpenMode, ReadLength, VfsFile};
use crate::{VfsError, VfsMetadata, VfsResult};

use super::{HostVfs, classify_io_error, make_relative};

struct NativeFile {
    state: Arc<FileState>,
}

struct FileState {
    file: std::fs::File,
    mode: OpenMode,
    #[cfg(windows)]
    operation: std::sync::Mutex<()>,
    // Every blocking operation retains this state until the actual operation
    // settles. Cancelling its waiter must not refund admission prematurely.
    _permit: OwnedSemaphorePermit,
}

pub(super) async fn open(
    vfs: &HostVfs,
    handle: &DirHandle,
    path: &str,
    mode: OpenMode,
    guard: FileOperationGuard,
) -> VfsResult<Arc<dyn VfsFile>> {
    // Refuse before any create/truncate effect when this native provider has
    // no positional backend. Standalone providers implement VfsFile directly.
    if !cfg!(any(unix, windows)) {
        return Err(VfsError::NotSupported("native positional files".to_owned()));
    }
    let dir = vfs.get_dir(handle).await?;
    let path = make_relative(path).to_owned();
    let permit = Arc::clone(&vfs.fd_semaphore)
        .try_acquire_owned()
        .map_err(|_| VfsError::PermissionDenied("Too many open files".to_owned()))?;
    join(tokio::task::spawn_blocking(move || {
        let _authority = guard;
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(matches!(mode, OpenMode::Read | OpenMode::ReadWrite))
            .write(!matches!(mode, OpenMode::Read))
            .create(matches!(mode, OpenMode::Write | OpenMode::Append))
            .append(matches!(mode, OpenMode::Append))
            .truncate(matches!(mode, OpenMode::Write));
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            // A guest-created FIFO must not leave an uncancellable open
            // waiting for a peer. Never acquire a controlling terminal either.
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
        }
        let file = dir.open_with(&path, &options).map_err(classify_io_error)?;
        if !file.metadata().map_err(classify_io_error)?.is_file() {
            return Err(VfsError::NotSupported("regular files only".to_owned()));
        }
        Ok(Arc::new(NativeFile {
            state: Arc::new(FileState {
                file: file.into_std(),
                mode,
                #[cfg(windows)]
                operation: std::sync::Mutex::new(()),
                _permit: permit,
            }),
        }) as Arc<dyn VfsFile>)
    }))
    .await
}

async fn join<T>(job: tokio::task::JoinHandle<VfsResult<T>>) -> VfsResult<T> {
    job.await
        .map_err(|error| VfsError::Io(io::Error::other(error)))?
}

impl NativeFile {
    async fn run<T: Send + 'static>(
        &self,
        guard: FileOperationGuard,
        operation: impl FnOnce(&FileState) -> VfsResult<T> + Send + 'static,
    ) -> VfsResult<T> {
        let state = Arc::clone(&self.state);
        join(tokio::task::spawn_blocking(move || {
            let _authority = guard;
            // Windows seek_read/seek_write affect the descriptor cursor.
            // Serialize them with append on this owned descriptor.
            #[cfg(windows)]
            let _operation = state
                .operation
                .lock()
                .map_err(|_| io::Error::other("file operation lock poisoned"))?;
            operation(&state)
        }))
        .await
    }
}

impl FileState {
    fn require_read(&self) -> VfsResult<()> {
        if matches!(self.mode, OpenMode::Read | OpenMode::ReadWrite) {
            Ok(())
        } else {
            Err(VfsError::PermissionDenied("file is write-only".to_owned()))
        }
    }

    fn require_write(&self) -> VfsResult<()> {
        if self.mode == OpenMode::Read {
            Err(VfsError::PermissionDenied("file is read-only".to_owned()))
        } else {
            Ok(())
        }
    }
}

fn require_range(offset: FileOffset, length: u64) -> VfsResult<()> {
    offset
        .bytes()
        .checked_add(length)
        .map(|_| ())
        .ok_or_else(|| VfsError::Io(io::Error::from(io::ErrorKind::InvalidInput)))
}

#[async_trait]
impl VfsFile for NativeFile {
    async fn read_at(
        &self,
        offset: FileOffset,
        length: ReadLength,
        guard: FileOperationGuard,
    ) -> VfsResult<Vec<u8>> {
        self.state.require_read()?;
        self.run(guard, move |state| {
            require_range(offset, u64::from(length.bytes()))?;
            let count = usize::try_from(length.bytes()).map_err(io::Error::other)?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(count).map_err(io::Error::other)?;
            bytes.resize(count, 0);
            let read = read_at(&state.file, &mut bytes, offset.bytes())?;
            bytes.truncate(read);
            Ok(bytes)
        })
        .await
    }

    async fn write_at(
        &self,
        offset: FileOffset,
        bytes: &[u8],
        guard: FileOperationGuard,
    ) -> VfsResult<usize> {
        self.state.require_write()?;
        if self.state.mode != OpenMode::Append {
            require_range(offset, bytes.len() as u64)?;
        }
        let bytes = bytes.to_vec();
        self.run(guard, move |state| {
            if state.mode == OpenMode::Append {
                // Use the native append offset selection across distinct opens;
                // return the actual count, including short writes.
                let mut file = &state.file;
                file.write(&bytes).map_err(classify_io_error)
            } else {
                write_at(&state.file, &bytes, offset.bytes()).map_err(classify_io_error)
            }
        })
        .await
    }

    async fn sync_data(&self, guard: FileOperationGuard) -> VfsResult<()> {
        self.run(guard, |state| {
            state.file.sync_data().map_err(classify_io_error)
        })
        .await
    }

    async fn sync_all(&self, guard: FileOperationGuard) -> VfsResult<()> {
        self.run(guard, |state| {
            state.file.sync_all().map_err(classify_io_error)
        })
        .await
    }

    async fn stat(&self, guard: FileOperationGuard) -> VfsResult<VfsMetadata> {
        self.run(guard, |state| {
            let meta = state.file.metadata().map_err(classify_io_error)?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_secs());
            Ok(VfsMetadata {
                is_dir: meta.is_dir(),
                is_file: meta.is_file(),
                size: meta.len(),
                mtime,
            })
        })
        .await
    }

    async fn set_len(&self, length: FileLength, guard: FileOperationGuard) -> VfsResult<()> {
        self.run(guard, move |state| {
            state.require_write()?;
            state
                .file
                .set_len(length.bytes())
                .map_err(classify_io_error)
        })
        .await
    }
}

std::cfg_select! {
    unix => {
        fn read_at(file: &std::fs::File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
            std::os::unix::fs::FileExt::read_at(file, bytes, offset)
        }
        fn write_at(file: &std::fs::File, bytes: &[u8], offset: u64) -> io::Result<usize> {
            std::os::unix::fs::FileExt::write_at(file, bytes, offset)
        }
    }
    windows => {
        fn read_at(file: &std::fs::File, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
            std::os::windows::fs::FileExt::seek_read(file, bytes, offset)
        }
        fn write_at(file: &std::fs::File, bytes: &[u8], offset: u64) -> io::Result<usize> {
            std::os::windows::fs::FileExt::seek_write(file, bytes, offset)
        }
    }
    _ => {
        fn read_at(_: &std::fs::File, _: &mut [u8], _: u64) -> io::Result<usize> {
            Err(io::ErrorKind::Unsupported.into())
        }
        fn write_at(_: &std::fs::File, _: &[u8], _: u64) -> io::Result<usize> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}

#[cfg(test)]
mod tests;
