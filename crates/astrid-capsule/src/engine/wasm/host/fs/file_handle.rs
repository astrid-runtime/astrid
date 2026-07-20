//! Resource-backed `astrid:fs` open-file operations.

use std::sync::Arc;

use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::fs::host::{
    ErrorCode, FileHandle, FileStat, HostFileHandle,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

use super::{WriteKind, audit_fs, gate_read, gate_write, map_vfs_err, to_file_stat};

const MAX_POSITIONAL_IO_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FileAccess {
    Read,
    Write,
    ReadWrite,
}

impl FileAccess {
    const fn readable(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    const fn writable(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

/// Host value stored behind the guest's opaque `file-handle` resource.
///
/// The slot retains the exact VFS capability and verified principal selected
/// at open time. Every later call still checks the live principal and gate;
/// retaining a guest resource across a pooled invocation cannot transfer its
/// authority to another principal.
pub(crate) struct OpenFileSlot {
    vfs: Arc<dyn astrid_vfs::Vfs>,
    handle: Option<astrid_capabilities::FileHandle>,
    access: FileAccess,
    physical_path: String,
    principal: astrid_core::PrincipalId,
    runtime_handle: tokio::runtime::Handle,
}

impl OpenFileSlot {
    pub(super) fn new(
        vfs: Arc<dyn astrid_vfs::Vfs>,
        handle: astrid_capabilities::FileHandle,
        access: FileAccess,
        physical_path: String,
        principal: astrid_core::PrincipalId,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            vfs,
            handle: Some(handle),
            access,
            physical_path,
            principal,
            runtime_handle,
        }
    }

    fn view(&self) -> Result<OpenFileView, ErrorCode> {
        Ok(OpenFileView {
            vfs: self.vfs.clone(),
            handle: self.handle.clone().ok_or(ErrorCode::Closed)?,
            access: self.access,
            physical_path: self.physical_path.clone(),
            principal: self.principal.clone(),
        })
    }

    fn take_handle(&mut self) -> Option<astrid_capabilities::FileHandle> {
        self.handle.take()
    }
}

impl Drop for OpenFileSlot {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        let vfs = self.vfs.clone();
        // Whole-table pool resets bypass the generated resource destructor.
        // Schedule close from the raw value's Drop so its VFS descriptor and
        // semaphore permit cannot leak. Runtime shutdown still drops the VFS
        // map itself as the final backstop.
        std::mem::drop(self.runtime_handle.spawn(async move {
            let _ = vfs.close(&handle).await;
        }));
    }
}

struct OpenFileView {
    vfs: Arc<dyn astrid_vfs::Vfs>,
    handle: astrid_capabilities::FileHandle,
    access: FileAccess,
    physical_path: String,
    principal: astrid_core::PrincipalId,
}

fn open_file_view(
    state: &mut HostState,
    resource: &Resource<FileHandle>,
) -> Result<OpenFileView, ErrorCode> {
    let slot = state
        .resource_table
        .get::<OpenFileSlot>(&Resource::new_borrow(resource.rep()))
        .map_err(|_| ErrorCode::Closed)?;
    let view = slot.view()?;
    if view.principal != state.effective_principal() {
        return Err(ErrorCode::Closed);
    }
    Ok(view)
}

fn map_handle_vfs_err(error: astrid_vfs::VfsError) -> ErrorCode {
    if matches!(error, astrid_vfs::VfsError::InvalidHandle) {
        ErrorCode::Closed
    } else {
        map_vfs_err(error)
    }
}

fn gate_metadata(state: &HostState, view: &OpenFileView) -> Result<(), ErrorCode> {
    if view.access.readable() {
        gate_read(state, std::path::Path::new(&view.physical_path))
    } else {
        gate_write(
            state,
            std::path::Path::new(&view.physical_path),
            WriteKind::Write,
        )
    }
}

impl HostFileHandle for HostState {
    fn read_at(
        &mut self,
        self_: Resource<FileHandle>,
        offset: u64,
        max_bytes: u32,
    ) -> Result<Vec<u8>, ErrorCode> {
        if max_bytes as usize > MAX_POSITIONAL_IO_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        let view = open_file_view(self, &self_)?;
        if !view.access.readable() {
            return Err(ErrorCode::Access);
        }
        gate_read(self, std::path::Path::new(&view.physical_path))?;
        let result = util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            view.vfs.read_at(&view.handle, offset, max_bytes),
        )
        .map_err(map_handle_vfs_err);
        audit_fs(
            self,
            "astrid:fs/file-handle.read-at",
            &view.physical_path,
            &result,
        );
        result
    }

    fn write_at(
        &mut self,
        self_: Resource<FileHandle>,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<u32, ErrorCode> {
        if data.len() > MAX_POSITIONAL_IO_BYTES || offset.checked_add(data.len() as u64).is_none() {
            return Err(ErrorCode::TooLarge);
        }
        let view = open_file_view(self, &self_)?;
        if !view.access.writable() {
            return Err(ErrorCode::Access);
        }
        gate_write(
            self,
            std::path::Path::new(&view.physical_path),
            WriteKind::Write,
        )?;
        let result = util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            view.vfs.write_at(&view.handle, offset, &data),
        )
        .map_err(map_handle_vfs_err);
        audit_fs(
            self,
            "astrid:fs/file-handle.write-at",
            &view.physical_path,
            &result,
        );
        result
    }

    fn sync_data(&mut self, self_: Resource<FileHandle>) -> Result<(), ErrorCode> {
        let view = open_file_view(self, &self_)?;
        gate_metadata(self, &view)?;
        let result = util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            view.vfs.sync_data(&view.handle),
        )
        .map_err(map_handle_vfs_err);
        audit_fs(
            self,
            "astrid:fs/file-handle.sync-data",
            &view.physical_path,
            &result,
        );
        result
    }

    fn sync_all(&mut self, self_: Resource<FileHandle>) -> Result<(), ErrorCode> {
        let view = open_file_view(self, &self_)?;
        gate_metadata(self, &view)?;
        let result = util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            view.vfs.sync_all(&view.handle),
        )
        .map_err(map_handle_vfs_err);
        audit_fs(
            self,
            "astrid:fs/file-handle.sync-all",
            &view.physical_path,
            &result,
        );
        result
    }

    fn stat(&mut self, self_: Resource<FileHandle>) -> Result<FileStat, ErrorCode> {
        let view = open_file_view(self, &self_)?;
        gate_metadata(self, &view)?;
        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                let metadata = view.vfs.file_stat(&view.handle).await?;
                let mode = view.vfs.file_mode(&view.handle).await?;
                Ok(to_file_stat(&metadata, mode))
            })
            .map_err(map_handle_vfs_err);
        audit_fs(
            self,
            "astrid:fs/file-handle.handle-stat",
            &view.physical_path,
            &result,
        );
        result
    }

    fn set_len(&mut self, self_: Resource<FileHandle>, size: u64) -> Result<(), ErrorCode> {
        let view = open_file_view(self, &self_)?;
        if !view.access.writable() {
            return Err(ErrorCode::Access);
        }
        gate_write(
            self,
            std::path::Path::new(&view.physical_path),
            WriteKind::Write,
        )?;
        let result = util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            view.vfs.set_len(&view.handle, size),
        )
        .map_err(map_handle_vfs_err);
        audit_fs(
            self,
            "astrid:fs/file-handle.set-len",
            &view.physical_path,
            &result,
        );
        result
    }

    fn drop(&mut self, rep: Resource<FileHandle>) -> wasmtime::Result<()> {
        self.file_handle_reps.remove(&rep.rep());
        if let Ok(mut slot) = self
            .resource_table
            .delete::<OpenFileSlot>(Resource::new_own(rep.rep()))
        {
            self.file_handle_count = self.file_handle_count.saturating_sub(1);
            if let Some(handle) = slot.take_handle() {
                let _ = util::bounded_block_on(
                    &self.runtime_handle,
                    &self.blocking_semaphore,
                    slot.vfs.close(&handle),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::engine::wasm::bindings::astrid::fs::host::{
        Host as HostFs, HostFileHandle, OpenMode,
    };
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    fn state_for(root: &std::path::Path) -> HostState {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        let root_handle = astrid_capabilities::DirHandle::new();
        state.workspace_root = root.to_path_buf();
        state.vfs = Arc::new(
            astrid_vfs::HostVfs::with_registered_dir(root_handle.clone(), root)
                .expect("registered test VFS"),
        );
        state.vfs_root_handle = root_handle;
        state
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_handle_supports_positional_io_resize_stat_and_drop() {
        let root = tempfile::tempdir().expect("root");
        let mut state = state_for(root.path());
        let owned = HostFs::fs_open(&mut state, "data.bin".to_string(), OpenMode::Write)
            .expect("create handle");
        let rep = owned.rep();

        assert_eq!(state.file_handle_count, 1);
        assert_eq!(
            HostFileHandle::write_at(&mut state, Resource::new_borrow(rep), 2, b"realm".to_vec(),)
                .expect("positional write"),
            5
        );
        HostFileHandle::set_len(&mut state, Resource::new_borrow(rep), 9).expect("extend file");
        HostFileHandle::sync_all(&mut state, Resource::new_borrow(rep)).expect("sync file");
        let stat = HostFileHandle::stat(&mut state, Resource::new_borrow(rep)).expect("fstat");
        assert_eq!(stat.size, 9);
        assert!(stat.mode & 0o600 != 0);
        assert!(matches!(
            HostFileHandle::read_at(&mut state, Resource::new_borrow(rep), 0, 16),
            Err(ErrorCode::Access)
        ));

        HostFileHandle::drop(&mut state, owned).expect("drop handle");
        assert_eq!(state.file_handle_count, 0);
        assert_eq!(
            std::fs::read(root.path().join("data.bin")).expect("host bytes"),
            b"\0\0realm\0\0"
        );

        let reader = HostFs::fs_open(&mut state, "data.bin".to_string(), OpenMode::Read)
            .expect("read handle");
        let bytes = HostFileHandle::read_at(&mut state, Resource::new_borrow(reader.rep()), 2, 5)
            .expect("positional read");
        assert_eq!(bytes, b"realm");
        HostFileHandle::drop(&mut state, reader).expect("drop reader");

        HostFs::fs_rename(
            &mut state,
            "data.bin".to_string(),
            "renamed.bin".to_string(),
        )
        .expect("rename within workspace");
        assert!(!root.path().join("data.bin").exists());
        assert!(root.path().join("renamed.bin").exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_handles_are_bounded_and_principal_affine() {
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("input"), b"x").expect("fixture");
        let mut state = state_for(root.path());
        let mut handles = Vec::new();
        for _ in 0..super::super::MAX_OPEN_FILE_HANDLES {
            handles.push(
                HostFs::fs_open(&mut state, "input".to_string(), OpenMode::Read)
                    .expect("handle under cap"),
            );
        }
        assert!(matches!(
            HostFs::fs_open(&mut state, "input".to_string(), OpenMode::Read),
            Err(ErrorCode::Quota)
        ));

        state.principal = astrid_core::PrincipalId::new("other").expect("principal");
        assert!(matches!(
            HostFileHandle::read_at(&mut state, Resource::new_borrow(handles[0].rep()), 0, 1,),
            Err(ErrorCode::Closed)
        ));

        for handle in handles {
            HostFileHandle::drop(&mut state, handle).expect("drop handle");
        }
        assert_eq!(state.file_handle_count, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn read_write_does_not_create_and_payload_limit_is_enforced() {
        let root = tempfile::tempdir().expect("root");
        let mut state = state_for(root.path());
        assert!(matches!(
            HostFs::fs_open(&mut state, "missing".to_string(), OpenMode::ReadWrite),
            Err(ErrorCode::NotFound)
        ));

        let writer =
            HostFs::fs_open(&mut state, "bounded".to_string(), OpenMode::Write).expect("writer");
        assert!(matches!(
            HostFileHandle::write_at(
                &mut state,
                Resource::new_borrow(writer.rep()),
                0,
                vec![0; MAX_POSITIONAL_IO_BYTES + 1],
            ),
            Err(ErrorCode::TooLarge)
        ));
        HostFileHandle::drop(&mut state, writer).expect("drop writer");
    }
}
