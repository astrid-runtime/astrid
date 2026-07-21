//! Principal-bound implementation of the `astrid:fs` open-file resource.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::fs::host::{
    ErrorCode, FileStat, HostFileHandle, OpenMode,
};
use crate::engine::wasm::host_state::HostState;
use crate::{HostAuditEvent, HostAuditOutcome};

use super::{WriteKind, audit_fs, gate_read, gate_write, map_vfs_err, resolve_path, resolve_vfs};

const MAX_OPEN_FILES: usize = 16;
const MAX_POSITIONAL_BYTES: usize = 1024 * 1024;

/// One capability-confined VFS file retained in the wasmtime resource table.
pub struct OpenFileHandle {
    vfs: Arc<dyn astrid_vfs::Vfs>,
    handle: Option<astrid_capabilities::FileHandle>,
    runtime: tokio::runtime::Handle,
    owner: astrid_core::PrincipalId,
    physical_path: String,
    readable: bool,
    writable: bool,
    append: bool,
    open_count: Arc<AtomicUsize>,
}

impl OpenFileHandle {
    fn handle(&self) -> Result<&astrid_capabilities::FileHandle, ErrorCode> {
        self.handle.as_ref().ok_or(ErrorCode::Closed)
    }
}

impl Drop for OpenFileHandle {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        self.open_count.fetch_sub(1, Ordering::AcqRel);
        let vfs = Arc::clone(&self.vfs);
        self.runtime.spawn(async move {
            let _ = vfs.close(&handle).await;
        });
    }
}

fn reserve_slot(counter: &AtomicUsize) -> Result<(), ErrorCode> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < MAX_OPEN_FILES).then_some(current + 1)
        })
        .map(|_| ())
        .map_err(|_| ErrorCode::Quota)
}

fn file_for_principal<'a>(
    state: &'a HostState,
    resource: &Resource<OpenFileHandle>,
    operation: &str,
) -> Result<&'a OpenFileHandle, ErrorCode> {
    let file = state
        .resource_table
        .get(resource)
        .map_err(|_| ErrorCode::Closed)?;
    if file.owner != state.effective_principal() {
        if let Some(sink) = state.audit_sink.as_ref() {
            let event = if matches!(operation, "read-at" | "stat") {
                HostAuditEvent::FileRead {
                    path: &file.physical_path,
                }
            } else {
                HostAuditEvent::FileWrite {
                    path: &file.physical_path,
                }
            };
            sink.record(
                &state.effective_principal(),
                event,
                HostAuditOutcome::Denied("open file belongs to another principal"),
            );
        }
        return Err(ErrorCode::CapabilityDenied);
    }
    Ok(file)
}

pub(super) fn open(
    state: &mut HostState,
    path: String,
    mode: OpenMode,
) -> Result<Resource<OpenFileHandle>, ErrorCode> {
    let resolved = resolve_path(state, &path).map_err(super::map_resolve_err)?;
    let (readable, writable, append, truncate, must_exist) = match mode {
        OpenMode::Read => (true, false, false, false, true),
        OpenMode::Write => (false, true, false, true, false),
        OpenMode::Append => (false, true, true, false, false),
        OpenMode::ReadWrite => (true, true, false, false, true),
    };
    if readable {
        gate_read(state, &resolved.physical)?;
    }
    if writable {
        gate_write(state, &resolved.physical, WriteKind::Write)?;
    }
    let vfs_path = resolve_vfs(state, &resolved).map_err(super::map_resolve_err)?;
    if must_exist {
        let exists = super::util::bounded_block_on(
            &state.runtime_handle,
            &state.blocking_semaphore,
            vfs_path.vfs.exists(
                &vfs_path.handle,
                vfs_path.relative.to_string_lossy().as_ref(),
            ),
        )
        .map_err(map_vfs_err)?;
        if !exists {
            return Err(ErrorCode::NotFound);
        }
    }

    reserve_slot(&state.open_file_count)?;
    let opened = super::util::bounded_block_on(
        &state.runtime_handle,
        &state.blocking_semaphore,
        vfs_path.vfs.open(
            &vfs_path.handle,
            vfs_path.relative.to_string_lossy().as_ref(),
            writable,
            truncate,
        ),
    );
    let handle = match opened {
        Ok(handle) => handle,
        Err(error) => {
            state.open_file_count.fetch_sub(1, Ordering::AcqRel);
            return Err(map_vfs_err(error));
        },
    };
    let physical_path = resolved.physical.to_string_lossy().into_owned();
    let resource = OpenFileHandle {
        vfs: vfs_path.vfs,
        handle: Some(handle),
        runtime: state.runtime_handle.clone(),
        owner: state.effective_principal(),
        physical_path: physical_path.clone(),
        readable,
        writable,
        append,
        open_count: Arc::clone(&state.open_file_count),
    };
    let result = state
        .resource_table
        .push(resource)
        .map_err(|error| ErrorCode::Unknown(error.to_string()));
    audit_fs(state, "astrid:fs/host.fs-open", &physical_path, &result);
    result
}

impl HostFileHandle for HostState {
    fn read_at(
        &mut self,
        self_: Resource<OpenFileHandle>,
        offset: u64,
        max_bytes: u32,
    ) -> Result<Vec<u8>, ErrorCode> {
        if usize::try_from(max_bytes).map_err(|_| ErrorCode::TooLarge)? > MAX_POSITIONAL_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        let file = file_for_principal(self, &self_, "read-at")?;
        if !file.readable {
            return Err(ErrorCode::CapabilityDenied);
        }
        let path = file.physical_path.clone();
        let result = super::util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            file.vfs.read_at(file.handle()?, offset, max_bytes),
        )
        .map_err(map_vfs_err);
        audit_fs(self, "astrid:fs/file-handle.read-at", &path, &result);
        result
    }

    fn write_at(
        &mut self,
        self_: Resource<OpenFileHandle>,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<u32, ErrorCode> {
        if data.len() > MAX_POSITIONAL_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        let file = file_for_principal(self, &self_, "write-at")?;
        if !file.writable {
            return Err(ErrorCode::CapabilityDenied);
        }
        let path = file.physical_path.clone();
        let offset = if file.append {
            super::util::bounded_block_on(
                &self.runtime_handle,
                &self.blocking_semaphore,
                file.vfs.file_stat(file.handle()?),
            )
            .map_err(map_vfs_err)?
            .size
        } else {
            offset
        };
        let result = super::util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            file.vfs.write_at(file.handle()?, offset, &data),
        )
        .map_err(map_vfs_err);
        audit_fs(self, "astrid:fs/file-handle.write-at", &path, &result);
        result
    }

    fn sync_data(&mut self, self_: Resource<OpenFileHandle>) -> Result<(), ErrorCode> {
        sync(self, &self_, true, "sync-data")
    }

    fn sync_all(&mut self, self_: Resource<OpenFileHandle>) -> Result<(), ErrorCode> {
        sync(self, &self_, false, "sync-all")
    }

    fn stat(&mut self, self_: Resource<OpenFileHandle>) -> Result<FileStat, ErrorCode> {
        let file = file_for_principal(self, &self_, "stat")?;
        let path = file.physical_path.clone();
        let result = super::util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            file.vfs.file_stat(file.handle()?),
        )
        .map(|metadata| super::to_file_stat(&metadata))
        .map_err(map_vfs_err);
        audit_fs(self, "astrid:fs/file-handle.stat", &path, &result);
        result
    }

    fn set_len(&mut self, self_: Resource<OpenFileHandle>, size: u64) -> Result<(), ErrorCode> {
        let file = file_for_principal(self, &self_, "set-len")?;
        if !file.writable {
            return Err(ErrorCode::CapabilityDenied);
        }
        let path = file.physical_path.clone();
        let result = super::util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            file.vfs.set_len(file.handle()?, size),
        )
        .map_err(map_vfs_err);
        audit_fs(self, "astrid:fs/file-handle.set-len", &path, &result);
        result
    }

    fn drop(&mut self, rep: Resource<OpenFileHandle>) -> wasmtime::Result<()> {
        let borrowed = Resource::new_borrow(rep.rep());
        if file_for_principal(self, &borrowed, "drop").is_err() {
            return Ok(());
        }
        let _ = self
            .resource_table
            .delete::<OpenFileHandle>(Resource::new_own(rep.rep()));
        Ok(())
    }
}

fn sync(
    state: &mut HostState,
    resource: &Resource<OpenFileHandle>,
    data_only: bool,
    operation: &str,
) -> Result<(), ErrorCode> {
    let file = file_for_principal(state, resource, operation)?;
    if !file.writable {
        return Err(ErrorCode::CapabilityDenied);
    }
    let path = file.physical_path.clone();
    let result = super::util::bounded_block_on(
        &state.runtime_handle,
        &state.blocking_semaphore,
        file.vfs.sync_file(file.handle()?, data_only),
    )
    .map_err(map_vfs_err);
    audit_fs(
        state,
        if data_only {
            "astrid:fs/file-handle.sync-data"
        } else {
            "astrid:fs/file-handle.sync-all"
        },
        &path,
        &result,
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    fn workspace_state(root: &std::path::Path) -> HostState {
        let root_handle = astrid_capabilities::DirHandle::new();
        let vfs =
            astrid_vfs::HostVfs::with_registered_dir(root_handle.clone(), root).expect("host VFS");
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state.workspace_root = root.to_path_buf();
        state.vfs = Arc::new(vfs);
        state.vfs_root_handle = root_handle;
        state
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_handles_are_principal_bound_and_support_the_frozen_contract() {
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("existing.txt"), b"abcdef").expect("fixture");
        let mut state = workspace_state(root.path());
        state.principal = astrid_core::PrincipalId::new("alice").expect("Alice principal");

        let handle = open(&mut state, "existing.txt".to_owned(), OpenMode::ReadWrite)
            .expect("open read-write");
        assert_eq!(state.open_file_count.load(Ordering::Acquire), 1);
        assert_eq!(
            <HostState as HostFileHandle>::read_at(
                &mut state,
                Resource::new_borrow(handle.rep()),
                1,
                3,
            )
            .expect("Alice reads"),
            b"bcd"
        );
        assert_eq!(
            <HostState as HostFileHandle>::write_at(
                &mut state,
                Resource::new_borrow(handle.rep()),
                2,
                b"XY".to_vec(),
            )
            .expect("Alice writes"),
            2
        );
        <HostState as HostFileHandle>::set_len(&mut state, Resource::new_borrow(handle.rep()), 5)
            .expect("Alice truncates");
        let stat =
            <HostState as HostFileHandle>::stat(&mut state, Resource::new_borrow(handle.rep()))
                .expect("Alice stats");
        assert_eq!(stat.size, 5);
        <HostState as HostFileHandle>::sync_all(&mut state, Resource::new_borrow(handle.rep()))
            .expect("Alice syncs");

        state.principal = astrid_core::PrincipalId::new("bob").expect("Bob principal");
        assert!(matches!(
            <HostState as HostFileHandle>::read_at(
                &mut state,
                Resource::new_borrow(handle.rep()),
                0,
                16,
            ),
            Err(ErrorCode::CapabilityDenied)
        ));
        <HostState as HostFileHandle>::drop(&mut state, Resource::new_own(handle.rep()))
            .expect("Bob's drop is ignored");
        assert_eq!(state.open_file_count.load(Ordering::Acquire), 1);

        state.principal = astrid_core::PrincipalId::new("alice").expect("Alice principal");
        assert_eq!(
            <HostState as HostFileHandle>::read_at(
                &mut state,
                Resource::new_borrow(handle.rep()),
                0,
                16,
            )
            .expect("Alice's handle remains live"),
            b"abXYe"
        );
        <HostState as HostFileHandle>::drop(&mut state, Resource::new_own(handle.rep()))
            .expect("Alice closes");
        assert_eq!(state.open_file_count.load(Ordering::Acquire), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_handle_quota_is_reclaimed_on_drop() {
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("existing.txt"), b"data").expect("fixture");
        let mut state = workspace_state(root.path());
        let mut handles = Vec::new();
        for _ in 0..MAX_OPEN_FILES {
            handles.push(
                open(&mut state, "existing.txt".to_owned(), OpenMode::Read).expect("within quota"),
            );
        }
        assert!(matches!(
            open(&mut state, "existing.txt".to_owned(), OpenMode::Read),
            Err(ErrorCode::Quota)
        ));

        for handle in handles {
            <HostState as HostFileHandle>::drop(&mut state, Resource::new_own(handle.rep()))
                .expect("close");
        }
        assert_eq!(state.open_file_count.load(Ordering::Acquire), 0);
        let reopened =
            open(&mut state, "existing.txt".to_owned(), OpenMode::Read).expect("quota reclaimed");
        <HostState as HostFileHandle>::drop(&mut state, Resource::new_own(reopened.rep()))
            .expect("close reopened file");
    }
}
