//! `astrid:fs@1.0.0` host implementation.
//!
//! Path-based ops route through the workspace / home / tmp VFS bundles
//! after passing the per-principal security gate. The FileHandle resource
//! is stubbed in `file_handle.rs` pending the dedicated handle-lifecycle
//! port-back.
//!
//! Live surface (the most-used legacy fns ported to typed errors):
//!
//! - fs-exists, fs-mkdir, fs-readdir, fs-stat, fs-unlink, read-file,
//!   write-file
//!
//! Stubbed (planned for follow-ups; all return Unknown so capsules can
//! handle them as transient failures):
//!
//! - fs-open + FileHandle resource (positional pread/pwrite, fsync, etc.)
//! - fs-mkdir-all, fs-stat-symlink, fs-append, fs-copy, fs-rename,
//!   fs-remove-dir-all, fs-canonicalize, fs-read-link, fs-hard-link
//!
//! Audit: every path-based op emits `astrid.audit.fs` per call
//! (capsule + principal + op + path).

mod file_handle;
mod resolve;

use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::fs::host::{
    self as fs, Datetime, ErrorCode, FileHandle, FileStat, FileType, OpenMode,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use resolve::{resolve_path, resolve_vfs};

/// Audit envelope for path-based fs operations.
fn audit_fs<T, E: std::fmt::Debug>(
    state: &HostState,
    op: &'static str,
    path: &str,
    result: &Result<T, E>,
) {
    let capsule_id = state.capsule_id.as_str();
    let principal = state.effective_principal();
    match result {
        Ok(_) => tracing::debug!(
            target: "astrid.audit.fs",
            %capsule_id,
            %principal,
            fn = op,
            path,
            "audit",
        ),
        Err(e) => tracing::debug!(
            target: "astrid.audit.fs",
            %capsule_id,
            %principal,
            fn = op,
            path,
            error = ?e,
            "audit",
        ),
    }
}

/// Map a path-resolution error into an `ErrorCode`. Boundary escapes and
/// missing principal mounts are flagged separately so the audit log can
/// distinguish "user mistyped a path" from "tried to escape the VFS."
fn map_resolve_err(e: String) -> ErrorCode {
    if e.contains("escapes root boundary") || e.contains("escaped canonical root") {
        ErrorCode::BoundaryEscape
    } else if e.contains("not available") || e.contains("not mounted") {
        ErrorCode::CapabilityDenied
    } else {
        ErrorCode::InvalidPath
    }
}

/// Map a VFS error into an ErrorCode. The VFS exposes a coarse error
/// type — finer classification (already-exists / not-empty / would-block)
/// comes back as Unknown until the VFS layer surfaces typed variants.
fn map_vfs_err(e: astrid_vfs::VfsError) -> ErrorCode {
    use astrid_vfs::VfsError;
    match e {
        VfsError::NotFound(_) => ErrorCode::NotFound,
        VfsError::PermissionDenied(_) => ErrorCode::Access,
        VfsError::SandboxViolation(_) => ErrorCode::BoundaryEscape,
        VfsError::InvalidHandle => ErrorCode::InvalidPath,
        VfsError::NotSupported(msg) => ErrorCode::Unknown(format!("not supported: {msg}")),
        VfsError::Io(io) => ErrorCode::Unknown(io.to_string()),
    }
}

/// Run the file-read security gate; returns CapabilityDenied on rejection.
fn gate_read(state: &HostState, physical: &std::path::Path) -> Result<(), ErrorCode> {
    if let Some(gate) = state.security.clone() {
        let capsule_id = state.capsule_id.as_str().to_owned();
        let p = physical.to_string_lossy().to_string();
        let home = state.effective_home_root_buf();
        let check = util::bounded_block_on(
            &state.runtime_handle,
            &state.blocking_semaphore,
            async move { gate.check_file_read(&capsule_id, &p, home.as_deref()).await },
        );
        if check.is_err() {
            return Err(ErrorCode::CapabilityDenied);
        }
    }
    Ok(())
}

/// Run the file-write security gate; returns CapabilityDenied on rejection.
fn gate_write(state: &HostState, physical: &std::path::Path) -> Result<(), ErrorCode> {
    if let Some(gate) = state.security.clone() {
        let capsule_id = state.capsule_id.as_str().to_owned();
        let p = physical.to_string_lossy().to_string();
        let home = state.effective_home_root_buf();
        let check = util::bounded_block_on(
            &state.runtime_handle,
            &state.blocking_semaphore,
            async move {
                gate.check_file_write(&capsule_id, &p, home.as_deref())
                    .await
            },
        );
        if check.is_err() {
            return Err(ErrorCode::CapabilityDenied);
        }
    }
    Ok(())
}

/// Convert a VFS metadata record into the WIT `FileStat`. The VFS only
/// exposes size / is_dir / mtime today; created/accessed timestamps and
/// POSIX mode bits land as defaults until the VFS surfaces them.
fn to_file_stat(meta: &astrid_vfs::VfsMetadata) -> FileStat {
    let kind = if meta.is_dir {
        FileType::Directory
    } else if meta.is_file {
        FileType::Regular
    } else {
        FileType::TypeUnknown
    };
    let modified = Some(Datetime {
        seconds: meta.mtime as i64,
        nanoseconds: 0,
    });
    FileStat {
        size: meta.size,
        kind,
        mode: 0,
        modified,
        created: None,
        accessed: None,
    }
}

impl fs::Host for HostState {
    fn fs_open(
        &mut self,
        _path: String,
        _mode: OpenMode,
    ) -> Result<Resource<FileHandle>, ErrorCode> {
        // FileHandle resource lifecycle (positional pread/pwrite, fsync,
        // set-len) lands in a follow-up. Capsules calling fs-open today
        // see `unknown("not yet implemented")` and can fall back to
        // read-file / write-file.
        Err(ErrorCode::Unknown(
            "fs-open: FileHandle resource port pending".to_string(),
        ))
    }

    fn fs_exists(&mut self, path: String) -> Result<bool, ErrorCode> {
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_read(self, &resolved.physical)?;
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;
        let exists =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                vfs_path
                    .vfs
                    .exists(
                        &vfs_path.handle,
                        vfs_path.relative.to_string_lossy().as_ref(),
                    )
                    .await
            })
            .unwrap_or(false);
        let result: Result<bool, ErrorCode> = Ok(exists);
        audit_fs(self, "astrid:fs/host.fs-exists", &path, &result);
        result
    }

    fn fs_mkdir(&mut self, path: String) -> Result<(), ErrorCode> {
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_write(self, &resolved.physical)?;
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;

        // Strict-create semantics per `astrid:fs@1.0.0` (fs-mkdir
        // distinguished from fs-mkdir-all by failing when an
        // intermediate parent is missing). The underlying VFS
        // `mkdir()` is `create_dir_all`-based for every impl
        // (host/overlay/worktree), so without this guard fs-mkdir
        // would silently create missing parents and fail-open against
        // the contract (Gemini #752 finding). Pre-check the parent
        // exists; the only TOCTOU window is between this check and
        // the mkdir call, which leaves the operation no less strict
        // than POSIX `mkdir(2)` against a concurrent mutator.
        let relative = vfs_path.relative.to_string_lossy().to_string();
        if let Some(parent) = vfs_path.relative.parent()
            && !parent.as_os_str().is_empty()
        {
            let parent_rel = parent.to_string_lossy().to_string();
            let parent_exists =
                util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                    vfs_path.vfs.exists(&vfs_path.handle, &parent_rel).await
                })
                .unwrap_or(false);
            if !parent_exists {
                let result: Result<(), ErrorCode> = Err(ErrorCode::NotFound);
                audit_fs(self, "astrid:fs/host.fs-mkdir", &path, &result);
                return result;
            }
        }

        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                vfs_path.vfs.mkdir(&vfs_path.handle, &relative).await
            })
            .map_err(map_vfs_err);
        audit_fs(self, "astrid:fs/host.fs-mkdir", &path, &result);
        result
    }

    fn fs_mkdir_all(&mut self, path: String) -> Result<(), ErrorCode> {
        // Same VFS call as `fs_mkdir` — every VFS impl already routes
        // through the host's `std::fs::create_dir_all`, so the
        // recursive semantics are already there. The WIT contract
        // distinguishes the two only by whether the call is idempotent
        // (`fs-mkdir-all`) or strict (`fs-mkdir`): see
        // `wit/host/fs@1.0.0.wit`. Tightening `fs-mkdir` to non-
        // recursive is a separate behaviour change; this commit only
        // unstubs the idempotent variant the capsule contract
        // promises.
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_write(self, &resolved.physical)?;
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;
        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                vfs_path
                    .vfs
                    .mkdir(
                        &vfs_path.handle,
                        vfs_path.relative.to_string_lossy().as_ref(),
                    )
                    .await
            })
            .map_err(map_vfs_err);
        audit_fs(self, "astrid:fs/host.fs-mkdir-all", &path, &result);
        result
    }

    fn fs_readdir(&mut self, path: String) -> Result<Vec<String>, ErrorCode> {
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_read(self, &resolved.physical)?;
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;
        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                vfs_path
                    .vfs
                    .readdir(
                        &vfs_path.handle,
                        vfs_path.relative.to_string_lossy().as_ref(),
                    )
                    .await
            })
            .map(|entries| entries.into_iter().map(|e| e.name).collect::<Vec<_>>())
            .map_err(map_vfs_err);
        audit_fs(self, "astrid:fs/host.fs-readdir", &path, &result);
        result
    }

    fn fs_stat(&mut self, path: String) -> Result<FileStat, ErrorCode> {
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_read(self, &resolved.physical)?;
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;
        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                vfs_path
                    .vfs
                    .stat(
                        &vfs_path.handle,
                        vfs_path.relative.to_string_lossy().as_ref(),
                    )
                    .await
            })
            .map(|m| to_file_stat(&m))
            .map_err(map_vfs_err);
        audit_fs(self, "astrid:fs/host.fs-stat", &path, &result);
        result
    }

    fn fs_stat_symlink(&mut self, _path: String) -> Result<FileStat, ErrorCode> {
        Err(ErrorCode::Unknown(
            "fs-stat-symlink: lstat port pending".to_string(),
        ))
    }

    fn fs_unlink(&mut self, path: String) -> Result<(), ErrorCode> {
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_write(self, &resolved.physical)?;
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;
        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                vfs_path
                    .vfs
                    .unlink(
                        &vfs_path.handle,
                        vfs_path.relative.to_string_lossy().as_ref(),
                    )
                    .await
            })
            .map_err(map_vfs_err);
        audit_fs(self, "astrid:fs/host.fs-unlink", &path, &result);
        result
    }

    fn read_file(&mut self, path: String) -> Result<Vec<u8>, ErrorCode> {
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_read(self, &resolved.physical)?;
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;
        // Sentinel string used to encode the "too large at stat time"
        // case as a `PermissionDenied` payload so we can re-raise it
        // as `TooLarge` outside the async block. Keep the marker on a
        // local constant so the `map_err` matcher can compare against
        // a single source of truth instead of an inline literal.
        const TOO_LARGE_TAG: &str = "astrid-read-file:too-large";
        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                let metadata = vfs_path
                    .vfs
                    .stat(
                        &vfs_path.handle,
                        vfs_path.relative.to_string_lossy().as_ref(),
                    )
                    .await?;
                if metadata.size > util::MAX_GUEST_PAYLOAD_LEN {
                    return Err(astrid_vfs::VfsError::PermissionDenied(
                        TOO_LARGE_TAG.to_string(),
                    ));
                }
                let handle = vfs_path
                    .vfs
                    .open(
                        &vfs_path.handle,
                        vfs_path.relative.to_string_lossy().as_ref(),
                        false,
                        false,
                    )
                    .await?;
                let data = vfs_path.vfs.read(&handle).await;
                let _ = vfs_path.vfs.close(&handle).await;
                data
            })
            .map_err(|e| {
                if matches!(&e, astrid_vfs::VfsError::PermissionDenied(msg) if msg == TOO_LARGE_TAG)
                {
                    ErrorCode::TooLarge
                } else {
                    map_vfs_err(e)
                }
            });
        // Post-read enforcement closes a TOCTOU window: the stat check
        // above sees the size at `t0`, but the file can grow between
        // stat and the open/read syscalls. The VFS read path has its
        // own ceiling (currently 50 MiB) which is higher than ours, so
        // a file that grew past 10 MiB but stayed below the VFS cap
        // would otherwise be returned in full. Cap the final buffer
        // here so the kernel's intended limit is the effective limit.
        let result = result.and_then(|data| {
            if data.len() as u64 > util::MAX_GUEST_PAYLOAD_LEN {
                Err(ErrorCode::TooLarge)
            } else {
                Ok(data)
            }
        });
        audit_fs(self, "astrid:fs/host.read-file", &path, &result);
        result
    }

    fn write_file(&mut self, path: String, content: Vec<u8>) -> Result<(), ErrorCode> {
        if content.len() as u64 > util::MAX_GUEST_PAYLOAD_LEN {
            return Err(ErrorCode::TooLarge);
        }
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_write(self, &resolved.physical)?;
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;
        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                let handle = vfs_path
                    .vfs
                    .open(
                        &vfs_path.handle,
                        vfs_path.relative.to_string_lossy().as_ref(),
                        true,
                        true,
                    )
                    .await?;
                let res = vfs_path.vfs.write(&handle, &content).await;
                let _ = vfs_path.vfs.close(&handle).await;
                res
            })
            .map_err(map_vfs_err);
        audit_fs(self, "astrid:fs/host.write-file", &path, &result);
        result
    }

    fn fs_append(&mut self, _path: String, _content: Vec<u8>) -> Result<(), ErrorCode> {
        Err(ErrorCode::Unknown(
            "fs-append: append-mode port pending".to_string(),
        ))
    }

    fn fs_copy(&mut self, _src: String, _dst: String) -> Result<(), ErrorCode> {
        Err(ErrorCode::Unknown(
            "fs-copy: VFS copy port pending".to_string(),
        ))
    }

    fn fs_rename(&mut self, _src: String, _dst: String) -> Result<(), ErrorCode> {
        Err(ErrorCode::Unknown(
            "fs-rename: VFS rename port pending".to_string(),
        ))
    }

    fn fs_remove_dir_all(&mut self, _path: String) -> Result<u64, ErrorCode> {
        Err(ErrorCode::Unknown(
            "fs-remove-dir-all: recursive remove port pending".to_string(),
        ))
    }

    fn fs_canonicalize(&mut self, _path: String) -> Result<String, ErrorCode> {
        Err(ErrorCode::Unknown(
            "fs-canonicalize: VFS-scheme canonicalization port pending".to_string(),
        ))
    }

    fn fs_read_link(&mut self, _path: String) -> Result<String, ErrorCode> {
        Err(ErrorCode::Unknown(
            "fs-read-link: readlink port pending".to_string(),
        ))
    }

    fn fs_hard_link(&mut self, _src: String, _link_path: String) -> Result<(), ErrorCode> {
        Err(ErrorCode::Unknown(
            "fs-hard-link: cross-scheme guard + hard-link port pending".to_string(),
        ))
    }
}
