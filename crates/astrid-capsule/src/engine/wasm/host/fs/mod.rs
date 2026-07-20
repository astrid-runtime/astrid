//! `astrid:fs@1.0.0` host implementation.
//!
//! Path-based ops route through the workspace / home / tmp VFS bundles
//! after passing the per-principal security gate. Open files are held as
//! principal-affine resources in Wasmtime's resource table and retain the VFS
//! capability selected at open time.
//!
//! Live surface (the most-used legacy fns ported to typed errors):
//!
//! - fs-open + FileHandle, fs-exists, fs-mkdir, fs-readdir, fs-stat,
//!   fs-unlink, read-file, write-file, fs-rename
//!
//! Stubbed (planned for follow-ups; all return Unknown so capsules can
//! handle them as transient failures):
//!
//! - fs-append, fs-copy,
//!   fs-remove-dir-all, fs-canonicalize, fs-read-link, fs-hard-link
//!
//! Audit: every implemented op emits `astrid.audit.fs` per call
//! (capsule + principal + op + path). Both the allowed and the denied paths
//! record the RESOLVED PHYSICAL path (the exact path the security gate
//! evaluated), not the guest-supplied logical path — so a `home://x` allow and
//! a `home://x` deny name the same on-disk target on the chain.

mod file_handle;
mod resolve;

use wasmtime::component::Resource;

use crate::audit_sink::{HostAuditEvent, HostAuditOutcome};
use crate::engine::wasm::bindings::astrid::fs::host::{
    self as fs, Datetime, ErrorCode, FileHandle, FileStat, FileType, OpenMode,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use resolve::{resolve_path, resolve_vfs};

use self::file_handle::{FileAccess, OpenFileSlot};

pub(crate) use self::file_handle::OpenFileSlot as PooledOpenFileSlot;

const MAX_OPEN_FILE_HANDLES: usize = 16;

/// Audit envelope for path-based fs operations.
///
/// Emits the off-by-default `astrid.audit.fs` observability line AND, when a
/// per-action [`HostAuditSink`](crate::audit_sink::HostAuditSink)
/// is installed, reports a typed event onto the kernel's signed audit chain.
/// The op string maps to an event class: content/metadata reads →
/// [`FileRead`], mutations → [`FileWrite`], removals → [`FileDelete`]. Ops
/// that don't clearly map skip the sink rather than invent a variant. Open is
/// classified by its concrete read-only or mutating mode at the call site.
pub(crate) fn audit_fs<T, E: std::fmt::Debug>(
    state: &HostState,
    op: &str,
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

    let Some(sink) = state.audit_sink.as_ref() else {
        return;
    };
    let Some(event) = fs_event_for_op(op, path) else {
        return;
    };
    let err_buf;
    let outcome = match result {
        Ok(_) => HostAuditOutcome::Allowed,
        Err(e) => {
            err_buf = format!("{e:?}");
            HostAuditOutcome::Failed(&err_buf)
        },
    };
    sink.record(&principal, event, outcome);
}

/// Map a filesystem op string to its typed audit event class. Returns `None`
/// for ops with no clear effect mapping so the sink is skipped rather than fed
/// a guessed variant. Handle operations retain their open-time physical path.
fn fs_event_for_op<'a>(op: &str, path: &'a str) -> Option<HostAuditEvent<'a>> {
    // `op` is a fully-qualified WIT path (`astrid:fs/host.read-file`) or a
    // bare verb in tests (`read-file`); match on the trailing verb so both
    // forms classify identically.
    let verb = op.rsplit('.').next().unwrap_or(op);
    match verb {
        "read-file" | "fs-readdir" | "readdir" | "fs-stat" | "stat" | "fs-stat-symlink"
        | "stat-symlink" | "fs-exists" | "exists" | "read-at" | "handle-stat" | "fs-open-read" => {
            Some(HostAuditEvent::FileRead { path })
        },
        "write-file" | "fs-mkdir" | "mkdir" | "fs-mkdir-all" | "write-at" | "set-len"
        | "sync-data" | "sync-all" | "fs-rename" | "fs-open-write" => {
            Some(HostAuditEvent::FileWrite { path })
        },
        "fs-unlink" | "unlink" | "remove" | "remove-dir" => {
            Some(HostAuditEvent::FileDelete { path })
        },
        _ => None,
    }
}

/// Report a denied path-based fs operation to the per-action audit sink.
///
/// The security gate (`gate_read`/`gate_write`) rejects a call before any
/// fs effect runs and early-returns, so the success-path [`audit_fs`] is
/// never reached on the deny path — this is the only audit report a denied
/// fs call makes, ensuring exactly-once recording. The `event` is the typed
/// [`HostAuditEvent`] describing the attempted access; `reason` is the
/// gate's rejection reason.
pub(crate) fn record_fs_denied(
    state: &HostState,
    event: crate::audit_sink::HostAuditEvent<'_>,
    reason: &str,
) {
    if let Some(sink) = state.audit_sink.as_ref() {
        sink.record(
            &state.effective_principal(),
            event,
            HostAuditOutcome::Denied(reason),
        );
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

/// Map a VFS error into an ErrorCode. Preserve native not-found and
/// permission-denied kinds even when the VFS operation wrapped them in the
/// coarse `Io` variant, so guests can safely distinguish optional inputs from
/// real I/O failures.
fn map_vfs_err(e: astrid_vfs::VfsError) -> ErrorCode {
    use astrid_vfs::VfsError;
    match e {
        VfsError::NotFound(_) => ErrorCode::NotFound,
        VfsError::PermissionDenied(_) => ErrorCode::Access,
        VfsError::SandboxViolation(_) => ErrorCode::BoundaryEscape,
        VfsError::InvalidHandle => ErrorCode::InvalidPath,
        VfsError::NotSupported(msg) => ErrorCode::Unknown(format!("not supported: {msg}")),
        VfsError::Io(io) => match io.kind() {
            std::io::ErrorKind::NotFound => ErrorCode::NotFound,
            std::io::ErrorKind::PermissionDenied => ErrorCode::Access,
            std::io::ErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
            std::io::ErrorKind::IsADirectory => ErrorCode::IsDirectory,
            std::io::ErrorKind::NotADirectory => ErrorCode::NotDirectory,
            std::io::ErrorKind::DirectoryNotEmpty => ErrorCode::NotEmpty,
            std::io::ErrorKind::FileTooLarge => ErrorCode::TooLarge,
            std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => ErrorCode::Quota,
            std::io::ErrorKind::CrossesDevices => ErrorCode::CrossVfs,
            _ => ErrorCode::Unknown(io.to_string()),
        },
    }
}

#[cfg(test)]
mod error_mapping_tests {
    use super::*;

    #[test]
    fn native_not_found_and_permission_denied_remain_typed() {
        let not_found =
            astrid_vfs::VfsError::Io(std::io::Error::from(std::io::ErrorKind::NotFound));
        let denied =
            astrid_vfs::VfsError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));

        assert!(matches!(map_vfs_err(not_found), ErrorCode::NotFound));
        assert!(matches!(map_vfs_err(denied), ErrorCode::Access));
    }

    #[test]
    fn unrelated_native_io_errors_remain_unknown() {
        let error =
            astrid_vfs::VfsError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));

        assert!(matches!(map_vfs_err(error), ErrorCode::Unknown(_)));
    }

    #[test]
    fn symlink_metadata_is_audited_as_a_file_read() {
        assert!(matches!(
            fs_event_for_op("astrid:fs/host.fs-stat-symlink", "/workspace"),
            Some(HostAuditEvent::FileRead { path: "/workspace" })
        ));
    }

    #[test]
    fn open_and_handle_operations_keep_their_effect_class() {
        for op in ["fs-open-read", "read-at", "handle-stat"] {
            assert!(matches!(
                fs_event_for_op(op, "/workspace/input"),
                Some(HostAuditEvent::FileRead { .. })
            ));
        }
        for op in ["fs-open-write", "write-at", "set-len", "sync-all"] {
            assert!(matches!(
                fs_event_for_op(op, "/workspace/output"),
                Some(HostAuditEvent::FileWrite { .. })
            ));
        }
    }
}

/// Run the file-read security gate; returns CapabilityDenied on rejection.
///
/// On rejection the denial is reported to the per-action audit sink as a
/// `FileRead`-`Denied` event before the early return — the deny path never
/// reaches the success-path [`audit_fs`], so this is the single record for a
/// denied read (exactly-once). The audited path is the resolved physical
/// path the gate evaluated.
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
        if let Err(reason) = check {
            let path = physical.to_string_lossy();
            record_fs_denied(
                state,
                HostAuditEvent::FileRead {
                    path: path.as_ref(),
                },
                &reason,
            );
            return Err(ErrorCode::CapabilityDenied);
        }
    }
    Ok(())
}

/// The mutation a write-gated fs op represents. Every mutation and removal
/// funnels through the one `check_file_write` gate, so this selects the typed
/// event recorded on denial — preserving the attempted effect on the audit
/// chain instead of always recording a write.
#[derive(Clone, Copy)]
enum WriteKind {
    /// A create or write (`write-file`, `mkdir`, `mkdir-all`).
    Write,
    /// A removal (`unlink`).
    Delete,
}

/// Run the file-write security gate; returns CapabilityDenied on rejection.
///
/// On rejection the denial is reported to the per-action audit sink before the
/// early return (exactly-once, same rationale as [`gate_read`]). `kind`
/// selects the recorded event: a denied `unlink` is audited as
/// `FileDelete`-`Denied`, a denied `write`/`mkdir` as `FileWrite`-`Denied`.
fn gate_write(
    state: &HostState,
    physical: &std::path::Path,
    kind: WriteKind,
) -> Result<(), ErrorCode> {
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
        if let Err(reason) = check {
            let path = physical.to_string_lossy();
            let event = match kind {
                WriteKind::Write => HostAuditEvent::FileWrite {
                    path: path.as_ref(),
                },
                WriteKind::Delete => HostAuditEvent::FileDelete {
                    path: path.as_ref(),
                },
            };
            record_fs_denied(state, event, &reason);
            return Err(ErrorCode::CapabilityDenied);
        }
    }
    Ok(())
}

/// Resolve and read-authorize a VFS path exposed to a sandboxed native child.
pub(super) fn authorize_process_read_path(
    state: &HostState,
    raw_path: &str,
) -> Result<std::path::PathBuf, ErrorCode> {
    let resolved = resolve_path(state, raw_path).map_err(map_resolve_err)?;
    gate_read(state, &resolved.physical)?;
    Ok(resolved.physical)
}

/// Write-authorize an already-resolved physical process path before adding it
/// to the native sandbox's writable roots.
pub(super) fn authorize_process_write_path(
    state: &HostState,
    physical: &std::path::Path,
) -> Result<(), ErrorCode> {
    gate_write(state, physical, WriteKind::Write)
}

/// Convert a VFS metadata record into the WIT `FileStat`. The VFS only
/// exposes size / is_dir / mtime today; created/accessed timestamps and
/// POSIX mode bits land as defaults until the VFS surfaces them.
fn to_file_stat(meta: &astrid_vfs::VfsMetadata, mode: u32) -> FileStat {
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
        mode,
        modified,
        created: None,
        accessed: None,
    }
}

impl fs::Host for HostState {
    fn fs_open(&mut self, path: String, mode: OpenMode) -> Result<Resource<FileHandle>, ErrorCode> {
        if self.file_handle_count >= MAX_OPEN_FILE_HANDLES {
            return Err(ErrorCode::Quota);
        }

        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        let (access, vfs_mode, audit_op) = match mode {
            OpenMode::Read => {
                gate_read(self, &resolved.physical)?;
                (
                    FileAccess::Read,
                    astrid_vfs::VfsOpenMode::Read,
                    "astrid:fs/host.fs-open-read",
                )
            },
            OpenMode::Write => {
                gate_write(self, &resolved.physical, WriteKind::Write)?;
                (
                    FileAccess::Write,
                    astrid_vfs::VfsOpenMode::Write,
                    "astrid:fs/host.fs-open-write",
                )
            },
            OpenMode::Append => {
                gate_write(self, &resolved.physical, WriteKind::Write)?;
                (
                    FileAccess::Write,
                    astrid_vfs::VfsOpenMode::Append,
                    "astrid:fs/host.fs-open-write",
                )
            },
            OpenMode::ReadWrite => {
                gate_read(self, &resolved.physical)?;
                gate_write(self, &resolved.physical, WriteKind::Write)?;
                (
                    FileAccess::ReadWrite,
                    astrid_vfs::VfsOpenMode::ReadWrite,
                    "astrid:fs/host.fs-open-write",
                )
            },
        };
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;
        let vfs = vfs_path.vfs;
        let relative = vfs_path.relative.to_string_lossy().to_string();
        let physical_path = resolved.physical.to_string_lossy().into_owned();
        let result = (|| {
            let vfs_handle = util::bounded_block_on(
                &self.runtime_handle,
                &self.blocking_semaphore,
                vfs.open_mode(&vfs_path.handle, &relative, vfs_mode),
            )
            .map_err(map_vfs_err)?;

            let slot = OpenFileSlot::new(
                vfs.clone(),
                vfs_handle,
                access,
                physical_path.clone(),
                self.effective_principal(),
                self.runtime_handle.clone(),
            );
            let table_resource = self.resource_table.push(slot).map_err(|error| {
                // `ResourceTable::push` consumed and dropped the slot. Its
                // destructor schedules the VFS close, including on this error
                // path and on whole-table pool resets.
                ErrorCode::Unknown(format!("resource table: {error}"))
            })?;
            self.file_handle_count += 1;
            self.file_handle_reps.insert(table_resource.rep());
            Ok(Resource::new_own(table_resource.rep()))
        })();
        audit_fs(self, audit_op, &physical_path, &result);
        result
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
        audit_fs(
            self,
            "astrid:fs/host.fs-exists",
            &resolved.physical.to_string_lossy(),
            &result,
        );
        result
    }

    fn fs_mkdir(&mut self, path: String) -> Result<(), ErrorCode> {
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_write(self, &resolved.physical, WriteKind::Write)?;
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
                audit_fs(
                    self,
                    "astrid:fs/host.fs-mkdir",
                    &resolved.physical.to_string_lossy(),
                    &result,
                );
                return result;
            }
        }

        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                vfs_path.vfs.mkdir(&vfs_path.handle, &relative).await
            })
            .map_err(map_vfs_err);
        audit_fs(
            self,
            "astrid:fs/host.fs-mkdir",
            &resolved.physical.to_string_lossy(),
            &result,
        );
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
        gate_write(self, &resolved.physical, WriteKind::Write)?;
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
        audit_fs(
            self,
            "astrid:fs/host.fs-mkdir-all",
            &resolved.physical.to_string_lossy(),
            &result,
        );
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
        audit_fs(
            self,
            "astrid:fs/host.fs-readdir",
            &resolved.physical.to_string_lossy(),
            &result,
        );
        result
    }

    fn fs_stat(&mut self, path: String) -> Result<FileStat, ErrorCode> {
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_read(self, &resolved.physical)?;
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;
        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                let relative = vfs_path.relative.to_string_lossy();
                let metadata = vfs_path
                    .vfs
                    .stat(&vfs_path.handle, relative.as_ref())
                    .await?;
                let mode = vfs_path
                    .vfs
                    .mode(&vfs_path.handle, relative.as_ref())
                    .await?;
                Ok(to_file_stat(&metadata, mode))
            })
            .map_err(map_vfs_err);
        audit_fs(
            self,
            "astrid:fs/host.fs-stat",
            &resolved.physical.to_string_lossy(),
            &result,
        );
        result
    }

    fn fs_stat_symlink(&mut self, path: String) -> Result<FileStat, ErrorCode> {
        // The VFS stat contract is deliberately non-following: HostVfs uses
        // cap-std's `symlink_metadata`, while the overlay/worktree backends
        // preserve the same node-type semantics. Keep this path separate from
        // `fs_stat` so the SDK's explicit lstat operation remains visible in
        // the audit trail.
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_read(self, &resolved.physical)?;
        let vfs_path = resolve_vfs(self, &resolved).map_err(map_resolve_err)?;
        let result =
            util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
                let relative = vfs_path.relative.to_string_lossy();
                let metadata = vfs_path
                    .vfs
                    .stat(&vfs_path.handle, relative.as_ref())
                    .await?;
                let mode = vfs_path
                    .vfs
                    .mode(&vfs_path.handle, relative.as_ref())
                    .await?;
                Ok(to_file_stat(&metadata, mode))
            })
            .map_err(map_vfs_err);
        audit_fs(
            self,
            "astrid:fs/host.fs-stat-symlink",
            &resolved.physical.to_string_lossy(),
            &result,
        );
        result
    }

    fn fs_unlink(&mut self, path: String) -> Result<(), ErrorCode> {
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_write(self, &resolved.physical, WriteKind::Delete)?;
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
        audit_fs(
            self,
            "astrid:fs/host.fs-unlink",
            &resolved.physical.to_string_lossy(),
            &result,
        );
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
        audit_fs(
            self,
            "astrid:fs/host.read-file",
            &resolved.physical.to_string_lossy(),
            &result,
        );
        result
    }

    fn write_file(&mut self, path: String, content: Vec<u8>) -> Result<(), ErrorCode> {
        if content.len() as u64 > util::MAX_GUEST_PAYLOAD_LEN {
            return Err(ErrorCode::TooLarge);
        }
        let resolved = resolve_path(self, &path).map_err(map_resolve_err)?;
        gate_write(self, &resolved.physical, WriteKind::Write)?;
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
        audit_fs(
            self,
            "astrid:fs/host.write-file",
            &resolved.physical.to_string_lossy(),
            &result,
        );
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

    fn fs_rename(&mut self, src: String, dst: String) -> Result<(), ErrorCode> {
        let src_resolved = resolve_path(self, &src).map_err(map_resolve_err)?;
        let dst_resolved = resolve_path(self, &dst).map_err(map_resolve_err)?;
        if src_resolved.target != dst_resolved.target {
            return Err(ErrorCode::CrossVfs);
        }
        gate_write(self, &src_resolved.physical, WriteKind::Write)?;
        gate_write(self, &dst_resolved.physical, WriteKind::Write)?;
        let src_vfs = resolve_vfs(self, &src_resolved).map_err(map_resolve_err)?;
        let dst_vfs = resolve_vfs(self, &dst_resolved).map_err(map_resolve_err)?;
        let src_relative = src_vfs.relative.to_string_lossy().to_string();
        let dst_relative = dst_vfs.relative.to_string_lossy().to_string();
        let result = util::bounded_block_on(
            &self.runtime_handle,
            &self.blocking_semaphore,
            src_vfs
                .vfs
                .rename(&src_vfs.handle, &src_relative, &dst_relative),
        )
        .map_err(map_vfs_err);
        let audit_path = format!(
            "{} -> {}",
            src_resolved.physical.to_string_lossy(),
            dst_resolved.physical.to_string_lossy()
        );
        audit_fs(self, "astrid:fs/host.fs-rename", &audit_path, &result);
        result
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
