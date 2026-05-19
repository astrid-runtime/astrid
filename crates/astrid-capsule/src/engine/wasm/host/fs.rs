use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::engine::wasm::bindings::astrid::capsule::fs;
use crate::engine::wasm::bindings::astrid::capsule::types::FileStat;
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

/// URI scheme prefix for the principal's home directory.
const HOME_SCHEME: &str = "home://";

/// URI scheme prefix for the daemon's current working directory.
const CWD_SCHEME: &str = "cwd://";

/// Path prefix that maps to the principal's tmp directory.
const TMP_PREFIX: &str = "/tmp/";

/// Strip any leading absolute slashes or prefixes (e.g. C:\) from the requested path
fn make_relative(requested: &str) -> &Path {
    let path = Path::new(requested);
    let mut components = path.components();
    while let Some(c) = components.clone().next() {
        if matches!(c, Component::RootDir | Component::Prefix(_)) {
            components.next(); // consume it
        } else {
            break;
        }
    }
    components.as_path()
}

/// Result of resolving a path to a physical absolute location on disk.
struct ResolvedPhysical {
    /// The fully resolved physical path (symlinks canonicalized where possible).
    physical: PathBuf,
    /// The canonical root this path was resolved against.
    canonical_root: PathBuf,
}

/// Compute the true physical absolute path for the security gate by canonicalizing on the host filesystem.
/// This prevents symlink bypass attacks where a lexical path passes the gate but cap-std follows a symlink.
fn resolve_physical_absolute(root: &Path, requested: &str) -> Result<ResolvedPhysical, String> {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    let relative_requested = make_relative(requested);
    let joined = canonical_root.join(relative_requested);

    let mut current_check = joined.clone();
    let mut unexisting_components = Vec::new();

    loop {
        if std::fs::symlink_metadata(&current_check).is_ok() {
            let canonical =
                std::fs::canonicalize(&current_check).unwrap_or_else(|_| current_check.clone());
            let mut final_path = canonical;
            for comp in unexisting_components.into_iter().rev() {
                final_path.push(comp);
            }
            if !final_path.starts_with(&canonical_root) {
                return Err(format!(
                    "path escapes root boundary: {requested} resolves to {}",
                    final_path.display()
                ));
            }
            return Ok(ResolvedPhysical {
                physical: final_path,
                canonical_root,
            });
        }
        if let Some(parent) = current_check.parent() {
            if let Some(file_name) = current_check.file_name() {
                unexisting_components.push(file_name.to_os_string());
            }
            current_check = parent.to_path_buf();
        } else {
            break;
        }
    }

    if !joined.starts_with(&canonical_root) {
        return Err(format!(
            "path escapes root boundary: {requested} resolves to {}",
            joined.display()
        ));
    }

    Ok(ResolvedPhysical {
        physical: joined,
        canonical_root,
    })
}

/// Which VFS target a resolved path points at.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VfsTarget {
    /// The workspace overlay VFS (default).
    Workspace,
    /// The principal's home directory (`home://`).
    Home,
    /// The principal's tmp directory (`/tmp/`).
    Tmp,
}

/// First-phase resolution result: physical path for the security gate,
/// the VFS-relative path, and which VFS to target.
struct ResolvedPath {
    /// Absolute physical path (for security gate check).
    physical: PathBuf,
    /// Path relative to the root (for VFS operations).
    relative: PathBuf,
    /// Which VFS this path targets.
    target: VfsTarget,
}

/// Second-phase resolution result: the VFS instance and capability handle
/// to use for the actual filesystem operation.
struct ResolvedVfsPath {
    /// Path relative to the VFS root.
    relative: PathBuf,
    /// The VFS instance to use.
    vfs: Arc<dyn astrid_vfs::Vfs>,
    /// The capability handle for the VFS root.
    handle: astrid_capabilities::DirHandle,
}

/// Phase 1: Resolve a raw guest path to a physical path and determine
/// whether it targets the workspace or home VFS.
///
/// Uses the *effective* home root and tmp dir, which prefer the per-invocation
/// principal's paths over the capsule's load-time paths when set by
/// `WasmEngine::invoke_interceptor`.
fn resolve_path(state: &HostState, raw_path: &str) -> Result<ResolvedPath, String> {
    if let Some(stripped) = raw_path.strip_prefix(CWD_SCHEME) {
        let resolved = resolve_physical_absolute(&state.workspace_root, stripped)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved cwd path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            physical: resolved.physical,
            relative,
            target: VfsTarget::Workspace,
        })
    } else if let Some(stripped) = raw_path.strip_prefix(HOME_SCHEME) {
        let home = state.effective_home().ok_or_else(|| {
            "home:// scheme is not available: no home directory is configured \
             for the calling principal."
                .to_string()
        })?;
        let resolved = resolve_physical_absolute(&home.root, stripped)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved home path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            physical: resolved.physical,
            relative,
            target: VfsTarget::Home,
        })
    } else if raw_path.starts_with(TMP_PREFIX) || raw_path == "/tmp" {
        let tmp_mount = state.effective_tmp().ok_or_else(|| {
            "/tmp is not available: no tmp directory is configured for this principal.".to_string()
        })?;
        let stripped = raw_path
            .strip_prefix(TMP_PREFIX)
            .or_else(|| raw_path.strip_prefix("/tmp"))
            .unwrap_or("");
        let resolved = resolve_physical_absolute(&tmp_mount.root, stripped)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved /tmp path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            physical: resolved.physical,
            relative,
            target: VfsTarget::Tmp,
        })
    } else {
        let resolved = resolve_physical_absolute(&state.workspace_root, raw_path)?;
        let relative = resolved
            .physical
            .strip_prefix(&resolved.canonical_root)
            .map_err(|_| "resolved path escaped canonical root".to_string())?
            .to_path_buf();
        Ok(ResolvedPath {
            physical: resolved.physical,
            relative,
            target: VfsTarget::Workspace,
        })
    }
}

/// Phase 2: Given a first-phase result, select the correct VFS instance
/// and capability handle.
///
/// For `Home` and `Tmp` targets, returns the *effective* bundle — the
/// per-invocation bundle if `WasmEngine::invoke_interceptor` installed one,
/// otherwise the capsule's load-time bundle.
fn resolve_vfs(state: &HostState, resolved: &ResolvedPath) -> Result<ResolvedVfsPath, String> {
    let (vfs, handle) = match resolved.target {
        VfsTarget::Home => {
            let m = state.effective_home().ok_or_else(|| {
                "home:// VFS is not mounted for the calling principal.".to_string()
            })?;
            (m.vfs.clone(), m.handle.clone())
        },
        VfsTarget::Tmp => {
            let m = state
                .effective_tmp()
                .ok_or_else(|| "/tmp VFS is not mounted for the calling principal.".to_string())?;
            (m.vfs.clone(), m.handle.clone())
        },
        VfsTarget::Workspace => (state.vfs.clone(), state.vfs_root_handle.clone()),
    };
    Ok(ResolvedVfsPath {
        relative: resolved.relative.clone(),
        vfs,
        handle,
    })
}

impl fs::Host for HostState {
    fn fs_exists(&mut self, path: String) -> Result<bool, String> {
        let capsule_id = self.capsule_id.as_str().to_owned();

        // Phase 1: resolve to physical path
        let resolved = resolve_path(self, &path)?;

        let security = self.security.clone();
        if let Some(gate) = security {
            let p = resolved.physical.to_string_lossy().to_string();
            let pid = capsule_id.clone();
            let home = self.effective_home_root_buf();
            let check =
                util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async move {
                    gate.check_file_read(&pid, &p, home.as_deref()).await
                });
            if let Err(reason) = check {
                return Err(format!("security denied exists check: {reason}"));
            }
        }

        let vfs_path = resolve_vfs(self, &resolved)?;

        let exists = util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            vfs_path
                .vfs
                .exists(
                    &vfs_path.handle,
                    vfs_path.relative.to_string_lossy().as_ref(),
                )
                .await
        })
        .unwrap_or(false);

        Ok(exists)
    }

    fn fs_mkdir(&mut self, path: String) -> Result<(), String> {
        let capsule_id = self.capsule_id.as_str().to_owned();

        let resolved = resolve_path(self, &path)?;

        let security = self.security.clone();
        if let Some(gate) = security {
            let p = resolved.physical.to_string_lossy().to_string();
            let pid = capsule_id.clone();
            let home = self.effective_home_root_buf();
            let check =
                util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async move {
                    gate.check_file_write(&pid, &p, home.as_deref()).await
                });
            if let Err(reason) = check {
                return Err(format!("security denied mkdir: {reason}"));
            }
        }

        let vfs_path = resolve_vfs(self, &resolved)?;

        util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            vfs_path
                .vfs
                .mkdir(
                    &vfs_path.handle,
                    vfs_path.relative.to_string_lossy().as_ref(),
                )
                .await
        })
        .map_err(|e| format!("mkdir failed: {e}"))
    }

    fn fs_readdir(&mut self, path: String) -> Result<Vec<String>, String> {
        let capsule_id = self.capsule_id.as_str().to_owned();

        let resolved = resolve_path(self, &path)?;

        let security = self.security.clone();
        if let Some(gate) = security {
            let p = resolved.physical.to_string_lossy().to_string();
            let pid = capsule_id.clone();
            let home = self.effective_home_root_buf();
            let check =
                util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async move {
                    gate.check_file_read(&pid, &p, home.as_deref()).await
                });
            if let Err(reason) = check {
                return Err(format!("security denied readdir: {reason}"));
            }
        }

        let vfs_path = resolve_vfs(self, &resolved)?;

        let entries = util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            vfs_path
                .vfs
                .readdir(
                    &vfs_path.handle,
                    vfs_path.relative.to_string_lossy().as_ref(),
                )
                .await
        })
        .map_err(|e| format!("readdir failed: {e}"))?;

        Ok(entries.into_iter().map(|e| e.name).collect())
    }

    fn fs_stat(&mut self, path: String) -> Result<FileStat, String> {
        let capsule_id = self.capsule_id.as_str().to_owned();

        let resolved = resolve_path(self, &path)?;

        let security = self.security.clone();
        if let Some(gate) = security {
            let p = resolved.physical.to_string_lossy().to_string();
            let pid = capsule_id.clone();
            let home = self.effective_home_root_buf();
            let check =
                util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async move {
                    gate.check_file_read(&pid, &p, home.as_deref()).await
                });
            if let Err(reason) = check {
                return Err(format!("security denied stat: {reason}"));
            }
        }

        let vfs_path = resolve_vfs(self, &resolved)?;

        let metadata = util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            vfs_path
                .vfs
                .stat(
                    &vfs_path.handle,
                    vfs_path.relative.to_string_lossy().as_ref(),
                )
                .await
        })
        .map_err(|e| format!("stat failed: {e}"))?;

        Ok(FileStat {
            size: metadata.size,
            is_dir: metadata.is_dir,
            mtime: Some(metadata.mtime),
        })
    }

    fn fs_unlink(&mut self, path: String) -> Result<(), String> {
        let capsule_id = self.capsule_id.as_str().to_owned();

        let resolved = resolve_path(self, &path)?;

        let security = self.security.clone();
        if let Some(gate) = security {
            let p = resolved.physical.to_string_lossy().to_string();
            let pid = capsule_id.clone();
            let home = self.effective_home_root_buf();
            let check =
                util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async move {
                    gate.check_file_write(&pid, &p, home.as_deref()).await
                });
            if let Err(reason) = check {
                return Err(format!("security denied unlink: {reason}"));
            }
        }

        let vfs_path = resolve_vfs(self, &resolved)?;

        util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            vfs_path
                .vfs
                .unlink(
                    &vfs_path.handle,
                    vfs_path.relative.to_string_lossy().as_ref(),
                )
                .await
        })
        .map_err(|e| format!("unlink failed: {e}"))
    }

    fn read_file(&mut self, path: String) -> Result<Vec<u8>, String> {
        let capsule_id = self.capsule_id.as_str().to_owned();

        let resolved = resolve_path(self, &path)?;

        let security = self.security.clone();
        if let Some(gate) = security {
            let p = resolved.physical.to_string_lossy().to_string();
            let pid = capsule_id.clone();
            let home = self.effective_home_root_buf();
            let check =
                util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async move {
                    gate.check_file_read(&pid, &p, home.as_deref()).await
                });
            if let Err(reason) = check {
                return Err(format!("security denied read_file: {reason}"));
            }
        }

        let vfs_path = resolve_vfs(self, &resolved)?;

        util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            let metadata = vfs_path
                .vfs
                .stat(
                    &vfs_path.handle,
                    vfs_path.relative.to_string_lossy().as_ref(),
                )
                .await?;
            if metadata.size > util::MAX_GUEST_PAYLOAD_LEN {
                return Err(astrid_vfs::VfsError::PermissionDenied(format!(
                    "File too large to read into memory ({} bytes > {} bytes)",
                    metadata.size,
                    util::MAX_GUEST_PAYLOAD_LEN
                )));
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
        .map_err(|e| format!("IO error: {e}"))
    }

    fn write_file(&mut self, path: String, content: Vec<u8>) -> Result<(), String> {
        let capsule_id = self.capsule_id.as_str().to_owned();

        let resolved = resolve_path(self, &path)?;

        let security = self.security.clone();
        if let Some(gate) = security {
            let p = resolved.physical.to_string_lossy().to_string();
            let pid = capsule_id.clone();
            let home = self.effective_home_root_buf();
            let check =
                util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async move {
                    gate.check_file_write(&pid, &p, home.as_deref()).await
                });
            if let Err(reason) = check {
                return Err(format!("security denied write_file: {reason}"));
            }
        }

        let vfs_path = resolve_vfs(self, &resolved)?;

        util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            // Note: pass truncate=true to emulate standard write behavior
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
        .map_err(|e| format!("write_file failed: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Chain tests for per-invocation home:// routing (#549).
//
// Exercises the wiring that `WasmEngine::invoke_interceptor` sets up at
// runtime: caller_context + invocation_home + invocation_tmp installed on
// HostState, fs::Host methods called synchronously (as WASM would), physical
// files landing under the invocation principal's physical tree. The bundle
// builder, security gate, and accessors each have their own focused tests;
// this file verifies they compose correctly end-to-end on the host side,
// without requiring a compiled WASM fixture.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::sync::Semaphore;
    use tokio_util::sync::CancellationToken;

    use crate::capsule::CapsuleId;
    use crate::engine::wasm::bindings::astrid::capsule::fs::Host as FsHost;
    use crate::engine::wasm::host::process::ProcessTracker;
    use crate::engine::wasm::host_state::{HostState, PrincipalMount};
    use crate::manifest::{CapabilitiesDef, CapsuleManifest, PackageDef};
    use crate::security::{CapsuleSecurityGate, ManifestSecurityGate};
    use astrid_storage::ScopedKvStore;
    use astrid_storage::secret::SecretStore;

    /// Build an [`IpcMessage`](astrid_events::ipc::IpcMessage) carrying just
    /// `principal` — the only field `invoke_interceptor` reads to derive
    /// invocation context.
    fn ctx_for(principal: &astrid_core::PrincipalId) -> astrid_events::ipc::IpcMessage {
        astrid_events::ipc::IpcMessage::new(
            "t",
            astrid_events::ipc::IpcPayload::RawJson(serde_json::Value::Null),
            uuid::Uuid::new_v4(),
        )
        .with_principal(principal.to_string())
    }

    /// Build a [`PrincipalMount`] rooted at `path`. Test-only; avoids the
    /// runtime-handle plumbing in `mount_dir` by calling `register_dir` on
    /// the current runtime. Canonicalizes `path` so the stored root matches
    /// the symlink-resolved paths the security gate sees (mirrors the
    /// production `mount_dir` behavior).
    async fn mount_at(path: &std::path::Path) -> PrincipalMount {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let vfs = astrid_vfs::HostVfs::new();
        let handle = astrid_capabilities::DirHandle::new();
        vfs.register_dir(handle.clone(), canonical.clone())
            .await
            .expect("register_dir");
        PrincipalMount {
            root: canonical,
            vfs: Arc::new(vfs) as Arc<dyn astrid_vfs::Vfs>,
            handle,
        }
    }

    fn make_manifest_home_rw() -> CapsuleManifest {
        CapsuleManifest {
            package: PackageDef {
                name: "test-capsule".into(),
                version: "0.1.0".into(),
                description: None,
                authors: vec![],
                repository: None,
                homepage: None,
                documentation: None,
                license: None,
                license_file: None,
                readme: None,
                keywords: vec![],
                categories: vec![],
                astrid_version: None,
                publish: None,
                include: None,
                exclude: None,
                metadata: None,
            },
            components: vec![],
            imports: HashMap::new(),
            exports: HashMap::new(),
            capabilities: CapabilitiesDef {
                net: vec![],
                net_bind: vec![],
                net_connect: vec![],
                kv: vec![],
                fs_read: vec!["home://".into()],
                fs_write: vec!["home://".into()],
                host_process: vec![],
                uplink: false,
                ipc_publish: vec![],
                ipc_subscribe: vec![],
                identity: vec![],
                allow_prompt_injection: false,
            },
            env: Default::default(),
            context_files: vec![],
            commands: vec![],
            mcp_servers: vec![],
            skills: vec![],
            uplinks: vec![],
            interceptors: vec![],
            topics: vec![],
            publishes: ::std::collections::HashMap::new(),
            subscribes: ::std::collections::HashMap::new(),
            tools: ::std::vec::Vec::new(),
        }
    }

    /// Construct a HostState with the capsule-owner rooted at `owner_home`,
    /// a `home://` security gate allow-listing read+write, and a runtime
    /// handle captured from the current tokio runtime.
    ///
    /// Caller populates `caller_context` + `invocation_home` directly to
    /// simulate what `WasmEngine::invoke_interceptor` would do at runtime.
    async fn make_host_state(
        owner_principal: astrid_core::PrincipalId,
        owner_home: &std::path::Path,
        workspace_root: std::path::PathBuf,
    ) -> HostState {
        let rt = tokio::runtime::Handle::current();
        let kv_store = Arc::new(astrid_storage::MemoryKvStore::new());
        let kv = ScopedKvStore::new(kv_store, "capsule:test").unwrap();
        let secret_store: Arc<dyn SecretStore> =
            Arc::new(astrid_storage::KvSecretStore::new(kv.clone(), rt.clone()));

        let owner_mount = mount_at(owner_home).await;

        let gate = Arc::new(ManifestSecurityGate::new(
            make_manifest_home_rw(),
            workspace_root.clone(),
            Some(owner_home.to_path_buf()),
        )) as Arc<dyn CapsuleSecurityGate>;

        HostState {
            wasi_ctx: wasmtime_wasi::WasiCtxBuilder::new().build(),
            resource_table: wasmtime::component::ResourceTable::new(),
            store_limits: wasmtime::StoreLimitsBuilder::new().build(),
            principal: owner_principal,
            capsule_uuid: uuid::Uuid::new_v4(),
            caller_context: None,
            invocation_kv: None,
            capsule_log: None,
            capsule_id: CapsuleId::from_static("test-capsule"),
            workspace_root,
            vfs: Arc::new(astrid_vfs::HostVfs::new()),
            vfs_root_handle: astrid_capabilities::DirHandle::new(),
            home: Some(owner_mount),
            tmp: None,
            invocation_home: None,
            invocation_tmp: None,
            invocation_secret_store: None,
            invocation_capsule_log: None,
            invocation_profile: None,
            overlay_vfs: None,
            upper_dir: None,
            kv,
            event_bus: astrid_events::EventBus::with_capacity(128),
            ipc_limiter: astrid_events::ipc::IpcRateLimiter::new(),
            subscriptions: HashMap::new(),
            next_subscription_id: 1,
            config: HashMap::new(),
            secret_env: std::collections::HashSet::new(),
            ipc_publish_patterns: Vec::new(),
            ipc_subscribe_patterns: Vec::new(),
            security: Some(gate),
            hook_manager: None,
            capsule_registry: None,
            runtime_handle: rt,
            has_uplink_capability: false,
            inbound_tx: None,
            registered_uplinks: Vec::new(),
            cli_socket_listener: None,
            active_streams: HashMap::new(),
            next_stream_id: 1,
            active_http_streams: HashMap::new(),
            next_http_stream_id: 1,
            lifecycle_phase: None,
            secret_store,
            ready_tx: None,
            host_semaphore: Arc::new(Semaphore::new(4)),
            cancel_token: CancellationToken::new(),
            session_token: None,
            interceptor_handles: Vec::new(),
            allowance_store: None,
            identity_store: None,
            background_processes: HashMap::new(),
            next_process_id: 1,
            process_tracker: Arc::new(ProcessTracker::new()),
        }
    }

    /// Drive one `fs_write` followed by one `read_file` from a blocking
    /// context, simulating a WASM guest calling these sync host functions.
    async fn write_then_read(
        mut state: HostState,
        path: &str,
        content: &[u8],
    ) -> (HostState, Result<Vec<u8>, String>) {
        let p = path.to_string();
        let c = content.to_vec();
        let (state, read) = tokio::task::spawn_blocking(move || {
            state.write_file(p.clone(), c).expect("write_file");
            let read = state.read_file(p);
            (state, read)
        })
        .await
        .expect("spawn_blocking join");
        (state, read)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn home_routes_to_invocation_principal_when_installed() {
        // owner = "capsule-owner", invoker = "alice". Write through `home://note.txt`
        // must land in Alice's physical dir, NOT the owner's.
        let tmp = tempfile::tempdir().unwrap();
        let owner_root = tmp.path().join("home/capsule-owner");
        let alice_root = tmp.path().join("home/alice");
        std::fs::create_dir_all(&owner_root).unwrap();
        std::fs::create_dir_all(&alice_root).unwrap();

        let owner = astrid_core::PrincipalId::new("capsule-owner").unwrap();
        let alice = astrid_core::PrincipalId::new("alice").unwrap();
        let mut state = make_host_state(owner, &owner_root, tmp.path().to_path_buf()).await;

        // Simulate `invoke_interceptor` installing invocation context for alice.
        state.caller_context = Some(ctx_for(&alice));
        state.invocation_home = Some(mount_at(&alice_root).await);

        let (_state, read) = write_then_read(state, "home://note.txt", b"alice-data").await;
        assert_eq!(read.expect("read ok"), b"alice-data");

        // Physical check: Alice's file exists, owner's does not.
        let alice_file = alice_root.join("note.txt");
        let owner_file = owner_root.join("note.txt");
        assert_eq!(std::fs::read(&alice_file).unwrap(), b"alice-data");
        assert!(
            !owner_file.exists(),
            "owner's home must not receive the write"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn home_falls_back_to_load_time_when_no_invocation() {
        // No invocation context: write routes to the owner's home (legacy
        // single-tenant behavior). This guards against accidental regressions
        // that would treat a missing invocation as a denial.
        let tmp = tempfile::tempdir().unwrap();
        let owner_root = tmp.path().join("home/capsule-owner");
        std::fs::create_dir_all(&owner_root).unwrap();

        let owner = astrid_core::PrincipalId::new("capsule-owner").unwrap();
        let state = make_host_state(owner, &owner_root, tmp.path().to_path_buf()).await;

        let (_state, read) = write_then_read(state, "home://note.txt", b"owner-data").await;
        assert_eq!(read.expect("read ok"), b"owner-data");
        assert_eq!(
            std::fs::read(owner_root.join("note.txt")).unwrap(),
            b"owner-data"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn home_writes_isolated_across_principals_on_shared_state() {
        // Same HostState, two sequential invocations for different principals:
        // each principal's write lands under its own physical tree and neither
        // can read the other's content through `home://`.
        let tmp = tempfile::tempdir().unwrap();
        let owner_root = tmp.path().join("home/capsule-owner");
        let alice_root = tmp.path().join("home/alice");
        let bob_root = tmp.path().join("home/bob");
        for d in [&owner_root, &alice_root, &bob_root] {
            std::fs::create_dir_all(d).unwrap();
        }

        let owner = astrid_core::PrincipalId::new("capsule-owner").unwrap();
        let alice = astrid_core::PrincipalId::new("alice").unwrap();
        let bob = astrid_core::PrincipalId::new("bob").unwrap();
        let mut state = make_host_state(owner, &owner_root, tmp.path().to_path_buf()).await;

        // Alice's invocation.
        state.caller_context = Some(ctx_for(&alice));
        state.invocation_home = Some(mount_at(&alice_root).await);
        let (mut state, read) = write_then_read(state, "home://note.txt", b"alice-content").await;
        assert_eq!(read.expect("alice read"), b"alice-content");

        // Clear (as invoke_interceptor does on exit), then Bob's invocation.
        state.caller_context = None;
        state.invocation_home = None;
        state.caller_context = Some(ctx_for(&bob));
        state.invocation_home = Some(mount_at(&bob_root).await);
        let (_state, read) = write_then_read(state, "home://note.txt", b"bob-content").await;
        assert_eq!(read.expect("bob read"), b"bob-content");

        // Physical-layer assertion: each principal wrote to their own tree.
        assert_eq!(
            std::fs::read(alice_root.join("note.txt")).unwrap(),
            b"alice-content"
        );
        assert_eq!(
            std::fs::read(bob_root.join("note.txt")).unwrap(),
            b"bob-content"
        );
        assert!(
            !owner_root.join("note.txt").exists(),
            "owner's home received no writes"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn home_traversal_into_other_principal_denied() {
        // Alice's invocation tries to escape her root via `..`. The security
        // gate's parent-dir-rejection fires first — path never reaches the VFS.
        let tmp = tempfile::tempdir().unwrap();
        let owner_root = tmp.path().join("home/capsule-owner");
        let alice_root = tmp.path().join("home/alice");
        let bob_root = tmp.path().join("home/bob");
        for d in [&owner_root, &alice_root, &bob_root] {
            std::fs::create_dir_all(d).unwrap();
        }
        // Seed Bob's file so the test would actually read it if the gate missed.
        std::fs::write(bob_root.join("secret.txt"), b"bob-secret").unwrap();

        let owner = astrid_core::PrincipalId::new("capsule-owner").unwrap();
        let alice = astrid_core::PrincipalId::new("alice").unwrap();
        let mut state = make_host_state(owner, &owner_root, tmp.path().to_path_buf()).await;
        state.caller_context = Some(ctx_for(&alice));
        state.invocation_home = Some(mount_at(&alice_root).await);

        let err =
            tokio::task::spawn_blocking(move || state.read_file("home://../bob/secret.txt".into()))
                .await
                .expect("join")
                .expect_err("traversal must be denied");
        assert!(
            err.contains("denied") || err.contains("escapes"),
            "expected denial, got: {err}"
        );
    }
}
