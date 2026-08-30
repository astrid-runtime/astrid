//! Native filesystem lease lifecycle and private callback service.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use astrid_core::PrincipalId;
use astrid_core::local_transport::{self, LocalListener, LocalStream};
use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_MAX_IO_BYTES, STORAGE_FILESYSTEM_PROTOCOL_V1,
    STORAGE_FILESYSTEM_PROTOCOL_V2, STORAGE_FILESYSTEM_SERVICE_LAUNCH_SCHEMA_V1,
    STORAGE_FILESYSTEM_SERVICE_READY_SCHEMA_V1, StorageFilesystemEntryKindV1,
    StorageFilesystemEntryV1, StorageFilesystemFailureV1, StorageFilesystemOperationV1,
    StorageFilesystemOutcomeV1, StorageFilesystemResponseV1, StorageFilesystemSuccessV1,
    StorageFilesystemTargetV1, StorageMountLeaseV1, StorageProviderParentLifetimeV1,
    StorageProviderServiceLaunchV1, StorageProviderServiceReadyV1,
    storage_provider_service_ready_challenge,
};
use astrid_core::storage_provider::{
    StorageMountId, StorageProviderAccessV1, StorageProviderViewV1,
};
use astrid_storage::{
    AstridFilesystem, FilesystemEntry, FilesystemEntryKind, FilesystemError, FilesystemPath,
    OwnerSubtreeFilesystem, StateOwner, WorkspaceBranchStore,
};
use base64::Engine as _;
use rand::{TryRng as _, rngs::SysRng};
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{oneshot, watch};

use crate::Kernel;

mod callback_wire;
mod filesystem;
use callback_wire::{CallbackRequest, CallbackResponse, read_request, response_v2, write_response};
use filesystem::{PrefixedFilesystem, execute_blocking};
#[cfg(test)]
mod admission;
mod cleanup;
mod lifecycle;
#[cfg(test)]
pub(crate) use admission::arm_issue_admission_gate;
#[cfg(test)]
pub(crate) use admission::clear_last_authorized_caller_for_test;
#[cfg(test)]
pub(crate) use admission::last_authorized_caller_uid;
#[cfg(test)]
pub(crate) use cleanup::MountCleanupStage;
use cleanup::cleanup_resource_paths;
#[cfg(test)]
pub(crate) use lifecycle::revoke_lease;
pub(crate) use lifecycle::{
    MountAdmission, MountGrant, MountOwnerScope, PrincipalBinding, lease_status_from_grant,
    mount_owner_scope_from_check, revoke_all_leases_for_principal, revoke_from_grant,
    sync_lease_from_grant,
};
use lifecycle::{
    PublicationProof, cleanup_unpublished, expire_idle_mapped_lease, refuse_if_retiring,
    revalidate_publication,
};
#[cfg(test)]
pub(crate) use lifecycle::{
    clear_cleanup_fault_for_test, expire_lease_for_test, inject_cleanup_fault_for_test,
};
#[cfg(test)]
pub(crate) use lifecycle::{lease_status, sync_lease};
#[cfg(any(unix, windows))]
use retained_jobs::{
    drain_accepted_tasks, drain_blocking_jobs, endpoint_became_absent, finish_retained_jobs,
};
#[cfg(any(unix, windows))]
mod process_broker;
#[cfg(any(unix, windows))]
mod retained_jobs;
#[cfg(any(unix, windows))]
pub(crate) use process_broker::KernelProcessStorageMountBroker;
pub(crate) use process_broker::ProcessStopPolicy;
#[cfg(all(test, any(unix, windows)))]
pub(super) use process_broker::{platform_process_provider_name, validate_process_provider_ready};

const LEASE_IDLE_TTL_SECS: u64 = 60 * 60;
/// Bound listener shutdown waits without turning a stalled listener into an
/// endpoint-removal race; timed-out cleanup remains mapped for retry.
const LISTENER_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Cancel idle callback connections quickly, but never use this bound to
/// discard a blocking filesystem job that has already been admitted.
const ACCEPTED_TASK_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const LEASE_MANIFEST_NAME: &str = "lease.json";

/// A synchronous admission ticket for callback or renewal work.
///
/// Revocation marks the lease under the same lock, so either admission is
/// linearized before revocation or the operation observes the revoked lease.
struct AdmissionGuard<'a> {
    _guard: std::sync::MutexGuard<'a, ()>,
}
/// In-memory authority fixed when a native filesystem lease is issued.
pub(crate) struct StorageMountLeaseState {
    mount_id: StorageMountId,
    requested_by: PrincipalId,
    requested_by_uid: astrid_core::PrincipalUid,
    owner: StateOwner,
    view: StorageProviderViewV1,
    target: StorageFilesystemTargetV1,
    access: StorageProviderAccessV1,
    provider: String,
    mountpoint: PathBuf,
    resource_path: PathBuf,
    callback_path: PathBuf,
    token_hash: [u8; 32],
    expires_at_epoch_secs: AtomicU64,
    revoked: AtomicBool,
    admission: std::sync::Mutex<()>,
    dirty: AtomicBool,
    in_flight_mutations: AtomicU64,
    shutdown_tx: watch::Sender<bool>,
    accepted_tasks: tokio::sync::Mutex<tokio::task::JoinSet<()>>,
    /// Filesystem workers retained across callback-connection cancellation.
    blocking_jobs: tokio::sync::Mutex<tokio::task::JoinSet<()>>,
    drain_timeouts: std::sync::Mutex<DrainTimeouts>,
    #[cfg(all(test, any(unix, windows)))]
    token_for_test: String,
    /// Set after the listener task has dropped its backend listener handle.
    ///
    /// Windows named-pipe endpoints are kernel objects rather than removable
    /// filesystem entries. Cleanup must wait for this acknowledgement before
    /// asking the transport backend to remove the endpoint.
    listener_closed_tx: watch::Sender<bool>,
    #[cfg(test)]
    mutation_test_gate: std::sync::Mutex<Option<Arc<MutationTestGate>>>,
    #[cfg(test)]
    cleanup_fault: std::sync::Mutex<Option<MountCleanupStage>>,
    /// Durable marker proving a mapped lease's host resources were removed.
    cleanup_ledger_path: PathBuf,
}

struct InFlightMutation {
    count: Arc<StorageMountLeaseState>,
}

impl InFlightMutation {
    fn begin(state: &Arc<StorageMountLeaseState>) -> Self {
        state.in_flight_mutations.fetch_add(1, Ordering::AcqRel);
        Self {
            count: Arc::clone(state),
        }
    }
}

impl Drop for InFlightMutation {
    fn drop(&mut self) {
        self.count
            .in_flight_mutations
            .fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
struct MutationTestGate {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

#[derive(Clone, Copy)]
struct DrainTimeouts {
    accepted_task: std::time::Duration,
    listener_shutdown: std::time::Duration,
}

impl StorageMountLeaseState {
    fn is_owned_by(&self, caller: astrid_core::PrincipalUid) -> bool {
        self.requested_by_uid == caller
    }

    fn is_live(&self) -> bool {
        !self.revoked.load(Ordering::Acquire)
            && now_epoch_secs() <= self.expires_at_epoch_secs.load(Ordering::Acquire)
    }

    async fn wait_listener_closed(&self) -> bool {
        let mut closed = self.listener_closed_tx.subscribe();
        let wait = async {
            while !*closed.borrow() {
                if closed.changed().await.is_err() {
                    return false;
                }
            }
            true
        };
        tokio::time::timeout(self.drain_timeouts().listener_shutdown, wait)
            .await
            .unwrap_or(false)
    }

    #[cfg(test)]
    fn set_drain_timeouts_for_test(&self, timeout: std::time::Duration) {
        *self
            .drain_timeouts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = DrainTimeouts {
            accepted_task: timeout,
            listener_shutdown: timeout,
        };
    }

    fn drain_timeouts(&self) -> DrainTimeouts {
        *self
            .drain_timeouts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn is_revoked_for_test(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    #[cfg(all(test, any(unix, windows)))]
    pub(crate) fn callback_identity_for_test(&self) -> (std::path::PathBuf, String) {
        (self.callback_path.clone(), self.token_for_test.clone())
    }

    fn renew(&self) {
        self.expires_at_epoch_secs.store(
            now_epoch_secs().saturating_add(LEASE_IDLE_TTL_SECS),
            Ordering::Release,
        );
    }

    fn try_admit(&self) -> Option<AdmissionGuard<'_>> {
        let guard = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.is_live() {
            return None;
        }
        self.renew();
        Some(AdmissionGuard { _guard: guard })
    }

    fn public_lease(&self, token: String) -> StorageMountLeaseV1 {
        StorageMountLeaseV1 {
            mount_id: self.mount_id,
            view: self.view.clone(),
            access: self.access,
            resource_path: self.resource_path.clone(),
            callback_path: self.callback_path.clone(),
            lease_token: token,
            expires_at_epoch_secs: self.expires_at_epoch_secs.load(Ordering::Acquire),
        }
    }
}

/// Resolve and issue one native mount lease.
pub(crate) async fn issue_lease(
    kernel: &Arc<Kernel>,
    admission: &MountAdmission,
    view: StorageProviderViewV1,
    target: StorageFilesystemTargetV1,
    access: StorageProviderAccessV1,
    provider: String,
    mountpoint: PathBuf,
) -> Result<StorageMountLeaseV1, String> {
    validate_issue_request(&provider, &mountpoint)?;
    #[cfg(test)]
    admission::record_authorized_caller(kernel, admission.caller().uid());
    refuse_if_retiring(kernel, admission.alias(), &view).await?;
    let (owner, target, proof) = resolve_owner(kernel, admission, access, &view, target).await?;
    #[cfg(test)]
    admission::pause_issue_admission_for_test(kernel).await;
    // Publication and drain share this lock. Recheck the authorized UID
    // binding, live policy, and owner facts here so an issue either
    // inserts before drain or sees drift and inserts nothing. The test
    // barrier stays above this lock, immediately after resolve_owner.
    let _publication = kernel.storage_mount_mutations.lock().await;
    revalidate_publication(kernel, admission, owner, &proof).await?;
    publish_issued_lease(
        kernel,
        admission.caller(),
        owner,
        view,
        target,
        access,
        provider,
        mountpoint,
    )
}

#[cfg(test)]
pub(crate) fn test_mount_admission(
    kernel: &Kernel,
    caller: &PrincipalId,
    owner_scope: MountOwnerScope,
) -> MountAdmission {
    MountAdmission::capture(kernel, caller, owner_scope).expect("test mount admission")
}

fn validate_issue_request(provider: &str, mountpoint: &Path) -> Result<(), String> {
    if provider.is_empty() || provider.len() > 128 || provider.chars().any(char::is_control) {
        return Err("native storage provider identity is invalid".to_owned());
    }
    if !mountpoint.is_absolute() {
        return Err("native storage mountpoint must be absolute".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn publish_issued_lease(
    kernel: &Arc<Kernel>,
    caller: &PrincipalBinding,
    owner: StateOwner,
    view: StorageProviderViewV1,
    target: StorageFilesystemTargetV1,
    access: StorageProviderAccessV1,
    provider: String,
    mountpoint: PathBuf,
) -> Result<StorageMountLeaseV1, String> {
    let mount_id = StorageMountId::new();
    #[cfg(unix)]
    let resource_path = private_mount_resource_path(mount_id)?;
    #[cfg(not(unix))]
    let resource_path = kernel
        .astrid_home
        .run_dir()
        .join("mounts")
        .join(mount_id.to_string());
    astrid_core::platform_fs::ensure_private_directory(&resource_path)
        .map_err(|error| format!("create private mount resource: {error}"))?;
    let (token, token_hash) = generate_lease_token()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (listener_closed_tx, _) = watch::channel(false);
    let cleanup_ledger_path = kernel
        .astrid_home
        .run_dir()
        .join("mount-cleanup")
        .join(format!("{mount_id}.cleaned"));
    #[cfg(unix)]
    let callback_path = resource_path.join("control.sock");
    #[cfg(not(unix))]
    let callback_path = resource_path.join("control.endpoint");
    let state = Arc::new(StorageMountLeaseState {
        mount_id,
        requested_by: caller.alias().clone(),
        requested_by_uid: caller.uid(),
        owner,
        view,
        target,
        access,
        provider,
        mountpoint,
        resource_path: resource_path.clone(),
        callback_path: callback_path.clone(),
        token_hash,
        expires_at_epoch_secs: AtomicU64::new(now_epoch_secs().saturating_add(LEASE_IDLE_TTL_SECS)),
        revoked: AtomicBool::new(false),
        admission: std::sync::Mutex::new(()),
        dirty: AtomicBool::new(false),
        in_flight_mutations: AtomicU64::new(0),
        shutdown_tx,
        accepted_tasks: tokio::sync::Mutex::new(tokio::task::JoinSet::new()),
        blocking_jobs: tokio::sync::Mutex::new(tokio::task::JoinSet::new()),
        drain_timeouts: std::sync::Mutex::new(DrainTimeouts {
            accepted_task: ACCEPTED_TASK_DRAIN_TIMEOUT,
            listener_shutdown: LISTENER_SHUTDOWN_TIMEOUT,
        }),
        #[cfg(all(test, any(unix, windows)))]
        token_for_test: token.clone(),
        listener_closed_tx,
        #[cfg(test)]
        mutation_test_gate: std::sync::Mutex::new(None),
        #[cfg(test)]
        cleanup_fault: std::sync::Mutex::new(None),
        cleanup_ledger_path,
    });

    #[cfg(any(unix, windows))]
    let listener = match bind_private_listener(&callback_path) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = cleanup_unpublished(&resource_path, &callback_path);
            return Err(error);
        },
    };
    #[cfg(not(any(unix, windows)))]
    {
        let _ = cleanup_unpublished(&resource_path, &callback_path);
        return Err(
            "native mount callback transport is not implemented on this platform".to_owned(),
        );
    }

    let lease = state.public_lease(token);
    if let Err(error) = write_private_manifest(&resource_path.join(LEASE_MANIFEST_NAME), &lease) {
        drop(listener);
        let cleanup = cleanup_unpublished(&resource_path, &callback_path);
        return Err(match cleanup {
            Ok(()) => format!("write private mount manifest: {error}"),
            Err(cleanup) => format!("write private mount manifest: {error}; {cleanup}"),
        });
    }
    kernel.storage_mounts.insert(mount_id, Arc::clone(&state));

    #[cfg(any(unix, windows))]
    {
        let weak_kernel = Arc::downgrade(kernel);
        astrid_runtime::spawn(serve_listener(weak_kernel, state, listener, shutdown_rx));
    }
    Ok(lease)
}

async fn resolve_owner(
    kernel: &Kernel,
    admission: &MountAdmission,
    access: StorageProviderAccessV1,
    view: &StorageProviderViewV1,
    target: StorageFilesystemTargetV1,
) -> Result<(StateOwner, StorageFilesystemTargetV1, PublicationProof), String> {
    let caller = admission.caller();
    let allow_cross_owner = admission.owner_scope().allows_foreign_issue(access);
    let (owner, mut proof) = authorize_view(kernel, caller, allow_cross_owner, view).await?;
    if let StorageFilesystemTargetV1::WorkspaceBranch { workspace } = &target {
        confirm_workspace_target(kernel, caller, allow_cross_owner, owner, *workspace)?;
        if !allow_cross_owner {
            proof = proof.with_workspace(*workspace);
        }
    }
    confirm_subtree_target(owner, &target)?;
    Ok((owner, target, proof))
}

async fn authorize_view(
    kernel: &Kernel,
    caller: &PrincipalBinding,
    allow_cross_owner: bool,
    view: &StorageProviderViewV1,
) -> Result<(StateOwner, PublicationProof), String> {
    Ok(match view {
        StorageProviderViewV1::Principal(principal) => {
            if principal != caller.alias() && !allow_cross_owner {
                return Err("principal filesystem view belongs to another principal".to_owned());
            }
            let viewed = PrincipalBinding::capture(kernel, principal)?;
            (
                StateOwner::Principal(viewed.uid()),
                PublicationProof::principal(viewed),
            )
        },
        StorageProviderViewV1::Fleet(fleet) => {
            if !allow_cross_owner {
                let ownership = kernel
                    .ownership_store()
                    .load()
                    .await
                    .map_err(|error| format!("read fleet ownership graph: {error}"))?;
                let admitted = ownership
                    .principal_owner(caller.uid())
                    .is_some_and(|owner| owner.fleet_uid == *fleet);
                if !admitted {
                    return Err(
                        "requested fleet filesystem is outside the caller's fleet".to_owned()
                    );
                }
            }
            (
                StateOwner::Fleet(*fleet),
                PublicationProof::fleet((!allow_cross_owner).then_some(*fleet)),
            )
        },
        StorageProviderViewV1::Admin => {
            if !allow_cross_owner {
                return Err("system filesystem view requires global storage authority".to_owned());
            }
            (StateOwner::System, PublicationProof::admin())
        },
    })
}

fn confirm_workspace_target(
    kernel: &Kernel,
    caller: &PrincipalBinding,
    allow_cross_owner: bool,
    owner: StateOwner,
    workspace: astrid_core::WorkspaceUid,
) -> Result<(), String> {
    let store = kernel
        .principal_store
        .clone()
        .ok_or_else(|| "native principal store is unavailable".to_owned())?;
    let descriptor = WorkspaceBranchStore::new(store.content())
        .describe(&owner, workspace)
        .map_err(|error| format!("resolve workspace branch: {error}"))?;
    // A caller-scoped branch lease may only target the branch that the
    // kernel's durable workspace binding assigned to that immutable UID.
    // Fleet membership authorizes the shared base owner, not another
    // principal's divergent branch. Global storage authority may inspect
    // an explicitly selected branch through the administrative path.
    if !allow_cross_owner && descriptor.binding_uid() != Some(caller.uid()) {
        return Err("workspace branch is not bound to the authenticated principal".to_owned());
    }
    Ok(())
}

fn confirm_subtree_target(
    owner: StateOwner,
    target: &StorageFilesystemTargetV1,
) -> Result<(), String> {
    let StorageFilesystemTargetV1::OwnerSubtree { prefix } = target else {
        return Ok(());
    };
    if prefix != "home" && prefix != "shared" {
        return Err("owner subtree prefix is not a kernel-admitted attachment".to_owned());
    }
    if prefix == "home" && !matches!(owner, StateOwner::Principal(_)) {
        return Err("principal HOME must resolve to the principal owner".to_owned());
    }
    if prefix == "shared" && !matches!(owner, StateOwner::Fleet(_)) {
        return Err("Fleet shared attachment requires a Fleet owner".to_owned());
    }
    FilesystemPath::new(prefix.clone())
        .map_err(|error| format!("resolve owner subtree prefix: {error}"))?;
    Ok(())
}

#[cfg(any(unix, windows))]
fn bind_private_listener(callback_path: &Path) -> Result<LocalListener, String> {
    let listener = local_transport::bind(callback_path)
        .map_err(|error| format!("bind private mount callback endpoint: {error}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(callback_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("restrict private mount callback socket: {error}"))?;
        validate_private_listener(callback_path)?;
    }

    Ok(listener)
}

#[cfg(unix)]
fn validate_private_listener(callback_path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::symlink_metadata(callback_path)
        .map_err(|error| format!("inspect private mount callback socket: {error}"))?;
    if !metadata.file_type().is_socket() {
        return Err("private mount callback path is not a socket".to_owned());
    }
    if metadata.uid() != nix::unistd::getuid().as_raw() {
        return Err("private mount callback socket is foreign-owned".to_owned());
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err("private mount callback socket is not owner-only".to_owned());
    }
    astrid_core::platform_fs::validate_no_extended_acl(callback_path)
        .map_err(|error| format!("validate private mount callback ACL: {error}"))?;
    let parent = callback_path
        .parent()
        .ok_or_else(|| "private mount callback socket has no parent".to_owned())?;
    astrid_core::platform_fs::validate_private_directory(parent)
        .map_err(|error| format!("validate private mount callback parent: {error}"))?;
    Ok(())
}

#[cfg(unix)]
fn private_mount_resource_path(mount_id: StorageMountId) -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    let temporary_root = "/private/tmp";
    #[cfg(not(target_os = "macos"))]
    let temporary_root = "/tmp";
    let root =
        PathBuf::from(temporary_root).join(format!("astrid-mounts-{}", nix::unistd::getuid()));
    astrid_core::platform_fs::ensure_private_directory(&root)
        .map_err(|error| format!("create private mount resource root: {error}"))?;
    Ok(root.join(mount_id.to_string()))
}

#[cfg(any(unix, windows))]
async fn serve_listener(
    kernel: std::sync::Weak<Kernel>,
    state: Arc<StorageMountLeaseState>,
    listener: LocalListener,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let expiry_period = std::time::Duration::from_mins(1);
    let first_expiry_check = tokio::time::Instant::now()
        .checked_add(expiry_period)
        .expect("one-minute mount expiry interval must fit in a monotonic instant");
    let mut expiry_check = tokio::time::interval_at(first_expiry_check, expiry_period);
    expiry_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Windows acceptance claims a connected pipe, installs its replacement,
    // then pre-reads one byte before authenticating the client. Keep that one
    // future alive across harmless expiry ticks: recreating it on every
    // `select!` iteration could drop a claimed pipe and break a valid client.
    let mut accepted = Box::pin(local_transport::accept(&listener));
    let mut expired = false;
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            _ = expiry_check.tick() => {
                if !state.revoked.load(Ordering::Acquire)
                    && now_epoch_secs() > state.expires_at_epoch_secs.load(Ordering::Acquire)
                {
                    let _ = state.shutdown_tx.send(true);
                    expired = true;
                    break;
                }
            },
            result = accepted.as_mut() => {
                accepted.set(local_transport::accept(&listener));
                match result {
                    Ok(stream) => {
                        let Some(kernel) = kernel.upgrade() else { break };
                        let connection_state = Arc::clone(&state);
                        let bookkeeping_state = Arc::clone(&state);
                        let mut accepted_tasks = bookkeeping_state.accepted_tasks.lock().await;
                        while let Some(result) = accepted_tasks.try_join_next() {
                            let _ = result;
                        }
                        accepted_tasks.spawn(async move {
                            handle_connection(kernel, connection_state, stream).await;
                        });
                    },
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof | io::ErrorKind::WouldBlock
                        ) => {},
                    Err(_) => break,
                }
            }
        }
    }

    // The accept future borrows the listener and may hold a backend-specific
    // pending handle. Drop it before releasing the listener so Windows can
    // observe the named-pipe endpoint as absent.
    drop(accepted);
    drop(listener);
    let accepted_drained = drain_accepted_tasks(&state).await;
    let blocking_drained = accepted_drained && drain_blocking_jobs(&state).await;
    if !blocking_drained {
        tracing::warn!("storage mount retained filesystem jobs exceeded their drain bound");
        finish_retained_jobs(&state).await;
        return;
    }
    if !endpoint_became_absent(&state.callback_path).await {
        return;
    }
    state.listener_closed_tx.send_replace(true);

    if expired {
        if let Some(kernel) = kernel.upgrade() {
            expire_idle_mapped_lease(&kernel, &state).await;
        } else {
            let _ = cleanup_resource_paths(&state.resource_path, &state.callback_path, None);
        }
    }
}

#[cfg(any(unix, windows))]
async fn handle_connection(
    kernel: Arc<Kernel>,
    state: Arc<StorageMountLeaseState>,
    mut stream: LocalStream,
) {
    loop {
        let Ok(Some(request)) = read_request(&mut stream).await else {
            return;
        };
        let response = dispatch_request(&kernel, &state, request).await;
        if write_response(&mut stream, response).await.is_err() {
            return;
        }
    }
}

async fn dispatch_request(
    kernel: &Arc<Kernel>,
    state: &Arc<StorageMountLeaseState>,
    callback: CallbackRequest,
) -> CallbackResponse {
    let request = callback.request;
    let request_id = request.request_id.clone();
    let outcome = if !state.is_live() {
        failure("stale-lease", "storage mount lease is expired or revoked")
    } else if !token_matches(&state.token_hash, &request.lease_token) {
        failure("unauthorized", "storage mount lease token is invalid")
    } else if state.try_admit().is_none() {
        failure("stale-lease", "storage mount lease is expired or revoked")
    } else {
        execute_operation(
            std::sync::Arc::clone(kernel),
            std::sync::Arc::clone(state),
            request.operation,
        )
        .await
    };
    let response = StorageFilesystemResponseV1 {
        protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V1,
        request_id,
        outcome,
    };
    match callback.response_version {
        STORAGE_FILESYSTEM_PROTOCOL_V1 => CallbackResponse::V1(response),
        STORAGE_FILESYSTEM_PROTOCOL_V2 => CallbackResponse::V2(response_v2(response)),
        _ => unreachable!("read_request validated the callback protocol version"),
    }
}

async fn execute_operation(
    kernel: Arc<Kernel>,
    state: Arc<StorageMountLeaseState>,
    operation: StorageFilesystemOperationV1,
) -> StorageFilesystemOutcomeV1 {
    let is_mutation = is_mutation(&operation);
    if !requires_mutation_serialization(&operation) && state.try_admit().is_none() {
        return failure("stale-lease", "storage mount lease is expired or revoked");
    }
    let is_sync = matches!(&operation, StorageFilesystemOperationV1::Sync);
    if is_mutation && state.access != StorageProviderAccessV1::ReadWrite {
        return failure("read-only", "storage mount lease is read-only");
    }
    let mutation_guard = if requires_mutation_serialization(&operation) {
        let guard = kernel.storage_mount_mutations.clone().lock_owned().await;
        if !state.is_live() {
            return failure("stale-lease", "storage mount lease is expired or revoked");
        }
        Some(guard)
    } else {
        None
    };
    let in_flight = is_mutation.then(|| InFlightMutation::begin(&state));
    let Some(store) = kernel.principal_store.clone() else {
        return failure("unavailable", "native principal store is unavailable");
    };
    let owner = state.owner;
    let target = state.target.clone();
    let retained_state = Arc::clone(&state);
    let (outcome_tx, outcome_rx) = oneshot::channel();
    state.blocking_jobs.lock().await.spawn(async move {
        // The guard moves with the retained job: cancelling the callback
        // connection cannot release the publication/drain fence early.
        let _mutation_guard = mutation_guard;
        let _in_flight = in_flight;
        #[cfg(test)]
        if is_mutation {
            pause_mutation_for_test(&retained_state).await;
        }
        let result = tokio::task::spawn_blocking(move || match target {
            StorageFilesystemTargetV1::OwnerRoot => {
                let filesystem = AstridFilesystem::new(store.content(), owner);
                execute_blocking(&filesystem, operation)
            },
            StorageFilesystemTargetV1::WorkspaceBranch { workspace } => {
                let branches = WorkspaceBranchStore::new(store.content());
                let filesystem = branches.filesystem(owner, workspace);
                execute_blocking(&filesystem, operation)
            },
            StorageFilesystemTargetV1::OwnerSubtree { prefix } => {
                if prefix == "shared" {
                    let filesystem = AstridFilesystem::new_fleet_shared(store.content(), owner);
                    execute_blocking(&filesystem, operation)
                } else {
                    let filesystem = PrefixedFilesystem {
                        inner: AstridFilesystem::new(store.content(), owner),
                        prefix,
                    };
                    execute_blocking(&filesystem, operation)
                }
            },
        })
        .await;
        if let Ok(Ok(_)) = result.as_ref() {
            if is_mutation {
                retained_state.dirty.store(true, Ordering::Release);
            } else if is_sync {
                retained_state.dirty.store(false, Ordering::Release);
            }
        }
        let _ = outcome_tx.send(result.map_err(|error| error.to_string()));
    });
    let result = outcome_rx
        .await
        .unwrap_or_else(|_| Err("filesystem worker was cancelled".to_owned()));
    match result {
        Ok(Ok(success)) => StorageFilesystemOutcomeV1::Success(success),
        Ok(Err(error)) => map_filesystem_error(&error),
        Err(error) => failure("internal", &format!("filesystem worker failed: {error}")),
    }
}

#[cfg(test)]
async fn pause_mutation_for_test(state: &StorageMountLeaseState) {
    let gate = state
        .mutation_test_gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(gate) = gate {
        gate.entered.add_permits(1);
        if let Ok(permit) = gate.release.acquire().await {
            permit.forget();
        }
    }
}

fn entry(value: &FilesystemEntry) -> StorageFilesystemEntryV1 {
    StorageFilesystemEntryV1 {
        name: value.name().to_owned(),
        kind: match value.kind() {
            FilesystemEntryKind::File => StorageFilesystemEntryKindV1::File,
            FilesystemEntryKind::Directory => StorageFilesystemEntryKindV1::Directory,
        },
        logical_bytes: value.logical_bytes(),
    }
}

fn map_filesystem_error(error: &FilesystemError) -> StorageFilesystemOutcomeV1 {
    let code = match error {
        FilesystemError::InvalidPath(_) => "invalid-path",
        FilesystemError::NotFound(_) => "not-found",
        FilesystemError::IsDirectory(_) => "is-directory",
        FilesystemError::NotDirectory(_) => "not-directory",
        FilesystemError::AlreadyExists(_) => "already-exists",
        FilesystemError::DirectoryNotEmpty(_) => "directory-not-empty",
        FilesystemError::NamespaceConflict(_) => "namespace-conflict",
        FilesystemError::Staging(_) => "staging",
        FilesystemError::Content(_) => "storage",
    };
    failure(code, &error.to_string())
}

fn failure(code: &str, message: &str) -> StorageFilesystemOutcomeV1 {
    StorageFilesystemOutcomeV1::Failure(StorageFilesystemFailureV1 {
        code: code.to_owned(),
        message: message.chars().take(1024).collect(),
    })
}

fn is_mutation(operation: &StorageFilesystemOperationV1) -> bool {
    matches!(
        operation,
        StorageFilesystemOperationV1::Write { .. }
            | StorageFilesystemOperationV1::SetLength { .. }
            | StorageFilesystemOperationV1::Create { .. }
            | StorageFilesystemOperationV1::Remove { .. }
            | StorageFilesystemOperationV1::Rename { .. }
    )
}

fn requires_mutation_serialization(operation: &StorageFilesystemOperationV1) -> bool {
    is_mutation(operation) || matches!(operation, StorageFilesystemOperationV1::Sync)
}

fn generate_lease_token() -> Result<(String, [u8; 32]), String> {
    let mut secret = [0_u8; 32];
    SysRng
        .try_fill_bytes(&mut secret)
        .map_err(|error| format!("generate mount lease token: {error}"))?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
    Ok((token.clone(), token_hash(&token)))
}

fn token_hash(token: &str) -> [u8; 32] {
    blake3::derive_key(
        "astrid native storage mount lease token v1",
        token.as_bytes(),
    )
}

fn token_matches(expected: &[u8; 32], supplied: &str) -> bool {
    bool::from(expected.ct_eq(&token_hash(supplied)))
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
pub(crate) async fn execute_operation_for_test(
    kernel: Arc<Kernel>,
    state: Arc<StorageMountLeaseState>,
    operation: StorageFilesystemOperationV1,
) -> StorageFilesystemOutcomeV1 {
    execute_operation(kernel, state, operation).await
}

fn write_private_manifest(path: &Path, lease: &StorageMountLeaseV1) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(lease).map_err(io::Error::other)?;
    bytes.push(b'\n');
    astrid_core::platform_fs::atomic_write_private_file(path, &bytes)
}

#[cfg(all(test, any(unix, windows)))]
mod tests;
