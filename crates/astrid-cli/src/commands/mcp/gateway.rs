//! Persistent per-user MCP gateway.
//!
//! The gateway owns one private Unix listener and one authenticated broker
//! uplink for the principal that minted its attach capability. Short-lived
//! `mcp attach` processes register their host, project, and host-session id on
//! that listener, then stream raw MCP bytes. The listener stays alive after an
//! attach EOF; only the gateway process owns the daemon lifetime.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, Result};
use rmcp::ServiceExt;
use rmcp::service::{Peer, RoleServer};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use super::idle::{ATTACH_IDLE_EOF, IdleEof, is_idle};

use super::lifecycle::{
    ATTACH_REGISTRATION_VERSION, AttachRegistration, GATEWAY_CONTROL_VERSION, GatewayControlAck,
    GatewayControlOperation, GatewayControlRequest, GatewayReady, GatewayStartupLease,
    prepare_gateway_socket, remove_gateway_ready, remove_gateway_startup_lease,
    try_acquire_gateway_lifecycle, write_gateway_ready, write_gateway_startup_lease,
};
use super::server::AstridMcpServer;

/// A gateway-side attach cap. It is intentionally process-local and bounded:
/// a hostile host can open many sockets, but cannot make one principal consume
/// an unbounded number of broker sessions.
const MAX_ATTACHES: usize = 16;
const MAX_REGISTRATION_BYTES: usize = 16 * 1024;
/// A client must finish its tiny registration preface promptly. This is a
/// protocol `DoS` ceiling, not an operator tuning knob: half-open sockets must
/// not retain listener tasks indefinitely.
#[cfg(not(test))]
const REGISTRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(test)]
const REGISTRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

type Client = Arc<Mutex<crate::socket_client::SocketClient>>;
type Peers = Arc<Mutex<HashMap<String, Peer<RoleServer>>>>;

struct AttachSlot {
    id: Uuid,
    cancel: CancellationToken,
    last_activity: Arc<StdMutex<Instant>>,
    done: Arc<Notify>,
}

struct AttachReservation {
    admission: OwnedMutexGuard<()>,
    permit: OwnedSemaphorePermit,
}

/// Bound cooperative teardown before a replacement may be admitted. This is
/// a protocol safety ceiling: a predecessor that does not release its slot
/// promptly must never let a reconnect consume a second permit.
const REPLACEMENT_TIMEOUT: Duration = Duration::from_secs(1);

struct GatewayState {
    daemon_root: PathBuf,
    principal: astrid_core::PrincipalId,
    hook_token: String,
    clients: Mutex<HashMap<String, Client>>,
    peers: Mutex<HashMap<String, Peers>>,
    permits: Mutex<HashMap<String, Arc<Semaphore>>>,
    slots: Mutex<HashMap<String, AttachSlot>>,
    admission: Arc<Mutex<()>>,
    initialize: Mutex<()>,
    shutdown: CancellationToken,
    active_connections: AtomicUsize,
    connections_drained: Notify,
    watchers: Mutex<Vec<JoinHandle<()>>>,
    shutdown_result: Mutex<Option<GatewayControlAck>>,
    shutdown_finished: Notify,
    shutdown_ack_sent: Notify,
    stop_ack_waiters: AtomicUsize,
}

impl GatewayState {
    fn new(daemon_root: PathBuf, principal: astrid_core::PrincipalId, hook_token: String) -> Self {
        Self {
            daemon_root,
            principal,
            hook_token,
            clients: Mutex::new(HashMap::new()),
            peers: Mutex::new(HashMap::new()),
            permits: Mutex::new(HashMap::new()),
            slots: Mutex::new(HashMap::new()),
            admission: Arc::new(Mutex::new(())),
            initialize: Mutex::new(()),
            shutdown: CancellationToken::new(),
            active_connections: AtomicUsize::new(0),
            connections_drained: Notify::new(),
            watchers: Mutex::new(Vec::new()),
            shutdown_result: Mutex::new(None),
            shutdown_finished: Notify::new(),
            shutdown_ack_sent: Notify::new(),
            stop_ack_waiters: AtomicUsize::new(0),
        }
    }

    /// Get or establish the one daemon uplink for `principal`.
    async fn client_for(&self, principal: &astrid_core::PrincipalId) -> Result<Client> {
        if self.shutdown.is_cancelled() {
            anyhow::bail!("MCP gateway is shutting down");
        }
        let key = principal.to_string();
        if let Some(client) = self.clients.lock().await.get(&key).cloned() {
            return Ok(client);
        }

        // Serialize first-use handshakes so two simultaneous attaches for a
        // new principal cannot create duplicate long-lived uplinks/watchers.
        let _initialize = self.initialize.lock().await;
        if self.shutdown.is_cancelled() {
            anyhow::bail!("MCP gateway is shutting down");
        }
        if let Some(client) = self.clients.lock().await.get(&key).cloned() {
            return Ok(client);
        }

        let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
        let mut client = crate::socket_client::connect_for_workspace(
            session,
            principal.clone(),
            Some(&self.daemon_root),
        )
        .await
        .with_context(|| format!("failed to connect MCP gateway uplink for principal {key}"))?;
        super::require_authenticated_unless_anonymous(principal, client.is_authenticated())?;
        if super::broker_readiness_required(principal) {
            super::readiness::wait_for_broker(&mut client, principal)
                .await
                .with_context(|| format!("MCP broker readiness failed for principal {key}"))?;
        }

        let shared = Arc::new(Mutex::new(client));
        let peers = Arc::new(Mutex::new(HashMap::new()));
        self.clients
            .lock()
            .await
            .insert(key.clone(), Arc::clone(&shared));
        self.peers
            .lock()
            .await
            .insert(key.clone(), Arc::clone(&peers));
        let watcher = tokio::spawn(super::watch::run_many(
            peers,
            key.clone(),
            self.daemon_root.clone(),
            self.shutdown.clone(),
        ));
        self.watchers.lock().await.push(watcher);
        info!(principal = %key, "MCP gateway opened persistent principal uplink");
        Ok(shared)
    }

    async fn verify_uplink(&self) -> Result<()> {
        let client = self.client_for(&self.principal).await?;
        let mut client = client.lock().await;
        let principal = self.principal.clone();
        crate::socket_client::reconnect_for_workspace(
            &mut client,
            principal.clone(),
            Some(&self.daemon_root),
            |connected| {
                super::require_authenticated_unless_anonymous(
                    &principal,
                    connected.is_authenticated(),
                )
            },
        )
        .await
        .context("failed to recover the persistent daemon uplink")?;
        Ok(())
    }

    async fn peers_for(&self, principal: &str) -> Result<Peers> {
        self.peers
            .lock()
            .await
            .get(principal)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("MCP gateway principal channel was not initialized"))
    }

    async fn semaphore_for(&self, principal: &str) -> Arc<Semaphore> {
        self.permits
            .lock()
            .await
            .entry(principal.to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_ATTACHES)))
            .clone()
    }

    async fn acquire(&self, principal: &str) -> Result<OwnedSemaphorePermit> {
        let semaphore = self.semaphore_for(principal).await;
        if let Ok(permit) = semaphore.clone().try_acquire_owned() {
            return Ok(permit);
        }
        if self.evict_lru_idle().await
            && let Ok(permit) = semaphore.try_acquire_owned()
        {
            return Ok(permit);
        }
        anyhow::bail!(
            "MCP gateway attach limit reached for principal '{principal}' ({MAX_ATTACHES})"
        )
    }

    /// Reserve a host session through replacement, cap admission, and slot
    /// installation as one linearizable operation. The reservation owns the
    /// admission guard until `install` publishes the new slot.
    async fn reserve_session(
        &self,
        host_session_id: &str,
        principal: &str,
    ) -> Result<AttachReservation> {
        let admission = Arc::clone(&self.admission).lock_owned().await;
        if self.shutdown.is_cancelled() {
            anyhow::bail!("MCP gateway is shutting down");
        }
        self.replace_session(host_session_id).await?;
        let permit = self.acquire(principal).await?;
        Ok(AttachReservation { admission, permit })
    }

    async fn replace_session(&self, host_session_id: &str) -> Result<()> {
        let slot = self.slots.lock().await.remove(host_session_id);
        if let Some(slot) = slot {
            let notified = slot.done.notified();
            tokio::pin!(notified);
            slot.cancel.cancel();
            timeout(REPLACEMENT_TIMEOUT, notified)
                .await
                .with_context(|| {
                    format!(
                        "MCP gateway attach replacement teardown timed out for host session '{host_session_id}'"
                    )
                })?;
        }
        Ok(())
    }

    async fn evict_lru_idle(&self) -> bool {
        let mut slots = self.slots.lock().await;
        let idle_key = slots
            .iter()
            .filter(|(_, slot)| is_idle(&slot.last_activity, ATTACH_IDLE_EOF))
            .min_by_key(|(_, slot)| {
                slot.last_activity
                    .lock()
                    .map_or_else(|_| Instant::now(), |instant| *instant)
            })
            .map(|(key, _)| key.clone());
        let Some(key) = idle_key else {
            return false;
        };
        let Some(slot) = slots.remove(&key) else {
            return false;
        };
        drop(slots);
        let notified = slot.done.notified();
        tokio::pin!(notified);
        slot.cancel.cancel();
        timeout(Duration::from_secs(1), notified).await.is_ok()
    }

    async fn install_slot(&self, host_session_id: String, slot: AttachSlot) {
        self.slots.lock().await.insert(host_session_id, slot);
    }

    async fn take_slot_if(&self, host_session_id: &str, id: Uuid) -> bool {
        let mut slots = self.slots.lock().await;
        if slots.get(host_session_id).is_some_and(|slot| slot.id == id) {
            slots.remove(host_session_id);
            true
        } else {
            false
        }
    }

    /// Remove a slot, release its cap, then wake replacement/eviction waiters.
    async fn finish_slot(
        &self,
        host_session_id: &str,
        id: Uuid,
        permit: OwnedSemaphorePermit,
        done: Arc<Notify>,
    ) {
        self.take_slot_if(host_session_id, id).await;
        #[cfg(test)]
        let semaphore = self.semaphore_for(self.principal.as_ref()).await;
        drop(permit);
        #[cfg(test)]
        tests::probe_finish_slot(&semaphore);
        done.notify_waiters();
    }

    fn connection(self: &Arc<Self>) -> ConnectionGuard {
        self.active_connections.fetch_add(1, Ordering::AcqRel);
        ConnectionGuard {
            state: Arc::clone(self),
            active: true,
        }
    }

    async fn wait_for_connections(&self) {
        loop {
            let drained = self.connections_drained.notified();
            if self.active_connections.load(Ordering::Acquire) == 0 {
                return;
            }
            drained.await;
        }
    }

    async fn cancel_attach_slots(&self) {
        for slot in self.slots.lock().await.values() {
            slot.cancel.cancel();
        }
    }

    async fn finish_shutdown(&self, result: GatewayControlAck) {
        *self.shutdown_result.lock().await = Some(result);
        self.shutdown_finished.notify_waiters();
    }

    async fn wait_for_shutdown(&self) -> GatewayControlAck {
        loop {
            let finished = self.shutdown_finished.notified();
            if let Some(result) = self.shutdown_result.lock().await.clone() {
                return result;
            }
            finished.await;
        }
    }

    fn begin_stop_ack(&self) {
        self.stop_ack_waiters.fetch_add(1, Ordering::AcqRel);
    }

    fn finish_stop_ack(&self) {
        let remaining = self.stop_ack_waiters.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(remaining > 0, "shutdown ACK waiter count underflow");
        if remaining == 1 {
            // Unlike `notify_waiters`, `notify_one` retains a permit when the
            // run loop has not yet registered. The waiter count, not the
            // notification, is what prevents the first ACK from releasing run.
            self.shutdown_ack_sent.notify_one();
        }
    }

    async fn wait_for_stop_acks(&self) {
        loop {
            let delivered = self.shutdown_ack_sent.notified();
            if self.stop_ack_waiters.load(Ordering::Acquire) == 0 {
                return;
            }
            delivered.await;
        }
    }
}

struct StartupLeaseGuard {
    boot_token: String,
    armed: bool,
}

impl StartupLeaseGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StartupLeaseGuard {
    fn drop(&mut self) {
        if self.armed
            && let Err(error) = remove_gateway_startup_lease(Some(&self.boot_token))
        {
            warn!(error = %error, "failed to remove MCP gateway startup lease");
        }
    }
}

struct ConnectionGuard {
    state: Arc<GatewayState>,
    active: bool,
}

impl ConnectionGuard {
    fn release(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let previous = self.state.active_connections.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "gateway connection count underflow");
        if previous == 1 {
            self.state.connections_drained.notify_waiters();
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl AttachReservation {
    async fn install(
        self,
        state: &GatewayState,
        host_session_id: String,
        slot: AttachSlot,
    ) -> OwnedSemaphorePermit {
        let Self { admission, permit } = self;
        state.install_slot(host_session_id, slot).await;
        drop(admission);
        permit
    }
}

/// Run the durable MCP gateway until it is terminated.
pub(crate) async fn run(principal: Option<&str>) -> Result<ExitCode> {
    let caller = super::lifecycle::resolve_principal(principal)?;
    let lifecycle = try_acquire_gateway_lifecycle()?.ok_or_else(|| {
        anyhow::anyhow!("another MCP gateway startup or lifecycle is already active")
    })?;
    let daemon_root = std::env::current_dir().context("failed to read MCP gateway cwd")?;

    let boot_token = mint_boot_token();
    let gateway_exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("failed to resolve MCP gateway executable identity")?;
    let startup_lease = GatewayStartupLease {
        version: 1,
        principal: caller.to_string(),
        boot_token: boot_token.clone(),
        supervisor_pid: std::process::id(),
        gateway_pid: Some(std::process::id()),
        gateway_exe: Some(gateway_exe),
    };
    write_gateway_startup_lease(&startup_lease)?;
    let mut lease_guard = StartupLeaseGuard {
        boot_token: boot_token.clone(),
        armed: true,
    };

    // Gateway startup is the one place that may create the persistent daemon.
    // `mcp serve` remains the explicitly requested per-session/ephemeral path.
    crate::commands::daemon::ensure_persistent_daemon("mcp-gateway")
        .await
        .context("failed to ensure persistent Astrid daemon for MCP gateway")?;

    let hook_token = mint_hook_token();
    let state = Arc::new(GatewayState::new(
        daemon_root,
        caller.clone(),
        hook_token.clone(),
    ));
    // Warm the authenticated principal selected by `ready`/`gateway` before
    // accepting any attach registration. The lease was published first so this
    // slow, pre-listener generation remains authenticated-stop capable.
    state.client_for(&caller).await?;
    let socket_path = prepare_gateway_socket(&lifecycle).await?;
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind MCP gateway at {}", socket_path.display()))?;
    set_socket_mode(&socket_path)?;
    let ready = GatewayReady {
        version: 1,
        // The readiness record binds every attach to the authenticated
        // process principal that bootstrapped this gateway.
        principal: caller.to_string(),
        pid: std::process::id(),
        hook_token,
    };
    write_gateway_ready(&ready)?;
    lease_guard.disarm();
    info!(
        principal = %caller,
        socket = %socket_path.display(),
        "MCP gateway ready"
    );

    let accept_result = accept_loop(listener, Arc::clone(&state)).await;
    let control_stop = state.shutdown.is_cancelled();
    state.shutdown.cancel();
    let cleanup_result = shutdown_gateway(
        &state,
        (!control_stop).then_some(&ready),
        &socket_path,
        &boot_token,
    )
    .await;

    if control_stop {
        let ack = match (&accept_result, &cleanup_result) {
            (Ok(_), Ok(())) => {
                GatewayControlAck::success(GatewayControlOperation::Stop, std::process::id())
            },
            (Err(error), _) | (Ok(_), Err(error)) => GatewayControlAck::failure(
                GatewayControlOperation::Stop,
                std::process::id(),
                format!("{error:#}"),
            ),
        };
        state.finish_shutdown(ack).await;
        timeout(
            crate::commands::daemon_control::GRACE,
            state.wait_for_stop_acks(),
        )
        .await
        .context("shutdown stage gateway.final_ack_delivery")?;
    }

    combine_gateway_results(accept_result, cleanup_result)
}

fn combine_gateway_results(accept: Result<ExitCode>, cleanup: Result<()>) -> Result<ExitCode> {
    match (accept, cleanup) {
        (Ok(exit), Ok(())) => Ok(exit),
        (Err(primary), Ok(())) | (Ok(_), Err(primary)) => Err(primary),
        (Err(primary), Err(secondary)) => {
            anyhow::bail!("{primary:#}; additional gateway cleanup failure: {secondary:#}")
        },
    }
}

async fn accept_loop(listener: UnixListener, state: Arc<GatewayState>) -> Result<ExitCode> {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("MCP gateway listener failed")?;
                let state = Arc::clone(&state);
                // Count the connection before spawning its task. Otherwise a
                // simultaneous stop can observe zero, finish cleanup, and let
                // the not-yet-polled task start after teardown.
                let connection = state.connection();
                tokio::spawn(async move {
                    if let Err(error) = serve_connection(stream, state, connection).await {
                        warn!(error = %error, "MCP gateway connection ended with an error");
                    }
                });
            }
            () = state.shutdown.cancelled() => {
                // Stop handing out new transports. `run` can now drain the
                // connections already admitted, finish teardown, and publish
                // the one final ACK without waiting for this loop.
                return Ok(ExitCode::SUCCESS);
            },
        }
    }
}

async fn shutdown_gateway(
    state: &Arc<GatewayState>,
    ready_to_remove: Option<&GatewayReady>,
    socket_path: &Path,
    boot_token: &str,
) -> Result<()> {
    state.cancel_attach_slots().await;
    timeout(
        crate::commands::daemon_control::GRACE,
        state.wait_for_connections(),
    )
    .await
    .context("shutdown stage gateway.attach_drain: timed out")?;

    let watchers = std::mem::take(&mut *state.watchers.lock().await);
    let mut watcher_failure = None;
    for mut watcher in watchers {
        match timeout(crate::commands::daemon_control::GRACE, &mut watcher).await {
            Ok(Ok(())) => {},
            Ok(Err(error)) => {
                watcher_failure.get_or_insert_with(|| {
                    format!("shutdown stage gateway.uplink_teardown: {error}")
                });
            },
            Err(_) => {
                watcher.abort();
                let _ = watcher.await;
                watcher_failure.get_or_insert_with(|| {
                    "shutdown stage gateway.uplink_teardown: timed out".to_string()
                });
            },
        }
    }

    state.peers.lock().await.clear();
    state.clients.lock().await.clear();
    state.permits.lock().await.clear();
    if !state.slots.lock().await.is_empty() {
        anyhow::bail!("shutdown stage gateway.attach_slots: slots remained after teardown");
    }
    astrid_core::local_transport::remove_endpoint(socket_path).with_context(|| {
        format!(
            "shutdown stage gateway.listener_cleanup: {}",
            socket_path.display()
        )
    })?;
    if let Some(failure) = watcher_failure {
        anyhow::bail!(failure);
    }
    // During an authenticated control stop, the caller removes the exact
    // readiness record only after this process has exited. Natural/error
    // shutdowns have no such caller, so the gateway cleans its own record.
    if let Some(ready) = ready_to_remove {
        remove_gateway_ready(ready).context("shutdown stage gateway.ready_cleanup")?;
    }
    remove_gateway_startup_lease(Some(boot_token))
        .context("shutdown stage gateway.startup_cleanup")?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum GatewayRequest {
    Control(GatewayControlRequest),
    Attach(AttachRegistration),
}

async fn serve_connection(
    stream: UnixStream,
    state: Arc<GatewayState>,
    connection: ConnectionGuard,
) -> Result<()> {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let request = if state.shutdown.is_cancelled() {
        read_gateway_request(&mut reader).await?
    } else {
        tokio::select! {
            () = state.shutdown.cancelled() => read_gateway_request(&mut reader).await?,
            request = read_gateway_request(&mut reader) => request?,
        }
    };
    match request {
        GatewayRequest::Control(request) => {
            serve_control(request, write_half, state, Some(connection)).await
        },
        GatewayRequest::Attach(registration) => {
            serve_attach(registration, reader, write_half, state).await
        },
    }
}

async fn serve_attach(
    registration: AttachRegistration,
    reader: BufReader<tokio::io::ReadHalf<UnixStream>>,
    write_half: tokio::io::WriteHalf<UnixStream>,
    state: Arc<GatewayState>,
) -> Result<()> {
    let principal = authenticate_registration(&registration, &state)?;
    let workspace = validate_workspace(&registration.workspace_abs)?;
    let principal_key = principal.to_string();
    let host_session_id = registration.host_session_id.clone();
    let client = state.client_for(&principal).await?;
    let peers = state.peers_for(&principal_key).await?;
    let reservation = state
        .reserve_session(&host_session_id, &principal_key)
        .await?;
    let last_activity = Arc::new(StdMutex::new(Instant::now()));
    // A child token preserves per-session replacement while guaranteeing a
    // session admitted concurrently with stop inherits global cancellation.
    let cancel = state.shutdown.child_token();
    let done = Arc::new(Notify::new());
    let slot_id = Uuid::new_v4();
    let permit = reservation
        .install(
            &state,
            host_session_id.clone(),
            AttachSlot {
                id: slot_id,
                cancel: cancel.clone(),
                last_activity: Arc::clone(&last_activity),
                done: Arc::clone(&done),
            },
        )
        .await;
    let reader = IdleEof::new(reader, ATTACH_IDLE_EOF, last_activity);

    info!(
        principal = %principal_key,
        workspace = %workspace.display(),
        host_session_id = %registration.host_session_id,
        "MCP gateway accepted attach"
    );
    let server = AstridMcpServer::new(client, principal, state.daemon_root.clone(), workspace)
        .context("Failed to initialize the MCP request-state codec");
    let result = match server {
        Ok(server) => {
            run_attached_session(server, reader, write_half, peers, slot_id, cancel).await
        },
        Err(error) => Err(error),
    };
    state
        .finish_slot(&host_session_id, slot_id, permit, done)
        .await;
    result
}

async fn serve_control<W>(
    request: GatewayControlRequest,
    mut writer: W,
    state: Arc<GatewayState>,
    mut connection: Option<ConnectionGuard>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let pid = std::process::id();
    let authenticated = request.version == GATEWAY_CONTROL_VERSION
        && request.pid == pid
        && request.hook_token == state.hook_token;
    if !authenticated {
        let ack = GatewayControlAck::failure(
            request.operation,
            pid,
            "gateway control authority did not match this process",
        );
        write_control_ack(&mut writer, &ack).await?;
        return Ok(());
    }

    match request.operation {
        GatewayControlOperation::Health => {
            let ack = match state.verify_uplink().await {
                Ok(()) => GatewayControlAck::success(GatewayControlOperation::Health, pid),
                Err(error) => GatewayControlAck::failure(
                    GatewayControlOperation::Health,
                    pid,
                    format!("{error:#}"),
                ),
            };
            write_control_ack(&mut writer, &ack).await
        },
        GatewayControlOperation::Stop => {
            // Only an authenticated stop may release itself from the drain.
            // A forged stop remains counted until its rejection is delivered.
            drop(connection.take());
            state.begin_stop_ack();
            state.shutdown.cancel();
            let ack = state.wait_for_shutdown().await;
            let result = write_control_ack(&mut writer, &ack).await;
            state.finish_stop_ack();
            result
        },
    }
}

async fn write_control_ack<W>(writer: &mut W, ack: &GatewayControlAck) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes =
        serde_json::to_vec(ack).context("failed to encode gateway control acknowledgement")?;
    writer
        .write_all(&bytes)
        .await
        .context("failed to write gateway control acknowledgement")?;
    writer
        .write_all(b"\n")
        .await
        .context("failed to terminate gateway control acknowledgement")?;
    writer
        .shutdown()
        .await
        .context("failed to finish gateway control acknowledgement")
}

async fn run_attached_session<S, R>(
    server: S,
    reader: R,
    write_half: tokio::io::WriteHalf<UnixStream>,
    peers: Peers,
    slot_id: Uuid,
    cancel: CancellationToken,
) -> Result<()>
where
    S: rmcp::Service<RoleServer>,
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let running = server
        .serve_with_ct((reader, write_half), cancel.clone())
        .await
        .context("MCP gateway failed to initialize attach session")?;
    // Use the slot generation rather than the host session id so a delayed
    // predecessor cannot remove a replacement's peer from the shared watcher.
    let peer_key = slot_id.to_string();
    peers
        .lock()
        .await
        .insert(peer_key.clone(), running.peer().clone());
    let result = tokio::select! {
        result = running.waiting() => result.context("MCP gateway attach transport terminated abnormally"),
        () = cancel.cancelled() => Err(anyhow::anyhow!("MCP attach replaced or idle-evicted")),
    };
    peers.lock().await.remove(&peer_key);
    result.map(|_| ())
}

async fn read_registration<R>(reader: &mut BufReader<R>) -> Result<AttachRegistration>
where
    R: AsyncRead + Unpin,
{
    timeout(REGISTRATION_TIMEOUT, read_registration_inner(reader))
        .await
        .context("timed out reading MCP attach registration")?
}

async fn read_registration_inner<R>(reader: &mut BufReader<R>) -> Result<AttachRegistration>
where
    R: AsyncRead + Unpin,
{
    match read_gateway_request_inner(reader).await? {
        GatewayRequest::Attach(registration) => Ok(registration),
        GatewayRequest::Control(_) => anyhow::bail!("expected MCP attach registration"),
    }
}

async fn read_gateway_request<R>(reader: &mut BufReader<R>) -> Result<GatewayRequest>
where
    R: AsyncRead + Unpin,
{
    timeout(REGISTRATION_TIMEOUT, read_gateway_request_inner(reader))
        .await
        .context("timed out reading MCP gateway registration")?
}

async fn read_gateway_request_inner<R>(reader: &mut BufReader<R>) -> Result<GatewayRequest>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let mut terminated = false;
    for _ in 0..=MAX_REGISTRATION_BYTES {
        let byte = reader
            .read_u8()
            .await
            .context("failed to read MCP attach registration")?;
        if byte == b'\n' {
            terminated = true;
            break;
        }
        line.push(byte);
    }
    if !terminated {
        anyhow::bail!("MCP attach registration is missing or too large");
    }
    let request: GatewayRequest =
        serde_json::from_slice(&line).context("MCP gateway registration is not valid JSON")?;
    match &request {
        GatewayRequest::Control(control) => {
            if control.version != GATEWAY_CONTROL_VERSION {
                anyhow::bail!(
                    "unsupported MCP gateway control version {}",
                    control.version
                );
            }
            if control.pid == 0 || control.hook_token.trim().is_empty() {
                anyhow::bail!("MCP gateway control authority is incomplete");
            }
        },
        GatewayRequest::Attach(registration) => validate_registration(registration)?,
    }
    Ok(request)
}

fn validate_registration(registration: &AttachRegistration) -> Result<()> {
    if registration.version != ATTACH_REGISTRATION_VERSION {
        anyhow::bail!(
            "unsupported MCP attach registration version {}",
            registration.version
        );
    }
    super::lifecycle::resolve_principal(Some(&registration.principal))?;
    if registration.host.trim().is_empty() {
        anyhow::bail!("MCP attach registration has an empty host");
    }
    if registration.host_session_id.trim().is_empty() {
        anyhow::bail!("MCP attach registration has an empty host_session_id");
    }
    if registration.hook_token.trim().is_empty() {
        anyhow::bail!("MCP attach registration is missing hook_token");
    }
    validate_workspace(&registration.workspace_abs)?;
    Ok(())
}

fn authenticate_registration(
    registration: &AttachRegistration,
    state: &GatewayState,
) -> Result<astrid_core::PrincipalId> {
    let principal = super::lifecycle::resolve_principal(Some(&registration.principal))?;
    if principal != state.principal {
        anyhow::bail!(
            "MCP attach registration principal '{}' is not the authenticated gateway principal '{}'",
            principal,
            state.principal
        );
    }
    if registration.hook_token != state.hook_token {
        anyhow::bail!("MCP attach registration hook_token is invalid");
    }
    Ok(principal)
}

fn mint_hook_token() -> String {
    format!(
        "{}{}",
        Uuid::new_v4().as_simple(),
        Uuid::new_v4().as_simple()
    )
}

fn mint_boot_token() -> String {
    Uuid::new_v4().as_simple().to_string()
}

fn validate_workspace(value: &str) -> Result<PathBuf> {
    if value.is_empty() {
        anyhow::bail!("MCP attach workspace is empty");
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        anyhow::bail!("MCP attach workspace must be absolute: {value}");
    }
    std::fs::canonicalize(&path)
        .with_context(|| format!("failed to resolve MCP attach workspace {value}"))
}

fn set_socket_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;
