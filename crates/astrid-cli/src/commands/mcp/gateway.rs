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
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, Result};
use rmcp::ServiceExt;
use rmcp::service::{Peer, RoleServer};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use super::idle::{ATTACH_IDLE_EOF, IdleEof, is_idle};

use super::lifecycle::{
    ATTACH_REGISTRATION_VERSION, AttachRegistration, GatewayReady, prepare_gateway_socket,
    remove_gateway_ready, write_gateway_ready,
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
        }
    }

    /// Get or establish the one daemon uplink for `principal`.
    async fn client_for(&self, principal: &astrid_core::PrincipalId) -> Result<Client> {
        let key = principal.to_string();
        if let Some(client) = self.clients.lock().await.get(&key).cloned() {
            return Ok(client);
        }

        // Serialize first-use handshakes so two simultaneous attaches for a
        // new principal cannot create duplicate long-lived uplinks/watchers.
        let _initialize = self.initialize.lock().await;
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
        tokio::spawn(super::watch::run_many(
            peers,
            key.clone(),
            self.daemon_root.clone(),
        ));
        info!(principal = %key, "MCP gateway opened persistent principal uplink");
        Ok(shared)
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
    let daemon_root = std::env::current_dir().context("failed to read MCP gateway cwd")?;

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
    // accepting any attach registration.
    state.client_for(&caller).await?;

    let socket_path = prepare_gateway_socket().await?;
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
    info!(
        principal = %caller,
        socket = %socket_path.display(),
        "MCP gateway ready"
    );

    let result = accept_loop(listener, state).await;
    remove_gateway_ready();
    let _ = std::fs::remove_file(socket_path);
    result
}

async fn accept_loop(listener: UnixListener, state: Arc<GatewayState>) -> Result<ExitCode> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("MCP gateway listener failed")?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = serve_attach(stream, state).await {
                warn!(error = %error, "MCP gateway attach session ended with an error");
            }
        });
    }
}

async fn serve_attach(stream: UnixStream, state: Arc<GatewayState>) -> Result<()> {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let registration = read_registration(&mut reader).await?;
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
    let cancel = CancellationToken::new();
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
    let registration: AttachRegistration =
        serde_json::from_slice(&line).context("MCP attach registration is not valid JSON")?;
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
    Ok(registration)
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
