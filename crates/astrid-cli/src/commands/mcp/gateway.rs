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
use std::sync::Arc;

use anyhow::{Context, Result};
use rmcp::ServiceExt;
use rmcp::service::{Peer, RoleServer};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tracing::{info, warn};
use uuid::Uuid;

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
const REGISTRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

type Client = Arc<Mutex<crate::socket_client::SocketClient>>;
type Peers = Arc<Mutex<HashMap<String, Peer<RoleServer>>>>;

struct GatewayState {
    daemon_root: PathBuf,
    principal: astrid_core::PrincipalId,
    hook_token: String,
    clients: Mutex<HashMap<String, Client>>,
    peers: Mutex<HashMap<String, Peers>>,
    permits: Mutex<HashMap<String, Arc<Semaphore>>>,
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

    async fn acquire(&self, principal: &str) -> Result<OwnedSemaphorePermit> {
        let semaphore = self
            .permits
            .lock()
            .await
            .entry(principal.to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_ATTACHES)))
            .clone();
        semaphore.try_acquire_owned().map_err(|_| {
            anyhow::anyhow!(
                "MCP gateway attach limit reached for principal '{principal}' ({MAX_ATTACHES})"
            )
        })
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
    let permit = state.acquire(&principal_key).await?;
    let client = state.client_for(&principal).await?;
    let peers = state.peers_for(&principal_key).await?;

    info!(
        principal = %principal_key,
        workspace = %workspace.display(),
        host_session_id = %registration.host_session_id,
        "MCP gateway accepted attach"
    );
    let server = AstridMcpServer::new(client, principal, state.daemon_root.clone(), workspace);
    let running = server
        .serve((reader, write_half))
        .await
        .context("MCP gateway failed to initialize attach session")?;
    peers
        .lock()
        .await
        .insert(host_session_id.clone(), running.peer().clone());
    let result = running
        .waiting()
        .await
        .context("MCP gateway attach transport terminated abnormally");
    peers.lock().await.remove(&host_session_id);
    drop(permit);
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
mod tests {
    use std::path::PathBuf;

    use super::{
        GatewayState, MAX_ATTACHES, authenticate_registration, mint_hook_token, validate_workspace,
    };
    use crate::commands::mcp::lifecycle::AttachRegistration;

    #[test]
    fn attach_cap_is_bounded_per_principal_channel() {
        assert_eq!(MAX_ATTACHES, 16);
    }

    #[tokio::test]
    async fn attach_cap_rejects_the_seventeenth_live_session() {
        let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
        let state = GatewayState::new(
            PathBuf::from("/runtime-home"),
            principal,
            "gateway-token".into(),
        );
        let mut permits = Vec::with_capacity(MAX_ATTACHES);
        for _ in 0..MAX_ATTACHES {
            permits.push(state.acquire("codex-code").await.expect("attach permit"));
        }
        assert!(state.acquire("codex-code").await.is_err());
        drop(permits);
        assert!(state.acquire("codex-code").await.is_ok());
    }

    #[test]
    fn registration_workspace_must_be_absolute() {
        let workspace = tempfile::tempdir().expect("workspace tempdir");
        assert!(validate_workspace(&workspace.path().to_string_lossy()).is_ok());
        assert!(validate_workspace("project").is_err());
        assert!(validate_workspace("").is_err());
    }

    #[test]
    fn forged_principal_cannot_select_another_gateway_uplink() {
        let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
        let forged = astrid_core::PrincipalId::new("other-agent").expect("principal");
        let state = GatewayState::new(
            PathBuf::from("/runtime-home"),
            principal,
            "gateway-token".into(),
        );
        let registration = AttachRegistration {
            version: super::ATTACH_REGISTRATION_VERSION,
            principal: forged.to_string(),
            host: "codex".into(),
            workspace_abs: "/tmp".into(),
            host_session_id: "thread-1".into(),
            hook_token: "gateway-token".into(),
        };
        let error = authenticate_registration(&registration, &state)
            .expect_err("forged principal must be rejected");
        assert!(
            error
                .to_string()
                .contains("authenticated gateway principal")
        );
    }

    #[test]
    fn missing_hook_token_is_rejected_before_uplink_selection() {
        let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
        let state = GatewayState::new(
            PathBuf::from("/runtime-home"),
            principal.clone(),
            "gateway-token".into(),
        );
        let registration = AttachRegistration {
            version: super::ATTACH_REGISTRATION_VERSION,
            principal: principal.to_string(),
            host: "codex".into(),
            workspace_abs: "/tmp".into(),
            host_session_id: "thread-1".into(),
            hook_token: String::new(),
        };
        let error = authenticate_registration(&registration, &state)
            .expect_err("missing token must be rejected");
        assert!(error.to_string().contains("hook_token is invalid"));
    }

    #[test]
    fn hook_token_is_minted_with_each_gateway_start() {
        let first = mint_hook_token();
        let second = mint_hook_token();
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
    }
}
