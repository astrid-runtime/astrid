//! `astrid agent spawn` — atomic locked-down throwaway session (#1217).
//!
//! Composes shipped primitives into one blocking call:
//!   1. **derive** a restricted principal with an explicit runtime capsule set,
//!      explicit state namespaces, explicit user-invocable capsules, and an
//!      explicit network allow-list. Nothing is inherited implicitly.
//!   2. **run** one bounded job under it — authenticate a fresh uplink *as* the
//!      throwaway (its keypair was minted by create), submit the prompt, drain
//!      the response. This command is the wall-clock watchdog; nothing in the
//!      runtime bounds a multi-turn react loop by wall-clock.
//!   3. **tear down** — delete the throwaway; `AgentDelete` reclaims its
//!      on-disk footprint (#1217), on success, failure, or timeout alike.
//!
//! The restricted profile is enforced again at network host-call time. An empty
//! `--allow-egress` set therefore means no outbound network access.

use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use astrid_core::kernel_api::{AdminRequestKind, AgentDeriveRequest};
use astrid_core::{PrincipalId, SessionId};
use clap::Args;

use crate::admin_client::{AdminClient, into_result};
use crate::socket_client::{self, SocketClient};

#[derive(Args, Debug, Clone)]
pub(crate) struct SpawnArgs {
    /// The job for the throwaway agent: a prompt, or the text/task to act on.
    /// Framed as untrusted work — the agent evaluates it, never obeys it.
    #[arg(long)]
    pub job: String,

    /// Principal to derive selected capsule installs/state from. Nothing is
    /// copied unless named by the corresponding flags. Defaults to the active
    /// agent.
    #[arg(long = "derive-from", value_name = "PRINCIPAL")]
    pub derive_from: Option<String>,

    /// Capsule installs required to execute the job (for example a harness and
    /// model provider). Repeat for each capsule; no capsule is loaded implicitly.
    #[arg(long = "load-capsule", value_name = "CAPSULE", required = true)]
    pub load_capsules: Vec<String>,

    /// Loaded capsule whose user-invocable tool surface the derived principal
    /// may call. Omitted capsules may still participate in internal orchestration.
    #[arg(long = "allow-capsule", value_name = "CAPSULE")]
    pub allow_capsules: Vec<String>,

    /// Loaded capsule whose env, KV, and declared secret state is copied from
    /// the source. Repeat explicitly; omitted namespaces remain empty.
    #[arg(long = "inherit-capsule-state", value_name = "CAPSULE")]
    pub inherit_capsule_state: Vec<String>,

    /// Outbound network endpoint allowed to the restricted principal, using a
    /// manifest-style `host:port` or `host:*` pattern. Empty means no egress.
    #[arg(long = "allow-egress", value_name = "HOST:PORT")]
    pub network_egress: Vec<String>,

    /// Explicit name for the throwaway principal. Defaults to
    /// `{derive_from}-spawn-{id}`.
    #[arg(long)]
    pub name: Option<String>,

    /// Wall-clock ceiling in seconds. The command blocks for the job's response
    /// up to this long, then cancels the turn and tears down regardless.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86_400))]
    pub timeout: u64,

    /// Leave the throwaway principal in place instead of deleting it (debug).
    #[arg(long)]
    pub keep: bool,
}

pub(crate) async fn run(args: SpawnArgs) -> Result<ExitCode> {
    crate::commands::daemon::ensure_daemon("agent-spawn").await?;

    // Resolve names client-side so a typo fails before any principal is minted.
    let derive_from = match args.derive_from.as_deref() {
        Some(p) => PrincipalId::new(p).context("invalid --derive-from principal")?,
        None => crate::principal::current(),
    };
    let session = SessionId::from_uuid(uuid::Uuid::new_v4());
    let derived_name = match &args.name {
        Some(n) => n.clone(),
        None => format!("{derive_from}-spawn-{}", short_suffix(&session)),
    };
    let derived = PrincipalId::new(&derived_name).context("invalid derived agent name")?;

    let mut admin = crate::admin_client::connect_as_active_agent().await?;

    // 1. Atomically provision the explicit restricted runtime shape. The
    // kernel validates that allowed/stateful capsules are a subset of the
    // loaded set and copies nothing outside those named namespaces.
    let create = admin
        .request_agent_derive(AgentDeriveRequest {
            name: derived_name.clone(),
            source: derive_from.clone(),
            load_capsules: args.load_capsules.clone(),
            allow_capsules: args.allow_capsules.clone(),
            inherit_capsule_state: args.inherit_capsule_state.clone(),
            network_egress: args.network_egress.clone(),
        })
        .await?;
    into_result(create).with_context(|| format!("failed to create throwaway '{derived}'"))?;
    eprintln!("[spawn] created restricted throwaway '{derived}' from '{derive_from}'");

    // 2. Run the one job under the throwaway. Teardown owns the security
    //    guarantee, so it must run whether the job succeeds, fails, or times
    //    out — hence the outcome is captured, not `?`-propagated here.
    let outcome = run_job_under(&derived, &session, &args.job, args.timeout).await;

    // 3. Teardown (delete reclaims the footprint) unless --keep.
    let teardown_outcome = if args.keep {
        eprintln!(
            "[spawn] --keep set: leaving '{derived}' in place \
             (reclaim with `astrid agent delete {derived}`)"
        );
        Ok(())
    } else {
        teardown(&mut admin, &derived).await
    };

    // 4. Surface the job outcome. The response goes to stdout so a caller can
    //    capture it (e.g. land it as a review item); status lines go to stderr.
    match (outcome, teardown_outcome) {
        (Ok(response), Ok(())) => {
            print!("{response}");
            if !response.ends_with('\n') {
                println!();
            }
            Ok(ExitCode::SUCCESS)
        },
        (Err(job), Ok(())) => {
            eprintln!("[spawn] job failed: {job:#}");
            Ok(ExitCode::from(1))
        },
        (Ok(_), Err(teardown)) => {
            eprintln!("[spawn] teardown failed: {teardown:#}");
            Ok(ExitCode::from(1))
        },
        (Err(job), Err(teardown)) => {
            eprintln!("[spawn] job failed: {job:#}");
            eprintln!("[spawn] teardown also failed: {teardown:#}");
            Ok(ExitCode::from(1))
        },
    }
}

/// Connect an uplink authenticated AS the throwaway, submit the job, and drain
/// the response under a wall-clock ceiling. On timeout, send the cooperative
/// cancel sentinel; the hard guarantee is the caller's teardown regardless.
async fn run_job_under(
    principal: &PrincipalId,
    session: &SessionId,
    job: &str,
    timeout_secs: u64,
) -> Result<String> {
    let mut client = socket_client::connect_for_workspace(session.clone(), principal.clone(), None)
        .await
        .map_err(|e| anyhow!("failed to connect as '{principal}': {e}"))?;

    client
        .send_input(job.to_string())
        .await
        .context("failed to submit job")?;

    let drained = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        drain_until_final(&mut client, session),
    )
    .await;

    let result = match drained {
        Ok(inner) => inner,
        Err(_elapsed) => {
            // Cooperative cancel so the react capsule aborts the in-flight turn
            // promptly; delete (which reclaims) is the hard stop regardless.
            let _ = send_cancel(&mut client, session).await;
            Err(anyhow!(
                "job exceeded the {timeout_secs}s wall-clock ceiling"
            ))
        },
    };

    // Best-effort disconnect; the connection also closes on drop.
    let disconnect = astrid_types::ipc::IpcMessage::new(
        astrid_types::Topic::client_disconnect(),
        astrid_types::ipc::IpcPayload::Disconnect {
            reason: Some("spawn".to_string()),
        },
        session.0,
    );
    let _ = client.send_message(disconnect).await;

    result
}

/// Read response events until the terminal `AgentResponse { is_final: true }`,
/// accumulating text. Approval requests are auto-DENIED: a locked-down
/// throwaway drafts a result for review, it never acts in the world.
async fn drain_until_final(client: &mut SocketClient, session: &SessionId) -> Result<String> {
    let mut response = String::new();
    loop {
        let message = match client.read_message().await {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                return Err(anyhow!(
                    "daemon closed the response stream before the final marker"
                ));
            },
            Err(e) => return Err(e.context("failed to read from daemon")),
        };
        match &message.payload {
            astrid_types::ipc::IpcPayload::AgentResponse { text, is_final, .. } => {
                response.push_str(text);
                if *is_final {
                    break;
                }
            },
            astrid_types::ipc::IpcPayload::ApprovalRequired { request_id, .. } => {
                let deny = astrid_types::ipc::IpcPayload::ApprovalResponse {
                    request_id: request_id.clone(),
                    decision: "deny".to_string(),
                    reason: Some("spawn: locked-down throwaway never acts".to_string()),
                };
                let topic = astrid_types::Topic::approval_response(request_id);
                let msg = astrid_types::ipc::IpcMessage::new(topic, deny, session.0);
                client.send_message(msg).await?;
            },
            _ => {},
        }
    }
    Ok(response)
}

/// Signal the react capsule to abort the current turn: an empty `UserInput`
/// carrying the `cancel_turn` sentinel (mirrors the TUI's cancel path).
async fn send_cancel(client: &mut SocketClient, session: &SessionId) -> Result<()> {
    let cancel = astrid_types::ipc::IpcPayload::UserInput {
        text: String::new(),
        session_id: session.0.to_string(),
        context: Some(serde_json::json!({ "action": "cancel_turn" })),
    };
    let msg =
        astrid_types::ipc::IpcMessage::new(astrid_types::Topic::user_prompt(), cancel, session.0);
    client.send_message(msg).await?;
    Ok(())
}

/// Delete the throwaway. `AgentDelete` always reclaims the footprint (#1217)
/// and closes authz first, so a reclamation hiccup can't re-open access or mask
/// the job's real outcome — it's surfaced as a warning.
async fn teardown(admin: &mut AdminClient, derived: &PrincipalId) -> Result<()> {
    let body = admin
        .request(AdminRequestKind::AgentDelete {
            principal: derived.clone(),
        })
        .await
        .with_context(|| format!("could not delete '{derived}'"))?;
    let outcome = into_result(body).with_context(|| format!("delete of '{derived}' failed"))?;
    if let astrid_events::kernel_api::AdminResponseBody::Success(value) = outcome
        && let Some(errors) = value
            .get("cleanup_errors")
            .and_then(|value| value.as_array())
        && !errors.is_empty()
    {
        let details = errors
            .iter()
            .filter_map(|error| error.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(anyhow!(
            "delete of '{derived}' left unreclaimed state: {details}"
        ));
    }
    eprintln!("[spawn] tore down '{derived}' (footprint reclaimed)");
    Ok(())
}

/// First 8 hex chars of the session uuid — short but unique per spawn.
fn short_suffix(session: &SessionId) -> String {
    session.0.simple().to_string()[..8].to_string()
}
