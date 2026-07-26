//! `astrid agent spawn` — atomic locked-down throwaway session (#1217).
//!
//! Composes shipped primitives into one blocking call:
//!   1. **create** a derived, least-privilege principal — empty grants + the
//!      default `agent` group ⇒ an empty capsule allow-list ⇒ it can invoke no
//!      tool capsule, so nothing it can drive can phone out. `inherit_from`
//!      (not `clone_from`) copies only the derive-from principal's env/KV/
//!      secrets, so its agent loop still gets the LLM api key **without**
//!      inheriting that principal's grants/capsules/egress reach.
//!   2. **run** one bounded job under it — authenticate a fresh uplink *as* the
//!      throwaway (its keypair was minted by create), submit the prompt, drain
//!      the response. This command is the wall-clock watchdog; nothing in the
//!      runtime bounds a multi-turn react loop by wall-clock.
//!   3. **tear down** — delete the throwaway and purge its on-disk footprint
//!      (the `AgentDelete { purge_home }` flag), on success, failure, or
//!      timeout alike.
//!
//! The security posture ("locked down, can't exfiltrate") is delivered by that
//! empty capsule allow-list — NOT by `network.egress`, which the runtime does
//! not enforce. See `docs/proposals/2026-07-26-1217-atomic-spawn-design.md`.

use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use astrid_core::kernel_api::AdminRequestKind;
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

    /// Principal to derive from. Its env/KV/secrets (the LLM api key) are
    /// inherited so the throwaway can still reach the model; its grants,
    /// capsule access, and egress are NOT. Defaults to the active agent.
    #[arg(long = "derive-from", value_name = "PRINCIPAL")]
    pub derive_from: Option<String>,

    /// Explicit name for the throwaway principal. Defaults to
    /// `{derive_from}-spawn-{id}`.
    #[arg(long)]
    pub name: Option<String>,

    /// Group membership for the throwaway (repeatable). Defaults to `agent`:
    /// self-scoped, no capsule/tool access — the locked-down posture.
    #[arg(long = "group", value_name = "NAME")]
    pub groups: Vec<String>,

    /// Wall-clock ceiling in seconds. The command blocks for the job's response
    /// up to this long, then cancels the turn and tears down regardless.
    #[arg(long, default_value_t = 300)]
    pub timeout: u64,

    /// Leave the throwaway principal in place instead of purging it (debug).
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

    // 1. Create the derived, least-privilege throwaway.
    let create = admin
        .request(AdminRequestKind::AgentCreate {
            name: derived_name.clone(),
            groups: args.groups.clone(),
            grants: Vec::new(),
            inherit_from: Some(derive_from.clone()),
            clone_from: None,
            allow_admin_clone: false,
        })
        .await?;
    into_result(create).with_context(|| format!("failed to create throwaway '{derived}'"))?;
    eprintln!(
        "[spawn] created throwaway '{derived}' (derived from '{derive_from}'; no tool/egress access)"
    );

    // 2. Run the one job under the throwaway. Teardown owns the security
    //    guarantee, so it must run whether the job succeeds, fails, or times
    //    out — hence the outcome is captured, not `?`-propagated here.
    let outcome = run_job_under(&derived, &session, &args.job, args.timeout).await;

    // 3. Teardown (+ footprint purge) unless --keep.
    if args.keep {
        eprintln!(
            "[spawn] --keep set: leaving '{derived}' in place \
             (reclaim with `astrid agent delete {derived} --purge-home`)"
        );
    } else {
        teardown(&mut admin, &derived).await;
    }

    // 4. Surface the job outcome. The response goes to stdout so a caller can
    //    capture it (e.g. land it as a review item); status lines go to stderr.
    match outcome {
        Ok(response) => {
            print!("{response}");
            if !response.ends_with('\n') {
                println!();
            }
            Ok(ExitCode::SUCCESS)
        },
        Err(e) => {
            eprintln!("[spawn] job failed: {e:#}");
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
            // promptly; delete + purge is the hard stop regardless.
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
            Ok(None) => break, // stream closed before a final marker
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

/// Delete the throwaway and reclaim its footprint. Best-effort and never
/// propagates: authz is already closed by the delete itself, so a purge hiccup
/// must not mask the job's real outcome — it's surfaced as a warning.
async fn teardown(admin: &mut AdminClient, derived: &PrincipalId) {
    match admin
        .request(AdminRequestKind::AgentDelete {
            principal: derived.clone(),
            purge_home: true,
        })
        .await
    {
        Ok(body) => match into_result(body) {
            Ok(_) => eprintln!("[spawn] tore down '{derived}' (footprint purged)"),
            Err(e) => eprintln!("[spawn] WARNING: teardown of '{derived}' reported: {e:#}"),
        },
        Err(e) => eprintln!(
            "[spawn] WARNING: could not tear down '{derived}': {e:#} — \
             reclaim with `astrid agent delete {derived} --purge-home`"
        ),
    }
}

/// First 8 hex chars of the session uuid — short but unique per spawn.
fn short_suffix(session: &SessionId) -> String {
    session.0.simple().to_string()[..8].to_string()
}
