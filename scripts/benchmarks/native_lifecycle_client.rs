//! Isolated native250 lifecycle diagnostic; never a production command.
//! Ownership root is compile-time bound via NATIVE250_OWNERSHIP_ROOT.
mod native250_admin;
use anyhow::{Context, ensure};
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, AgentDeriveRequest};
use astrid_core::{FleetGenesis, FleetIdentity, PrincipalId, SessionId};
use astrid_storage::principal_state::RuntimeLifecycleGuard;
use astrid_storage::{KvQuotaResolver, OwnershipStore, PrincipalDirectory, StateOwner};
use astrid_types::{
    Topic,
    ipc::{IpcMessage, IpcPayload},
};
use astrid_uplink::{admin_client::into_result, socket_client::SocketClient};
use native250_admin::AuthenticatedAdmin as AdminClient;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

const OWNERSHIP_ROOT: &str = env!("NATIVE250_OWNERSHIP_ROOT");
const OWNERSHIP_SENTINEL: &str = "isolated native250 portable fixture 20261103\n";

fn reject_traversal(path: &std::path::Path, label: &str) -> anyhow::Result<()> {
    ensure!(path.is_absolute(), "{label} must be absolute");
    ensure!(
        !path.components().any(|component| matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )),
        "{label} must not contain '.' or '..' components"
    );
    Ok(())
}

fn require_non_symlink(path: &std::path::Path, label: &str) -> anyhow::Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| format!("stat {label}"))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "{label} must not be a symlink"
    );
    Ok(metadata)
}

fn owned_home() -> anyhow::Result<String> {
    ensure!(
        !OWNERSHIP_ROOT.is_empty(),
        "compile-time ownership root required"
    );
    let root = std::path::Path::new(OWNERSHIP_ROOT);
    reject_traversal(root, "compile-time ownership root")?;
    let root_meta = require_non_symlink(root, "compile-time ownership root")?;
    ensure!(
        root_meta.is_dir(),
        "compile-time ownership root must be a directory"
    );
    let root_canon = std::fs::canonicalize(root).context("canonicalize ownership root")?;

    let home = std::env::var("ASTRID_HOME")?;
    let home_path = std::path::Path::new(&home);
    reject_traversal(home_path, "ASTRID_HOME")?;
    let home_meta = require_non_symlink(home_path, "ASTRID_HOME")?;
    ensure!(home_meta.is_dir(), "ASTRID_HOME must be a directory");
    ensure!(
        home_path.file_name().and_then(|name| name.to_str()) == Some("home"),
        "ASTRID_HOME leaf must be exactly 'home'"
    );
    let home_canon = std::fs::canonicalize(home_path).context("canonicalize ASTRID_HOME")?;
    ensure!(
        home_canon.file_name().and_then(|name| name.to_str()) == Some("home"),
        "canonical ASTRID_HOME leaf must be exactly 'home'"
    );

    let parent = home_canon.parent().context("ASTRID_HOME parent")?;
    let parent_name = parent
        .file_name()
        .and_then(|name| name.to_str())
        .context("ASTRID_HOME parent name")?;
    ensure!(
        parent_name == "seed" || parent_name.starts_with("life-"),
        "ASTRID_HOME must live under ownership-root/seed or ownership-root/life-*"
    );
    let rel = parent
        .strip_prefix(&root_canon)
        .context("home parent escapes compile-time ownership root")?;
    ensure!(
        rel.components().count() == 1,
        "ASTRID_HOME parent must be a direct child of the compile-time ownership root"
    );
    require_non_symlink(parent, "ownership parent")?;

    let ownership = parent.join("ownership.txt");
    reject_traversal(&ownership, "ownership sentinel path")?;
    let ownership_meta = require_non_symlink(&ownership, "ownership sentinel")?;
    ensure!(
        ownership_meta.is_file(),
        "ownership sentinel must be a regular file"
    );
    ensure!(
        std::fs::read_to_string(&ownership)? == OWNERSHIP_SENTINEL,
        "missing or forged ownership guard"
    );
    // Return the operator-provided absolute home only after canonical containment checks.
    Ok(home)
}

fn principal(index: u64) -> anyhow::Result<PrincipalId> {
    Ok(PrincipalId::new(format!("scale-agent-{index:05}"))?)
}

fn fleet(index: u64, user: astrid_core::UserUid) -> anyhow::Result<FleetIdentity> {
    Ok(FleetIdentity::from_genesis(FleetGenesis::from_parts(
        Uuid::from_u128(0x20261025000000000000000000000000u128 + u128::from(index)),
        chrono::DateTime::from_timestamp(1_700_000_001, 0).context("fixture timestamp")?,
        user,
    ))?)
}

fn main() -> anyhow::Result<()> {
    let mode = std::env::args().nth(1).context("mode required")?;
    if matches!(
        mode.as_str(),
        "prepare-fleets" | "rehome-roots" | "offline-census"
    ) {
        let home = owned_home()?;
        let guard = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(offline(&mode, &home))?
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(guard.finish())?;
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let _home = owned_home()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().context("mode required")?.as_str();
    let start: u64 = args.get(1).map(String::as_str).unwrap_or("0").parse()?;
    let end: u64 = args.get(2).map(String::as_str).unwrap_or("10000").parse()?;
    ensure!(start <= end && end <= 10000, "bounded diagnostic range");
    let mut admin = AdminClient::connect(PrincipalId::default())
        .await?
        .with_timeout(Duration::from_secs(600));
    if mode == "census" {
        let response = into_result(admin.request(AdminRequestKind::AgentList).await?)?;
        if let AdminResponseBody::AgentList(agents) = response {
            println!("{}", serde_json::to_string(&agents)?);
            return Ok(());
        }
        anyhow::bail!("unexpected census response");
    }
    let mut current_fleet = None;
    let mut root_client = None;
    for index in start..end {
        if mode == "create-roots" && index % 100 != 0 {
            continue;
        }
        if mode == "derive" && index % 100 == 0 {
            continue;
        }
        let id = principal(index)?;
        let began = Instant::now();
        match mode {
            "create-roots" => {
                into_result(
                    admin
                        .request(AdminRequestKind::AgentCreate {
                            name: id.to_string(),
                            groups: vec![],
                            grants: vec![],
                            inherit_from: None,
                            clone_from: Some(PrincipalId::default()),
                            allow_admin_clone: true,
                        })
                        .await?,
                )?;
            },
            "derive" => {
                let f = index / 100;
                if current_fleet != Some(f) {
                    root_client = Some(
                        AdminClient::connect(principal(f * 100)?)
                            .await?
                            .with_timeout(Duration::from_secs(600)),
                    );
                    current_fleet = Some(f);
                }
                into_result(
                    root_client
                        .as_mut()
                        .context("derived fleet client missing after authenticated connect")?
                        .request_agent_derive(AgentDeriveRequest {
                            name: id.to_string(),
                            source: PrincipalId::default(),
                            load_capsules: vec!["codewall-e2e-driver".into()],
                            allow_capsules: vec!["codewall-e2e-driver".into()],
                            inherit_capsule_state: vec!["codewall-e2e-driver".into()],
                            network_egress: vec![],
                        })
                        .await?,
                )?;
            },
            "delete" => {
                into_result(
                    admin
                        .request(AdminRequestKind::AgentDelete { principal: id })
                        .await?,
                )?;
            },
            "probe-pattern" | "probe" | "probe-wrong-marker" | "empty" => {
                let mut client = SocketClient::connect(SessionId::new(), id.clone()).await?;
                ensure!(
                    client.is_authenticated(),
                    "principal {id} did not authenticate"
                );
                let req = Uuid::new_v4().simple().to_string();
                let writes = if mode == "probe-pattern" {
                    1 + index % 2
                } else {
                    0
                };
                let marker = format!("generation-1:{id}");
                let expected_sequence = if mode == "probe-wrong-marker" {
                    2
                } else {
                    index % 2
                };
                let op = if mode == "empty" {
                    "memory-probe-empty"
                } else {
                    "memory-probe"
                };
                client
                    .send_message(IpcMessage::new(
                        Topic::cli_command_run("codewall-e2e-driver"),
                        IpcPayload::RawJson(serde_json::json!({
                            "req_id": req, "command": "codewall-fixture",
                            "args": [op, writes.to_string(), marker, expected_sequence.to_string()]
                        })),
                        Uuid::new_v4(),
                    ))
                    .await?;
                let reply = client
                    .read_until_topic(
                        Topic::cli_command_result(&req).as_str(),
                        Duration::from_secs(60),
                    )
                    .await?;
                ensure!(
                    reply["payload"]["req_id"].as_str() == Some(req.as_str()),
                    "principal response correlation mismatch: {reply}"
                );
                if mode == "probe-wrong-marker" {
                    ensure!(
                        reply["payload"]["exit_code"] == 1
                            && reply["payload"]["error"]
                                .as_str()
                                .unwrap_or("")
                                .contains("external expected-content readback mismatch"),
                        "wrong expected bytes were not rejected: {reply}"
                    );
                    println!("stage=expected-content-negative index={index} rejected=true");
                    continue;
                }
                ensure!(reply["payload"]["exit_code"] == 0, "agent {index}: {reply}");
                let output: serde_json::Value = serde_json::from_str(
                    reply["payload"]["output"]
                        .as_str()
                        .context("missing probe output")?,
                )?;
                ensure!(
                    output["verified"] == true && output["writes"] == writes,
                    "agent {index}: {output}"
                );
                if mode == "empty" {
                    ensure!(
                        output["empty"] == true
                            && output["live_value_bytes"] == 0
                            && output["marker"] == marker
                            && output["sequence"] == index % 2,
                        "agent {index}: {output}"
                    );
                } else {
                    ensure!(
                        output["empty"] == false
                            && output["sequence"] == index % 2
                            && output["marker"] == marker
                            && output["live_value_bytes"].as_u64().unwrap_or(0) > 4096,
                        "agent {index}: {output}"
                    );
                }
            },
            _ => anyhow::bail!("unknown mode {mode}"),
        }
        println!(
            "stage=agent mode={mode} index={index} elapsed_ns={}",
            began.elapsed().as_nanos()
        );
    }
    println!("stage=complete mode={mode} start={start} end={end}");
    Ok(())
}

async fn offline(mode: &str, owned_home: &str) -> anyhow::Result<RuntimeLifecycleGuard> {
    let cohort_end: u64 = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "10000".into())
        .parse()?;
    ensure!(
        cohort_end > 0 && cohort_end <= 10000,
        "bounded fleet cohort"
    );
    let fleet_count = cohort_end.div_ceil(100);
    let home = AstridHome::from_path(owned_home);
    let guard = RuntimeLifecycleGuard::acquire(&home)?;
    let directory = PrincipalDirectory::default();
    let policy_directory = directory.clone();
    let profiles =
        Arc::new(astrid_capsule::profile_cache::PrincipalProfileCache::with_home(home.clone()));
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> =
        Arc::new(move |owner: &StateOwner| match owner {
            StateOwner::System => Ok(None),
            StateOwner::Fleet(_) => Ok(Some(astrid_core::profile::DEFAULT_MAX_STORAGE_BYTES)),
            StateOwner::Principal(uid) => {
                let alias = policy_directory.alias_for(*uid)?;
                profiles
                    .resolve(&alias)
                    .map(|p| Some(p.quotas.max_storage_bytes))
                    .map_err(|e| astrid_storage::StorageError::Internal(e.to_string()))
            },
        });
    let store = astrid_storage::open_runtime_principal_store_with_directory(
        &home,
        quota,
        directory.clone(),
    )
    .await?;
    let graph = OwnershipStore::new(store.kv(), directory.clone())?;
    let snapshot = graph.load().await?;
    let default_uid = directory.uid_for(&PrincipalId::default())?;
    let operator = snapshot
        .principal_owner(default_uid)
        .context("bootstrap did not assign default")?;
    let f0 = operator.fleet_uid;
    let user = operator.assigned_by;
    let key = astrid_crypto::KeyPair::from_secret_key(&std::fs::read(
        home.keys_dir().join("default.key"),
    )?)?;
    if mode == "prepare-fleets" {
        ensure!(
            snapshot
                .fleet(f0)
                .and_then(|f| f.membership(user))
                .is_some(),
            "bootstrap owner must be a fleet member"
        );
        graph
            .bind_user_device(default_uid, *key.public_key_bytes(), user, user)
            .await?;
        for f in 1..fleet_count {
            graph.create_fleet(fleet(f, user)?).await?;
        }
        println!(
            "stage=prepared fleets={fleet_count} default_uid={default_uid} fleet0={f0} user={user}"
        );
    } else if mode == "rehome-roots" {
        let branches = store.content().workspace_branches();
        let prefix = astrid_storage::ContentName::new("workspace/default")?;
        for f in 1..fleet_count {
            let id = principal(f * 100)?;
            let uid = directory.uid_for(&id)?;
            ensure!(
                graph
                    .load()
                    .await?
                    .principal_owner(uid)
                    .map(|o| o.fleet_uid)
                    == Some(f0),
                "root must still belong to F0 before rollback"
            );
            let before = branches.list_branches(&StateOwner::Fleet(f0))?.len();
            let mut rolled_back = false;
            if let Some(binding) = branches.binding_for_uid(&StateOwner::Fleet(f0), uid, &prefix)? {
                ensure!(
                    binding.binding_uid() == Some(uid)
                        && binding.lifecycle() == astrid_storage::WorkspaceBindingLifecycle::Live,
                    "unexpected root branch state"
                );
                branches.rollback(&StateOwner::Fleet(f0), binding.branch_id())?;
                rolled_back = true;
            }
            let after = branches.list_branches(&StateOwner::Fleet(f0))?.len();
            ensure!(
                if rolled_back {
                    after + 1 == before
                } else {
                    after == before
                },
                "rollback did not retire exactly the leaver branch"
            );
            graph
                .transfer_principal(uid, f0, fleet(f, user)?.uid, user)
                .await?;
            println!(
                "stage=rehome index={} rolled_back={rolled_back} branches_before={before} branches_after={after}",
                f * 100
            );
        }
    } else {
        let now = graph.load().await?;
        let mut counts = std::collections::BTreeMap::new();
        for (alias, uid) in directory.bindings() {
            if let Some(index) = alias.as_str().strip_prefix("scale-agent-") {
                let index: u64 = index.parse()?;
                let expected = if index / 100 == 0 {
                    f0
                } else {
                    fleet(index / 100, user)?.uid
                };
                let actual = now
                    .principal_owner(uid)
                    .context("unowned scale agent")?
                    .fleet_uid;
                ensure!(actual == expected, "wrong fleet for {alias}");
                *counts.entry(actual.to_string()).or_insert(0u64) += 1;
            }
        }
        println!("{}", serde_json::to_string(&counts)?);
    }
    drop(snapshot);
    drop(graph);
    drop(store);
    Ok(guard)
}
