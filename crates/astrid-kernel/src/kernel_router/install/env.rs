//! Owner-scoped environment staging and rollback for daemon installs.

use std::collections::HashSet;
use std::sync::Arc;

use astrid_core::kernel_api::{CapsuleInstallEnv, EnvStorageScope, EnvValueKind};
use astrid_storage::{KvBatchCondition, KvBatchMutation, KvEntryKey, KvMutationBatch};

#[derive(Clone)]
pub(super) struct EnvSnapshot {
    pub(super) kind: EnvValueKind,
    pub(super) scope: EnvStorageScope,
    key: String,
    previous: Option<Vec<u8>>,
    staged: Option<Vec<u8>>,
}

pub(super) struct EnvTransaction {
    uid: astrid_core::identity::PrincipalUid,
    capsule: String,
    snapshots: Vec<EnvSnapshot>,
}

impl EnvTransaction {
    pub(super) async fn rollback(self, kernel: &Arc<crate::Kernel>) {
        let (agent, shared) = partition_env_snapshots(self.snapshots);
        rollback_env_snapshot_group(kernel, self.uid, &self.capsule, agent).await;
        rollback_env_snapshot_group(kernel, self.uid, &self.capsule, shared).await;
    }
}

pub(super) async fn stage_env_values(
    kernel: &Arc<crate::Kernel>,
    caller: &astrid_core::principal::PrincipalId,
    source: &std::path::Path,
    values: &[CapsuleInstallEnv],
) -> Result<Option<EnvTransaction>, String> {
    if values.is_empty() {
        return Ok(None);
    }
    let manifest = if source.is_dir() {
        astrid_capsule::discovery::load_manifest(&source.join("Capsule.toml"))
            .map_err(|error| format!("validate capsule manifest: {error}"))?
    } else {
        astrid_capsule_install::read_archive_manifest(source)
            .map_err(|error| format!("validate capsule manifest: {error:#}"))?
    };
    let capsule = manifest.package.name.clone();
    let uid = kernel
        .principal_directory
        .uid_for(caller)
        .map_err(|error| format!("resolve durable principal UID: {error}"))?;
    validate_env_values(&manifest, values)?;

    let mut snapshots = Vec::with_capacity(values.len());
    for value in values {
        // Install secrets are the site credential. Every assigned principal
        // reads them via Shared fallback unless they set their own Agent secret.
        // Non-secret values stay Agent-scoped so AgentModify can copy `__env:`.
        let scope = match value.kind {
            EnvValueKind::Secret => EnvStorageScope::Shared,
            EnvValueKind::Text => EnvStorageScope::Agent,
        };
        let namespace = env_namespace(uid, &capsule, value.kind, scope);
        let key = env_storage_key(value);
        let previous = kernel
            .kv
            .get(&namespace, &key)
            .await
            .map_err(|error| format!("read previous environment value: {error}"))?;
        let staged = if value.kind == EnvValueKind::Secret && value.value.is_empty() {
            None
        } else {
            Some(value.value.as_bytes().to_vec())
        };
        if previous == staged {
            continue;
        }
        snapshots.push(EnvSnapshot {
            kind: value.kind,
            scope,
            key,
            previous,
            staged,
        });
    }
    if snapshots.is_empty() {
        return Ok(None);
    }
    let (agent, shared) = partition_env_snapshots(snapshots);
    if !apply_env_snapshot_group(kernel, uid, &capsule, &agent, false).await? {
        return Err(
            "stage install environment values lost a concurrent update; retry the install"
                .to_owned(),
        );
    }
    match apply_env_snapshot_group(kernel, uid, &capsule, &shared, false).await {
        Ok(true) => {},
        Ok(false) => {
            rollback_env_snapshot_group(kernel, uid, &capsule, agent.clone()).await;
            return Err(
                "stage install environment values lost a concurrent update; retry the install"
                    .to_owned(),
            );
        },
        Err(error) => {
            rollback_env_snapshot_group(kernel, uid, &capsule, agent.clone()).await;
            return Err(error);
        },
    }
    let mut snapshots = agent;
    snapshots.extend(shared);
    Ok(Some(EnvTransaction {
        uid,
        capsule,
        snapshots,
    }))
}

fn validate_env_values(
    manifest: &astrid_capsule::manifest::CapsuleManifest,
    values: &[CapsuleInstallEnv],
) -> Result<(), String> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value.key.clone()) {
            return Err(format!("duplicate install environment key {:?}", value.key));
        }
        if value.key.is_empty() || value.key.contains('\0') || value.key.contains(':') {
            return Err(
                "install environment key must be non-empty and must not contain ':'".into(),
            );
        }
        let declaration = manifest.env.get(&value.key).ok_or_else(|| {
            format!(
                "install environment key {:?} is not declared by capsule",
                value.key
            )
        })?;
        let is_secret = declaration.env_type.eq_ignore_ascii_case("secret");
        if is_secret != (value.kind == EnvValueKind::Secret) {
            return Err(format!(
                "install environment key {:?} has the wrong typed projection",
                value.key
            ));
        }
        let limit = if is_secret { 64 * 1024 } else { 1 << 20 };
        if value.value.len() > limit {
            return Err(format!(
                "install environment value for {:?} exceeds {limit}-byte limit",
                value.key
            ));
        }
        if !declaration.enum_values.is_empty()
            && !declaration
                .enum_values
                .iter()
                .any(|allowed| allowed == &value.value)
        {
            return Err(format!(
                "invalid value for install environment key {:?}",
                value.key
            ));
        }
    }

    Ok(())
}

fn env_namespace(
    uid: astrid_core::identity::PrincipalUid,
    capsule: &str,
    kind: EnvValueKind,
    scope: EnvStorageScope,
) -> String {
    match (kind, scope) {
        (EnvValueKind::Text, EnvStorageScope::Agent) => {
            astrid_storage::env::principal_capsule_namespace(uid, capsule)
        },
        (EnvValueKind::Text, EnvStorageScope::Shared) => {
            astrid_storage::env::system_capsule_namespace(capsule)
        },
        (EnvValueKind::Secret, EnvStorageScope::Agent) => {
            astrid_storage::env::principal_secret_namespace(uid, capsule)
        },
        (EnvValueKind::Secret, EnvStorageScope::Shared) => {
            astrid_storage::env::system_secret_namespace(capsule)
        },
    }
}

fn env_storage_key(value: &CapsuleInstallEnv) -> String {
    match value.kind {
        EnvValueKind::Text => astrid_storage::env::env_key(&value.key),
        EnvValueKind::Secret => format!("{}{}", astrid_storage::env::SECRET_KEY_PREFIX, value.key),
    }
}

fn partition_env_snapshots(snapshots: Vec<EnvSnapshot>) -> (Vec<EnvSnapshot>, Vec<EnvSnapshot>) {
    let mut agent = Vec::new();
    let mut shared = Vec::new();
    for snapshot in snapshots {
        match snapshot.scope {
            EnvStorageScope::Agent => agent.push(snapshot),
            EnvStorageScope::Shared => shared.push(snapshot),
        }
    }
    (agent, shared)
}

async fn apply_env_snapshot_group(
    kernel: &Arc<crate::Kernel>,
    uid: astrid_core::identity::PrincipalUid,
    capsule: &str,
    snapshots: &[EnvSnapshot],
    rollback: bool,
) -> Result<bool, String> {
    if snapshots.is_empty() {
        return Ok(true);
    }
    let mut conditions = Vec::with_capacity(snapshots.len());
    let mut mutations = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        let namespace = env_namespace(uid, capsule, snapshot.kind, snapshot.scope);
        let key = KvEntryKey::new(namespace, snapshot.key.clone())
            .map_err(|error| format!("create environment batch key: {error}"))?;
        let (expected, replacement) = if rollback {
            (snapshot.staged.clone(), snapshot.previous.clone())
        } else {
            (snapshot.previous.clone(), snapshot.staged.clone())
        };
        conditions.push(KvBatchCondition::ValueEquals {
            key: key.clone(),
            expected,
        });
        mutations.push(match replacement {
            Some(value) => KvBatchMutation::Set { key, value },
            None => KvBatchMutation::Delete { key },
        });
    }
    let batch = KvMutationBatch::new(conditions, mutations)
        .map_err(|error| format!("construct environment mutation batch: {error}"))?;
    let outcome = kernel
        .kv
        .apply_batch(&batch)
        .await
        .map_err(|error| format!("stage install environment values atomically: {error}"))?;
    Ok(outcome.applied)
}

async fn rollback_env_snapshot_group(
    kernel: &Arc<crate::Kernel>,
    uid: astrid_core::identity::PrincipalUid,
    capsule: &str,
    snapshots: Vec<EnvSnapshot>,
) {
    match apply_env_snapshot_group(kernel, uid, capsule, &snapshots, true).await {
        Ok(true) => {},
        Ok(false) => tracing::warn!(
            capsule = %capsule,
            "environment rollback skipped after a concurrent value change"
        ),
        Err(error) => tracing::error!(
            capsule = %capsule,
            error = %error,
            "failed to restore pre-install environment values atomically"
        ),
    }
}
