//! Kernel-side `InstallCapsule` handler.
//!
//! Delegates to the shared install library at
//! [`astrid_capsule_install`]. The handler is **path-only**: network
//! sources (`@org/repo`, GitHub URLs, `gh:`, raw HTTPS)
//! are rejected with a structured error. The daemon must not fetch
//! arbitrary bytes during an install — that posture is enforced here.
//!
//! Flow:
//!
//! 1. Resolve the source string to a local path (rejecting remote shapes
//!    and `file://` is stripped to a real path).
//! 2. Hand the path to the authorized archive/directory installer. The daemon
//!    has no human interaction channel here, so only artifacts signed by this
//!    runtime's build identity are accepted automatically.
//! 3. On success, content-addressing has populated `bin/<hash>.wasm` /
//!    `wit/<hash>.wit` and the per-capsule directory now holds the
//!    manifest + meta. Reconcile that exact capsule into a fresh live runtime
//!    generation so installs and upgrades take effect without daemon restart.
//! 4. Serialize the [`InstallOutput`] as a flat JSON payload the
//!    dashboard can render.
//!
//! [`InstallOutput`]: astrid_capsule_install::InstallOutput

use std::collections::HashSet;
use std::sync::Arc;

use astrid_capsule_install::{
    AuthorityDecision, InstallOptions, InstallOutput, InstallPhase,
    inspect_archive_for_principal_with_layout, inspect_directory_for_principal_with_layout,
    read_archive_manifest,
};
use astrid_core::kernel_api::{
    CapsuleInstallAuthority, CapsuleInstallBatchMember, CapsuleInstallEnv,
    CapsuleInstallProvenance, EnvStorageScope, EnvValueKind, InstalledCapsuleGeneration,
};
use astrid_events::kernel_api::KernelResponse;
use astrid_storage::{KvBatchCondition, KvBatchMutation, KvEntryKey, KvMutationBatch};

#[derive(Clone)]
struct EnvSnapshot {
    kind: EnvValueKind,
    scope: EnvStorageScope,
    key: String,
    previous: Option<Vec<u8>>,
    staged: Option<Vec<u8>>,
}

struct EnvTransaction {
    uid: astrid_core::identity::PrincipalUid,
    capsule: String,
    snapshots: Vec<EnvSnapshot>,
    _default_fence: tokio::sync::OwnedRwLockWriteGuard<()>,
}

impl EnvTransaction {
    async fn rollback(self, kernel: &Arc<crate::Kernel>) {
        let (agent, shared) = partition_env_snapshots(self.snapshots);
        rollback_env_snapshot_group(kernel, self.uid, &self.capsule, agent).await;
        rollback_env_snapshot_group(kernel, self.uid, &self.capsule, shared).await;
    }
}

/// Handle `KernelRequest::InstallCapsule` by delegating to the shared
/// install library.
pub(super) struct InstallCapsuleRequest<'a> {
    pub(super) caller: &'a astrid_core::principal::PrincipalId,
    pub(super) requested_target: Option<&'a astrid_core::principal::PrincipalId>,
    pub(super) source: &'a str,
    pub(super) workspace: bool,
    pub(super) provenance: Option<&'a CapsuleInstallProvenance>,
    pub(super) authority: CapsuleInstallAuthority,
    pub(super) env: &'a [CapsuleInstallEnv],
    pub(super) expected_generation: Option<&'a InstalledCapsuleGeneration>,
    pub(super) batch_member: Option<&'a CapsuleInstallBatchMember>,
}

pub(super) async fn handle_install_capsule(
    kernel: &Arc<crate::Kernel>,
    request: InstallCapsuleRequest<'_>,
) -> KernelResponse {
    let expected_package_generation = match super::install_generation::expected_package_generation(
        request.expected_generation,
        request.batch_member,
    ) {
        Ok(generation) => generation,
        Err(error) => return KernelResponse::Error(error),
    };
    let InstallCapsuleRequest {
        caller,
        requested_target,
        source,
        workspace,
        provenance,
        authority,
        env,
        expected_generation: _,
        batch_member,
    } = request;
    if workspace {
        return KernelResponse::Error(
            "workspace installs are CLI-only — the daemon has no meaningful CWD; \
             use a daemon install (drop the --workspace flag) instead"
                .to_string(),
        );
    }

    let path = match local_install_path(source) {
        Ok(path) => path,
        Err(error) => return KernelResponse::Error(error),
    };

    // Batch callers control the source pathname. Copy its one safely-opened
    // file description into memory before any digest, manifest, authority,
    // environment, or install work. Every later archive stage consumes these
    // immutable bytes and never reopens a temporary pathname.
    let batch_archive =
        match super::install_batch_archive::prepare_batch_archive(&path, batch_member) {
            Ok(archive) => archive,
            Err(error) => return KernelResponse::Error(error),
        };

    let target = requested_target.unwrap_or(caller);
    if let Err(error) = validate_install_provenance(
        &path,
        batch_archive
            .as_ref()
            .map(|archive| archive.bytes.as_slice()),
        provenance,
    ) {
        return KernelResponse::Error(error);
    }
    // Resolve the immutable UID before any environment or package mutation.
    // A caller may name only a principal already present in the authenticated
    // directory; aliases never become durable package authorities.
    if let Err(error) = kernel
        .principal_directory
        .uid_for(target)
        .map_err(|error| format!("resolve target principal {target}: {error}"))
    {
        return KernelResponse::Error(error);
    }

    let env_transaction = match stage_env_values(
        kernel,
        target,
        &path,
        batch_archive.as_ref().map(|archive| &archive.manifest),
        env,
    )
    .await
    {
        Ok(transaction) => transaction,
        Err(error) => return KernelResponse::Error(error),
    };

    match install_and_activate(
        kernel,
        target,
        source,
        path,
        batch_archive,
        provenance,
        authority,
        env_transaction,
        expected_package_generation,
    )
    .await
    {
        Ok(output) => KernelResponse::Success(install_output_json(&output)),
        Err(error) => KernelResponse::Error(error),
    }
}

/// Install against the kernel-bound home, then activate once, rolling env back on failure.
#[allow(clippy::too_many_arguments)]
async fn install_and_activate(
    kernel: &Arc<crate::Kernel>,
    target: &astrid_core::principal::PrincipalId,
    source: &str,
    path: std::path::PathBuf,
    batch_archive: Option<super::install_batch_archive::BatchArchive>,
    provenance: Option<&CapsuleInstallProvenance>,
    authority: CapsuleInstallAuthority,
    env_transaction: Option<EnvTransaction>,
    expected_package_generation: Option<astrid_storage::CapsulePackageGeneration>,
) -> Result<InstallOutput, String> {
    let home = kernel.astrid_home.clone();
    let options = daemon_install_options(kernel, source, provenance, expected_package_generation);
    let install = match batch_archive {
        Some(archive) => {
            super::install_batch_archive::run_authorized_archive_install(
                kernel,
                target,
                archive.bytes,
                home,
                options,
                authority,
            )
            .await
        },
        None => run_authorized_install(kernel, target, path, home, options, authority).await,
    };
    let output = match install {
        Ok(output) => output,
        Err(error) => {
            if let Some(transaction) = env_transaction {
                transaction.rollback(kernel).await;
            }
            return Err(error);
        },
    };

    // Reconcile the exact installed capsule into the live runtime. An upgrade
    // must create a new runtime generation even when its bytes/hash are
    // unchanged (configuration and lifecycle state may have changed); merely
    // calling `ensure_principal_loaded` would return early on the old view.
    if let Err(error) = activate_installed_capsule(kernel, target, &output).await {
        if let Some(transaction) = env_transaction {
            transaction.rollback(kernel).await;
        }
        return Err(error);
    }
    Ok(output)
}

fn daemon_install_options(
    kernel: &Arc<crate::Kernel>,
    source: &str,
    provenance: Option<&CapsuleInstallProvenance>,
    expected_package_generation: Option<astrid_storage::CapsulePackageGeneration>,
) -> InstallOptions {
    InstallOptions {
        workspace: false,
        original_source: Some(source.to_string()),
        skip_import_check: false,
        // Kernel installs run unattended. Capsules needing install-time
        // elicitation must receive configuration through the request env.
        lifecycle_bus: None,
        storage: kernel.principal_store.clone().map(Arc::new),
        provenance_distro: provenance.and_then(|value| value.distro.clone()),
        provenance_source_digest: provenance.and_then(|value| value.source_digest.clone()),
        expected_package_generation,
    }
}

fn local_install_path(source: &str) -> Result<std::path::PathBuf, String> {
    let is_remote = source.starts_with("https://")
        || source.starts_with("http://")
        || source.starts_with("github.com/")
        || source.starts_with('@')
        || source.starts_with("gh:");
    if is_remote {
        return Err(format!(
            "kernel-side install accepts only local paths; resolve '{source}' via the \
             gateway registry route first (the daemon never fetches URLs)"
        ));
    }
    let path = std::path::PathBuf::from(source.strip_prefix("file://").unwrap_or(source));
    if path.exists() {
        Ok(path)
    } else {
        Err(format!("source path does not exist: {}", path.display()))
    }
}

async fn run_authorized_install(
    kernel: &Arc<crate::Kernel>,
    principal: &astrid_core::principal::PrincipalId,
    path: std::path::PathBuf,
    home: astrid_core::dirs::AstridHome,
    options: InstallOptions,
    authority: CapsuleInstallAuthority,
) -> Result<InstallOutput, String> {
    let workspace_layout = kernel.workspace_layout.clone();
    let workspace_root = kernel.workspace_root.clone();
    let principal = principal.clone();
    let is_archive = path.is_file()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("capsule"));
    let source_display = path.display().to_string();
    let authority =
        daemon_authority_decision(&path, &home, &principal, &workspace_layout, authority)?;
    let task = if is_archive {
        tokio::task::spawn_blocking(move || {
            astrid_capsule_install::unpack_and_install_authorized_for_principal_in_workspace(
                &path,
                &home,
                options,
                &principal,
                Some(&workspace_root),
                &authority,
                &workspace_layout,
            )
        })
    } else if path.is_dir() {
        tokio::task::spawn_blocking(move || {
            astrid_capsule_install::install_from_local_path_authorized_for_principal_in_workspace(
                &path,
                &home,
                options,
                &principal,
                Some(&workspace_root),
                &authority,
                &workspace_layout,
            )
        })
    } else {
        return Err(format!(
            "source must be a directory containing Capsule.toml or a *.capsule archive: \
             {source_display}"
        ));
    };
    task.await
        .map_err(|error| format!("install task panicked: {error}"))?
        .map_err(|error| format!("install failed: {error:#}"))
}

fn daemon_authority_decision(
    path: &std::path::Path,
    home: &astrid_core::dirs::AstridHome,
    principal: &astrid_core::principal::PrincipalId,
    workspace_layout: &astrid_core::dirs::WorkspaceLayout,
    authority: CapsuleInstallAuthority,
) -> Result<AuthorityDecision, String> {
    if authority == CapsuleInstallAuthority::Automatic {
        return Ok(AuthorityDecision::Automatic);
    }
    let inspection = if path.is_file() {
        inspect_archive_for_principal_with_layout(path, home, principal, false, workspace_layout)
    } else {
        inspect_directory_for_principal_with_layout(path, home, principal, false, workspace_layout)
    }
    .map_err(|error| format!("inspect capsule install authority: {error:#}"))?;
    Ok(match authority {
        CapsuleInstallAuthority::Automatic => AuthorityDecision::Automatic,
        CapsuleInstallAuthority::ExplicitApproval => AuthorityDecision::ExplicitApproval {
            content_digest: inspection.content_digest,
        },
        CapsuleInstallAuthority::OperatorDistribution => AuthorityDecision::OperatorDistribution {
            content_digest: inspection.content_digest,
        },
    })
}

const MAX_PROVENANCE_TEXT_BYTES: usize = 128;
const MAX_SOURCE_DIGEST_BYTES: u64 = 64 * 1024 * 1024;

/// Validate and, when supplied, bind source provenance to the exact local
/// archive bytes before the install transaction stages env or publishes a
/// durable package. The wire accepts only canonical lowercase BLAKE3 text;
/// callers cannot use a path or an arbitrary label as a digest.
fn validate_install_provenance(
    source: &std::path::Path,
    archive: Option<&[u8]>,
    provenance: Option<&CapsuleInstallProvenance>,
) -> Result<(), String> {
    let Some(provenance) = provenance else {
        return Ok(());
    };
    if let Some(distro) = provenance.distro.as_deref()
        && (distro.is_empty()
            || distro.len() > MAX_PROVENANCE_TEXT_BYTES
            || distro.chars().any(char::is_control))
    {
        return Err(
            "install provenance distro must be 1..=128 bytes and contain no control characters"
                .to_owned(),
        );
    }
    let Some(expected) = provenance.source_digest.as_deref() else {
        return Ok(());
    };
    if expected.len() != 71
        || !expected.starts_with("blake3:")
        || !expected[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(
            "install provenance source_digest must be canonical blake3:<64 lowercase hex>"
                .to_owned(),
        );
    }
    let bytes = if let Some(bytes) = archive {
        std::borrow::Cow::Borrowed(bytes)
    } else {
        let metadata = std::fs::metadata(source)
            .map_err(|error| format!("inspect provenance source {}: {error}", source.display()))?;
        if !metadata.is_file() {
            return Err(
                "install provenance source_digest is supported only for a local capsule archive"
                    .to_owned(),
            );
        }
        if metadata.len() > MAX_SOURCE_DIGEST_BYTES {
            return Err(format!(
                "install provenance source exceeds {MAX_SOURCE_DIGEST_BYTES}-byte digest limit"
            ));
        }
        std::borrow::Cow::Owned(
            std::fs::read(source)
                .map_err(|error| format!("read provenance source {}: {error}", source.display()))?,
        )
    };
    if bytes.len() as u64 > MAX_SOURCE_DIGEST_BYTES {
        return Err(format!(
            "install provenance source exceeds {MAX_SOURCE_DIGEST_BYTES}-byte digest limit"
        ));
    }
    let actual = format!("blake3:{}", blake3::hash(bytes.as_ref()).to_hex());
    if actual != expected {
        return Err(format!(
            "install provenance source_digest mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

async fn stage_env_values(
    kernel: &Arc<crate::Kernel>,
    caller: &astrid_core::principal::PrincipalId,
    source: &std::path::Path,
    batch_manifest: Option<&astrid_capsule::manifest::CapsuleManifest>,
    values: &[CapsuleInstallEnv],
) -> Result<Option<EnvTransaction>, String> {
    if values.is_empty() {
        return Ok(None);
    }
    let loaded_manifest;
    let manifest = if let Some(manifest) = batch_manifest {
        manifest
    } else {
        loaded_manifest = if source.is_dir() {
            astrid_capsule::discovery::load_manifest(&source.join("Capsule.toml"))
                .map_err(|error| format!("validate capsule manifest: {error}"))?
        } else {
            read_archive_manifest(source)
                .map_err(|error| format!("validate capsule manifest: {error:#}"))?
        };
        &loaded_manifest
    };
    let capsule = manifest.package.name.clone();
    let uid = kernel
        .principal_directory
        .uid_for(caller)
        .map_err(|error| format!("resolve durable principal UID: {error}"))?;
    validate_env_values(manifest, values)?;

    // Keep defaults and other install transactions out through commit/rollback.
    // Otherwise one rollback can restore another failed install's staged value.
    // Never wait here: activation may itself request an install.
    let default_fence = Arc::clone(&kernel.env_install_fence)
        .try_write_owned()
        .map_err(|_| "environment transaction in progress; retry the install".to_owned())?;
    // Serialize shared/agent environment staging with admin default writes.
    // Keep the lock only for the KV transaction, never capsule activation.
    let _env_guard = kernel.admin_write_lock.lock().await;

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
        _default_fence: default_fence,
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
    // Staging is all-or-nothing, but rollback must preserve each later edit
    // independently. One changed key must not strand unrelated staged values.
    // Each single-key batch still atomically compares and restores its snapshot.
    for snapshot in snapshots {
        match apply_env_snapshot_group(kernel, uid, capsule, std::slice::from_ref(&snapshot), true)
            .await
        {
            Ok(true) => {},
            Ok(false) => tracing::warn!(
                capsule = %capsule,
                "environment rollback preserved a concurrently changed key"
            ),
            Err(error) => tracing::error!(
                capsule = %capsule,
                error = %error,
                "failed to restore a pre-install environment value"
            ),
        }
    }
}

async fn activate_installed_capsule(
    kernel: &Arc<crate::Kernel>,
    caller: &astrid_core::principal::PrincipalId,
    output: &InstallOutput,
) -> Result<(), String> {
    let manifest =
        astrid_capsule::discovery::load_manifest(&output.target_dir.join("Capsule.toml"))
            .map_err(|error| format!("installed capsule could not be activated: {error}"))?;
    let id = astrid_capsule_types::CapsuleId::from_static(&manifest.package.name);
    kernel
        .reload_one_capsule(&id, caller)
        .await
        .map_err(|error| format!("capsule installed on disk but live activation failed: {error:#}"))
}

fn install_output_json(o: &InstallOutput) -> serde_json::Value {
    serde_json::json!({
        "target_dir": o.target_dir.display().to_string(),
        "phase": match o.phase {
            InstallPhase::Install => "install",
            InstallPhase::Upgrade => "upgrade",
        },
        "installed_version": o.installed_version,
        "previous_version": o.previous_version,
        "wasm_hash": o.wasm_hash,
        "env_path": o.env_path.display().to_string(),
        "env_needs_prompt": o.env_needs_prompt,
        "missing_imports": o.missing_imports.iter().map(|m| serde_json::json!({
            "namespace": m.namespace,
            "interface": m.interface,
            "requirement": m.requirement,
        })).collect::<Vec<_>>(),
        "export_conflicts": o.export_conflicts.iter().map(|c| serde_json::json!({
            "interface": c.interface,
            "existing_capsule": c.existing_capsule,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
#[path = "install_internal_tests.rs"]
mod tests;
