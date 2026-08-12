//! State inheritance for `agent.create` (issue #672).
//!
//! When an `agent.create` opts into a source principal — via `inherit_from`
//! (state only) or `clone_from` (profile + state) — these helpers copy that
//! source's runtime state into the new principal's slots so the agent works
//! out of the box: env JSON (non-secret config), per-capsule KV namespaces,
//! and per-capsule secret files.
//!
//! This is the STATE half of provisioning only. The capability profile
//! (groups / grants / revokes / network / process / quotas) is handled by the
//! `agent.create` handler itself — `inherit_from` copies no profile, while
//! `clone_from` copies the source's profile before calling in here for state.
//!
//! Everything here is best-effort: any single failure logs at `warn` and the
//! rest proceeds. The new principal's home tree already exists by the time
//! these run (its absence is what makes the handler's fail-closed rollback
//! necessary, not this), so a partial copy leaves a "needs manual setup"
//! agent, never a confidentiality break.

use std::collections::HashSet;
use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use tracing::info;

/// Copy the `source` principal's env JSON, per-capsule KV namespaces, and
/// per-capsule secret files into `principal`'s slots.
///
/// Invoked ONLY when the operator opts in (`inherit_from` or `clone_from`);
/// the default path copies nothing. The caller has already verified that
/// `source` exists and is not the new principal.
pub(super) async fn inherit_from_principal(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
) {
    let _ = copy_env_dir(kernel, source, principal, None);
    let (capsule_ids, secret_keys_by_capsule) = snapshot_loaded_capsule_state(kernel).await;
    let _ = copy_capsule_state(
        kernel,
        source,
        principal,
        &capsule_ids,
        &secret_keys_by_capsule,
    )
    .await;
}

/// Copy only the named capsule state namespaces for a derived principal.
pub(super) async fn inherit_selected_capsule_state(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
    capsules: &[String],
) -> Result<(), String> {
    let selected: HashSet<&str> = capsules.iter().map(String::as_str).collect();
    let mut errors = copy_env_dir(kernel, source, principal, Some(&selected));

    let mut capsule_ids = Vec::with_capacity(capsules.len());
    let mut secret_keys_by_capsule = Vec::new();
    let source_capsules = kernel.astrid_home.principal_home(source).capsules_dir();
    for name in capsules {
        let capsule_id = match astrid_capsule::capsule::CapsuleId::new(name.clone()) {
            Ok(capsule_id) => capsule_id,
            Err(error) => {
                errors.push(format!("invalid selected capsule '{name}': {error}"));
                continue;
            },
        };
        let manifest_path = source_capsules.join(name).join("Capsule.toml");
        match astrid_capsule::discovery::load_manifest(&manifest_path) {
            Ok(manifest) => {
                let keys = manifest
                    .env
                    .iter()
                    .filter(|(_, def)| def.env_type == "secret")
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                if !keys.is_empty() {
                    secret_keys_by_capsule.push((capsule_id.clone(), keys));
                }
                capsule_ids.push(capsule_id);
            },
            Err(error) => errors.push(format!(
                "selected capsule '{name}' manifest could not be read: {error}"
            )),
        }
    }
    errors.extend(
        copy_capsule_state(
            kernel,
            source,
            principal,
            &capsule_ids,
            &secret_keys_by_capsule,
        )
        .await,
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn snapshot_loaded_capsule_state(
    kernel: &Arc<crate::Kernel>,
) -> (
    Vec<astrid_capsule::capsule::CapsuleId>,
    Vec<(astrid_capsule::capsule::CapsuleId, Vec<String>)>,
) {
    // Snapshot manifest data under the registry lock, then drop it
    // before any async / blocking I/O. Holding the read lock across
    // `copy_kv_namespaces` (async KV) and `copy_secret_files`
    // (blocking fs) would serialise every concurrent install / update
    // / remove against the inherit path for as long as the copy ran.
    {
        let registry = kernel.capsules.read().await;
        let ids: Vec<_> = registry.list().into_iter().cloned().collect();
        let mut secrets: Vec<(astrid_capsule::capsule::CapsuleId, Vec<String>)> = Vec::new();
        for id in &ids {
            if let Some(capsule) = registry.get(id) {
                let keys: Vec<String> = capsule
                    .manifest()
                    .env
                    .iter()
                    .filter(|(_, def)| def.env_type == "secret")
                    .map(|(k, _)| k.clone())
                    .collect();
                if !keys.is_empty() {
                    secrets.push((id.clone(), keys));
                }
            }
        }
        (ids, secrets)
    }
}

async fn copy_capsule_state(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
    capsule_ids: &[astrid_capsule::capsule::CapsuleId],
    secret_keys_by_capsule: &[(astrid_capsule::capsule::CapsuleId, Vec<String>)],
) -> Vec<String> {
    let (total_keys, mut errors) = copy_kv_namespaces(kernel, source, principal, capsule_ids).await;
    let (probed_secrets, copied_secrets, secret_errors) =
        copy_secret_files(kernel, source, principal, secret_keys_by_capsule);
    errors.extend(secret_errors);

    info!(
        %principal,
        %source,
        total_keys,
        copied_secrets,
        probed_secrets,
        "agent.create: inherited source's env JSON + KV namespaces + secrets"
    );
    errors
}

fn copy_env_dir(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
    selected: Option<&HashSet<&str>>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let source_env = kernel.astrid_home.principal_home(source).env_dir();
    let agent_env = kernel.astrid_home.principal_home(principal).env_dir();
    if !source_env.is_dir() {
        return errors;
    }
    if let Err(e) = std::fs::create_dir_all(&agent_env) {
        tracing::warn!(%principal, error = %e, "agent.create: env_dir mkdir failed");
        errors.push(format!("env destination create failed: {e}"));
        return errors;
    }
    let entries = match std::fs::read_dir(&source_env) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(format!("env source read failed: {error}"));
            return errors;
        },
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let selected_name = name
            .to_str()
            .and_then(|name| name.strip_suffix(".env.json"));
        if selected.is_some_and(|set| selected_name.is_none_or(|name| !set.contains(name))) {
            continue;
        }
        let src = entry.path();
        let dst = agent_env.join(&name);
        if let Err(e) = std::fs::copy(&src, &dst) {
            tracing::warn!(
                %principal,
                file = %name.to_string_lossy(),
                error = %e,
                "agent.create: env JSON copy failed"
            );
            errors.push(format!(
                "env file {} copy failed: {e}",
                name.to_string_lossy()
            ));
        }
    }
    errors
}

async fn copy_kv_namespaces(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
    capsule_ids: &[astrid_capsule::capsule::CapsuleId],
) -> (usize, Vec<String>) {
    let mut total_keys = 0usize;
    let mut errors = Vec::new();
    for capsule_id in capsule_ids {
        let src_ns = format!("{source}:capsule:{capsule_id}");
        let dst_ns = format!("{principal}:capsule:{capsule_id}");
        let keys = match kernel.kv.list_keys(&src_ns).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(
                    %principal,
                    capsule_id = %capsule_id,
                    error = %e,
                    "agent.create: KV list_keys failed for capsule namespace"
                );
                errors.push(format!("KV namespace {src_ns} list failed: {e}"));
                continue;
            },
        };
        if !keys.is_empty() {
            info!(
                %principal,
                capsule_id = %capsule_id,
                key_count = keys.len(),
                src_ns = %src_ns,
                "agent.create: copying KV namespace"
            );
            total_keys = total_keys.saturating_add(keys.len());
        }
        for key in keys {
            match kernel.kv.get(&src_ns, &key).await {
                Ok(Some(value)) => {
                    if let Err(e) = kernel.kv.set(&dst_ns, &key, value).await {
                        tracing::warn!(
                            %principal,
                            capsule_id = %capsule_id,
                            key = %key,
                            error = %e,
                            "agent.create: KV copy write failed"
                        );
                        errors.push(format!("KV namespace {dst_ns} key {key} write failed: {e}"));
                    }
                },
                Ok(None) => { /* benign race: key disappeared between list and get */ },
                Err(e) => {
                    tracing::warn!(
                        %principal,
                        capsule_id = %capsule_id,
                        key = %key,
                        error = %e,
                        "agent.create: KV copy read failed"
                    );
                    errors.push(format!("KV namespace {src_ns} key {key} read failed: {e}"));
                },
            }
        }
    }
    (total_keys, errors)
}

fn copy_secret_files(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
    secret_keys_by_capsule: &[(astrid_capsule::capsule::CapsuleId, Vec<String>)],
) -> (usize, usize, Vec<String>) {
    use astrid_storage::{FileSecretStore, SecretStore};
    let mut probed = 0usize;
    let mut copied = 0usize;
    let mut errors = Vec::new();
    let secrets_root = kernel.astrid_home.secrets_dir();
    for (capsule_id, secret_keys) in secret_keys_by_capsule {
        let src =
            FileSecretStore::new(secrets_root.join(source.as_str()).join(capsule_id.as_str()));
        let dst = FileSecretStore::new(
            secrets_root
                .join(principal.as_str())
                .join(capsule_id.as_str()),
        );
        for key in secret_keys {
            probed = probed.saturating_add(1);
            let value = match src.get(key) {
                Ok(Some(v)) => v,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(
                        %principal,
                        capsule_id = %capsule_id,
                        key = %key,
                        error = %e,
                        security_event = true,
                        "agent.create: secret read failed for source's slot"
                    );
                    errors.push(format!("secret {capsule_id}/{key} read failed: {e}"));
                    continue;
                },
            };
            if let Err(e) = dst.set(key, &value) {
                tracing::warn!(
                    %principal,
                    capsule_id = %capsule_id,
                    key = %key,
                    error = %e,
                    security_event = true,
                    "agent.create: secret write failed for new principal"
                );
                errors.push(format!("secret {capsule_id}/{key} write failed: {e}"));
            } else {
                copied = copied.saturating_add(1);
            }
        }
    }
    (probed, copied, errors)
}
