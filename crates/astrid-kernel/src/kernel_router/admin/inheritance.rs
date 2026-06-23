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
    copy_env_dir(kernel, source, principal);

    // Snapshot manifest data under the registry lock, then drop it
    // before any async / blocking I/O. Holding the read lock across
    // `copy_kv_namespaces` (async KV) and `copy_secret_files`
    // (blocking fs) would serialise every concurrent install / update
    // / remove against the inherit path for as long as the copy ran.
    let (capsule_ids, secret_keys_by_capsule): (
        Vec<astrid_capsule::capsule::CapsuleId>,
        Vec<(astrid_capsule::capsule::CapsuleId, Vec<String>)>,
    ) = {
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
    };

    let total_keys = copy_kv_namespaces(kernel, source, principal, &capsule_ids).await;
    let (probed_secrets, copied_secrets) =
        copy_secret_files(kernel, source, principal, &secret_keys_by_capsule);

    info!(
        %principal,
        %source,
        total_keys,
        copied_secrets,
        probed_secrets,
        "agent.create: inherited source's env JSON + KV namespaces + secrets"
    );
}

fn copy_env_dir(kernel: &Arc<crate::Kernel>, source: &PrincipalId, principal: &PrincipalId) {
    let source_env = kernel.astrid_home.principal_home(source).env_dir();
    let agent_env = kernel.astrid_home.principal_home(principal).env_dir();
    if !source_env.is_dir() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(&agent_env) {
        tracing::warn!(%principal, error = %e, "agent.create: env_dir mkdir failed");
        return;
    }
    let Ok(entries) = std::fs::read_dir(&source_env) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let src = entry.path();
        let dst = agent_env.join(&name);
        if let Err(e) = std::fs::copy(&src, &dst) {
            tracing::warn!(
                %principal,
                file = %name.to_string_lossy(),
                error = %e,
                "agent.create: env JSON copy failed"
            );
        }
    }
}

async fn copy_kv_namespaces(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
    capsule_ids: &[astrid_capsule::capsule::CapsuleId],
) -> usize {
    use astrid_storage::KvStore;
    let mut total_keys = 0usize;
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
                },
            }
        }
    }
    total_keys
}

fn copy_secret_files(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
    secret_keys_by_capsule: &[(astrid_capsule::capsule::CapsuleId, Vec<String>)],
) -> (usize, usize) {
    use astrid_storage::{FileSecretStore, SecretStore};
    let mut probed = 0usize;
    let mut copied = 0usize;
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
            } else {
                copied = copied.saturating_add(1);
            }
        }
    }
    (probed, copied)
}
