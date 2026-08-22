//! State inheritance for `agent.create` (issue #672).
//!
//! When an `agent.create` opts into a source principal — via `inherit_from`
//! (state only) or `clone_from` (profile + state) — these helpers copy that
//! source's runtime state into the new principal's slots so the agent works
//! out of the box: typed env state, per-capsule KV namespaces, and
//! per-capsule secrets.
//!
//! This is the STATE half of provisioning only. The capability profile
//! (groups / grants / revokes / network / process / quotas) is handled by the
//! `agent.create` handler itself — `inherit_from` copies no profile, while
//! `clone_from` copies the source's profile before calling in here for state.
//!
//! Each storage projection is copied through a preflighted, idempotent helper;
//! conflicting destination values fail closed and writes made by a failed
//! projection are rolled back. Native env/secrets directories are never read.

use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use tracing::info;

/// Copy the `source` principal's typed env, per-capsule KV namespaces, and
/// per-capsule secrets into `principal`'s slots.
///
/// Invoked ONLY when the operator opts in (`inherit_from` or `clone_from`);
/// the default path copies nothing. The caller has already verified that
/// `source` exists and is not the new principal.
pub(super) async fn inherit_from_principal(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
) {
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
    let mut errors = Vec::new();

    let mut capsule_ids = Vec::with_capacity(capsules.len());
    let mut secret_keys_by_capsule = Vec::new();
    let Some(store) = kernel.principal_store.as_ref() else {
        return Err("authoritative principal store is unavailable".to_owned());
    };
    let source_uid = kernel
        .principal_directory
        .uid_for(source)
        .map_err(|error| format!("resolve source principal UID: {error}"))?;
    let owner = astrid_storage::StateOwner::Principal(source_uid);
    for name in capsules {
        let capsule_id = match astrid_capsule::capsule::CapsuleId::new(name.clone()) {
            Ok(capsule_id) => capsule_id,
            Err(error) => {
                errors.push(format!("invalid selected capsule '{name}': {error}"));
                continue;
            },
        };
        let Some(snapshot) = store
            .capsules()
            .get_snapshot(&owner, name)
            .map_err(|error| format!("read durable capsule '{name}': {error}"))?
        else {
            errors.push(format!(
                "selected capsule '{name}' is not durably installed"
            ));
            continue;
        };
        let temporary = tempfile::tempdir()
            .map_err(|error| format!("create capsule inspection root for '{name}': {error}"))?;
        let manifest_path = temporary.path().join(name).join("Capsule.toml");
        if let Err(error) = astrid_capsule_install::materialize_capsule_package(
            snapshot.package(),
            temporary.path().join(name).as_path(),
        ) {
            errors.push(format!(
                "selected capsule '{name}' package is invalid: {error:#}"
            ));
            continue;
        }
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
    // `copy_kv_namespaces` (async KV) and `copy_secret_stores`
    // (synchronous SecretStore calls) would serialise every concurrent install / update
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
    let (env_fields, env_errors) =
        copy_env_namespaces(kernel, source, principal, capsule_ids).await;
    errors.extend(env_errors);
    let (probed_secrets, copied_secrets, secret_errors) =
        copy_secret_stores(kernel, source, principal, secret_keys_by_capsule).await;
    errors.extend(secret_errors);

    info!(
        %principal,
        %source,
        total_keys,
        env_fields,
        copied_secrets,
        probed_secrets,
        "agent.create: inherited source's typed env + KV namespaces + secrets"
    );
    errors
}

/// Copy only non-secret host-control env for capsules newly assigned to a
/// principal. Capsule package assignment uses the default principal as the
/// trusted install source, but secrets remain principal-owned and are never
/// copied by this path.
pub(super) async fn copy_non_secret_env_from_principal(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
    capsules: &[String],
) -> Result<(), String> {
    let mut capsule_ids = Vec::with_capacity(capsules.len());
    for name in capsules {
        let id = astrid_capsule::capsule::CapsuleId::new(name.clone())
            .map_err(|error| format!("invalid capsule id '{name}': {error}"))?;
        capsule_ids.push(id);
    }
    let (_, errors) = copy_env_namespaces(kernel, source, principal, &capsule_ids).await;
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Copy the default principal's non-secret environment for an `agent.modify`
/// capsule assignment, preserving the handler's internal-error context.
pub(super) async fn copy_modify_env(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    capsules: &[String],
) -> Result<(), String> {
    copy_non_secret_env_from_principal(kernel, &PrincipalId::default(), principal, capsules)
        .await
        .map_err(|error| {
            format!("copy default capsule environment for {principal} failed: {error}")
        })
}

async fn copy_env_namespaces(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
    capsule_ids: &[astrid_capsule::capsule::CapsuleId],
) -> (usize, Vec<String>) {
    let mut copied = 0usize;
    let mut errors = Vec::new();
    let source_uid = match kernel.principal_directory.uid_for(source) {
        Ok(uid) => uid,
        Err(error) => {
            return (
                0,
                vec![format!("source principal UID lookup failed: {error}")],
            );
        },
    };
    let destination_uid = match kernel.principal_directory.uid_for(principal) {
        Ok(uid) => uid,
        Err(error) => {
            return (
                0,
                vec![format!("destination principal UID lookup failed: {error}")],
            );
        },
    };
    for capsule_id in capsule_ids {
        let source_scope = match astrid_storage::env::principal_env_store(
            Arc::clone(&kernel.kv),
            source_uid,
            capsule_id.as_str(),
        ) {
            Ok(scope) => scope,
            Err(error) => {
                errors.push(format!("source env scope {capsule_id} failed: {error}"));
                continue;
            },
        };
        let destination_scope = match astrid_storage::env::principal_env_store(
            Arc::clone(&kernel.kv),
            destination_uid,
            capsule_id.as_str(),
        ) {
            Ok(scope) => scope,
            Err(error) => {
                errors.push(format!(
                    "destination env scope {capsule_id} failed: {error}"
                ));
                continue;
            },
        };
        match astrid_storage::env::copy_env_namespace(&source_scope, &destination_scope).await {
            Ok(count) => copied = copied.saturating_add(count),
            Err(error) => {
                tracing::warn!(
                    %principal,
                    capsule_id = %capsule_id,
                    error = %error,
                    "agent.create: typed environment copy failed"
                );
                errors.push(format!("env namespace {capsule_id} copy failed: {error}"));
            },
        }
    }
    (copied, errors)
}

#[allow(
    clippy::too_many_lines,
    reason = "the read, conflict probe, CAS writes, and exact rollback form one ordered transaction"
)]
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
        let mut values = Vec::with_capacity(keys.len());
        let mut failed = false;
        for key in &keys {
            match kernel.kv.get(&src_ns, key).await {
                Ok(Some(value)) => values.push((key.clone(), value)),
                Ok(None) => {},
                Err(error) => {
                    failed = true;
                    errors.push(format!(
                        "KV namespace {src_ns} key {key} read failed: {error}"
                    ));
                    break;
                },
            }
        }
        if failed {
            continue;
        }
        let mut pending = Vec::new();
        for (key, value) in &values {
            match kernel.kv.get(&dst_ns, key).await {
                Ok(Some(existing)) if existing != *value => {
                    failed = true;
                    errors.push(format!(
                        "KV namespace {dst_ns} key {key} conflicts with destination"
                    ));
                    break;
                },
                Ok(Some(_)) => {},
                Ok(None) => pending.push((key.clone(), value.clone())),
                Err(error) => {
                    failed = true;
                    errors.push(format!(
                        "KV namespace {dst_ns} key {key} probe failed: {error}"
                    ));
                    break;
                },
            }
        }
        if failed {
            continue;
        }
        if !values.is_empty() {
            info!(
                %principal,
                capsule_id = %capsule_id,
                key_count = keys.len(),
                src_ns = %src_ns,
                "agent.create: copying KV namespace"
            );
            total_keys = total_keys.saturating_add(values.len());
        }
        // Keep the exact bytes inserted by this invocation.  A concurrent
        // owner may update a key after our insert; rollback must never delete
        // that newer value.  KvStore has no compare-and-delete primitive, so
        // the equality probe is the narrowest safe cleanup available here.
        let mut written: Vec<(String, Vec<u8>)> = Vec::with_capacity(pending.len());
        for (key, value) in pending {
            match kernel
                .kv
                .compare_and_swap(&dst_ns, &key, None, value.clone())
                .await
            {
                Ok(true) => written.push((key, value)),
                Ok(false) => {
                    rollback_kv_writes(kernel, &dst_ns, written).await;
                    errors.push(format!(
                        "KV namespace {dst_ns} changed during copy; no partial state retained"
                    ));
                    break;
                },
                Err(e) => {
                    rollback_kv_writes(kernel, &dst_ns, written).await;
                    tracing::warn!(
                        %principal,
                        capsule_id = %capsule_id,
                        key = %key,
                        error = %e,
                        "agent.create: KV copy read failed"
                    );
                    errors.push(format!("KV namespace {dst_ns} key {key} write failed: {e}"));
                    break;
                },
            }
        }
    }
    (total_keys, errors)
}

async fn rollback_kv_writes(
    kernel: &crate::Kernel,
    namespace: &str,
    written: Vec<(String, Vec<u8>)>,
) {
    for (key, value) in written {
        if kernel
            .kv
            .get(namespace, &key)
            .await
            .ok()
            .flatten()
            .as_deref()
            == Some(value.as_slice())
        {
            let _ = kernel.kv.delete(namespace, &key).await;
        }
    }
}

async fn copy_secret_stores(
    kernel: &Arc<crate::Kernel>,
    source: &PrincipalId,
    principal: &PrincipalId,
    secret_keys_by_capsule: &[(astrid_capsule::capsule::CapsuleId, Vec<String>)],
) -> (usize, usize, Vec<String>) {
    let mut probed = 0usize;
    let mut copied = 0usize;
    let mut errors = Vec::new();
    let source_uid = match kernel.principal_directory.uid_for(source) {
        Ok(uid) => uid,
        Err(error) => {
            return (
                0,
                0,
                vec![format!("source principal UID lookup failed: {error}")],
            );
        },
    };
    let destination_uid = match kernel.principal_directory.uid_for(principal) {
        Ok(uid) => uid,
        Err(error) => {
            return (
                0,
                0,
                vec![format!("destination principal UID lookup failed: {error}")],
            );
        },
    };
    for (capsule_id, secret_keys) in secret_keys_by_capsule {
        let source_scope = match astrid_storage::ScopedKvStore::new(
            Arc::clone(&kernel.kv),
            astrid_storage::env::principal_secret_namespace(source_uid, capsule_id.as_str()),
        ) {
            Ok(scope) => scope,
            Err(error) => {
                errors.push(format!("source secret scope {capsule_id} failed: {error}"));
                continue;
            },
        };
        let destination_scope = match astrid_storage::ScopedKvStore::new(
            Arc::clone(&kernel.kv),
            astrid_storage::env::principal_secret_namespace(destination_uid, capsule_id.as_str()),
        ) {
            Ok(scope) => scope,
            Err(error) => {
                errors.push(format!(
                    "destination secret scope {capsule_id} failed: {error}"
                ));
                continue;
            },
        };
        probed = probed.saturating_add(secret_keys.len());
        match astrid_storage::env::copy_secret_scope(&source_scope, &destination_scope, secret_keys)
            .await
        {
            Ok(count) => copied = copied.saturating_add(count),
            Err(error) => {
                tracing::warn!(
                    %principal,
                    capsule_id = %capsule_id,
                    error = %error,
                    security_event = true,
                    "agent.create: principal secret copy failed"
                );
                errors.push(format!("secret scope {capsule_id} copy failed: {error}"));
            },
        }
    }
    (probed, copied, errors)
}
