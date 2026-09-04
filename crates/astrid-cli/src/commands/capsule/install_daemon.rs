//! Authenticated daemon-owned capsule installation helpers.
//!
//! The CLI must not open the principal package store for a normal install:
//! the running kernel is the sole durable writer.  This module validates
//! `--var` against the source manifest and sends the values through the typed
//! typed daemon install transaction.  Values are staged before the install
//! lifecycle runs and written again after a successful install through the
//! typed admin API so a lifecycle and the newly loaded runtime observe the
//! same projection.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{
    AdminRequestKind, AdminResponseBody, CapsuleInstallAuthority, CapsuleInstallEnv,
    CapsuleInstallProvenance, EnvStorageScope, EnvValueKind, InstalledCapsuleGeneration,
    InstalledCapsuleIdentity, KernelRequest, KernelResponse,
};

use super::install::ManualInstallOptions;
use super::install_batch::InstalledCapsuleOutcome;

const MAX_BATCH_INSTALL_REQUESTS: usize = 10;
static BATCH_INSTALL_REQUESTS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, thiserror::Error)]
#[error("batch install pass reached the ten-request kernel budget")]
pub(crate) struct BatchInstallBudgetExhausted;

pub(crate) fn reset_batch_install_budget() {
    BATCH_INSTALL_REQUESTS.store(0, Ordering::Relaxed);
}

pub(crate) fn batch_install_budget_exhausted(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<BatchInstallBudgetExhausted>()
        .is_some()
}

fn reserve_batch_install_request() -> bool {
    BATCH_INSTALL_REQUESTS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MAX_BATCH_INSTALL_REQUESTS)
                .then(|| count.checked_add(1))
                .flatten()
        })
        .is_ok()
}

/// A validated operator value ready for the typed daemon API.
#[derive(Debug, Clone)]
struct DaemonEnvValue {
    key: String,
    value: String,
    kind: EnvValueKind,
}

/// Install through the daemon and decode the bounded outcome used by distro
/// provisioning. The daemon remains the only durable writer; this helper only
/// turns its response into the CLI's display record.
pub(super) async fn install_local_via_daemon_outcome(
    source: &str,
    prompt: &ManualInstallOptions,
    authority: CapsuleInstallAuthority,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let principal = crate::principal::current();
    crate::commands::daemon::ensure_persistent_daemon("capsule install")
        .await
        .context("capsule install could not ensure the runtime daemon")?;
    let manifest = load_source_manifest(source)?;
    let capsule_id = CapsuleId::new(manifest.package.name.clone())?;
    let existing_keys = list_existing_keys(&principal, capsule_id.as_str()).await?;
    let vars = if super::install::BATCH_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        prompt
            .vars
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect()
    } else {
        super::install_prompts::collect_install_env_fields(
            &manifest.env,
            capsule_id.as_str(),
            &existing_keys,
            &prompt.vars,
            prompt.yes,
            &astrid_core::dirs::AstridHome::resolve()?.config_path(),
        )?
    };
    install_local_via_daemon_for_target(source, &vars, &principal, None, authority).await
}

async fn list_existing_keys(
    principal: &PrincipalId,
    capsule: &str,
) -> anyhow::Result<std::collections::HashSet<String>> {
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let response = client
        .request(AdminRequestKind::EnvList {
            principal: principal.clone(),
            capsule: Some(capsule.to_owned()),
        })
        .await?;
    let response = crate::admin_client::into_result(response)?;
    let AdminResponseBody::EnvList(entries) = response else {
        bail!("unexpected env list response: {response:?}");
    };
    Ok(entries.into_iter().map(|entry| entry.key).collect())
}

/// Install a local artifact into an explicit authenticated principal's
/// durable registry. The kernel enforces whether the caller may select that
/// target; this helper never opens the principal store itself.
pub(crate) async fn install_local_via_daemon_for_target(
    source: &str,
    vars: &[String],
    target: &PrincipalId,
    provenance: Option<CapsuleInstallProvenance>,
    authority: CapsuleInstallAuthority,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    install_local_via_daemon_for_target_with_generation(
        source, vars, target, provenance, authority, None,
    )
    .await
}

/// Install through the daemon after checking the authenticated caller's
/// durable package identity. The optional generation is test/distro evidence;
/// production callers accept any well-formed generation returned for the
/// matching source digest.
pub(crate) async fn install_local_via_daemon_for_target_with_generation(
    source: &str,
    vars: &[String],
    target: &PrincipalId,
    provenance: Option<CapsuleInstallProvenance>,
    authority: CapsuleInstallAuthority,
    expected_generation: Option<InstalledCapsuleGeneration>,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    crate::commands::daemon::ensure_persistent_daemon("capsule install")
        .await
        .context("capsule install could not ensure the runtime daemon")?;
    let manifest = load_source_manifest(source)?;
    let capsule_id = CapsuleId::new(manifest.package.name.clone())?;
    let values = validate_values(&manifest, vars)?;

    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    // A cross-principal install may be authorized, but the read-only query is
    // deliberately bound to the authenticated caller and never to a request
    // supplied target. Do not compare the caller's package with another owner.
    let caller = crate::principal::current();
    if resume_skip_allowed(&caller, target, &values) {
        let source_path = source.strip_prefix("file://").unwrap_or(source);
        // Digest calculation is only evidence for the skip decision. If the
        // local source is unreadable or malformed, fail closed for resume but
        // continue with the ordinary daemon install path so the kernel can
        // return its canonical install error.
        if let Ok(source_digest) =
            astrid_capsule_install::archive_digest_for_source(Path::new(source_path))
            && let Ok(KernelResponse::InstalledCapsuleIdentity(Some(identity))) = client
                .request(KernelRequest::GetInstalledCapsuleIdentity {
                    id: capsule_id.to_string(),
                })
                .await
            && let Some(outcome) = matching_skip_outcome(
                &identity,
                &capsule_id,
                &manifest.package.version,
                &source_digest,
                expected_generation.as_ref(),
            )
        {
            return Ok(outcome);
        }
    }
    if super::install::BATCH_MODE.load(Ordering::Relaxed) && !reserve_batch_install_request() {
        return Err(BatchInstallBudgetExhausted.into());
    }
    let response = client
        .request(KernelRequest::InstallCapsule {
            source: source.to_owned(),
            workspace: false,
            target_principal: Some(target.clone()),
            provenance,
            authority,
            env: values
                .iter()
                .map(|value| CapsuleInstallEnv {
                    key: value.key.clone(),
                    value: value.value.clone(),
                    kind: value.kind,
                })
                .collect(),
        })
        .await?;
    match response {
        KernelResponse::Success(output) => {
            if !values.is_empty() {
                let mut admin = crate::admin_client::connect_as_active_agent().await?;
                apply_values(&mut admin, target, capsule_id.as_str(), &values).await?;
            }
            let version = output
                .get("installed_version")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(manifest.package.version.as_str())
                .to_owned();
            let wasm_hash = output
                .get("wasm_hash")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            Ok(InstalledCapsuleOutcome {
                id: capsule_id,
                version,
                wasm_hash,
                skipped: false,
            })
        },
        KernelResponse::Error(message) => bail!("daemon rejected capsule install: {message}"),
        other => bail!("unexpected daemon response: {other:?}"),
    }
}

fn resume_matches(
    identity: &InstalledCapsuleIdentity,
    expected_id: &CapsuleId,
    source_digest: &str,
    expected_generation: Option<&InstalledCapsuleGeneration>,
) -> bool {
    identity.id == expected_id.as_str()
        && is_digest(source_digest)
        && identity.archive_digest == source_digest
        && identity.wasm_hash.as_deref().is_some_and(is_digest)
        && is_generation_well_formed(&identity.generation)
        && expected_generation.is_none_or(|expected| expected == &identity.generation)
}

fn matching_skip_outcome(
    identity: &InstalledCapsuleIdentity,
    expected_id: &CapsuleId,
    version: &str,
    source_digest: &str,
    expected_generation: Option<&InstalledCapsuleGeneration>,
) -> Option<InstalledCapsuleOutcome> {
    if !resume_matches(identity, expected_id, source_digest, expected_generation) {
        return None;
    }
    Some(InstalledCapsuleOutcome {
        id: expected_id.clone(),
        version: version.to_owned(),
        wasm_hash: identity.wasm_hash.clone(),
        skipped: true,
    })
}

fn resume_skip_allowed(
    caller: &PrincipalId,
    target: &PrincipalId,
    values: &[DaemonEnvValue],
) -> bool {
    values.is_empty() && resume_query_allowed(caller, target)
}

fn resume_query_allowed(caller: &PrincipalId, target: &PrincipalId) -> bool {
    caller == target
}

fn is_generation_well_formed(generation: &InstalledCapsuleGeneration) -> bool {
    is_digest(&generation.archive)
        && is_digest(&generation.metadata)
        && is_digest(&generation.authority)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn apply_values(
    client: &mut crate::admin_client::AdminClient,
    principal: &PrincipalId,
    capsule: &str,
    values: &[DaemonEnvValue],
) -> anyhow::Result<()> {
    for value in values {
        let response = if value.kind == EnvValueKind::Secret && value.value.is_empty() {
            client
                .request(AdminRequestKind::EnvDelete {
                    principal: principal.clone(),
                    capsule: capsule.to_owned(),
                    key: value.key.clone(),
                    kind: value.kind,
                    scope: EnvStorageScope::Agent,
                })
                .await?
        } else {
            client
                .request(AdminRequestKind::EnvSet {
                    principal: principal.clone(),
                    capsule: capsule.to_owned(),
                    key: value.key.clone(),
                    value: value.value.clone(),
                    kind: value.kind,
                    scope: EnvStorageScope::Agent,
                    append: false,
                })
                .await?
        };
        crate::admin_client::into_result(response)?;
    }
    Ok(())
}

fn load_source_manifest(source: &str) -> anyhow::Result<CapsuleManifest> {
    let source = source.strip_prefix("file://").unwrap_or(source);
    let path = Path::new(source);
    if path.is_dir() {
        return astrid_capsule::discovery::load_manifest(&path.join("Capsule.toml"))
            .map_err(Into::into);
    }
    if path.is_file() {
        return astrid_capsule_install::read_archive_manifest(path)
            .with_context(|| format!("read Capsule.toml from {}", path.display()));
    }
    bail!("source path does not exist: {source}")
}

fn validate_values(
    manifest: &CapsuleManifest,
    items: &[String],
) -> anyhow::Result<Vec<DaemonEnvValue>> {
    let mut parsed = HashMap::new();
    for item in items {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--var must be KEY=VALUE (got {item:?})"))?;
        if key.is_empty() || key.contains('\0') || key.contains(':') {
            bail!("--var has an invalid key (got {key:?})");
        }
        if parsed.insert(key.to_owned(), value.to_owned()).is_some() {
            bail!("--var '{key}' was supplied more than once");
        }
    }

    let mut values = Vec::with_capacity(parsed.len());
    for (key, value) in parsed {
        let definition = manifest.env.get(&key).ok_or_else(|| {
            anyhow::anyhow!(
                "--var names no [env] field in {}: {key}",
                manifest.package.name
            )
        })?;
        let kind = if definition.env_type.eq_ignore_ascii_case("secret") {
            if value.len() > 64 * 1024 {
                bail!("secret value for {key} exceeds 65536-byte limit");
            }
            EnvValueKind::Secret
        } else {
            if value.len() > 1 << 20 {
                bail!("environment value for {key} exceeds 1048576-byte limit");
            }
            EnvValueKind::Text
        };
        if !definition.enum_values.is_empty()
            && !definition
                .enum_values
                .iter()
                .any(|allowed| allowed == &value)
        {
            bail!(
                "invalid value for {}.{}: expected one of {}, got {value:?}",
                manifest.package.name,
                key,
                definition.enum_values.join(", "),
            );
        }
        values.push(DaemonEnvValue { key, value, kind });
    }
    values.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(digest: &str, generation: InstalledCapsuleGeneration) -> InstalledCapsuleIdentity {
        InstalledCapsuleIdentity {
            id: "example".into(),
            generation,
            archive_digest: digest.into(),
            wasm_hash: Some("e".repeat(64)),
        }
    }

    fn generation(seed: char) -> InstalledCapsuleGeneration {
        let value = seed.to_string().repeat(64);
        InstalledCapsuleGeneration {
            archive: value.clone(),
            metadata: value.clone(),
            authority: value,
        }
    }

    fn manifest() -> CapsuleManifest {
        toml::from_str(
            r#"
                [package]
                name = "example"
                version = "1.0.0"
                [env.API_KEY]
                type = "secret"
                [env.MODEL]
                type = "select"
                enum_values = ["small", "large"]
            "#,
        )
        .unwrap()
    }

    #[test]
    fn vars_are_typed_and_manifest_bound() {
        let values = validate_values(
            &manifest(),
            &["API_KEY=secret".into(), "MODEL=small".into()],
        )
        .unwrap();
        assert_eq!(values[0].key, "API_KEY");
        assert_eq!(values[0].kind, EnvValueKind::Secret);
        assert_eq!(values[1].kind, EnvValueKind::Text);
    }

    #[test]
    fn vars_reject_unknown_and_invalid_select_values() {
        assert!(validate_values(&manifest(), &["UNKNOWN=x".into()]).is_err());
        assert!(validate_values(&manifest(), &["MODEL=other".into()]).is_err());
    }

    #[test]
    fn matching_durable_generation_skips_before_install_capsule() {
        let id = CapsuleId::new("example").expect("id");
        let generation = generation('a');
        let digest = "b".repeat(64);
        let installed = identity(&digest, generation.clone());
        assert!(resume_matches(&installed, &id, &digest, Some(&generation)));
    }

    #[test]
    fn matching_skip_carries_canonical_wasm_hash() {
        let id = CapsuleId::new("example").expect("id");
        let generation = generation('a');
        let digest = "b".repeat(64);
        let installed = identity(&digest, generation.clone());
        let outcome = matching_skip_outcome(&installed, &id, "1.0.0", &digest, Some(&generation))
            .expect("matching identity should produce a skip outcome");
        let expected_hash = "e".repeat(64);
        assert!(outcome.skipped);
        assert!(outcome.wasm_hash.as_deref().is_some_and(is_digest));
        assert_eq!(outcome.wasm_hash.as_deref(), Some(expected_hash.as_str()));
    }

    #[test]
    fn missing_wasm_hash_does_not_skip() {
        let id = CapsuleId::new("example").expect("id");
        let generation = generation('a');
        let digest = "b".repeat(64);
        let mut installed = identity(&digest, generation.clone());
        installed.wasm_hash = None;
        assert!(!resume_matches(&installed, &id, &digest, Some(&generation)));
    }

    #[test]
    fn archive_digest_mismatch_does_not_skip() {
        let id = CapsuleId::new("example").expect("id");
        let installed = identity(&"a".repeat(64), generation('b'));
        assert!(!resume_matches(&installed, &id, &"c".repeat(64), None));
    }

    #[test]
    fn generation_mismatch_does_not_skip() {
        let id = CapsuleId::new("example").expect("id");
        let digest = "a".repeat(64);
        let installed = identity(&digest, generation('b'));
        assert!(!resume_matches(
            &installed,
            &id,
            &digest,
            Some(&generation('c'))
        ));
    }

    #[test]
    fn malformed_generation_does_not_skip() {
        let id = CapsuleId::new("example").expect("id");
        let digest = "a".repeat(64);
        let installed = identity(
            &digest,
            InstalledCapsuleGeneration {
                archive: "not-a-digest".into(),
                metadata: "b".repeat(64),
                authority: "c".repeat(64),
            },
        );
        assert!(!resume_matches(&installed, &id, &digest, None));
    }

    #[test]
    fn principal_b_does_not_skip_from_principal_a_snapshot() {
        let principal_a = PrincipalId::new("alice").expect("principal");
        let principal_b = PrincipalId::new("bob").expect("principal");
        assert!(!resume_query_allowed(&principal_b, &principal_a));
    }

    #[test]
    fn non_empty_values_do_not_attempt_resume_skip() {
        let principal = PrincipalId::new("alice").expect("principal");
        let values = validate_values(&manifest(), &["MODEL=small".into()]).expect("valid vars");
        assert!(!resume_skip_allowed(&principal, &principal, &values));
    }

    #[test]
    fn twenty_two_member_distro_resumes_without_reissuing_completed() {
        let mut completed = [false; 22];
        let mut sent_per_pass = Vec::new();
        for _ in 0..3 {
            reset_batch_install_budget();
            let mut sent = 0;
            for member in &mut completed {
                if *member {
                    continue;
                }
                if !reserve_batch_install_request() {
                    break;
                }
                *member = true;
                sent += 1;
            }
            sent_per_pass.push(sent);
        }
        assert_eq!(sent_per_pass, [10, 10, 2]);
        assert!(completed.into_iter().all(|done| done));
    }
}
