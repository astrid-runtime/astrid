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

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{
    AdminRequestKind, CapsuleInstallEnv, CapsuleInstallProvenance, EnvStorageScope, EnvValueKind,
    KernelRequest, KernelResponse,
};

use super::install_batch::InstalledCapsuleOutcome;

/// A validated operator value ready for the typed daemon API.
#[derive(Debug, Clone)]
struct DaemonEnvValue {
    key: String,
    value: String,
    kind: EnvValueKind,
}

/// Install a local directory/archive through the authenticated kernel API.
///
/// `--var` values are checked against the source manifest before any daemon
/// mutation.  They are staged by the kernel's rollback-aware install
/// transaction before the lifecycle hook and replayed through `EnvSet` after
/// success to make the post-install projection explicit and idempotent.
pub(super) async fn install_local_via_daemon(source: &str, vars: &[String]) -> anyhow::Result<()> {
    install_local_via_daemon_outcome(source, vars)
        .await
        .map(|_| ())
}

/// Install through the daemon and decode the bounded outcome used by distro
/// provisioning. The daemon remains the only durable writer; this helper only
/// turns its response into the CLI's display record.
pub(super) async fn install_local_via_daemon_outcome(
    source: &str,
    vars: &[String],
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let principal = crate::principal::current();
    install_local_via_daemon_for_target(source, vars, &principal, None).await
}

/// Install a local artifact into an explicit authenticated principal's
/// durable registry. The kernel enforces whether the caller may select that
/// target; this helper never opens the principal store itself.
pub(crate) async fn install_local_via_daemon_for_target(
    source: &str,
    vars: &[String],
    target: &PrincipalId,
    provenance: Option<CapsuleInstallProvenance>,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let manifest = load_source_manifest(source)?;
    let capsule_id = CapsuleId::new(manifest.package.name.clone())?;
    let values = validate_values(&manifest, vars)?;

    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    let response = client
        .request(KernelRequest::InstallCapsule {
            source: source.to_owned(),
            workspace: false,
            target_principal: Some(target.clone()),
            provenance,
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
            })
        },
        KernelResponse::Error(message) => bail!("daemon rejected capsule install: {message}"),
        other => bail!("unexpected daemon response: {other:?}"),
    }
}

pub(super) fn is_local_source(source: &str) -> bool {
    source.starts_with('.')
        || source.starts_with('/')
        || source.ends_with(".capsule")
        || Path::new(source.strip_prefix("file://").unwrap_or(source)).exists()
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
}
