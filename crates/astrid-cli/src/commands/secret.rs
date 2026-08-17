//! `astrid secret` — capsule env-var configuration for an agent.
//!
//! Routes through the capsule manifest's declared `env_type`:
//!
//! * `type = "secret"` — value lands in the daemon's host-only typed
//!   SecretStore projection. `<scope>` is the principal when
//!   `--scope=agent` (the fail-closed default) or the system owner when
//!   `--scope=shared`.
//!
//! * everything else — value lands in the daemon's host-only typed
//!   environment projection for the selected principal/capsule.
//!
//! Values are sent to the daemon over the authenticated admin API; the CLI
//! never opens a native env or secret path.

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule::manifest::EnvScope;
#[cfg(test)]
use astrid_capsule::manifest::{CapsuleManifest, EnvDef};
#[cfg(test)]
use astrid_core::PrincipalId;
#[cfg(test)]
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use astrid_core::kernel_api::{
    AdminRequestKind, AdminResponseBody, EnvEntry, EnvStorageScope, EnvValueKind, KernelRequest,
};
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::Serialize;

use crate::context;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

/// Load the manifest for `capsule` using runtime discovery precedence:
/// selected-principal install registry first, then the verified workspace.
/// Returns `None` when the capsule isn't installed — caller falls back
/// to env JSON, and the load-time migration handles the value on
/// install.
#[cfg(test)]
fn load_capsule_manifest(
    principal: &PrincipalId,
    capsule: &CapsuleId,
) -> Result<Option<CapsuleManifest>> {
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    load_capsule_manifest_with_workspace_resolver(
        &home,
        principal,
        capsule,
        crate::workspace_layout::current(),
        || std::env::current_dir().context("Failed to resolve current workspace directory"),
    )
}

#[cfg(test)]
fn load_capsule_manifest_with_workspace_resolver(
    home: &AstridHome,
    principal: &PrincipalId,
    capsule: &CapsuleId,
    workspace_layout: &WorkspaceLayout,
    resolve_workspace_root: impl FnOnce() -> Result<PathBuf>,
) -> Result<Option<CapsuleManifest>> {
    if let Some(manifest) = load_capsule_manifest_from_home_in_workspace(
        home,
        principal,
        capsule,
        None,
        workspace_layout,
    )? {
        return Ok(Some(manifest));
    }
    let workspace_root = resolve_workspace_root()?;
    load_capsule_manifest_from_home_in_workspace(
        home,
        principal,
        capsule,
        Some(&workspace_root),
        workspace_layout,
    )
}

#[cfg(test)]
fn load_capsule_manifest_from_home(
    home: &AstridHome,
    principal: &PrincipalId,
    capsule: &CapsuleId,
) -> Result<Option<CapsuleManifest>> {
    load_capsule_manifest_from_home_in_workspace(
        home,
        principal,
        capsule,
        None,
        &WorkspaceLayout::default(),
    )
}

#[cfg(test)]
fn load_capsule_manifest_from_home_in_workspace(
    home: &AstridHome,
    principal: &PrincipalId,
    capsule: &CapsuleId,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> Result<Option<CapsuleManifest>> {
    let principal_manifest = home
        .principal_home(principal)
        .capsules_dir()
        .join(capsule.as_str())
        .join("Capsule.toml");
    if principal_manifest.exists() {
        return read_capsule_manifest(&principal_manifest).map(Some);
    }

    let Some(workspace_root) = workspace_root else {
        return Ok(None);
    };
    let workspace = workspace_layout
        .resolve(workspace_root)
        .context("Failed to resolve the selected workspace")?;
    let capsules_dir = workspace
        .verify_tree("capsules")
        .context("Workspace capsule directory is unsafe")?;
    let workspace_manifest = capsules_dir.join(capsule.as_str()).join("Capsule.toml");
    if !workspace_manifest.exists() {
        workspace.verify_tree("capsules").map_err(|e| {
            anyhow::anyhow!("Workspace capsule directory changed during manifest lookup: {e}")
        })?;
        return Ok(None);
    }
    let manifest = read_capsule_manifest(&workspace_manifest)?;
    workspace
        .verify_tree("capsules")
        .context("Workspace capsule directory changed while reading its manifest")?;
    Ok(Some(manifest))
}

#[cfg(test)]
fn read_capsule_manifest(manifest_path: &Path) -> Result<CapsuleManifest> {
    let contents = fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read {}", manifest_path.display()))?;
    let manifest: CapsuleManifest = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse {}", manifest_path.display()))?;
    Ok(manifest)
}

/// Returns `Some(EnvDef)` when the manifest declares `key` AND
/// `env_type = "secret"`. Non-secret declarations and missing
/// declarations both return `None` (operator-set values for those
/// use the typed text namespace).
#[cfg(test)]
fn lookup_secret_decl<'a>(manifest: Option<&'a CapsuleManifest>, key: &str) -> Option<&'a EnvDef> {
    manifest?
        .env
        .get(key)
        .filter(|d| d.env_type.eq_ignore_ascii_case("secret"))
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum SecretCommand {
    /// Store a secret value for an agent (and optionally a specific capsule).
    Set(SetArgs),
    /// List secret keys for an agent (values redacted).
    List(ListArgs),
    /// Remove a secret.
    Delete(DeleteArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct SetArgs {
    /// Secret key (e.g. `OPENAI_API_KEY`).
    pub key: String,
    /// Secret value.
    pub value: String,
    /// Agent name (defaults to active context).
    #[arg(short, long)]
    pub agent: Option<String>,
    /// Capsule that consumes this env var. Required when the secret
    /// is capsule-specific; omitted for shared secrets in the host control
    /// scope.
    #[arg(long, value_name = "NAME")]
    pub capsule: Option<String>,
    /// Override the capsule manifest's declared `scope` for this
    /// secret. `agent` stores per-principal; `shared` stores
    /// host-wide (visible to every agent's per-invocation lookup as
    /// a fall-through). Only meaningful for keys the manifest
    /// declares as `env_type = "secret"`. Defaults to the manifest's
    /// declared scope (which itself defaults to `agent`).
    #[arg(long, value_name = "agent|shared")]
    pub scope: Option<ScopeArg>,
}

/// CLI flag value for `--scope`. Mirrors
/// [`astrid_capsule::manifest::EnvScope`]; kept separate so clap can
/// derive `ValueEnum` without leaking the manifest type into clap's
/// public surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ScopeArg {
    /// Per-principal storage. Each agent has their own value.
    Agent,
    /// Host-wide storage. Every agent's per-invocation lookup
    /// falls through to this on per-agent miss.
    Shared,
}

impl From<ScopeArg> for EnvScope {
    fn from(s: ScopeArg) -> Self {
        match s {
            ScopeArg::Agent => Self::Agent,
            ScopeArg::Shared => Self::Shared,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ListArgs {
    /// Agent name (defaults to active context).
    #[arg(short, long)]
    pub agent: Option<String>,
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct DeleteArgs {
    /// Secret key.
    pub key: String,
    /// Agent name (defaults to active context).
    #[arg(short, long)]
    pub agent: Option<String>,
    /// Capsule the secret belongs to.
    #[arg(long, value_name = "NAME")]
    pub capsule: Option<String>,
}

/// Top-level dispatcher for `astrid secret`.
pub(crate) async fn run(cmd: SecretCommand) -> Result<ExitCode> {
    match cmd {
        SecretCommand::Set(args) => run_set(&args).await,
        SecretCommand::List(args) => run_list(&args).await,
        SecretCommand::Delete(args) => run_delete(&args).await,
    }
}

fn validate_optional_capsule(capsule: Option<&str>) -> Result<CapsuleId> {
    CapsuleId::new(
        capsule
            .ok_or_else(|| {
                anyhow::anyhow!("--capsule is required; native default env storage was retired")
            })?
            .to_owned(),
    )
    .context("invalid capsule name")
}

/// Resolve one capsule's non-secret schema through the authenticated daemon
/// inventory. The CLI must not inspect a materialized `Capsule.toml` under a
/// principal home: the registry snapshot is the authority for installed
/// capsule metadata, while workspace capsules are only visible through the
/// explicit workspace inventory.
async fn capsule_env_kind(capsule: &CapsuleId, key: &str) -> Result<Option<EnvValueKind>> {
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    let response = client.request(KernelRequest::GetCapsuleMetadata).await?;
    let entries = match response {
        astrid_core::kernel_api::KernelResponse::CapsuleMetadata(entries) => entries,
        astrid_core::kernel_api::KernelResponse::Error(error) => {
            anyhow::bail!("daemon metadata lookup failed: {error}");
        },
        other => anyhow::bail!("unexpected daemon metadata response: {other:?}"),
    };
    Ok(entries
        .into_iter()
        .find(|entry| entry.name == capsule.as_str())
        .and_then(|entry| {
            entry.env.get(key).map(|field| {
                if field.env_type.eq_ignore_ascii_case("secret") {
                    EnvValueKind::Secret
                } else {
                    EnvValueKind::Text
                }
            })
        }))
}

async fn run_set(args: &SetArgs) -> Result<ExitCode> {
    if args.key.is_empty() {
        anyhow::bail!("invalid key: must not be empty");
    }
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let capsule = validate_optional_capsule(args.capsule.as_deref())?;

    // --scope only applies to secrets. Resolve the type from the daemon's
    // durable registry rather than reading a native principal-home manifest.
    let kind = capsule_env_kind(&capsule, &args.key)
        .await?
        .unwrap_or(EnvValueKind::Text);
    let secret_declared = kind == EnvValueKind::Secret;

    if args.scope.is_some() && !secret_declared {
        anyhow::bail!(
            "--scope requires the capsule manifest to declare '{}' as type=\"secret\" \
             (manifest declares either a non-secret env field, or no field at all for this key)",
            args.key
        );
    }

    let scope = args
        .scope
        .map_or(EnvStorageScope::Agent, |scope| match scope {
            ScopeArg::Agent => EnvStorageScope::Agent,
            ScopeArg::Shared => EnvStorageScope::Shared,
        });
    if matches!(kind, EnvValueKind::Text) && !matches!(scope, EnvStorageScope::Agent) {
        anyhow::bail!("--scope=shared is only valid for manifest-declared secrets");
    }
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let body = client
        .request(AdminRequestKind::EnvSet {
            principal: principal.clone(),
            capsule: capsule.to_string(),
            key: args.key.clone(),
            value: args.value.clone(),
            kind,
            scope,
            append: false,
        })
        .await?;
    crate::admin_client::into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!(
            "Stored '{}' for agent '{}' (capsule {})",
            args.key, principal, capsule
        ))
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_list(args: &ListArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let format = ValueFormat::parse(&args.format);
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let body = client
        .request(AdminRequestKind::EnvList {
            principal,
            capsule: None,
        })
        .await?;
    let body = crate::admin_client::into_result(body)?;
    let AdminResponseBody::EnvList(entries) = body else {
        anyhow::bail!("unexpected response from kernel: {body:?}");
    };
    let mut keys = entries
        .into_iter()
        .map(secret_key_from_entry)
        .collect::<Vec<_>>();

    keys.sort_by(|a, b| a.capsule.cmp(&b.capsule).then_with(|| a.key.cmp(&b.key)));
    if !format.is_pretty() {
        emit_structured(&keys, format)?;
        return Ok(ExitCode::SUCCESS);
    }
    if keys.is_empty() {
        println!("{}", Theme::info("(no secrets stored)"));
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{:<24}  {:<32}  {:<12}  {}",
        "CAPSULE".bold(),
        "KEY".bold(),
        "STORAGE".bold(),
        "SCOPE".bold(),
    );
    for k in &keys {
        let storage = match k.storage {
            SecretStorage::SecretStore => "secret-store".green().to_string(),
            SecretStorage::EnvStore => "env-store".dimmed().to_string(),
        };
        let scope = match k.scope {
            Some(EnvScope::Agent) => "agent",
            Some(EnvScope::Shared) => "shared",
            None => "—",
        };
        println!("{:<24}  {:<32}  {:<12}  {scope}", k.capsule, k.key, storage);
    }
    Ok(ExitCode::SUCCESS)
}

fn secret_key_from_entry(entry: EnvEntry) -> SecretKey {
    SecretKey {
        capsule: entry.capsule,
        key: entry.key,
        storage: match entry.kind {
            EnvValueKind::Secret => SecretStorage::SecretStore,
            EnvValueKind::Text => SecretStorage::EnvStore,
        },
        scope: Some(match entry.scope {
            EnvStorageScope::Agent => EnvScope::Agent,
            EnvStorageScope::Shared => EnvScope::Shared,
        }),
    }
}

async fn run_delete(args: &DeleteArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let capsule = validate_optional_capsule(args.capsule.as_deref())?;
    let kind = capsule_env_kind(&capsule, &args.key)
        .await?
        .unwrap_or(EnvValueKind::Text);
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let scopes = if matches!(kind, EnvValueKind::Secret) {
        vec![EnvStorageScope::Agent, EnvStorageScope::Shared]
    } else {
        vec![EnvStorageScope::Agent]
    };
    let mut removed = false;
    for scope in scopes {
        let body = client
            .request(AdminRequestKind::EnvDelete {
                principal: principal.clone(),
                capsule: capsule.to_string(),
                key: args.key.clone(),
                kind,
                scope,
            })
            .await?;
        let body = crate::admin_client::into_result(body)?;
        if let AdminResponseBody::Success(value) = body {
            removed |= value
                .get("deleted")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
        }
    }
    if !removed {
        eprintln!("{}", Theme::warning(&format!("'{}' not set", args.key)));
        return Ok(ExitCode::from(1));
    }
    println!(
        "{}",
        Theme::success(&format!("Removed '{}' for agent '{}'", args.key, principal))
    );
    Ok(ExitCode::SUCCESS)
}

/// JSON/YAML/TOML emission shape — keys only, values redacted.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SecretKey {
    /// The capsule whose host-owned projection holds the key.
    pub capsule: String,
    /// The env-var key.
    pub key: String,
    /// Which host-owned typed projection contains this value.
    pub storage: SecretStorage,
    /// Sharing model resolved from the host-owned projection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<EnvScope>,
}

/// Storage backend for a `secret list` row.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SecretStorage {
    /// Host-only typed SecretStore projection.
    SecretStore,
    /// Host-only typed non-secret environment projection.
    EnvStore,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_id() -> CapsuleId {
        CapsuleId::new("provider").unwrap()
    }

    #[test]
    fn capsule_names_are_validated_before_path_construction() {
        assert!(validate_optional_capsule(Some("../../outside")).is_err());
        assert!(validate_optional_capsule(Some("Provider")).is_err());
        assert_eq!(
            validate_optional_capsule(Some("safe-provider"))
                .unwrap()
                .as_str(),
            "safe-provider"
        );
    }

    #[test]
    fn manifest_lookup_is_scoped_to_the_requested_principal() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        let default = PrincipalId::default();
        let alice = PrincipalId::new("alice").unwrap();

        for (principal, description) in [(&default, "default manifest"), (&alice, "alice manifest")]
        {
            let capsule_dir = home
                .principal_home(principal)
                .capsules_dir()
                .join("provider");
            fs::create_dir_all(&capsule_dir).unwrap();
            fs::write(
                capsule_dir.join("Capsule.toml"),
                format!(
                    r#"
                    [package]
                    name = "provider"
                    version = "1.0.0"

                    [env.api_key]
                    type = "secret"
                    description = "{description}"
                    "#
                ),
            )
            .unwrap();
        }

        let manifest = load_capsule_manifest_from_home(&home, &alice, &provider_id())
            .unwrap()
            .expect("Alice manifest");
        assert_eq!(
            manifest.env["api_key"].description.as_deref(),
            Some("alice manifest")
        );
    }

    #[test]
    fn principal_manifest_lookup_does_not_require_a_workspace_directory() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        let alice = PrincipalId::new("alice").unwrap();
        let capsule_dir = home.principal_home(&alice).capsules_dir().join("provider");
        fs::create_dir_all(&capsule_dir).unwrap();
        fs::write(
            capsule_dir.join("Capsule.toml"),
            r#"
            [package]
            name = "provider"
            version = "1.0.0"
            "#,
        )
        .unwrap();

        let manifest = load_capsule_manifest_with_workspace_resolver(
            &home,
            &alice,
            &provider_id(),
            &WorkspaceLayout::default(),
            || anyhow::bail!("workspace resolution must remain lazy"),
        )
        .unwrap()
        .expect("principal manifest");

        assert_eq!(manifest.package.name, "provider");
    }

    #[test]
    fn manifest_lookup_falls_back_to_the_verified_workspace() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let workspace = tempfile::tempdir().unwrap();
        let capsule_dir = workspace.path().join(".astrid/capsules/provider");
        fs::create_dir_all(&capsule_dir).unwrap();
        fs::write(
            capsule_dir.join("Capsule.toml"),
            r#"
            [package]
            name = "provider"
            version = "1.0.0"

            [env.api_key]
            type = "secret"
            description = "workspace manifest"
            "#,
        )
        .unwrap();

        let manifest = load_capsule_manifest_from_home_in_workspace(
            &home,
            &PrincipalId::new("alice").unwrap(),
            &provider_id(),
            Some(workspace.path()),
            &WorkspaceLayout::default(),
        )
        .unwrap()
        .expect("workspace manifest");

        assert_eq!(
            lookup_secret_decl(Some(&manifest), "api_key")
                .and_then(|decl| decl.description.as_deref()),
            Some("workspace manifest")
        );
    }

    #[test]
    fn principal_manifest_takes_precedence_over_workspace_manifest() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let workspace = tempfile::tempdir().unwrap();
        let principal = PrincipalId::new("alice").unwrap();
        let principal_capsule = home
            .principal_home(&principal)
            .capsules_dir()
            .join("provider");
        let workspace_capsule = workspace.path().join(".astrid/capsules/provider");
        for (capsule_dir, description) in [
            (&principal_capsule, "principal manifest"),
            (&workspace_capsule, "workspace manifest"),
        ] {
            fs::create_dir_all(capsule_dir).unwrap();
            fs::write(
                capsule_dir.join("Capsule.toml"),
                format!(
                    r#"
                    [package]
                    name = "provider"
                    version = "1.0.0"

                    [env.api_key]
                    type = "secret"
                    description = "{description}"
                    "#
                ),
            )
            .unwrap();
        }

        let manifest = load_capsule_manifest_from_home_in_workspace(
            &home,
            &principal,
            &provider_id(),
            Some(workspace.path()),
            &WorkspaceLayout::default(),
        )
        .unwrap()
        .expect("principal manifest");

        assert_eq!(
            manifest.env["api_key"].description.as_deref(),
            Some("principal manifest")
        );
    }

    #[cfg(unix)]
    #[test]
    fn manifest_lookup_rejects_redirected_workspace_capsules() {
        use std::os::unix::fs::symlink;

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join(".astrid")).unwrap();
        symlink(outside.path(), workspace.path().join(".astrid/capsules")).unwrap();

        let result = load_capsule_manifest_from_home_in_workspace(
            &home,
            &PrincipalId::new("alice").unwrap(),
            &provider_id(),
            Some(workspace.path()),
            &WorkspaceLayout::default(),
        );

        assert!(result.is_err());
    }
}
