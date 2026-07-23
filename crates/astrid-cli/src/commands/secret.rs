//! `astrid secret` — capsule env-var configuration for an agent.
//!
//! Routes through the capsule manifest's declared `env_type`:
//!
//! * `type = "secret"` — value lands in
//!   `~/.astrid/secrets/<scope>/<capsule>/<key>` via
//!   [`astrid_storage::FileSecretStore`], `0600` on the file and
//!   `0700` on the parent directories. `<scope>` is the agent
//!   principal name when `--scope=agent` (the fail-closed default)
//!   or the `__host__` sentinel when `--scope=shared`. The kernel
//!   read side resolves the same path so a value written here is
//!   immediately visible to the running capsule.
//!
//! * everything else — value lands in
//!   `<principal_home>/.config/env/<capsule>.env.json` (the same path
//!   the capsule installer writes), `0o600` on the file, `0o700` on
//!   the parent. Used for non-secret operator-tunable config
//!   (registry endpoints, model names, log levels).
//!
//! When the operator omits `--capsule` we can't read a manifest to
//! decide; we fall back to the env-JSON path. When the capsule is
//! not yet installed (no manifest on disk), same fall-back — the
//! load-time migration in `Kernel::load_capsule` heals the value
//! when the capsule eventually installs.
//!
//! ## Why file-based and not the OS keychain
//!
//! The keychain was tried first (rationale: OS-level encryption at
//! rest, ACL-gated reads). It does not survive the dev rebuild loop
//! without a stable code-signing identity — every `cargo build`
//! changes the binary's cdhash, so the OS prompts the operator on
//! every read. Astrid ships via Homebrew/Cargo source-build paths
//! where each customer's build is unsigned, so the prompt problem
//! would chase end users too. File-per-secret with `0600` matches
//! how the rest of the CLI-tool ecosystem stores credentials
//! (`gh`, `aws`, `kubectl`, `npm`, `docker` default helper) — the
//! OS user account is the trust boundary, and the file mode
//! enforces the access bound.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_capsule::manifest::{CapsuleManifest, EnvDef, EnvScope};
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_storage::{FileSecretStore, SecretStore, SecretStoreError};
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::context;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

/// Sentinel scope name for shared (`__host__`) secrets — the slot
/// the kernel's secret-resolve falls back to when a per-agent
/// lookup misses. Operator-typed principal names are constrained
/// to `[a-z0-9_-]+` by `PrincipalId::new`, so `__host__` cannot
/// collide with a real principal.
const HOST_SCOPE_SENTINEL: &str = "__host__";

/// Build the on-disk directory for a `(scope, capsule)` pair under
/// `~/.astrid/secrets/`. Pivoted from the keychain service-name
/// path because system-keychain prompts kept landing on every
/// rebuild without a stable code-signing identity (see Astrid
/// shipping via Homebrew/Cargo source-build distribution — no
/// Developer ID, so the OS gates each read).
fn secret_dir(home: &AstridHome, scope: &str, capsule: &str) -> PathBuf {
    home.secrets_dir().join(scope).join(capsule)
}

/// Open the file-backed secret store for a `(principal, capsule,
/// scope)` triple. Returns a fresh [`FileSecretStore`] each call —
/// cheap, just a path under `~/.astrid/secrets/`.
fn open_secret_store(
    home: &AstridHome,
    principal: &PrincipalId,
    capsule: &str,
    scope: EnvScope,
) -> FileSecretStore {
    let principal_seg = match scope {
        EnvScope::Shared => HOST_SCOPE_SENTINEL.to_string(),
        EnvScope::Agent => principal.as_str().to_string(),
    };
    FileSecretStore::new(secret_dir(home, &principal_seg, capsule))
}

/// Map a [`SecretStoreError`] to a CLI error with an operator-
/// friendly hint. The file backend's failure modes are filesystem
/// errors (permission denied on `~/.astrid/secrets/`, full disk)
/// rather than keychain-locked, so the hint reflects that.
fn secret_store_error(op: &str, e: &SecretStoreError) -> anyhow::Error {
    anyhow::anyhow!("secret {op} failed: {e}")
}

/// Load the installed manifest for `capsule` from the selected principal's
/// install registry.
/// Returns `None` when the capsule isn't installed — caller falls back
/// to env JSON, and the load-time migration handles the value on
/// install.
fn load_capsule_manifest(
    principal: &PrincipalId,
    capsule: &str,
) -> Result<Option<CapsuleManifest>> {
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    load_capsule_manifest_from_home(&home, principal, capsule)
}

fn load_capsule_manifest_from_home(
    home: &AstridHome,
    principal: &PrincipalId,
    capsule: &str,
) -> Result<Option<CapsuleManifest>> {
    let manifest_path = home
        .principal_home(principal)
        .capsules_dir()
        .join(capsule)
        .join("Capsule.toml");
    if !manifest_path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&manifest_path)
        .with_context(|| format!("Failed to read {}", manifest_path.display()))?;
    let manifest: CapsuleManifest = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse {}", manifest_path.display()))?;
    Ok(Some(manifest))
}

/// Returns `Some(EnvDef)` when the manifest declares `key` AND
/// `env_type = "secret"`. Non-secret declarations and missing
/// declarations both return `None` (operator-set values for those
/// land in the env-JSON path).
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
    /// is capsule-specific; omitted for shared secrets that go in
    /// `default.env.json`.
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
pub(crate) fn run(cmd: SecretCommand) -> Result<ExitCode> {
    match cmd {
        SecretCommand::Set(args) => run_set(&args),
        SecretCommand::List(args) => run_list(&args),
        SecretCommand::Delete(args) => run_delete(&args),
    }
}

fn env_dir(principal: &PrincipalId) -> Result<PathBuf> {
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    Ok(home.principal_home(principal).env_dir())
}

fn env_file(principal: &PrincipalId, capsule: Option<&str>) -> Result<PathBuf> {
    let dir = env_dir(principal)?;
    let name = capsule.unwrap_or("default");
    Ok(dir.join(format!("{name}.env.json")))
}

fn read_env(path: &std::path::Path) -> Result<Map<String, Value>> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let contents =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    if contents.trim().is_empty() {
        return Ok(Map::new());
    }
    let value: Value = serde_json::from_str(&contents)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => anyhow::bail!("{} is not a JSON object", path.display()),
    }
}

fn write_env(path: &std::path::Path, env: &Map<String, Value>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            // Best-effort: tighten if we created the directory; ignore
            // failures (e.g. existing directory we don't own).
            let _ = fs::set_permissions(parent, perms);
        }
    }
    let contents = serde_json::to_string_pretty(env).context("Failed to serialize env JSON")?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &contents).with_context(|| format!("Failed to write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&tmp, perms)
            .with_context(|| format!("Failed to chmod {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("Failed to rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

fn classify_env_storage(is_declared_secret: bool, value: &Value) -> Option<SecretStorage> {
    if !is_declared_secret {
        return Some(SecretStorage::EnvJson);
    }
    if value.as_str() == Some("") {
        return None;
    }
    Some(SecretStorage::EnvJsonLegacy)
}

fn run_set(args: &SetArgs) -> Result<ExitCode> {
    if args.key.is_empty() {
        anyhow::bail!("invalid key: must not be empty");
    }
    let principal = context::resolve_agent(args.agent.as_deref())?;

    // --scope only applies to secrets. Reject it on a non-secret key
    // up front so an operator who's confused about which knob does
    // what gets a clear error, not a silent ignore.
    if args.scope.is_some() && args.capsule.is_none() {
        anyhow::bail!(
            "--scope requires --capsule (the manifest is read from the named capsule to confirm \
             the key is declared as a secret)"
        );
    }

    let manifest = match args.capsule.as_deref() {
        Some(c) => load_capsule_manifest(&principal, c)?,
        None => None,
    };
    let secret_decl = args
        .capsule
        .as_deref()
        .and_then(|_| lookup_secret_decl(manifest.as_ref(), &args.key));

    if args.scope.is_some() && secret_decl.is_none() {
        anyhow::bail!(
            "--scope requires the capsule manifest to declare '{}' as type=\"secret\" \
             (manifest declares either a non-secret env field, or no field at all for this key)",
            args.key
        );
    }

    if secret_decl.is_some() {
        // Secret-typed: route through the file secret store
        // (`~/.astrid/secrets/<scope>/<capsule>/<key>`, 0600). The
        // env JSON path is bypassed entirely so the value is never
        // co-mingled with non-secret operator config.
        //
        // Scope is operator-decided: `--scope` flag or the
        // fail-closed `agent` default. The manifest declares only
        // "this is a secret"; it does NOT dictate sharing, because
        // capsules come from external sources and can't be trusted
        // to mark their own credentials as host-shared (privilege
        // escalation vector — bot tokens, OAuth bindings).
        let scope: EnvScope = args.scope.map_or(EnvScope::Agent, EnvScope::from);
        let capsule = args
            .capsule
            .as_deref()
            .expect("capsule name required to route a secret-typed key — the loader above already gates on Some(manifest), which requires args.capsule");
        let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
        let store = open_secret_store(&home, &principal, capsule, scope);
        store
            .set(&args.key, &args.value)
            .map_err(|e| secret_store_error("set", &e))?;
        let target = match scope {
            EnvScope::Agent => format!("agent '{principal}' (capsule {capsule})"),
            EnvScope::Shared => format!("host-wide (capsule {capsule})"),
        };
        println!(
            "{}",
            Theme::success(&format!("Stored '{}' for {target}", args.key))
        );
    } else {
        // Non-secret (or no manifest for the capsule): env JSON
        // path. Same behaviour as pre-#19.
        let path = env_file(&principal, args.capsule.as_deref())?;
        let mut env = read_env(&path)?;
        env.insert(args.key.clone(), Value::String(args.value.clone()));
        write_env(&path, &env)?;
        println!(
            "{}",
            Theme::success(&format!(
                "Stored '{}' for agent '{}'{}",
                args.key,
                principal,
                args.capsule
                    .as_deref()
                    .map_or_else(String::new, |c| format!(" (capsule {c})"))
            ))
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn run_list(args: &ListArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let format = ValueFormat::parse(&args.format);
    let dir = env_dir(&principal)?;
    let mut keys: Vec<SecretKey> = Vec::new();

    // 1. Enumerate env JSON entries (non-secret config). Plus any
    //    legacy plaintext-secret entries the load-time migration
    //    hasn't healed yet — flagged separately so operators see
    //    pre-#19 state on disk that should be migrated.
    if dir.exists() {
        for entry in
            fs::read_dir(&dir).with_context(|| format!("Failed to read {}", dir.display()))?
        {
            let entry = entry?;
            let p = entry.path();
            let Some(file_name) = p.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(stem) = file_name.strip_suffix(".env.json") else {
                continue;
            };
            let env = read_env(&p)?;
            // Cross-reference the manifest if this is a capsule-
            // scoped file (stem matches an installed capsule name).
            // I/O errors propagate — a stale-on-disk env file paired
            // with a manifest read failure must not get silently
            // classified as `EnvJson` (non-secret) when it might be a
            // legacy plaintext secret.
            let manifest = load_capsule_manifest(&principal, stem)?;
            for (k, value) in &env {
                let is_declared_secret = manifest
                    .as_ref()
                    .and_then(|m| m.env.get(k))
                    .is_some_and(|d| d.env_type.eq_ignore_ascii_case("secret"));
                let Some(storage) = classify_env_storage(is_declared_secret, value) else {
                    continue;
                };
                keys.push(SecretKey {
                    capsule: stem.to_string(),
                    key: k.clone(),
                    storage,
                    scope: None,
                });
            }
        }
    }

    // 2. Probe the file secret store for every secret-typed env
    //    field every installed capsule declares. Drive the lookup
    //    from the manifests rather than walking the secrets
    //    directory directly — that keeps the listing scoped to
    //    declared secrets (capability boundary: stale on-disk files
    //    from a removed capsule don't appear here).
    if let Ok(home) = AstridHome::resolve() {
        let capsules_dir = home.principal_home(&principal).capsules_dir();
        if capsules_dir.is_dir() {
            for entry in fs::read_dir(&capsules_dir)
                .with_context(|| format!("Failed to read {}", capsules_dir.display()))?
            {
                let entry = entry?;
                let capsule = entry.file_name().to_string_lossy().into_owned();
                let Some(manifest) = load_capsule_manifest_from_home(&home, &principal, &capsule)?
                else {
                    continue;
                };
                for (key, decl) in &manifest.env {
                    if !decl.env_type.eq_ignore_ascii_case("secret") {
                        continue;
                    }
                    // Scope is operator-decided at set time, not
                    // manifest-declared — probe both slots and
                    // report whichever is populated. A value can
                    // exist in either or both (per-agent override
                    // alongside a host-wide fall-through).
                    for scope in [EnvScope::Agent, EnvScope::Shared] {
                        let store = open_secret_store(&home, &principal, &capsule, scope);
                        if store.exists(key).unwrap_or(false) {
                            keys.push(SecretKey {
                                capsule: capsule.clone(),
                                key: key.clone(),
                                storage: SecretStorage::File,
                                scope: Some(scope),
                            });
                        }
                    }
                }
            }
        }
    }

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
            SecretStorage::File => "file".green().to_string(),
            SecretStorage::EnvJson => "env-json".dimmed().to_string(),
            SecretStorage::EnvJsonLegacy => "env-json (LEGACY!)".red().to_string(),
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

fn run_delete(args: &DeleteArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;

    // Try the file secret store first if the manifest declares this
    // key secret. Try BOTH per-agent and host-wide slots — the
    // operator could have stored at either, and we want delete to
    // be unambiguous regardless of where the value landed. The
    // env-JSON path is still hit afterwards in case the value
    // pre-dates the load-time strip.
    if let Some(capsule) = args.capsule.as_deref() {
        let manifest = load_capsule_manifest(&principal, capsule)?;
        if lookup_secret_decl(manifest.as_ref(), &args.key).is_some() {
            let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
            let mut removed = false;
            for scope in [EnvScope::Agent, EnvScope::Shared] {
                let store = open_secret_store(&home, &principal, capsule, scope);
                match store.delete(&args.key) {
                    Ok(true) => removed = true,
                    Ok(false) => {},
                    Err(e) => return Err(secret_store_error("delete", &e)),
                }
            }
            if removed {
                println!(
                    "{}",
                    Theme::success(&format!(
                        "Removed '{}' for agent '{}' (capsule {})",
                        args.key, principal, capsule
                    ))
                );
                return Ok(ExitCode::SUCCESS);
            }
            // No keychain entry — fall through to env JSON.
        }
    }

    let path = env_file(&principal, args.capsule.as_deref())?;
    let mut env = read_env(&path)?;
    if env.remove(&args.key).is_none() {
        eprintln!("{}", Theme::warning(&format!("'{}' not set", args.key)));
        return Ok(ExitCode::from(1));
    }
    if env.is_empty() {
        match fs::remove_file(&path) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to remove {}", path.display()));
            },
        }
    } else {
        write_env(&path, &env)?;
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
    /// The capsule whose env file or keychain namespace holds the
    /// key (`default` for ungated env JSON entries).
    pub capsule: String,
    /// The env-var key.
    pub key: String,
    /// Where this value actually lives on disk.
    pub storage: SecretStorage,
    /// Sharing model resolved from the capsule manifest. `None` for
    /// non-secret env JSON entries that have no scope concept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<EnvScope>,
}

/// Storage backend for a `secret list` row.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SecretStorage {
    /// File-per-secret under `~/.astrid/secrets/<scope>/<capsule>/<key>`
    /// (`0600`). Durable home for secret-typed values after the
    /// pivot away from the OS keychain prompt-on-rebuild problem.
    File,
    /// Plaintext env JSON — fine for non-secret config (registry
    /// endpoints, model names).
    EnvJson,
    /// Plaintext env JSON for a key the manifest declares as a
    /// secret. Pre-pivot state that the load-time migration should
    /// have healed but hasn't yet — flagged red so operators see it.
    EnvJsonLegacy,
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let manifest = load_capsule_manifest_from_home(&home, &alice, "provider")
            .unwrap()
            .expect("Alice manifest");
        assert_eq!(
            manifest.env["api_key"].description.as_deref(),
            Some("alice manifest")
        );
    }

    #[test]
    fn read_env_handles_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("does-not-exist.env.json");
        assert!(read_env(&p).unwrap().is_empty());
    }

    #[test]
    fn read_env_handles_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.env.json");
        fs::write(&p, "").unwrap();
        assert!(read_env(&p).unwrap().is_empty());
    }

    #[test]
    fn write_env_atomic_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.env.json");
        let mut env = Map::new();
        env.insert("KEY".into(), Value::String("value".into()));
        write_env(&p, &env).unwrap();
        let read = read_env(&p).unwrap();
        assert_eq!(read.get("KEY").and_then(|v| v.as_str()), Some("value"));
        let tmp = p.with_extension("json.tmp");
        assert!(!tmp.exists(), "tempfile should be renamed away");
    }

    #[test]
    fn read_env_rejects_non_object() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.env.json");
        fs::write(&p, r#"["not", "an", "object"]"#).unwrap();
        let err = read_env(&p).expect_err("malformed");
        assert!(err.to_string().contains("not a JSON object"), "got: {err}");
    }

    #[test]
    fn read_env_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.env.json");
        fs::write(&p, "{not json").unwrap();
        let err = read_env(&p).expect_err("malformed");
        assert!(err.to_string().contains("not valid JSON"), "got: {err}");
    }

    #[test]
    fn empty_secret_marker_is_not_reported_as_legacy_plaintext() {
        assert!(classify_env_storage(true, &Value::String(String::new())).is_none());
        assert!(matches!(
            classify_env_storage(true, &Value::String("secret".into())),
            Some(SecretStorage::EnvJsonLegacy)
        ));
        assert!(matches!(
            classify_env_storage(false, &Value::String(String::new())),
            Some(SecretStorage::EnvJson)
        ));
    }
}
