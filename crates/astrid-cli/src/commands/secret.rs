//! `astrid secret` — capsule env-var configuration for an agent.
//!
//! Secrets are stored as `KEY = "value"` pairs in
//! `<principal_home>/.config/env/<capsule>.env.json`, the same JSON
//! file the capsule installer writes (see capsule `install` /
//! `remove --purge`). This command is intentionally a thin wrapper
//! over file IO — there is no kernel-side IPC because the kernel does
//! not consume secret values; capsules read them directly when the
//! kernel injects per-invocation env into the WASM guest.
//!
//! Filesystem permissions: `0o600` on every secret file (Unix). The
//! parent directory is `0o700`. We do NOT touch `~/.astrid/keys/` —
//! that's the runtime signing key, which is unrelated.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::context;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

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

fn run_set(args: &SetArgs) -> Result<ExitCode> {
    if args.key.is_empty() {
        anyhow::bail!("invalid key: must not be empty");
    }
    let principal = context::resolve_agent(args.agent.as_deref())?;
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
    Ok(ExitCode::SUCCESS)
}

fn run_list(args: &ListArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let format = ValueFormat::parse(&args.format);
    let dir = env_dir(&principal)?;
    let mut keys: Vec<SecretKey> = Vec::new();
    if dir.exists() {
        for entry in
            fs::read_dir(&dir).with_context(|| format!("Failed to read {}", dir.display()))?
        {
            let entry = entry?;
            let p = entry.path();
            // Look for `<name>.env.json`. file_stem strips one dot.
            let Some(file_name) = p.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(stem) = file_name.strip_suffix(".env.json") else {
                continue;
            };
            let env = read_env(&p)?;
            for k in env.keys() {
                keys.push(SecretKey {
                    capsule: stem.to_string(),
                    key: k.clone(),
                });
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
    println!("{:<24}  {}", "CAPSULE".bold(), "KEY".bold());
    for k in &keys {
        println!("{:<24}  {}", k.capsule, k.key);
    }
    Ok(ExitCode::SUCCESS)
}

fn run_delete(args: &DeleteArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
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
    /// The capsule whose env file holds the key (`default` for shared).
    pub capsule: String,
    /// The env-var key.
    pub key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
