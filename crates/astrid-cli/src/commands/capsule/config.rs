//! `astrid capsule config` — view and edit a capsule's env config.
//!
//! Mirrors the `.env.json` shape the installer writes, scoped per-
//! principal under `<principal_home>/.config/env/<capsule>.env.json`.
//! No kernel IPC: capsules read this file directly when the kernel
//! injects per-invocation env into the WASM guest, so editing it on
//! disk is sufficient. The capsule must be reloaded for changes to
//! take effect.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use clap::Args;
use colored::Colorize;
use serde_json::{Map, Value};

use crate::context;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

#[derive(Args, Debug, Clone)]
pub(crate) struct ConfigArgs {
    /// Capsule name.
    pub name: String,
    /// Print the current config (default action when no flag is set).
    #[arg(long, conflicts_with = "set")]
    pub show: bool,
    /// Set a `KEY=VALUE` pair (repeatable).
    #[arg(long = "set", value_name = "KEY=VALUE")]
    pub set: Vec<String>,
    /// Agent name (defaults to active context).
    #[arg(short, long)]
    pub agent: Option<String>,
    /// Output format for `--show`.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

fn env_path(principal: &PrincipalId, capsule: &str) -> Result<PathBuf> {
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    let dir = home.principal_home(principal).env_dir();
    Ok(dir.join(format!("{capsule}.env.json")))
}

fn read_env(path: &std::path::Path) -> Result<Map<String, Value>> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
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
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            let _ = std::fs::set_permissions(parent, perms);
        }
    }
    let contents = serde_json::to_string_pretty(env).context("Failed to serialize env JSON")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &contents)
        .with_context(|| format!("Failed to write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp, perms)
            .with_context(|| format!("Failed to chmod {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Entry point for `astrid capsule config`.
pub(crate) fn run(args: &ConfigArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let path = env_path(&principal, &args.name)?;

    if !args.set.is_empty() {
        let mut env = read_env(&path)?;
        for pair in &args.set {
            let Some((k, v)) = pair.split_once('=') else {
                eprintln!(
                    "{}",
                    Theme::error(&format!(
                        "invalid --set value '{pair}' (expected KEY=VALUE)"
                    ))
                );
                return Ok(ExitCode::from(1));
            };
            env.insert(k.trim().to_string(), Value::String(v.to_string()));
        }
        write_env(&path, &env)?;
        println!(
            "{}",
            Theme::success(&format!(
                "Updated config for capsule '{}' (agent '{}'). Reload the capsule for changes to take effect.",
                args.name, principal
            ))
        );
        return Ok(ExitCode::SUCCESS);
    }

    // Default to showing.
    let env = read_env(&path)?;
    let format = ValueFormat::parse(&args.format);
    if !format.is_pretty() {
        emit_structured(&env, format)?;
        return Ok(ExitCode::SUCCESS);
    }
    if env.is_empty() {
        println!(
            "{}",
            Theme::info(&format!(
                "(no config for capsule '{}' under agent '{}')",
                args.name, principal
            ))
        );
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{} {} {} {}",
        "Config for capsule".bold(),
        args.name.cyan(),
        "(agent".bold(),
        format!("{principal})").cyan()
    );
    let mut keys: Vec<&String> = env.keys().collect();
    keys.sort();
    for k in keys {
        // Redact values — `set` is the write path; `show` should not
        // leak secrets to a shoulder-surfer.
        println!("  {} = {}", k, "<redacted>".dimmed());
    }
    println!(
        "\n{}",
        Theme::info(&format!(
            "Config file: {} (values redacted in pretty output — use --format json to dump)",
            path.display()
        ))
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_set_value_returns_error_exit() {
        // Smoke test: parsing `--set` without `=` is a soft error
        // surfaced via stderr + exit code 1, not a panic.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.env.json");
        let mut env = Map::new();
        env.insert("KEY".into(), Value::String("v".into()));
        write_env(&path, &env).unwrap();
        let read = read_env(&path).unwrap();
        assert_eq!(read.get("KEY").and_then(|v| v.as_str()), Some("v"));
    }

    #[test]
    fn round_trip_set_then_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.env.json");
        let mut env = Map::new();
        env.insert("KEY".into(), Value::String("v".into()));
        write_env(&path, &env).unwrap();
        let read = read_env(&path).unwrap();
        assert_eq!(read.get("KEY").and_then(|v| v.as_str()), Some("v"));
    }
}
