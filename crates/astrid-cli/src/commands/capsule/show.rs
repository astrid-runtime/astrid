//! `astrid capsule show <name>` — manifest, interfaces, source.
//!
//! Reads the installed capsule's `Capsule.toml` and `meta.json` from
//! `<principal_home>/.local/capsules/<name>/`. No daemon round-trip is
//! needed — the manifest is on disk, identical for every connected
//! client.

use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::dirs::AstridHome;
use clap::Args;
use colored::Colorize;
use serde::Serialize;

use crate::context;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

#[derive(Args, Debug, Clone)]
pub(crate) struct ShowArgs {
    /// Capsule name.
    pub name: String,
    /// Agent name (defaults to the active context).
    #[arg(short, long)]
    pub agent: Option<String>,
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// JSON/YAML/TOML emission shape — captures what's surfaced in pretty
/// mode plus the on-disk manifest body for scripting.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CapsuleShow {
    /// Capsule name.
    pub name: String,
    /// On-disk version recorded in `meta.json`.
    pub version: String,
    /// Where the capsule was installed from (registry id, local path).
    pub source: String,
    /// `BLAKE3` content hash of the WASM blob.
    pub wasm_hash: String,
    /// ISO 8601 install timestamp.
    pub installed_at: String,
    /// ISO 8601 last-update timestamp.
    pub updated_at: String,
    /// Verbatim `Capsule.toml` body.
    pub manifest: String,
}

/// Entry point for `astrid capsule show`.
pub(crate) fn run(args: &ShowArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let format = ValueFormat::parse(&args.format);
    let home = AstridHome::resolve().context("Failed to resolve Astrid home directory")?;
    let capsule_dir = home
        .principal_home(&principal)
        .root()
        .join(".local")
        .join("capsules")
        .join(&args.name);
    if !capsule_dir.exists() {
        eprintln!(
            "{}",
            Theme::error(&format!(
                "capsule '{}' is not installed for agent '{principal}'",
                args.name
            ))
        );
        return Ok(ExitCode::from(1));
    }
    let manifest_path = capsule_dir.join("Capsule.toml");
    let meta_path = capsule_dir.join("meta.json");
    let manifest = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("Failed to read {}", manifest_path.display()))?;
    let meta_raw = std::fs::read_to_string(&meta_path)
        .with_context(|| format!("Failed to read {}", meta_path.display()))?;
    let meta: serde_json::Value = serde_json::from_str(&meta_raw)
        .with_context(|| format!("{} is not valid JSON", meta_path.display()))?;

    let record = CapsuleShow {
        name: args.name.clone(),
        version: meta
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        source: meta
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        wasm_hash: meta
            .get("wasm_hash")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        installed_at: meta
            .get("installed_at")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        updated_at: meta
            .get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        manifest: manifest.clone(),
    };

    if !format.is_pretty() {
        emit_structured(&record, format)?;
        return Ok(ExitCode::SUCCESS);
    }

    println!("{} {}", "Capsule".bold(), args.name.cyan());
    println!("  Version:      {}", record.version);
    println!("  Source:       {}", record.source);
    println!("  Hash:         {}", record.wasm_hash);
    println!("  Installed:    {}", record.installed_at);
    println!("  Updated:      {}", record.updated_at);
    println!("  Agent:        {principal}");
    println!();
    println!("{}", "Manifest".bold());
    for line in manifest.lines() {
        println!("  {line}");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips_to_json() {
        let rec = CapsuleShow {
            name: "x".into(),
            version: "0.1.0".into(),
            source: "local".into(),
            wasm_hash: "abc".into(),
            installed_at: "2026-04-28T00:00:00Z".into(),
            updated_at: "2026-04-28T00:00:00Z".into(),
            manifest: "[package]\nname = \"x\"\n".into(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "x");
        assert_eq!(parsed["version"], "0.1.0");
    }
}
