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
    /// This capsule's pinned `astrid-contracts.wit` BLAKE3 hex, if it
    /// vendors one (`None` otherwise).
    pub contracts_pin: Option<String>,
    /// The daemon canonical `astrid-contracts.wit` BLAKE3 hex, if a
    /// canonical exists on this home (`None` on a fresh home).
    pub contracts_canonical: Option<String>,
    /// Skew classification: `match`, `mismatch`, `no-canonical`, or
    /// `not-pinned`.
    pub contracts_status: String,
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

    // Contracts skew — compare this capsule's astrid-contracts.wit pin
    // against the daemon canonical. Warn-only and degrades silently when
    // no canonical exists.
    let skew = contracts_skew_from_meta(&home, &meta);
    let (contracts_status, contracts_pin, contracts_canonical) = skew_fields(&skew);

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
        contracts_pin,
        contracts_canonical,
        contracts_status: contracts_status.to_string(),
        manifest,
    };

    if !format.is_pretty() {
        emit_structured(&record, format)?;
        return Ok(ExitCode::SUCCESS);
    }

    println!("{} {}", "Capsule".bold(), args.name.cyan());
    println!("  Version:      {}", record.version);
    println!("  Source:       {}", record.source);
    println!("  Hash:         {}", record.wasm_hash);
    if let Some(line) = contracts_line(&skew) {
        println!("  Contracts:    {line}");
    }
    println!("  Installed:    {}", record.installed_at);
    println!("  Updated:      {}", record.updated_at);
    println!("  Agent:        {principal}");
    println!();
    println!("{}", "Manifest".bold());
    for line in record.manifest.lines() {
        println!("  {line}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Classify a capsule's contracts skew by reading its on-disk `meta.json`
/// from `capsule_dir` and comparing against the daemon canonical.
///
/// Returns [`ContractsSkew::NotPinned`] — the silent case — when the meta
/// is missing or unreadable, so a warn-only diagnostic never surfaces an
/// install or read path as failed. Shared with the install flow so the
/// install-time notice reflects the same pins `show` / `list` read.
pub(super) fn contracts_skew_at(
    capsule_dir: &std::path::Path,
    home: &AstridHome,
) -> astrid_capsule_install::ContractsSkew {
    match std::fs::read_to_string(capsule_dir.join("meta.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
    {
        Some(meta) => contracts_skew_from_meta(home, &meta),
        None => astrid_capsule_install::ContractsSkew::NotPinned,
    }
}

/// Classify a capsule's contracts pin against the daemon canonical from
/// its on-disk `meta.json` value, extracting the `wit_files` map.
fn contracts_skew_from_meta(
    home: &AstridHome,
    meta: &serde_json::Value,
) -> astrid_capsule_install::ContractsSkew {
    let wit_files: std::collections::HashMap<String, String> = meta
        .get("wit_files")
        .and_then(serde_json::Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    astrid_capsule_install::contracts_skew(home, &wit_files)
}

/// Flatten a [`ContractsSkew`] into the `(status, pin, canonical)` triple
/// carried in the structured `capsule show` output.
fn skew_fields(
    skew: &astrid_capsule_install::ContractsSkew,
) -> (&'static str, Option<String>, Option<String>) {
    use astrid_capsule_install::ContractsSkew;
    match skew {
        ContractsSkew::NotPinned => ("not-pinned", None, None),
        ContractsSkew::NoCanonical { pin } => ("no-canonical", Some(pin.clone()), None),
        ContractsSkew::Match { pin } => ("match", Some(pin.clone()), Some(pin.clone())),
        ContractsSkew::Mismatch { pin, canonical } => {
            ("mismatch", Some(pin.clone()), Some(canonical.clone()))
        },
    }
}

/// Print the warn-only install-time contracts-skew notice to stderr, or
/// nothing when the pin is aligned / not pinned / has no canonical to
/// compare against. Shared with the install flow so the wording stays
/// consistent with `show` / `list`; a differing pin is surfaced, never
/// treated as an error.
pub(super) fn print_install_skew_notice(
    capsule_id: &str,
    skew: &astrid_capsule_install::ContractsSkew,
) {
    use astrid_capsule_install::{ContractsSkew, short_hash};
    if let ContractsSkew::Mismatch { pin, canonical } = skew {
        eprintln!();
        eprintln!(
            "{}",
            Theme::warning(&format!(
                "Contracts skew: {capsule_id} pins astrid-contracts.wit {} but the daemon canonical is {}.",
                short_hash(pin),
                short_hash(canonical),
            ))
        );
        eprintln!(
            "{}",
            Theme::dimmed(
                "  Record shapes may differ from the running daemon. This is a warning, not an error."
            )
        );
    }
}

/// Render the pretty-mode `Contracts:` value for a capsule's skew, or
/// `None` when the capsule vendors no `astrid-contracts.wit` (nothing to
/// show). Warn-only: `MISMATCH` is a coloured marker, never an error.
///
/// Shared with `capsule list --verbose` so both render pins identically.
pub(super) fn contracts_line(skew: &astrid_capsule_install::ContractsSkew) -> Option<String> {
    use astrid_capsule_install::{ContractsSkew, short_hash};
    match skew {
        ContractsSkew::NotPinned => None,
        ContractsSkew::NoCanonical { pin } => Some(format!(
            "{}  {}",
            short_hash(pin),
            Theme::dimmed("(no daemon canonical to compare)")
        )),
        ContractsSkew::Match { pin } => Some(format!(
            "{}  {}",
            short_hash(pin),
            Theme::success("(matches daemon canonical)")
        )),
        ContractsSkew::Mismatch { pin, canonical } => Some(format!(
            "{}  {}",
            short_hash(pin),
            Theme::warning(&format!(
                "MISMATCH (daemon canonical {})",
                short_hash(canonical)
            ))
        )),
    }
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
            contracts_pin: Some("abc123".into()),
            contracts_canonical: Some("abc123".into()),
            contracts_status: "match".into(),
            manifest: "[package]\nname = \"x\"\n".into(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "x");
        assert_eq!(parsed["version"], "0.1.0");
        assert_eq!(parsed["contracts_status"], "match");
    }
}
