//! `astrid capsule show <name>` — manifest, interfaces, source.
//!
//! Reads the authenticated capsule metadata snapshot from the daemon-owned
//! registry. The CLI never opens a principal's native home or cache as an
//! authority; any materialized capsule directory is disposable projection
//! state owned by the daemon.

use std::process::ExitCode;

use anyhow::Result;
use astrid_capsule_types::capability_presentation::{SemanticCapability, semantic_capabilities};
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use clap::Args;
use colored::Colorize;
use serde::Serialize;

use crate::context;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

use super::station;

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
    /// Version recorded in the daemon registry snapshot.
    pub version: String,
    /// Registry source identity, when present.
    pub source: String,
    /// `BLAKE3` content hash of the WASM blob, when surfaced by the registry.
    pub wasm_hash: String,
    /// ISO 8601 install timestamp, when surfaced by the registry.
    pub installed_at: String,
    /// ISO 8601 last-update timestamp, when surfaced by the registry.
    pub updated_at: String,
    /// This capsule's pinned `astrid-contracts.wit` BLAKE3 hex, if it
    /// vendors one (`None` otherwise).
    pub contracts_pin: Option<String>,
    /// The daemon canonical `astrid-contracts.wit` BLAKE3 hex, when queried.
    pub contracts_canonical: Option<String>,
    /// Skew classification: `match`, `mismatch`, `no-canonical`, or
    /// `not-pinned`.
    pub contracts_status: String,
    /// Verbatim `Capsule.toml` body.
    pub manifest: String,
    /// Human-facing permissions derived from the manifest.
    pub permissions: Vec<SemanticCapability>,
    /// Station coordinate/publication identity, when this owner has a
    /// Station lock. This is separate from the daemon `source` UUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_source: Option<String>,
}

/// Entry point for `astrid capsule show`.
pub(crate) async fn run(args: &ShowArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let format = ValueFormat::parse(&args.format);
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    let entries = match client.request(KernelRequest::GetCapsuleMetadata).await? {
        KernelResponse::CapsuleMetadata(entries) => entries,
        KernelResponse::Error(message) => {
            anyhow::bail!("daemon rejected capsule metadata request: {message}")
        },
        other => anyhow::bail!("unexpected daemon response: {other:?}"),
    };
    let Some(entry) = entries.into_iter().find(|entry| entry.name == args.name) else {
        eprintln!(
            "{}",
            Theme::error(&format!(
                "capsule '{}' is not installed for agent '{principal}'",
                args.name
            ))
        );
        return Ok(ExitCode::from(1));
    };
    let capabilities: astrid_capsule_types::manifest::CapabilitiesDef =
        serde_json::from_value(entry.capabilities.clone())?;
    let permissions = semantic_capabilities(&capabilities);
    let station_lock = station::load_lock(&principal, &entry.name).await?;
    let registry_source = station_lock.as_ref().map(|lock| {
        format!(
            "@{}/{} ({})",
            lock.coordinate.namespace, lock.coordinate.name, lock.publication_digest
        )
    });
    let manifest = serde_json::to_string_pretty(&serde_json::json!({
        "package": {
            "name": entry.name,
            "version": entry.version,
            "description": entry.description,
        },
        "env": entry.env,
        "interceptor_events": entry.interceptor_events,
    }))?;

    let record = CapsuleShow {
        name: args.name.clone(),
        version: entry.version,
        source: entry
            .source_id
            .map_or_else(|| "unloaded".to_owned(), |id| id.to_string()),
        wasm_hash: entry.wasm_hash.unwrap_or_default(),
        installed_at: String::new(),
        updated_at: String::new(),
        contracts_pin: None,
        contracts_canonical: None,
        contracts_status: "daemon-registry".to_owned(),
        manifest,
        permissions,
        registry_source,
    };

    if !format.is_pretty() {
        emit_structured(&record, format)?;
        return Ok(ExitCode::SUCCESS);
    }

    println!("{} {}", "Capsule".bold(), args.name.cyan());
    println!("  Version:      {}", record.version);
    println!("  Source:       {}", record.source);
    println!(
        "  Registry:     {}",
        record.registry_source.as_deref().unwrap_or("daemon-owned")
    );
    println!("  Agent:        {principal}");
    println!();
    print_permissions(&record.permissions);
    println!();
    println!("{}", "Manifest".bold());
    for line in record.manifest.lines() {
        println!("  {line}");
    }
    Ok(ExitCode::SUCCESS)
}

fn print_permissions(permissions: &[SemanticCapability]) {
    println!("{}", "Permissions".bold());
    if permissions.is_empty() {
        println!("  No host capabilities beyond in-sandbox execution");
        return;
    }
    for permission in permissions {
        println!("  - {}", permission.action);
        if !permission.scope.is_empty() {
            println!("    Scope: {}", permission.scope.join("; "));
        }
        println!("    Impact: {}", permission.impact);
    }
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
            permissions: Vec::new(),
            registry_source: None,
        };
        let json = serde_json::to_string(&rec).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "x");
        assert_eq!(parsed["version"], "0.1.0");
        assert_eq!(parsed["contracts_status"], "match");
    }

    #[test]
    fn source_uuid_and_station_registry_identity_are_separate() {
        let rec = CapsuleShow {
            name: "demo".into(),
            version: "1.0.0".into(),
            source: "8d5f2f7d-c89f-4d8f-9ac8-4b5e3d7c7b2d".into(),
            wasm_hash: String::new(),
            installed_at: String::new(),
            updated_at: String::new(),
            contracts_pin: None,
            contracts_canonical: None,
            contracts_status: "daemon-registry".into(),
            manifest: String::new(),
            permissions: Vec::new(),
            registry_source: Some(
                "@official/demo (blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)"
                    .into(),
            ),
        };
        let json = serde_json::to_value(rec).unwrap();
        assert_eq!(json["source"], "8d5f2f7d-c89f-4d8f-9ac8-4b5e3d7c7b2d");
        assert_eq!(
            json["registry_source"],
            "@official/demo (blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)"
        );
    }
}
