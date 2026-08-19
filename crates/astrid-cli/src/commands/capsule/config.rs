//! `astrid capsule config` — view and edit a capsule's typed env config.
//!
//! All reads and writes go through the daemon admin API. Native `.env.json`
//! files are legacy migration input only and are never consulted here.

use std::process::ExitCode;

use anyhow::Result;
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{EnvStorageScope, EnvValueKind};
use clap::Args;
use colored::Colorize;

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

fn entries(
    principal: &PrincipalId,
    capsule: &str,
) -> Result<Vec<astrid_core::kernel_api::EnvEntry>> {
    super::install_headless::list_env_entries(principal, capsule)
}

/// Entry point for `astrid capsule config`.
pub(crate) fn run(args: &ConfigArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.agent.as_deref())?;
    let existing = entries(&principal, &args.name)?;

    if !args.set.is_empty() {
        let mut set_values = Vec::new();
        for pair in &args.set {
            let Some((key, value)) = pair.split_once('=') else {
                eprintln!(
                    "{}",
                    Theme::error(&format!(
                        "invalid --set value '{pair}' (expected KEY=VALUE)"
                    ))
                );
                return Ok(ExitCode::from(1));
            };
            let key = key.trim();
            if key.is_empty() {
                eprintln!("{}", Theme::error("environment key must not be empty"));
                return Ok(ExitCode::from(1));
            }
            // Preserve an existing secret declaration; new keys default to
            // text until the capsule manifest declares them secret.
            let kind = existing
                .iter()
                .find(|entry| entry.key == key)
                .map_or(EnvValueKind::Text, |entry| entry.kind);
            super::install_headless::set_env_entry(
                &principal,
                &args.name,
                key,
                value,
                kind,
                EnvStorageScope::Agent,
            )?;
            set_values.push(value.to_owned());
        }

        let config_path = astrid_core::dirs::AstridHome::resolve()?.config_path();
        for value in &set_values {
            super::local_egress::maybe_prompt_local_egress(&args.name, value, &config_path);
        }
        println!(
            "{}",
            Theme::success(&format!(
                "Updated config for capsule '{}' (agent '{}').",
                args.name, principal
            ))
        );
        return Ok(ExitCode::SUCCESS);
    }

    // The admin list intentionally contains metadata only. Values, including
    // secret values, are never emitted by this command.
    let mut redacted = serde_json::Map::new();
    for entry in existing {
        redacted.insert(
            entry.key,
            serde_json::Value::String("<redacted>".to_owned()),
        );
    }
    let format = ValueFormat::parse(&args.format);
    if !format.is_pretty() {
        emit_structured(&redacted, format)?;
        return Ok(ExitCode::SUCCESS);
    }
    if redacted.is_empty() {
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
    let mut keys: Vec<&String> = redacted.keys().collect();
    keys.sort();
    for key in keys {
        println!("  {} = {}", key, "<redacted>".dimmed());
    }
    println!(
        "\n{}",
        Theme::info("Configuration is stored in the daemon control namespace (values redacted).")
    );
    Ok(ExitCode::SUCCESS)
}
