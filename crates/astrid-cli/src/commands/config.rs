//! CLI handlers for the `astrid config` subcommand.

use anyhow::Result;
use astrid_config::{Config, ResolvedConfig, ShowFormat};

/// Show the resolved configuration with source annotations.
pub(crate) fn show_config(format: &str, section: Option<&str>) -> Result<()> {
    let workspace_root = std::env::current_dir().ok();
    let resolved = Config::load(workspace_root.as_deref())?;

    let show_format = match format {
        "json" => ShowFormat::Json,
        _ => ShowFormat::Toml,
    };

    let output = resolved
        .show(show_format, section)
        .map_err(|e| anyhow::anyhow!("failed to format config: {e}"))?;

    println!("{output}");
    Ok(())
}

/// Validate the current configuration.
#[expect(clippy::unnecessary_wraps)]
pub(crate) fn validate_config() -> Result<()> {
    let workspace_root = std::env::current_dir().ok();

    match Config::load(workspace_root.as_deref()) {
        Ok(resolved) => {
            println!("Configuration is valid.");
            if !resolved.loaded_files.is_empty() {
                println!("\nLoaded files:");
                for path in &resolved.loaded_files {
                    println!("  - {path}");
                }
            }
            Ok(())
        },
        Err(e) => {
            eprintln!("Configuration error: {e}");
            std::process::exit(1);
        },
    }
}

/// Open the global runtime config file (`~/.astrid/etc/config.toml`)
/// in `$EDITOR` (falling back to `$VISUAL`, then `vi`). Creates the
/// file if missing so the editor opens on a real path.
pub(crate) fn edit_config() -> Result<()> {
    let home = astrid_core::dirs::AstridHome::resolve()
        .map_err(|e| anyhow::anyhow!("Failed to resolve Astrid home: {e}"))?;
    let path = home.config_path();
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, "# Astrid runtime configuration\n")?;
    }
    let editor = std::env::var("EDITOR")
        .ok()
        .or_else(|| std::env::var("VISUAL").ok())
        .unwrap_or_else(|| "vi".to_string());
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to launch '{editor}': {e}"))?;
    if !status.success() {
        anyhow::bail!("editor '{editor}' exited with non-zero status");
    }
    Ok(())
}

/// Show all config file paths that are checked.
#[expect(clippy::unnecessary_wraps)]
pub(crate) fn show_paths() -> Result<()> {
    let home = directories::BaseDirs::new().map(|d| d.home_dir().to_string_lossy().to_string());

    let workspace = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    let paths = ResolvedConfig::config_paths(home.as_deref(), workspace.as_deref());

    println!("Configuration files checked (in precedence order):\n");
    for (i, path) in paths.iter().enumerate() {
        let exists = std::path::Path::new(path).exists();
        let status = if exists { "found" } else { "not found" };
        println!("  {}. {path}  [{status}]", i.saturating_add(1));
    }

    println!("\nEnvironment variable fallbacks:");
    println!("  ANTHROPIC_API_KEY  -> model.api_key");
    println!("  ANTHROPIC_MODEL    -> model.model");
    println!("  ASTRID_LOG_LEVEL -> logging.level");
    println!("  ASTRID_MODEL     -> model.model");
    println!("  ASTRID_WORKSPACE_MODE -> workspace.mode");

    Ok(())
}
