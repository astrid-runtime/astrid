//! Config file discovery and layered loading.
//!
//! Implements the `Config::load()` algorithm:
//! 1. Parse `defaults.toml` → base
//! 2. Merge `/etc/astrid/config.toml` (system)
//! 3. Merge `$ASTRID_HOME/config.toml` or `~/.astrid/config.toml` (user)
//! 4. Merge the selected workspace config + restriction enforcement
//! 5. Apply env var fallbacks for unset fields
//! 6. Deserialize merged tree → `Config`
//! 7. Resolve `${VAR}` references
//! 8. Validate
//! 9. Return `ResolvedConfig`

use std::path::{Path, PathBuf};

use astrid_core::dirs::WorkspaceLayout;
use tracing::{debug, info};

use crate::env::{
    apply_env_fallbacks, collect_env_vars, resolve_env_references,
    resolve_env_references_restricted,
};
use crate::error::{ConfigError, ConfigResult};
use crate::merge::{ConfigLayer, FieldSources, deep_merge_tracking, enforce_restrictions};
use crate::show::ResolvedConfig;
use crate::types::Config;
use crate::validate;

/// Embedded default configuration.
const DEFAULTS_TOML: &str = include_str!("defaults.toml");

/// Load the unified configuration with layered file precedence.
///
/// `workspace_root` is the root of the current project (e.g. the git
/// repo root or `cwd`). If `None`, the workspace layer is skipped.
///
/// `astrid_home_override` provides an alternate home directory for user-level
/// config discovery, bypassing the default search logic and `ASTRID_HOME`.
///
/// # Errors
///
/// Returns a [`ConfigError`] if any config file is malformed, or if the
/// final merged configuration fails validation.
pub fn load(
    workspace_root: Option<&Path>,
    astrid_home_override: Option<&Path>,
) -> ConfigResult<ResolvedConfig> {
    load_with_layout(
        workspace_root,
        astrid_home_override,
        &WorkspaceLayout::default(),
    )
}

/// Load the unified configuration using an explicit workspace layout.
///
/// # Errors
///
/// Returns a [`ConfigError`] if any config file is malformed, or if the
/// final merged configuration fails validation.
#[allow(clippy::too_many_lines)]
pub fn load_with_layout(
    workspace_root: Option<&Path>,
    astrid_home_override: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> ConfigResult<ResolvedConfig> {
    let env_vars = collect_env_vars();
    let home_dir = if let Some(h) = astrid_home_override {
        h.to_path_buf()
    } else {
        home_directory()?
    };

    // 1. Parse embedded defaults.
    let mut merged: toml::Value =
        toml::from_str(DEFAULTS_TOML).map_err(|e| ConfigError::ParseError {
            path: "<embedded defaults>".to_owned(),
            source: e,
        })?;

    let mut field_sources = FieldSources::new();
    let mut loaded_files = Vec::new();

    // Mark all defaults.
    record_defaults(&merged, "", &mut field_sources);

    // 2. System config (/etc/astrid/config.toml).
    let system_path = PathBuf::from("/etc/astrid/config.toml");
    if let Some(overlay) = try_load_file(&system_path)? {
        reject_legacy_model_section(&overlay, &system_path.display().to_string())?;
        deep_merge_tracking(
            &mut merged,
            &overlay,
            "",
            &ConfigLayer::System,
            &mut field_sources,
        );
        loaded_files.push(system_path.display().to_string());
        info!(path = %system_path.display(), "loaded system config");
    }

    // 3. User config.
    let user_config = if let Some(h) = astrid_home_override {
        // When overridden, treat the path as the .astrid directory itself.
        let path = h.join("config.toml");
        try_load_file(&path)?.map(|overlay| (overlay, path))
    } else {
        discover_user_config(&home_dir, env_vars.get("ASTRID_HOME").map(String::as_str))?
    };

    if let Some((overlay, path)) = user_config {
        reject_legacy_model_section(&overlay, &path.display().to_string())?;
        deep_merge_tracking(
            &mut merged,
            &overlay,
            "",
            &ConfigLayer::User,
            &mut field_sources,
        );
        loaded_files.push(path.display().to_string());
        info!(path = %path.display(), "loaded user config");
    }

    // 4. Selected workspace config.
    //    Snapshot the merged config *before* the workspace layer as the baseline
    //    for restriction enforcement. This ensures restrictions work even when
    //    no user config file exists (the baseline includes defaults + system).
    if let Some(ws_root) = workspace_root {
        let workspace =
            workspace_layout
                .resolve(ws_root)
                .map_err(|source| ConfigError::ReadError {
                    path: workspace_layout.state_dir(ws_root).display().to_string(),
                    source,
                })?;
        let ws_path = workspace
            .config_path()
            .map_err(|source| ConfigError::ReadError {
                path: workspace.state_dir().display().to_string(),
                source,
            })?;
        let workspace_overlay = try_load_file(&ws_path)?;
        workspace
            .verify()
            .map_err(|source| ConfigError::ReadError {
                path: ws_path.display().to_string(),
                source,
            })?;
        if let Some(mut overlay) = workspace_overlay {
            reject_legacy_model_section(&overlay, &ws_path.display().to_string())?;

            // Resolve ${VAR} references in workspace overlay with restricted
            // env vars (only ASTRID_*). This prevents a
            // malicious workspace config from exfiltrating sensitive env vars.
            resolve_env_references_restricted(&mut overlay, &env_vars);

            let pre_workspace_baseline = merged.clone();
            let ws_overlay = overlay.clone();
            deep_merge_tracking(
                &mut merged,
                &overlay,
                "",
                &ConfigLayer::Workspace,
                &mut field_sources,
            );

            // Enforce restriction semantics: workspace can only tighten.
            enforce_restrictions(&mut merged, &pre_workspace_baseline, &ws_overlay);

            loaded_files.push(ws_path.display().to_string());
            info!(path = %ws_path.display(), "loaded workspace config");
            workspace
                .verify()
                .map_err(|source| ConfigError::ReadError {
                    path: workspace.state_dir().display().to_string(),
                    source,
                })?;
        }
    }

    // 5. Apply env var fallbacks for unset fields.
    let env_count = apply_env_fallbacks(&mut merged, &mut field_sources, &env_vars);
    if env_count > 0 {
        debug!(count = env_count, "applied environment variable fallbacks");
    }

    // 6–7. Resolve ${VAR} references in string values, then deserialize.
    resolve_env_references(&mut merged, &env_vars);
    let config: Config =
        merged
            .try_into()
            .map_err(|e: toml::de::Error| ConfigError::ParseError {
                path: "<merged config>".to_owned(),
                source: e,
            })?;

    // 8. Validate.
    validate::validate(&config)?;

    // 9. Return ResolvedConfig.
    Ok(ResolvedConfig {
        config,
        field_sources,
        loaded_files,
    })
}

/// Load a config from a specific file path (no layering).
///
/// # Errors
///
/// Returns a [`ConfigError`] if the file cannot be read or parsed.
pub fn load_file(path: &Path) -> ConfigResult<Config> {
    // Check file size before reading to prevent OOM.
    let metadata = std::fs::metadata(path).map_err(|e| ConfigError::ReadError {
        path: path.display().to_string(),
        source: e,
    })?;
    if metadata.len() > MAX_CONFIG_FILE_SIZE {
        return Err(ConfigError::ValidationError {
            field: path.display().to_string(),
            message: format!(
                "config file is {} bytes, exceeding the {} byte limit",
                metadata.len(),
                MAX_CONFIG_FILE_SIZE
            ),
        });
    }

    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadError {
        path: path.display().to_string(),
        source: e,
    })?;

    let value: toml::Value = toml::from_str(&content).map_err(|e| ConfigError::ParseError {
        path: path.display().to_string(),
        source: e,
    })?;
    reject_legacy_model_section(&value, &path.display().to_string())?;

    let config: Config =
        value
            .try_into()
            .map_err(|e: toml::de::Error| ConfigError::ParseError {
                path: path.display().to_string(),
                source: e,
            })?;

    validate::validate(&config)?;
    Ok(config)
}

/// Maximum allowed config file size (1 MB).
const MAX_CONFIG_FILE_SIZE: u64 = 1_048_576;

/// Try to load a file, returning `None` if the file doesn't exist.
///
/// Uses a single read operation to avoid TOCTOU races (no separate
/// exists/metadata checks before reading).
fn try_load_file(path: &Path) -> ConfigResult<Option<toml::Value>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(path = %path.display(), "config file not found, skipping");
            return Ok(None);
        },
        Err(e) => {
            return Err(ConfigError::ReadError {
                path: path.display().to_string(),
                source: e,
            });
        },
    };

    // Check size after reading to avoid TOCTOU between stat and read.
    if content.len() as u64 > MAX_CONFIG_FILE_SIZE {
        return Err(ConfigError::ValidationError {
            field: path.display().to_string(),
            message: format!(
                "config file is {} bytes, exceeding the {} byte limit",
                content.len(),
                MAX_CONFIG_FILE_SIZE
            ),
        });
    }

    let value: toml::Value = toml::from_str(&content).map_err(|e| ConfigError::ParseError {
        path: path.display().to_string(),
        source: e,
    })?;

    Ok(Some(value))
}

fn discover_user_config(
    home_dir: &Path,
    astrid_home: Option<&str>,
) -> ConfigResult<Option<(toml::Value, PathBuf)>> {
    if let Some(astrid_home) = astrid_home {
        let validated = validate_astrid_home(astrid_home, home_dir);
        if let Some(canonical) = validated {
            let path = canonical.join("config.toml");
            if let Some(overlay) = try_load_file(&path)? {
                return Ok(Some((overlay, path)));
            }
        } else {
            tracing::warn!(
                path = astrid_home,
                "ASTRID_HOME is not a valid directory owned by current user; ignoring"
            );
        }
    }

    let user_path = home_dir.join(".astrid").join("config.toml");
    try_load_file(&user_path).map(|overlay| overlay.map(|overlay| (overlay, user_path)))
}

/// Validate that an `ASTRID_HOME` path is a real directory owned by the
/// same user who owns `home_dir`. Returns the canonicalized path on success.
fn validate_astrid_home(raw_path: &str, home_dir: &Path) -> Option<PathBuf> {
    let canonical = PathBuf::from(raw_path).canonicalize().ok()?;

    if !canonical.is_dir() {
        return None;
    }

    // On Unix, verify the directory is owned by the same user who owns
    // the home directory (which we already trust).
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dir_uid = canonical.metadata().ok()?.uid();
        let home_uid = home_dir.metadata().ok()?.uid();
        if dir_uid != home_uid {
            return None;
        }
    }

    #[cfg(not(unix))]
    let _ = home_dir;

    Some(canonical)
}

/// Reject host-owned model configuration before any credential can be merged.
///
/// Model execution is capsule-owned. The old host `[model]` table is not a
/// compatibility surface: accepting it would either silently ignore operator
/// settings or carry provider credentials through the host config pipeline.
fn reject_legacy_model_section(config: &toml::Value, path: &str) -> ConfigResult<()> {
    if config.get("model").is_some() {
        return Err(ConfigError::ValidationError {
            field: "model".to_owned(),
            message: format!(
                "legacy host [model] in {path} is no longer supported; move model/provider \
                 selection to a principal-scoped capsule using capsule [env] and the model registry"
            ),
        });
    }
    Ok(())
}

/// Determine the user's home directory.
fn home_directory() -> ConfigResult<PathBuf> {
    directories::BaseDirs::new()
        .map(|d| d.home_dir().to_path_buf())
        .ok_or(ConfigError::NoHomeDir)
}

/// Mark all leaf values in the defaults tree with the `Defaults` layer.
fn record_defaults(val: &toml::Value, prefix: &str, sources: &mut FieldSources) {
    if let toml::Value::Table(table) = val {
        for (key, child) in table {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            record_defaults(child, &path, sources);
        }
    } else {
        sources.insert(prefix.to_owned(), ConfigLayer::Defaults);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_parse() {
        let val: toml::Value = toml::from_str(DEFAULTS_TOML).unwrap();
        assert!(!val.as_table().unwrap().contains_key("model"));
        assert!(val.as_table().unwrap().contains_key("runtime"));
        assert!(val.as_table().unwrap().contains_key("security"));
    }

    #[test]
    fn test_defaults_deserialize_to_config() {
        let config: Config = toml::from_str(DEFAULTS_TOML).unwrap();
        assert_eq!(config.runtime.max_context_tokens, 100_000);
        assert!((config.budget.session_max_usd - 100.0).abs() < f64::EPSILON);
        assert_eq!(config.timeouts.request_secs, 120);
        assert_eq!(config.timeouts.daemon_ready_secs, 600);
    }

    #[test]
    fn test_load_without_files() {
        // This should succeed using only embedded defaults + env vars.
        // It may fail if home dir can't be found, so we just test
        // that defaults parse correctly.
        let config = Config::default();
        assert!(validate::validate(&config).is_ok());
    }

    #[test]
    fn workspace_config_uses_only_injected_layout() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let default_dir = workspace.path().join(".astrid");
        let alternate_dir = workspace.path().join(".alternate-runtime");
        std::fs::create_dir_all(&default_dir).unwrap();
        std::fs::create_dir_all(&alternate_dir).unwrap();
        std::fs::write(
            default_dir.join("config.toml"),
            "[runtime]\nsystem_prompt = \"default\"\n",
        )
        .unwrap();
        std::fs::write(
            alternate_dir.join("config.toml"),
            "[runtime]\nsystem_prompt = \"alternate\"\n",
        )
        .unwrap();

        let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
        let resolved =
            load_with_layout(Some(workspace.path()), Some(home.path()), &layout).unwrap();

        assert_eq!(resolved.config.runtime.system_prompt, "alternate");
        assert!(
            resolved
                .loaded_files
                .iter()
                .any(|path| path.ends_with(".alternate-runtime/config.toml"))
        );
        assert!(
            resolved
                .loaded_files
                .iter()
                .all(|path| !path.ends_with(".astrid/config.toml"))
        );
    }

    #[test]
    fn workspace_config_cannot_change_operator_uplinks() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let state = workspace.path().join(".astrid");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            home.path().join("config.toml"),
            r#"
                [[uplinks]]
                plugin = "operator-approved-uplink"
                profile = "chat"
            "#,
        )
        .unwrap();
        std::fs::write(
            state.join("config.toml"),
            r#"
                [[uplinks]]
                plugin = "workspace-controlled-uplink"
                profile = "bridge"
            "#,
        )
        .unwrap();

        let resolved = load_with_layout(
            Some(workspace.path()),
            Some(home.path()),
            &WorkspaceLayout::default(),
        )
        .unwrap();

        assert_eq!(resolved.config.uplinks.len(), 1);
        assert_eq!(
            resolved.config.uplinks[0].plugin,
            "operator-approved-uplink"
        );
        assert_eq!(resolved.config.uplinks[0].profile, "chat");
    }

    #[cfg(unix)]
    #[test]
    fn workspace_config_rejects_redirected_state_directory() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("config.toml"),
            "[runtime]\nsystem_prompt = \"outside\"\n",
        )
        .unwrap();
        symlink(outside.path(), workspace.path().join(".alternate-runtime")).unwrap();

        let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
        assert!(load_with_layout(Some(workspace.path()), Some(home.path()), &layout).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn workspace_config_rejects_redirected_config_file() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let state = workspace.path().join(".alternate-runtime");
        std::fs::create_dir(&state).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "[runtime]\nsystem_prompt = \"outside\"\n").unwrap();
        symlink(outside.path(), state.join("config.toml")).unwrap();

        let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
        assert!(load_with_layout(Some(workspace.path()), Some(home.path()), &layout).is_err());
    }

    #[test]
    fn test_load_file_nonexistent() {
        let result = load_file(Path::new("/nonexistent/config.toml"));
        assert!(matches!(result, Err(ConfigError::ReadError { .. })));
    }

    #[test]
    fn test_try_load_file_missing() {
        let result = try_load_file(Path::new("/nonexistent/config.toml")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_astrid_home_config_precedes_home_config() {
        let home = tempfile::tempdir().unwrap();
        let astrid_home = tempfile::tempdir().unwrap();
        let home_astrid = home.path().join(".astrid");
        std::fs::create_dir_all(&home_astrid).unwrap();
        std::fs::write(
            home_astrid.join("config.toml"),
            r#"
            [runtime]
            system_prompt = "home"
            "#,
        )
        .unwrap();
        std::fs::write(
            astrid_home.path().join("config.toml"),
            r#"
            [runtime]
            system_prompt = "astrid-home"
            "#,
        )
        .unwrap();

        let (_overlay, path) =
            discover_user_config(home.path(), Some(astrid_home.path().to_str().unwrap()))
                .unwrap()
                .expect("ASTRID_HOME config should be discovered");

        assert_eq!(
            path.canonicalize().unwrap(),
            astrid_home
                .path()
                .join("config.toml")
                .canonicalize()
                .unwrap()
        );
    }

    #[test]
    fn test_record_defaults() {
        let val: toml::Value = toml::from_str(
            r#"
            [runtime]
            system_prompt = "seed"
            keep_recent_count = 10
        "#,
        )
        .unwrap();

        let mut sources = FieldSources::new();
        record_defaults(&val, "", &mut sources);

        assert_eq!(
            sources.get("runtime.system_prompt"),
            Some(&ConfigLayer::Defaults)
        );
        assert_eq!(
            sources.get("runtime.keep_recent_count"),
            Some(&ConfigLayer::Defaults)
        );
    }

    // ---- Legacy host model configuration ----

    #[test]
    fn legacy_user_model_section_fails_with_migration_guidance() {
        let astrid_home = tempfile::tempdir().unwrap();
        std::fs::write(
            astrid_home.path().join("config.toml"),
            r#"
            [model]
            provider = "claude"
            api_key = "sk-host-secret"
            "#,
        )
        .unwrap();

        let result = load_with_layout(None, Some(astrid_home.path()), &WorkspaceLayout::default());

        let error = result.unwrap_err().to_string();
        assert!(error.contains("legacy host [model]"));
        assert!(error.contains("principal-scoped capsule"));
        assert!(error.contains("model registry"));
        assert!(!error.contains("sk-host-secret"));
    }

    #[test]
    fn legacy_workspace_model_section_fails_before_env_resolution() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let state = workspace.path().join(".astrid");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("config.toml"),
            r#"
            [model]
            api_key = "${ANTHROPIC_API_KEY}"
            "#,
        )
        .unwrap();

        let result = load_with_layout(
            Some(workspace.path()),
            Some(home.path()),
            &WorkspaceLayout::default(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn legacy_model_section_fails_single_file_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[model]\napi_key = \"sk-host-secret\"\n").unwrap();

        let error = load_file(&path).unwrap_err().to_string();

        assert!(error.contains("legacy host [model]"));
        assert!(error.contains("capsule [env]"));
        assert!(!error.contains("sk-host-secret"));
    }

    #[test]
    fn test_server_section_debug_redacts_env() {
        use crate::types::ServerSection;
        let mut section = ServerSection::default();
        section
            .env
            .insert("SECRET_KEY".to_owned(), "super-secret-value".to_owned());

        let debug_str = format!("{section:?}");
        assert!(
            !debug_str.contains("super-secret-value"),
            "Debug output must not contain env var values"
        );
        assert!(debug_str.contains("SECRET_KEY"));
        assert!(debug_str.contains("***"));
    }

    // ---- Step 7: Oversized config ----

    #[test]
    fn test_oversized_config_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("huge.toml");
        // Write a file exceeding 1 MB.
        let data = "x = \"".to_owned() + &"a".repeat(1_100_000) + "\"";
        std::fs::write(&file_path, data).unwrap();

        let result = try_load_file(&file_path);
        assert!(
            matches!(result, Err(ConfigError::ValidationError { .. })),
            "Expected ValidationError for oversized config, got: {result:?}"
        );
    }
}
