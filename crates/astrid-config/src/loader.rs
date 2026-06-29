//! Config file discovery and layered loading.
//!
//! Implements the `Config::load()` algorithm:
//! 1. Parse `defaults.toml` → base
//! 2. Merge `/etc/astrid/config.toml` (system)
//! 3. Merge `$ASTRID_HOME/config.toml` or `~/.astrid/config.toml` (user)
//! 4. Merge `{workspace}/.astrid/config.toml` (workspace) + restriction enforcement
//! 5. Apply env var fallbacks for unset fields
//! 6. Deserialize merged tree → `Config`
//! 7. Resolve `${VAR}` references
//! 8. Validate
//! 9. Return `ResolvedConfig`

use std::path::{Path, PathBuf};

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

    // 4. Workspace config ({workspace}/.astrid/config.toml).
    //    Snapshot the merged config *before* the workspace layer as the baseline
    //    for restriction enforcement. This ensures restrictions work even when
    //    no user config file exists (the baseline includes defaults + system).
    if let Some(ws_root) = workspace_root {
        let ws_path = ws_root.join(".astrid").join("config.toml");
        if let Some(mut overlay) = try_load_file(&ws_path)? {
            // Resolve ${VAR} references in workspace overlay with restricted
            // env vars (only ASTRID_* and ANTHROPIC_*). This prevents a
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

    let config: Config = toml::from_str(&content).map_err(|e| ConfigError::ParseError {
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
        assert!(val.as_table().unwrap().contains_key("model"));
        assert!(val.as_table().unwrap().contains_key("runtime"));
        assert!(val.as_table().unwrap().contains_key("security"));
    }

    #[test]
    fn test_defaults_deserialize_to_config() {
        let config: Config = toml::from_str(DEFAULTS_TOML).unwrap();
        assert_eq!(config.model.provider, "unknown");
        assert_eq!(config.model.max_tokens, 4096);
        assert!((config.budget.session_max_usd - 100.0).abs() < f64::EPSILON);
        assert_eq!(config.timeouts.request_secs, 120);
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
            [model]
            provider = "home"
            "#,
        )
        .unwrap();
        std::fs::write(
            astrid_home.path().join("config.toml"),
            r#"
            [model]
            provider = "astrid-home"
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
            [model]
            provider = "claude"
            max_tokens = 4096
        "#,
        )
        .unwrap();

        let mut sources = FieldSources::new();
        record_defaults(&val, "", &mut sources);

        assert_eq!(sources.get("model.provider"), Some(&ConfigLayer::Defaults));
        assert_eq!(
            sources.get("model.max_tokens"),
            Some(&ConfigLayer::Defaults)
        );
    }

    // ---- Step 1: Debug/Serialize redaction ----

    #[test]
    fn test_model_config_debug_redacts_api_key() {
        use crate::types::ModelConfig;
        let cfg = ModelConfig {
            api_key: Some("sk-secret-12345".to_owned()),
            api_url: Some("https://my-proxy.example.com".to_owned()),
            ..ModelConfig::default()
        };

        let debug_str = format!("{cfg:?}");
        assert!(
            !debug_str.contains("sk-secret-12345"),
            "Debug output must not contain API key value"
        );
        assert!(
            !debug_str.contains("my-proxy.example.com"),
            "Debug output must not contain API URL value"
        );
        assert!(debug_str.contains("has_api_key: true"));
        assert!(debug_str.contains("has_api_url: true"));
    }

    #[test]
    fn test_model_config_serialize_omits_api_key() {
        use crate::types::ModelConfig;
        let cfg = ModelConfig {
            api_key: Some("sk-secret-12345".to_owned()),
            api_url: Some("https://my-proxy.example.com".to_owned()),
            ..ModelConfig::default()
        };

        let json = serde_json::to_string(&cfg).unwrap();
        assert!(
            !json.contains("sk-secret-12345"),
            "Serialized output must not contain API key"
        );
        assert!(
            !json.contains("my-proxy.example.com"),
            "Serialized output must not contain API URL"
        );
        assert!(!json.contains("api_key"));
        assert!(!json.contains("api_url"));
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
