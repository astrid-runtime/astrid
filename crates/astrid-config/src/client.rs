//! Pre-mount client configuration.
//!
//! This plane intentionally contains only local CLI behavior. It has no
//! dependency on, or route into, the layered runtime configuration tree.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{ConfigError, ConfigResult};

/// Historical and absent-file default for the `astrid run` idle boundary.
pub const DEFAULT_RUN_IDLE_TIMEOUT_SECS: u64 = 120;

/// The only timeout ceiling shared by the client parser and CLI argument parser.
pub const MAX_RUN_IDLE_TIMEOUT_SECS: u64 = 86_400;

/// Explicit client-file override selected by the operator or launcher.
const CLIENT_CONFIG_PATH_VAR: &str = "ASTRID_CLIENT_CONFIG_PATH";

/// Bound the narrow file even though it can contain only one key.
const MAX_CLIENT_CONFIG_FILE_SIZE: u64 = 1024 * 1024;

/// Pre-mount behavior for Astrid CLI clients.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientConfig {
    /// Seconds `astrid run` may wait for its next active-run message.
    pub run_idle_secs: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            run_idle_secs: DEFAULT_RUN_IDLE_TIMEOUT_SECS,
        }
    }
}

/// Resolve the client configuration path without consulting `ASTRID_HOME`.
///
/// `ASTRID_CLIENT_CONFIG_PATH` must name an absolute private regular file and
/// is used even when it does not yet exist (loading then fails closed). With no
/// override, the AOS canonical path is used when present.
///
/// # Errors
///
/// Returns an error for a relative override, no usable home directory, or a
/// default candidate that exists but cannot be stat'ed safely.
pub fn client_config_path(
    explicit: Option<&OsStr>,
    home_dir: Option<&Path>,
) -> ConfigResult<Option<PathBuf>> {
    if let Some(raw_path) = explicit {
        let path = PathBuf::from(raw_path);
        if !path.is_absolute() {
            return Err(ConfigError::ValidationError {
                field: CLIENT_CONFIG_PATH_VAR.to_owned(),
                message: "must be an absolute path".to_owned(),
            });
        }
        return Ok(Some(path));
    }

    let Some(home_dir) = home_dir else {
        return Err(ConfigError::NoHomeDir);
    };
    let path = home_dir.join(".aos/etc/astrid/client.toml");
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ConfigError::ValidationError {
            field: path.display().to_string(),
            message: "canonical client config must not be a symlink".to_owned(),
        }),
        Ok(metadata) if metadata.is_file() => Ok(Some(path)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ConfigError::ReadError {
            path: path.display().to_string(),
            source: error,
        }),
    }
}

/// Resolve the production client path from the environment and home directory.
///
/// # Errors
///
/// See [`client_config_path`].
pub fn production_client_config_path() -> ConfigResult<Option<PathBuf>> {
    let home_dir = directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf());
    client_config_path(
        std::env::var_os(CLIENT_CONFIG_PATH_VAR).as_deref(),
        home_dir.as_deref(),
    )
}

/// Load and validate a client configuration from one explicit path.
///
/// Runtime configuration is deliberately not accepted here: unknown keys fail
/// rather than becoming a silent policy channel. The platform filesystem
/// boundary rejects redirects, foreign ownership, and permissive access.
///
/// # Errors
///
/// Returns an error when the path is unsafe, unreadable, oversized, unknown,
/// malformed, or contains an invalid timeout.
pub fn load_client_config(path: &Path) -> ConfigResult<ClientConfig> {
    if !path.is_absolute() {
        return Err(ConfigError::ValidationError {
            field: path.display().to_string(),
            message: "client config path must be absolute".to_owned(),
        });
    }

    astrid_core::platform_fs::verify_no_redirects(path).map_err(|error| {
        ConfigError::ReadError {
            path: path.display().to_string(),
            source: error,
        }
    })?;
    astrid_core::platform_fs::validate_private_file(path).map_err(|error| {
        ConfigError::ValidationError {
            field: path.display().to_string(),
            message: format!("client config must be a private regular file: {error}"),
        }
    })?;

    let metadata = std::fs::metadata(path).map_err(|error| ConfigError::ReadError {
        path: path.display().to_string(),
        source: error,
    })?;
    if metadata.len() > MAX_CLIENT_CONFIG_FILE_SIZE {
        return Err(ConfigError::ValidationError {
            field: path.display().to_string(),
            message: format!(
                "client config is {} bytes, exceeding the {MAX_CLIENT_CONFIG_FILE_SIZE} byte limit",
                metadata.len()
            ),
        });
    }

    let content = std::fs::read_to_string(path).map_err(|error| ConfigError::ReadError {
        path: path.display().to_string(),
        source: error,
    })?;
    let config: ClientConfig =
        toml::from_str(&content).map_err(|error| ConfigError::ParseError {
            path: path.display().to_string(),
            source: error,
        })?;
    validate_run_idle_secs(config.run_idle_secs)?;
    Ok(config)
}

/// Load the run idle timeout from one client file.
///
/// # Errors
///
/// See [`load_client_config`].
pub fn load_run_idle_timeout(path: &Path) -> ConfigResult<u64> {
    load_client_config(path).map(|config| config.run_idle_secs)
}

/// Resolve the `astrid run` idle timeout without reading runtime configuration.
///
/// An explicit CLI value bypasses client-file parsing entirely and retains the
/// highest precedence. A missing canonical file uses the historical default.
///
/// # Errors
///
/// Returns an error if the selected explicit client file is missing, unsafe, or
/// malformed. The same validation bounds an explicit CLI value.
pub fn resolve_run_idle_timeout(
    explicit: Option<u64>,
    client_path: Option<&Path>,
) -> ConfigResult<u64> {
    if let Some(explicit) = explicit {
        validate_run_idle_secs(explicit)?;
        return Ok(explicit);
    }

    if let Some(path) = client_path {
        load_run_idle_timeout(path)
    } else {
        validate_run_idle_secs(DEFAULT_RUN_IDLE_TIMEOUT_SECS)?;
        Ok(DEFAULT_RUN_IDLE_TIMEOUT_SECS)
    }
}

/// Validate the one client timeout against the shared one-day ceiling.
fn validate_run_idle_secs(value: u64) -> ConfigResult<()> {
    if value == 0 {
        return Err(ConfigError::ValidationError {
            field: "run_idle_secs".to_owned(),
            message: "run_idle_secs must be greater than 0".to_owned(),
        });
    }
    if value > MAX_RUN_IDLE_TIMEOUT_SECS {
        return Err(ConfigError::ValidationError {
            field: "run_idle_secs".to_owned(),
            message: format!("run_idle_secs must be at most {MAX_RUN_IDLE_TIMEOUT_SECS} seconds"),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
