//! Discover compatible user overlays in ascending precedence order.

use std::path::{Path, PathBuf};

use super::{ConfigResult, try_load_file};

/// Root configuration remains supported. The file written by the canonical
/// editor overlays it, preserving legacy-only fields while giving explicit
/// canonical settings precedence. A malformed source is never skipped.
pub(super) fn load_home_configs(root: &Path) -> ConfigResult<Vec<(toml::Value, PathBuf)>> {
    let home = astrid_core::dirs::AstridHome::from_path(root);
    let mut overlays = Vec::new();
    for path in [root.join("config.toml"), home.config_path()] {
        if let Some(overlay) = try_load_file(&path)? {
            overlays.push((overlay, path));
        }
    }
    Ok(overlays)
}

pub(super) fn discover_user_config(
    home_dir: &Path,
    astrid_home: Option<&str>,
) -> ConfigResult<Vec<(toml::Value, PathBuf)>> {
    if let Some(astrid_home) = astrid_home {
        if let Some(canonical) = validate_astrid_home(astrid_home, home_dir) {
            let overlays = load_home_configs(&canonical)?;
            if !overlays.is_empty() {
                return Ok(overlays);
            }
        } else {
            tracing::warn!(
                path = astrid_home,
                "ASTRID_HOME is not a valid directory owned by current user; ignoring"
            );
        }
    }
    load_home_configs(&home_dir.join(".astrid"))
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
