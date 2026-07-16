//! Validation and host-side resolution of native process context.

use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path, PathBuf};

use crate::engine::wasm::bindings::astrid::process1_1_0::host::{ErrorCode, SpawnRequest};
use crate::engine::wasm::host_state::HostState;

pub(super) struct PreparedSpawnContext {
    pub(super) cwd: PathBuf,
    pub(super) env: Vec<(String, String)>,
    pub(super) read_paths: Vec<PathBuf>,
    pub(super) write_paths: Vec<PathBuf>,
}

/// Resolve the guest-controlled context after filesystem policy approves the
/// requested `home://` paths. The spawned child receives their physical paths;
/// no physical path is added to the process host-call response.
pub(super) fn prepare_spawn_context(
    state: &HostState,
    request: &SpawnRequest,
) -> Result<PreparedSpawnContext, ErrorCode> {
    const PASSTHROUGH: &[&str] = &["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ"];
    const MAX_ENV_VARS: usize = 256;
    const MAX_ENV_VALUE_BYTES: usize = 64 * 1024;

    if request.env.len() > MAX_ENV_VARS {
        return Err(ErrorCode::TooLarge);
    }

    let mut env = BTreeMap::new();
    for key in PASSTHROUGH {
        if let Ok(value) = std::env::var(key) {
            env.insert((*key).to_string(), value);
        }
    }

    let mut supplied = HashSet::new();
    let mut read_paths = Vec::new();
    let mut write_paths = Vec::new();
    for item in &request.env {
        let key = item.key.as_str();
        if !valid_env_key(key)
            || item.value.contains('\0')
            || item.value.len() > MAX_ENV_VALUE_BYTES
            || !supplied.insert(key.to_string())
            || reserved_process_env(key)
        {
            return Err(ErrorCode::InvalidInput);
        }

        let value = if key == "HOME" && item.value.starts_with("home://") {
            let physical = super::super::fs::authorize_process_read_path(state, &item.value)
                .map_err(map_fs_path_error)?;
            add_home_process_paths(state, &physical, &mut read_paths, &mut write_paths)?;
            physical.to_string_lossy().into_owned()
        } else {
            item.value.clone()
        };
        env.insert(key.to_string(), value);
    }

    let cwd = match request.cwd.as_deref() {
        Some(path) if path.starts_with("home://") => {
            let physical = super::super::fs::authorize_process_read_path(state, path)
                .map_err(map_fs_path_error)?;
            add_home_process_paths(state, &physical, &mut read_paths, &mut write_paths)?;
            physical
        },
        Some(path) => resolve_workspace_cwd(&state.workspace_root, path)?,
        None => state.workspace_root.clone(),
    };

    read_paths.sort();
    read_paths.dedup();
    write_paths.sort();
    write_paths.dedup();
    Ok(PreparedSpawnContext {
        cwd,
        env: env.into_iter().collect(),
        read_paths,
        write_paths,
    })
}

fn add_home_process_paths(
    state: &HostState,
    requested: &Path,
    read_paths: &mut Vec<PathBuf>,
    write_paths: &mut Vec<PathBuf>,
) -> Result<(), ErrorCode> {
    read_paths.push(requested.to_path_buf());
    let Some(home) = state.effective_home_root_buf() else {
        return Err(ErrorCode::CapabilityDenied);
    };
    let home = home.canonicalize().unwrap_or(home);
    let Some(gate) = state.security.as_ref() else {
        return Err(ErrorCode::CapabilityDenied);
    };
    for path in gate.process_home_write_paths(&home) {
        let path = path.canonicalize().unwrap_or(path);
        if !path.starts_with(&home) || !path.exists() {
            continue;
        }
        super::super::fs::authorize_process_write_path(state, &path).map_err(map_fs_path_error)?;
        write_paths.push(path);
    }
    Ok(())
}

fn map_fs_path_error(
    error: crate::engine::wasm::bindings::astrid::fs::host::ErrorCode,
) -> ErrorCode {
    use crate::engine::wasm::bindings::astrid::fs::host::ErrorCode as FsError;
    match error {
        FsError::BoundaryEscape => ErrorCode::BoundaryEscape,
        FsError::CapabilityDenied | FsError::Access => ErrorCode::CapabilityDenied,
        FsError::TooLarge => ErrorCode::TooLarge,
        FsError::Quota => ErrorCode::Quota,
        _ => ErrorCode::InvalidInput,
    }
}

pub(super) fn valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Environment variables that can redirect command resolution, inject code
/// before the approved executable starts, or impersonate a host-issued session.
pub(super) fn reserved_process_env(key: &str) -> bool {
    key == "PATH"
        || key == "ASTRID_SESSION_TOKEN"
        || key == "BASH_ENV"
        || key == "ENV"
        || key == "GCONV_PATH"
        || key == "NODE_OPTIONS"
        || key == "PERL5OPT"
        || key == "PYTHONHOME"
        || key == "PYTHONPATH"
        || key == "RUBYOPT"
        || key == "ZDOTDIR"
        || key.starts_with("DYLD_")
        || key.starts_with("LD_")
}

fn resolve_workspace_cwd(workspace_root: &Path, requested: &str) -> Result<PathBuf, ErrorCode> {
    let requested = requested.strip_prefix("cwd://").unwrap_or(requested);
    let path = Path::new(requested);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ErrorCode::BoundaryEscape);
    }

    let root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let cwd = root
        .join(path)
        .canonicalize()
        .map_err(|_| ErrorCode::InvalidInput)?;
    if !cwd.starts_with(&root) {
        return Err(ErrorCode::BoundaryEscape);
    }
    Ok(cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_keys_are_strict_and_portable() {
        assert!(valid_env_key("HOME"));
        assert!(valid_env_key("_AOS_1"));
        assert!(!valid_env_key(""));
        assert!(!valid_env_key("1HOME"));
        assert!(!valid_env_key("BAD-NAME"));
        assert!(reserved_process_env("PATH"));
        assert!(reserved_process_env("LD_PRELOAD"));
        assert!(reserved_process_env("DYLD_INSERT_LIBRARIES"));
        assert!(reserved_process_env("ASTRID_SESSION_TOKEN"));
        assert!(!reserved_process_env("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn workspace_cwd_rejects_absolute_and_parent_escapes() {
        let root = tempfile::tempdir().expect("root");
        std::fs::create_dir(root.path().join("inside")).expect("inside");
        assert_eq!(
            resolve_workspace_cwd(root.path(), "inside").expect("inside cwd"),
            root.path()
                .canonicalize()
                .expect("canonical root")
                .join("inside")
        );
        assert!(matches!(
            resolve_workspace_cwd(root.path(), "../outside"),
            Err(ErrorCode::BoundaryEscape)
        ));
        assert!(matches!(
            resolve_workspace_cwd(root.path(), "/outside"),
            Err(ErrorCode::BoundaryEscape)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_cwd_rejects_symlink_escape() {
        let root = tempfile::tempdir().expect("root");
        let workspace = root.path().join("workspace");
        let outside = root.path().join("outside");
        std::fs::create_dir(&workspace).expect("workspace");
        std::fs::create_dir(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, workspace.join("escape")).expect("escape symlink");

        assert!(matches!(
            resolve_workspace_cwd(&workspace, "escape"),
            Err(ErrorCode::BoundaryEscape)
        ));
    }
}
