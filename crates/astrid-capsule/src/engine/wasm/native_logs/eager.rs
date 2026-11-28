//! Existing eager opening and rotation retained for public embeddings and history.

use std::path::Path;
use std::sync::{Arc, Mutex};

use super as native_logs;
use super::super::today_date_string;

/// Test fixture for opening the daily log of a registered principal.
#[cfg(test)]
pub(in crate::engine::wasm) fn open_capsule_log_at(
    log_root: &Path,
    directory: &astrid_storage::PrincipalDirectory,
    principal: &astrid_core::PrincipalId,
    capsule_name: &str,
    prune: bool,
) -> Option<Arc<Mutex<std::fs::File>>> {
    let uid = directory.uid_for(principal).ok()?;
    open_capsule_log_at_uid(log_root, uid, capsule_name, prune)
}

/// Open an operational log under `log/principals/<uid>/<capsule>/`, outside
/// the durable home VFS. Only load-time callers request pruning, which scans
/// existing rotated files in this directory.
pub(super) fn open_capsule_log_at_uid(
    log_root: &Path,
    uid: astrid_core::PrincipalUid,
    capsule_name: &str,
    prune: bool,
) -> Option<Arc<Mutex<std::fs::File>>> {
    if !native_logs::valid_name(capsule_name) {
        return None;
    }
    astrid_core::platform_fs::ensure_private_directory(log_root).ok()?;
    let principals_root = log_root.join("principals");
    astrid_core::platform_fs::ensure_private_directory(&principals_root).ok()?;
    let uid_root = principals_root.join(uid.to_string());
    astrid_core::platform_fs::ensure_private_directory(&uid_root).ok()?;
    let log_dir = uid_root.join(capsule_name);
    astrid_core::platform_fs::ensure_private_directory(&log_dir).ok()?;
    if prune {
        prune_old_logs(&log_dir, 7);
    }
    let today = today_date_string();
    let path = log_dir.join(format!("{today}.log"));
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let file = options.open(&path).ok()?;
    astrid_core::platform_fs::restrict_private_file(&path).ok()?;
    Some(Arc::new(Mutex::new(file)))
}

/// Delete log files older than `max_days` from a capsule log directory.
///
/// Only deletes files matching the `YYYY-MM-DD.log` pattern.
fn prune_old_logs(log_dir: &std::path::Path, max_days: u64) {
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(max_days * 86400))
        .unwrap_or(std::time::UNIX_EPOCH);

    let Ok(entries) = std::fs::read_dir(log_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Only touch files matching YYYY-MM-DD.log pattern.
        if !name_str.ends_with(".log") || name_str.len() != 14 {
            continue;
        }
        if let Ok(meta) = entry.metadata()
            && let Ok(modified) = meta.modified()
            && modified < cutoff
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}
