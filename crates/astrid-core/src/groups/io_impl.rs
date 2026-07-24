//! Atomic on-disk persistence for [`GroupConfig`] (issue #672, Layer 6).
//!
//! Mirrors [`crate::profile::io_impl`]: a tempfile with `0o600` is written
//! next to the target, then renamed atomically. A failed rename cleans up
//! the tempfile so secret-adjacent state never leaks. Only custom groups
//! are serialized — built-ins are baked in and rebuilt on load.

use std::collections::HashMap;
#[cfg(not(windows))]
use std::fs;
use std::io;
use std::path::Path;
// Only used by the `#[cfg(unix)]` atomic-write path below.
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use super::{Group, GroupConfig, GroupConfigError, GroupConfigResult, is_builtin};
use crate::dirs::AstridHome;

/// Wire shape for the on-disk `groups.toml` file — mirrors the private
/// `GroupsFile` loader struct but owns the data so we can serialize it.
#[derive(Debug, Default, Serialize)]
struct GroupsFileOwned {
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    groups: HashMap<String, Group>,
}

impl GroupConfig {
    /// Save the config's **custom** groups to `home`'s `etc/groups.toml`,
    /// creating `etc/` if needed.
    ///
    /// Built-in groups are never serialized — they are baked into
    /// [`GroupConfig::builtin_only`] and rebuilt on load. The result is
    /// idempotent: loading the written file back yields the same in-memory
    /// config.
    ///
    /// # Errors
    ///
    /// See [`Self::save_to_path`].
    pub fn save(&self, home: &AstridHome) -> GroupConfigResult<()> {
        self.save_to_path(&Self::path_for(home))
    }

    /// Save to an explicit path. See [`Self::save`] for semantics.
    ///
    /// # Errors
    ///
    /// - [`GroupConfigError::Io`] on filesystem failure (parent create,
    ///   tempfile open/write, rename).
    /// - `GroupConfigError::Parse` never — serialization is infallible
    ///   for the shape we produce.
    pub fn save_to_path(&self, path: &Path) -> GroupConfigResult<()> {
        let mut custom = HashMap::new();
        for (name, group) in &self.groups {
            if is_builtin(name) {
                continue;
            }
            custom.insert(name.clone(), group.clone());
        }
        let file = GroupsFileOwned { groups: custom };
        let content = toml::to_string_pretty(&file).map_err(|e| {
            GroupConfigError::Io(io::Error::other(format!(
                "failed to serialize groups.toml: {e}"
            )))
        })?;
        write_atomic(path, content.as_bytes())
    }
}

#[cfg(unix)]
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_atomic(path: &Path, data: &[u8]) -> GroupConfigResult<()> {
    let parent = path.parent().ok_or_else(|| {
        GroupConfigError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "groups path has no parent directory",
        ))
    })?;
    #[cfg(windows)]
    crate::platform_fs::ensure_private_directory(parent)?;
    #[cfg(not(windows))]
    fs::create_dir_all(parent)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = path.with_extension(format!("toml.tmp.{}.{seq}", std::process::id()));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);

        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(GroupConfigError::Io(e));
        }
    }

    #[cfg(windows)]
    {
        crate::platform_fs::atomic_write_private_file(path, data)?;
    }

    #[cfg(not(any(unix, windows)))]
    {
        fs::write(path, data)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::groups::{BUILTIN_ADMIN, BUILTIN_AGENT, BUILTIN_RESTRICTED, Group, GroupConfig};

    use tempfile::tempdir;

    fn custom_group(caps: &[&str]) -> Group {
        Group {
            capabilities: caps.iter().map(|s| (*s).to_string()).collect(),
            description: None,
            unsafe_admin: false,
        }
    }

    #[test]
    fn save_then_load_roundtrips_custom_groups() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("groups.toml");

        let base = GroupConfig::builtin_only();
        let with_ops = base
            .insert_custom_group("ops".to_string(), custom_group(&["capsule:install"]))
            .unwrap();

        with_ops.save_to_path(&path).unwrap();
        let loaded = GroupConfig::load_from_path(&path).unwrap();
        assert!(loaded.get("ops").is_some());
        assert_eq!(
            loaded.get("ops").unwrap().capabilities,
            vec!["capsule:install".to_string()]
        );
        // Built-ins are still there after load.
        assert!(loaded.get(BUILTIN_ADMIN).is_some());
        assert!(loaded.get(BUILTIN_AGENT).is_some());
        assert!(loaded.get(BUILTIN_RESTRICTED).is_some());
    }

    #[test]
    fn save_does_not_persist_builtins_to_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("groups.toml");

        GroupConfig::builtin_only().save_to_path(&path).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("[groups.admin]"));
        assert!(!raw.contains("[groups.agent]"));
        assert!(!raw.contains("[groups.restricted]"));
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("groups.toml");
        GroupConfig::builtin_only().save_to_path(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn save_does_not_leave_temp_file_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("groups.toml");
        GroupConfig::builtin_only().save_to_path(&path).unwrap();
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(entries.contains(&"groups.toml".to_string()));
        assert!(
            !entries.iter().any(|n| n.contains(".tmp.")),
            "temp files should be renamed away: {entries:?}"
        );
    }

    #[test]
    fn save_creates_parent_directory_if_missing() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        let path = nested.join("groups.toml");
        assert!(!nested.exists());
        GroupConfig::builtin_only().save_to_path(&path).unwrap();
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn save_atomic_rename_failure_cleans_up_tempfile() {
        // Target path is a directory — rename(file, dir) fails. The tempfile
        // must be removed on the error path so no secret-adjacent stale
        // tempfile is left behind.
        let dir = tempdir().unwrap();
        let dir_path = dir.path().join("groups.toml"); // we'll make it a directory
        fs::create_dir(&dir_path).unwrap();

        let err = GroupConfig::builtin_only().save_to_path(&dir_path);
        assert!(err.is_err());

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !entries.iter().any(|n| n.contains(".tmp.")),
            "failed rename must not leave temp file behind: {entries:?}"
        );
    }
}
