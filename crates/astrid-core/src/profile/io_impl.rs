//! On-disk IO for [`PrincipalProfile`]: path resolution, load, atomic save.
//!
//! Profile files live at `~/.astrid/etc/profiles/{principal}.toml` —
//! NOT inside the principal's own home directory. Profile contents are
//! 100% system-managed policy (enabled, groups, grants, revokes, quotas,
//! auth public keys, egress, process allowlist) so a capsule running
//! as that principal must not be able to read or write its own policy.
//! Putting profiles under `etc/` keeps them outside the `home://` VFS
//! scheme entirely — capsules cannot reach them no matter what their
//! manifest declares.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{PrincipalProfile, ProfileError, ProfileResult};
use crate::dirs::AstridHome;
use crate::principal::PrincipalId;

impl PrincipalProfile {
    /// Canonical on-disk path for a principal's profile:
    /// `~/.astrid/etc/profiles/{principal}.toml`.
    ///
    /// See the module-level docs on why this lives outside the
    /// principal's home directory.
    #[must_use]
    pub fn path_for(home: &AstridHome, principal: &PrincipalId) -> PathBuf {
        home.profile_path(principal)
    }

    /// Load the profile for `principal` under `home`, falling back to
    /// [`Self::default`] if the file does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Io`] on IO failure other than `NotFound`,
    /// [`ProfileError::Parse`] on malformed or unknown-field TOML, and
    /// [`ProfileError::Invalid`] on semantic validation failure.
    pub fn load(home: &AstridHome, principal: &PrincipalId) -> ProfileResult<Self> {
        Self::load_from_path(&Self::path_for(home, principal))
    }

    /// Load a profile from an explicit path. Exposed for tests and tools
    /// that don't own an [`AstridHome`].
    ///
    /// # Errors
    ///
    /// See [`Self::load`].
    pub fn load_from_path(path: &Path) -> ProfileResult<Self> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Self::default());
            },
            Err(e) => return Err(ProfileError::Io(e)),
        };
        let profile: Self = toml::from_str(&content)?;
        profile.validate()?;
        Ok(profile)
    }

    /// Save the profile for `principal` under `home`, creating
    /// `etc/profiles/` if needed.
    ///
    /// The write is atomic on Unix: a temp file is written with mode
    /// `0o600` and then `rename`d over the target. A failed rename leaves
    /// the original file untouched.
    ///
    /// # Errors
    ///
    /// Validates before writing. Returns [`ProfileError::Invalid`] if the
    /// in-memory profile is malformed, [`ProfileError::Serialize`] on
    /// serialization failure, and [`ProfileError::Io`] on filesystem
    /// failure.
    pub fn save(&self, home: &AstridHome, principal: &PrincipalId) -> ProfileResult<()> {
        self.save_to_path(&Self::path_for(home, principal))
    }

    /// Save the profile to an explicit path. See [`Self::save`].
    ///
    /// # Errors
    ///
    /// See [`Self::save`].
    pub fn save_to_path(&self, path: &Path) -> ProfileResult<()> {
        self.validate()?;
        let content = toml::to_string_pretty(self)?;
        write_atomic(path, content.as_bytes())
    }
}

/// Per-process monotonic counter disambiguating concurrent tmp filenames.
/// PID alone is not enough — two threads in the same daemon calling `save`
/// would race on the same tmp path and corrupt each other's writes.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_atomic(path: &Path, data: &[u8]) -> ProfileResult<()> {
    let parent = path.parent().ok_or_else(|| {
        ProfileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "profile path has no parent directory",
        ))
    })?;
    fs::create_dir_all(parent)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        // Same-filesystem temp sibling so `rename` is atomic. PID + monotonic
        // counter → unique per call across threads within a process and
        // across processes sharing the directory.
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
            // Rename failed; don't leave a secret-adjacent temp file.
            let _ = fs::remove_file(&tmp_path);
            return Err(ProfileError::Io(e));
        }
    }

    // Non-Unix fallback: no atomic rename, no explicit permissions.
    // Astrid's supported platforms are Unix; this exists only to keep
    // the crate buildable on Windows.
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)] // tests mutate a known-good baseline
mod tests {
    use super::*;

    use crate::profile::CURRENT_PROFILE_VERSION;

    use tempfile::tempdir;

    /// Tempdir-rooted `(AstridHome, PrincipalId)` fixture for profile
    /// IO tests. Pre-creates `etc/profiles/` so tests that hand-write
    /// the file before loading don't have to.
    fn scratch_home() -> (tempfile::TempDir, AstridHome, PrincipalId) {
        let dir = tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        fs::create_dir_all(home.profiles_dir()).expect("mkdir etc/profiles");
        let principal = PrincipalId::new("alice").unwrap();
        (dir, home, principal)
    }

    // ── Load ──────────────────────────────────────────────────────────

    #[test]
    fn load_missing_file_returns_default() {
        let (_d, home, principal) = scratch_home();
        assert!(!PrincipalProfile::path_for(&home, &principal).exists());
        let loaded = PrincipalProfile::load(&home, &principal).unwrap();
        assert_eq!(loaded, PrincipalProfile::default());
    }

    #[test]
    fn load_malformed_toml_is_hard_error() {
        let (_d, home, principal) = scratch_home();
        let path = PrincipalProfile::path_for(&home, &principal);
        fs::write(&path, "this is not valid = = toml [").unwrap();
        let err = PrincipalProfile::load(&home, &principal).unwrap_err();
        assert!(matches!(err, ProfileError::Parse(_)), "got: {err:?}");
    }

    #[test]
    fn load_empty_file_is_valid_default_like() {
        // Empty TOML is a valid document → all #[serde(default)] fire.
        // File existence is not a "reset"; the defaults are the same
        // whether the file is absent or empty.
        let (_d, home, principal) = scratch_home();
        let path = PrincipalProfile::path_for(&home, &principal);
        fs::write(&path, "").unwrap();
        let loaded = PrincipalProfile::load(&home, &principal).unwrap();
        assert_eq!(loaded, PrincipalProfile::default());
    }

    #[test]
    fn load_rejects_unknown_top_level_field() {
        let (_d, home, principal) = scratch_home();
        let path = PrincipalProfile::path_for(&home, &principal);
        fs::write(&path, "enabled = true\nenableed = true\n").unwrap();
        let err = PrincipalProfile::load(&home, &principal).unwrap_err();
        assert!(matches!(err, ProfileError::Parse(_)), "got: {err:?}");
    }

    #[test]
    fn load_rejects_unknown_auth_method_variant() {
        // Enum variant typo (`passky`) must fail loudly at parse time.
        let (_d, home, principal) = scratch_home();
        let path = PrincipalProfile::path_for(&home, &principal);
        fs::write(&path, "[auth]\nmethods = [\"passky\"]\n").unwrap();
        let err = PrincipalProfile::load(&home, &principal).unwrap_err();
        assert!(matches!(err, ProfileError::Parse(_)), "got: {err:?}");
    }

    #[test]
    fn load_accepts_known_auth_method_variants() {
        let (_d, home, principal) = scratch_home();
        let path = PrincipalProfile::path_for(&home, &principal);
        fs::write(
            &path,
            "[auth]\nmethods = [\"keypair\", \"passkey\", \"system\"]\n",
        )
        .unwrap();
        let loaded = PrincipalProfile::load(&home, &principal).unwrap();
        assert_eq!(loaded.auth.methods.len(), 3);
    }

    #[test]
    fn load_rejects_unknown_nested_field() {
        let (_d, home, principal) = scratch_home();
        let path = PrincipalProfile::path_for(&home, &principal);
        fs::write(
            &path,
            "[quotas]\nmax_memory_bytes = 1048576\ntypo_field = 42\n",
        )
        .unwrap();
        let err = PrincipalProfile::load(&home, &principal).unwrap_err();
        assert!(matches!(err, ProfileError::Parse(_)), "got: {err:?}");
    }

    #[test]
    fn load_roundtrips_cpu_fuel_quota() {
        let (_d, home, principal) = scratch_home();
        let mut p = PrincipalProfile::default();
        p.quotas.max_cpu_fuel_per_sec = 1_500_000_000;
        p.save(&home, &principal).unwrap();
        let loaded = PrincipalProfile::load(&home, &principal).unwrap();
        assert_eq!(loaded.quotas.max_cpu_fuel_per_sec, 1_500_000_000);
    }

    #[test]
    fn load_quotas_missing_cpu_fuel_uses_default() {
        // A pre-existing profile.toml that predates the field still loads,
        // with `max_cpu_fuel_per_sec` falling back to the serde default
        // (deny_unknown_fields rejects UNKNOWN fields, not missing ones).
        let (_d, home, principal) = scratch_home();
        let path = PrincipalProfile::path_for(&home, &principal);
        fs::write(&path, "[quotas]\nmax_memory_bytes = 1048576\n").unwrap();
        let loaded = PrincipalProfile::load(&home, &principal).unwrap();
        assert_eq!(loaded.quotas.max_memory_bytes, 1_048_576);
        assert_eq!(
            loaded.quotas.max_cpu_fuel_per_sec,
            super::super::DEFAULT_MAX_CPU_FUEL_PER_SEC
        );
    }

    #[test]
    fn load_rejects_future_version() {
        let (_d, home, principal) = scratch_home();
        let path = PrincipalProfile::path_for(&home, &principal);
        let toml_doc = format!("profile_version = {}\n", CURRENT_PROFILE_VERSION + 1);
        fs::write(&path, toml_doc).unwrap();
        let err = PrincipalProfile::load(&home, &principal).unwrap_err();
        match err {
            ProfileError::Invalid(msg) => assert!(msg.contains("profile_version"), "msg: {msg}"),
            other => panic!("expected Invalid, got: {other:?}"),
        }
    }

    #[test]
    fn load_accepts_current_version() {
        let (_d, home, principal) = scratch_home();
        let path = PrincipalProfile::path_for(&home, &principal);
        let toml_doc = format!("profile_version = {CURRENT_PROFILE_VERSION}\n");
        fs::write(&path, toml_doc).unwrap();
        let loaded = PrincipalProfile::load(&home, &principal).unwrap();
        assert_eq!(loaded.profile_version, CURRENT_PROFILE_VERSION);
    }

    // ── Save ──────────────────────────────────────────────────────────

    #[test]
    fn save_then_load_roundtrips() {
        let (_d, home, principal) = scratch_home();
        let mut p = PrincipalProfile::default();
        p.enabled = false;
        p.groups.push("admins".into());
        p.save(&home, &principal).unwrap();

        let loaded = PrincipalProfile::load(&home, &principal).unwrap();
        assert_eq!(loaded, p);
    }

    #[test]
    fn save_creates_profiles_dir_if_missing() {
        // Tempdir alone — no etc/profiles/ pre-created.  save() must
        // create the parent directory before writing.
        let dir = tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let principal = PrincipalId::new("bob").unwrap();
        assert!(!home.profiles_dir().exists());
        PrincipalProfile::default().save(&home, &principal).unwrap();
        assert!(home.profiles_dir().exists());
        assert!(PrincipalProfile::path_for(&home, &principal).exists());
    }

    #[test]
    fn save_rejects_invalid_profile() {
        let (_d, home, principal) = scratch_home();
        let mut p = PrincipalProfile::default();
        p.quotas.max_memory_bytes = 0;
        let err = p.save(&home, &principal).unwrap_err();
        assert!(matches!(err, ProfileError::Invalid(_)));
        assert!(
            !PrincipalProfile::path_for(&home, &principal).exists(),
            "invalid profile must not be written"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let (_d, home, principal) = scratch_home();
        PrincipalProfile::default().save(&home, &principal).unwrap();
        let path = PrincipalProfile::path_for(&home, &principal);
        let perms = fs::metadata(&path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "profile.toml must be owner-only",
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_overwrites_preserves_mode() {
        use std::os::unix::fs::PermissionsExt;

        let (_d, home, principal) = scratch_home();
        PrincipalProfile::default().save(&home, &principal).unwrap();
        let mut p = PrincipalProfile::default();
        p.enabled = false;
        p.save(&home, &principal).unwrap();
        let path = PrincipalProfile::path_for(&home, &principal);
        let perms = fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn save_does_not_leave_temp_file() {
        let (_d, home, principal) = scratch_home();
        PrincipalProfile::default().save(&home, &principal).unwrap();
        let entries: Vec<_> = fs::read_dir(home.profiles_dir())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        // The on-disk filename is `{principal}.toml`, not `profile.toml`.
        assert!(
            entries.iter().any(|n| n == "alice.toml"),
            "got: {entries:?}"
        );
        assert!(
            !entries.iter().any(|n| n.contains(".tmp.")),
            "temp files should be renamed away: {entries:?}",
        );
    }
}
