//! Directory scaffolding for Astrid home and workspace directories.
//!
//! Two key directory structures:
//!
//! - [`AstridHome`]: Global durable root at `~/.astrid/` (or `$ASTRID_HOME`).
//!   Stopped state is exactly the private `astrid.volume` media file. While a
//!   daemon runs, volume-backed files are projected at their historical paths;
//!   transients use `ASTRID_RUN_DIR` or a disposable runtime directory.
//!
//! - [`WorkspaceDir`]: Selected per-project state directory.
//!   Holds project configuration, capsules, hooks, and instructions.
//!   Contains a `workspace-id` UUID that links the project to its global state.
//!
//! - [`PrincipalHome`]: Legacy per-principal import source under
//!   `~/.astrid/home/{id}/`. It remains addressable for no-follow migration,
//!   but normal v2 boot does not create or use it as runtime authority.
//!
//! # Layout
//!
//! ```text
//! ~/.astrid/                           (AstridHome)
//! └── astrid.volume                    Astrid-owned durable media (stopped)
//!
//! Principal `home/` content is projected from the durable owner catalog and
//! is not represented by a native directory in a fresh v2 layout.
//!
//! <project>/<selected-state-dir>/      (WorkspaceDir)
//! ├── workspace-id                       UUID linking project to global state
//! ├── config.toml                        project configuration
//! ├── capsules/                          project-installed capsules
//! ├── hooks/                             project hooks
//! └── ASTRID.md                          project instructions
//! ```

use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use crate::principal::PrincipalId;

/// Current layout version. Historical sentinels are migration inputs only.
pub const LAYOUT_VERSION: &str = "2";
/// Latest released layout accepted for an in-place upgrade.
pub const LEGACY_LAYOUT_VERSION: &str = "1";
#[path = "dirs_layout.rs"]
mod dirs_layout;
pub use dirs_layout::{LayoutMigrationTarget, retire_legacy_source_tree};
#[path = "dirs_run_dir.rs"]
mod run_dir;
#[path = "dirs_workspace.rs"]
mod workspace_dir;
pub use workspace_dir::WorkspaceDir;
/// Default per-project runtime state directory.
pub const DEFAULT_WORKSPACE_STATE_DIR: &str = ".astrid";

/// Validated per-project runtime layout.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceLayout {
    state_dir_name: String,
}
#[path = "workspace_security.rs"]
mod workspace_security;

pub use workspace_security::{
    WorkspaceSelection, checked_workspace_selection_fingerprint, workspace_selection_fingerprint,
};
impl WorkspaceLayout {
    /// Create a layout from one portable relative directory name.
    ///
    /// # Errors
    ///
    /// Returns an error for empty names, absolute paths, traversal,
    /// separators, control characters, or non-portable characters.
    pub fn new(name: impl Into<String>) -> Result<Self, WorkspaceLayoutError> {
        let name = name.into();
        if name.is_empty() {
            return Err(WorkspaceLayoutError::Empty);
        }
        if name == "." || name == ".." {
            return Err(WorkspaceLayoutError::Ambiguous(name));
        }
        if name.len() > 64 {
            return Err(WorkspaceLayoutError::TooLong);
        }
        if name.ends_with('.') {
            return Err(WorkspaceLayoutError::Ambiguous(name));
        }
        if name.contains('/') || name.contains('\\') {
            return Err(WorkspaceLayoutError::Separator);
        }
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(WorkspaceLayoutError::InvalidCharacter);
        }

        let portable_stem = name.trim_start_matches('.').split('.').next().unwrap_or("");
        let upper = portable_stem.to_ascii_uppercase();
        if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || upper.strip_prefix("COM").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
            || upper.strip_prefix("LPT").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
        {
            return Err(WorkspaceLayoutError::Reserved(name));
        }

        let path = Path::new(&name);
        let mut components = path.components();
        if path.is_absolute()
            || !matches!(components.next(), Some(Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(WorkspaceLayoutError::Ambiguous(name));
        }

        Ok(Self {
            state_dir_name: name,
        })
    }
    /// Relative directory name used for project state.
    #[must_use]
    pub fn state_dir_name(&self) -> &str {
        &self.state_dir_name
    }

    /// Project state directory under `project_root`.
    #[must_use]
    pub fn state_dir(&self, project_root: &Path) -> PathBuf {
        project_root.join(&self.state_dir_name)
    }

    /// Workspace capsule directory under `project_root`.
    #[must_use]
    pub fn capsules_dir(&self, project_root: &Path) -> PathBuf {
        self.state_dir(project_root).join("capsules")
    }

    /// Workspace configuration path under `project_root`.
    #[must_use]
    pub fn config_path(&self, project_root: &Path) -> PathBuf {
        self.state_dir(project_root).join("config.toml")
    }

    /// Workspace hooks directory under `project_root`.
    #[must_use]
    pub fn hooks_dir(&self, project_root: &Path) -> PathBuf {
        self.state_dir(project_root).join("hooks")
    }

    /// Resolve and validate this layout beneath `project_root`.
    ///
    /// The root must exist and be a directory. If the state directory exists,
    /// it must be a real directory whose canonical path is exactly the selected
    /// direct child of the canonical root. A missing state directory is valid;
    /// callers that create it must use [`WorkspaceSelection::ensure_state_dir`]
    /// so the boundary is checked again after creation.
    ///
    /// # Errors
    ///
    /// Returns an error when the root cannot be canonicalized, is not a
    /// directory, or the selected state path is redirected or is not a
    /// directory.
    pub fn resolve(&self, project_root: &Path) -> io::Result<WorkspaceSelection> {
        WorkspaceSelection::resolve(project_root, self.clone())
    }
}

impl Default for WorkspaceLayout {
    fn default() -> Self {
        Self {
            state_dir_name: DEFAULT_WORKSPACE_STATE_DIR.to_owned(),
        }
    }
}

impl fmt::Display for WorkspaceLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.state_dir_name)
    }
}

impl FromStr for WorkspaceLayout {
    type Err = WorkspaceLayoutError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Invalid workspace layout input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkspaceLayoutError {
    /// The name is empty.
    #[error("workspace state directory name must not be empty")]
    Empty,
    /// The name is `.` or `..`, or does not resolve to one directory component.
    #[error("workspace state directory name is ambiguous: {0:?}")]
    Ambiguous(String),
    /// The name contains a path separator.
    #[error("workspace state directory name must not contain path separators")]
    Separator,
    /// The name contains a non-portable character.
    #[error(
        "workspace state directory name may contain only ASCII letters, digits, '.', '_', and '-'"
    )]
    InvalidCharacter,
    /// The name exceeds the portable length bound.
    #[error("workspace state directory name must be at most 64 bytes")]
    TooLong,
    /// The name is reserved by a supported filesystem.
    #[error("workspace state directory name is reserved: {0:?}")]
    Reserved(String),
}

/// Reject paths containing `..` (parent directory) components.
fn reject_parent_traversal(path: &Path, var_name: &str) -> io::Result<()> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{var_name} must not contain '..' path components"),
        ));
    }
    Ok(())
}

// ── AstridHome (system-level) ────────────────────────────────────────────

/// Global Astrid home directory (`~/.astrid/`, Windows `LocalAppData`, or
/// `$ASTRID_HOME`).
///
/// FHS-aligned system layout with config (`etc/`), persistent state (`var/`),
/// runtime (`run/`), logs (`log/`), keys (`keys/`), and shared modules (`lib/`).
/// Principal content is authoritative in `AstridFilesystem`; native `home/` is
/// retained only as a legacy migration source.
#[derive(Debug, Clone)]
pub struct AstridHome {
    root: PathBuf,
}

impl AstridHome {
    /// Resolve the home directory.
    ///
    /// Checks `$ASTRID_HOME` first. Unix falls back to `$HOME/.astrid/`;
    /// Windows uses the per-user `LocalAppData` known folder.
    ///
    /// # Errors
    ///
    /// Returns an error if neither `$ASTRID_HOME` nor `$HOME` is set.
    pub fn resolve() -> io::Result<Self> {
        let astrid_home = std::env::var("ASTRID_HOME").ok();
        if astrid_home.is_some() {
            return Self::resolve_with_env(astrid_home, None);
        }

        #[cfg(windows)]
        {
            Ok(Self {
                root: crate::platform_fs::default_astrid_home_root()?,
            })
        }

        #[cfg(not(windows))]
        {
            Self::resolve_with_env(None, std::env::var("HOME").ok())
        }
    }

    /// Internal resolver used to mock environment variables in tests securely.
    fn resolve_with_env(astrid_home: Option<String>, home: Option<String>) -> io::Result<Self> {
        let root = if let Some(custom) = astrid_home {
            let p = PathBuf::from(&custom);
            if !p.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ASTRID_HOME must be an absolute path",
                ));
            }
            reject_parent_traversal(&p, "ASTRID_HOME")?;
            p
        } else {
            let home = home.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "neither ASTRID_HOME nor HOME environment variable is set",
                )
            })?;
            let home_path = PathBuf::from(&home);
            if !home_path.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "HOME must be an absolute path",
                ));
            }
            reject_parent_traversal(&home_path, "HOME")?;
            home_path.join(".astrid")
        };

        Ok(Self { root })
    }

    /// Create from an explicit path (useful for testing).
    #[must_use]
    pub fn from_path(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Validate the durable root without creating a parallel state tree.
    ///
    /// Fresh initialization leaves only the private root for the storage layer
    /// to fill with `astrid.volume`. Released homes retain their historical
    /// directories and sentinel as one-time migration inputs until verified
    /// cutover. Running projections are created later from mounted volume
    /// state, never by this admission boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or permission setting fails.
    pub fn ensure(&self) -> io::Result<()> {
        self.validate_run_dir()?;
        let existing_layout = self.layout_version()?;
        if let Some(version) = existing_layout.as_deref()
            && version != LEGACY_LAYOUT_VERSION
            && version != LAYOUT_VERSION
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported Astrid home layout version {version:?}"),
            ));
        }
        if existing_layout.is_none() {
            match std::fs::symlink_metadata(self.root()) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Astrid home without a layout sentinel is redirected or not a directory: {}",
                            self.root().display()
                        ),
                    ));
                },
                Ok(_) => {},
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
        }
        let mut dirs = Vec::<PathBuf>::new();
        if existing_layout.as_deref() == Some(LEGACY_LAYOUT_VERSION) {
            dirs.extend([
                self.etc_dir(),
                self.hooks_dir(),
                self.var_dir(),
                self.run_dir(),
                self.log_dir(),
                self.keys_dir(),
                self.bin_dir(),
                self.wit_dir(),
                self.wit_store_dir(),
            ]);
        }
        crate::platform_fs::ensure_private_directory(self.root())?;
        for dir in &dirs {
            crate::platform_fs::ensure_private_directory(dir)?;
        }

        match existing_layout.as_deref() {
            None => self.validate_fresh_root_entries()?,
            Some(LEGACY_LAYOUT_VERSION) => {},
            Some(LAYOUT_VERSION) => {
                // Before the singleton-owned migration barrier, v2 boot only
                // validates legacy paths (redirects/special entries fail closed).
                // The barrier owns source admission/receipts; complete_layout_v2
                // is the only retirement entry point.
                self.validate_layout_v2_legacy_sources()?;
            },
            Some(_) => unreachable!("layout version was validated before directory creation"),
        }
        #[cfg(windows)]
        if self.layout_version_path().exists() {
            crate::platform_fs::restrict_private_file(&self.layout_version_path())?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(self.root(), perms.clone())?;
            for dir in &dirs {
                std::fs::set_permissions(dir, perms.clone())?;
            }
        }

        #[cfg(windows)]
        {
            for private_file in [self.runtime_key_path(), self.token_path()] {
                if private_file.exists() {
                    crate::platform_fs::validate_private_file(&private_file)?;
                }
            }
        }
        Ok(())
    }

    fn validate_fresh_root_entries(&self) -> io::Result<()> {
        let mut entries = self.root().read_dir()?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if entry.file_name() != std::ffi::OsStr::new("astrid.volume") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unadmitted entry in a fresh Astrid durable root: {}",
                        path.display()
                    ),
                ));
            }
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Astrid durable media is redirected or not a regular file: {}",
                        path.display()
                    ),
                ));
            }
            crate::platform_fs::validate_private_file(&path)?;
        }
        Ok(())
    }

    /// Root directory path (`~/.astrid/`).
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Configuration directory (`etc/`).
    #[must_use]
    pub fn etc_dir(&self) -> PathBuf {
        self.root.join("etc")
    }

    /// Path to the global runtime configuration file (`etc/config.toml`).
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.etc_dir().join("config.toml")
    }

    /// Path to the MCP servers configuration file (`etc/servers.toml`).
    #[must_use]
    pub fn servers_config_path(&self) -> PathBuf {
        self.etc_dir().join("servers.toml")
    }

    /// Path to the gateway daemon configuration file (`etc/gateway.toml`).
    #[must_use]
    pub fn gateway_config_path(&self) -> PathBuf {
        self.etc_dir().join("gateway.toml")
    }

    /// System hooks directory (`etc/hooks/`).
    #[must_use]
    pub fn hooks_dir(&self) -> PathBuf {
        self.etc_dir().join("hooks")
    }

    /// Per-principal profile directory (`etc/profiles/`).
    ///
    /// Per-principal `profile.toml` files live here, NOT inside the
    /// principal's own home directory. Profile contents (enabled,
    /// groups, grants, revokes, quotas, auth public keys, egress
    /// policy, process allowlist) are system-managed policy: a capsule
    /// running as a principal with `fs_read = ["home://"]` must not be
    /// able to read its own policy, and `fs_write` must not let it
    /// self-elevate. Keeping profiles under `etc/` puts them outside
    /// the `home://` VFS scheme entirely.
    #[must_use]
    pub fn profiles_dir(&self) -> PathBuf {
        self.etc_dir().join("profiles")
    }

    /// Per-principal profile path (`etc/profiles/{principal}.toml`).
    /// See [`Self::profiles_dir`] for why this lives outside the
    /// principal's home directory.
    #[must_use]
    pub fn profile_path(&self, id: &PrincipalId) -> PathBuf {
        self.profiles_dir().join(format!("{id}.toml"))
    }

    /// Persistent state directory (`var/`).
    #[must_use]
    pub fn var_dir(&self) -> PathBuf {
        self.root.join("var")
    }

    /// Path to the legacy system KV import source (`var/state.db/`).
    #[must_use]
    pub fn state_db_path(&self) -> PathBuf {
        self.var_dir().join("state.db")
    }

    /// Private native write-staging area for principal content (`var/content-staging/`).
    ///
    /// Filesystem providers acknowledge writes from this area before content
    /// ingestion publishes them into the authoritative principal store. It is
    /// engine-private state and must never be projected into a guest view.
    #[must_use]
    pub fn content_staging_path(&self) -> PathBuf {
        self.var_dir().join("content-staging")
    }

    /// Legacy path for the retired OS-level workspace copy-on-write tree.
    ///
    /// Layout v2 does not create this directory. During upgrade/re-entry, any
    /// existing tree is validated and retired before the home is served. The
    /// accessor remains temporarily for callers migrating away from the old
    /// workspace backend; it is not part of the canonical Astrid-home layout.
    #[must_use]
    pub fn cow_dir(&self) -> PathBuf {
        self.root.join("cow")
    }

    /// Ephemeral runtime directory (`run/`).
    #[must_use]
    pub fn run_dir(&self) -> PathBuf {
        run_dir::configured_path(self).unwrap_or_else(|_| self.root.join("run"))
    }

    /// Reject an `ASTRID_RUN_DIR` override that can overlap durable authority.
    ///
    /// Admission calls this before creating the durable root or any running
    /// projection. Path-only callers get a disposable fallback below the root
    /// rather than a sentinel file, but they must never drive lifecycle work
    /// without first passing [`Self::ensure`].
    ///
    /// # Errors
    ///
    /// Returns an error when the override is empty, relative, traverses a
    /// parent, is redirected, or is physically equal to, inside, or a parent
    /// of the durable root.
    pub fn validate_run_dir(&self) -> io::Result<()> {
        run_dir::validate(self)
    }

    /// Clear stale per-principal runtime scratch from a prior daemon process.
    ///
    /// Only the disposable `run/principals/` subtree is touched. The complete
    /// tree is validated without following redirects before anything is
    /// removed; symlinks, mount boundaries, and special entries fail closed.
    /// The subtree root is retained and private UID scratch directories are
    /// recreated on demand by the capsule runtime.
    ///
    /// # Errors
    ///
    /// Returns an error and leaves the subtree untouched when a redirect,
    /// mount boundary, or special entry is present.
    pub fn clear_runtime_principal_scratch(&self) -> io::Result<()> {
        crate::runtime_scratch::clear_principal_scratch(&self.run_dir().join("principals"))
    }

    /// Portable endpoint token for the kernel's host-local transport.
    ///
    /// Unix uses this as the domain-socket path (`run/system.sock`). Windows
    /// derives its named-pipe endpoint from the current process token SID and
    /// deliberately ignores the filesystem-shaped value.
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.run_dir().join("system.sock")
    }

    /// Path to the session authentication token (`run/system.token`).
    #[must_use]
    pub fn token_path(&self) -> PathBuf {
        self.run_dir().join("system.token")
    }

    /// Path to the daemon readiness sentinel (`run/system.ready`).
    ///
    /// Written by the daemon after all capsules are loaded and accepting
    /// connections. The CLI polls for this file instead of the socket file
    /// to avoid connecting before the daemon is fully initialized.
    #[must_use]
    pub fn ready_path(&self) -> PathBuf {
        self.run_dir().join("system.ready")
    }

    /// Path to the daemon PID file (`run/system.pid`).
    ///
    /// Written by the daemon at boot (after it has acquired the singleton
    /// lock) and best-effort-removed on graceful shutdown. The CLI reads it
    /// in `astrid stop`/`astrid restart` so that, when the socket is present
    /// but unreachable (a wedged half-dead daemon still holding the state-db
    /// lock), it can signal the orphaned process instead of merely deleting
    /// the socket and leaving the lock held — which would wedge the next
    /// `astrid start`.
    #[must_use]
    pub fn pid_path(&self) -> PathBuf {
        self.run_dir().join("system.pid")
    }

    /// Path to the deferred queue database (`run/deferred.db/`).
    #[must_use]
    pub fn deferred_db_path(&self) -> PathBuf {
        self.run_dir().join("deferred.db")
    }

    /// System log directory (`log/`).
    #[must_use]
    pub fn log_dir(&self) -> PathBuf {
        self.root.join("log")
    }

    /// Legacy file-secret directory (`secrets/`).
    ///
    /// This accessor exists only for explicit released-home migration and
    /// retirement. Runtime secret resolution uses the authoritative storage
    /// control namespace; fresh homes never create this directory.
    #[must_use]
    pub fn secrets_dir(&self) -> PathBuf {
        self.root.join("secrets")
    }

    /// Keys directory (`keys/`).
    #[must_use]
    pub fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }

    /// Path to the runtime signing key (`keys/runtime.key`).
    #[must_use]
    pub fn runtime_key_path(&self) -> PathBuf {
        self.keys_dir().join("runtime.key")
    }

    /// Content-addressed compiled WASM binaries (`bin/`).
    #[must_use]
    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// WIT interface directory (`wit/`).
    ///
    /// Holds the daemon's canonical named `.wit` copies (e.g.
    /// `wit/astrid-contracts.wit`, the shared data-shape contracts the
    /// runtime links capsules against). The content-addressed blob store
    /// lives one level down at [`Self::wit_store_dir`] so `wit gc` can
    /// sweep the store without touching these canonical named files.
    #[must_use]
    pub fn wit_dir(&self) -> PathBuf {
        self.root.join("wit")
    }

    /// Content-addressed WIT blob store (`wit/store/`).
    ///
    /// Stores BLAKE3-keyed `.wit` blobs (`wit/store/<hash>.wit`) retained
    /// at capsule install so a `wit_files` pin recorded in `meta.json` can
    /// always be dereferenced from local disk — the WIT analogue of the
    /// `bin/<hash>.wasm` binary store. Append-only from the installer's
    /// perspective; pruned only by the explicit admin `wit gc` sweep.
    #[must_use]
    pub fn wit_store_dir(&self) -> PathBuf {
        self.wit_dir().join("store")
    }

    /// Shared WASM component libraries (`lib/`).
    ///
    /// Reserved for future WIT interface components that capsules can import.
    /// Not created eagerly — will be populated when component linking lands.
    #[must_use]
    pub fn lib_dir(&self) -> PathBuf {
        self.root.join("lib")
    }

    /// Principal home directories root (`home/`).
    #[must_use]
    pub fn home_dir(&self) -> PathBuf {
        self.root.join("home")
    }

    /// Get the home directory for a specific principal.
    #[must_use]
    pub fn principal_home(&self, id: &PrincipalId) -> PrincipalHome {
        PrincipalHome {
            root: self.home_dir().join(id.as_str()),
        }
    }
}

// ── PrincipalHome (per-user) ─────────────────────────────────────────────

/// Legacy per-principal home source (`~/.astrid/home/{principal}/`).
///
/// This accessor exists for no-follow migration and explicit legacy fixtures.
/// Runtime capsule home access is the UID-bound `AstridFilesystem` `home/`
/// subtree, not this host path.
#[derive(Debug, Clone)]
pub struct PrincipalHome {
    root: PathBuf,
}

impl PrincipalHome {
    /// Create from an explicit path (useful for testing).
    #[must_use]
    pub fn from_path(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Ensure the legacy principal directory tree exists with secure permissions.
    ///
    /// Normal v2 boot must not call this method; it is retained for explicit
    /// legacy fixtures and dedicated native migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or permission setting fails.
    pub fn ensure(&self) -> io::Result<()> {
        let dirs = [
            self.capsules_dir(),
            self.kv_dir(),
            self.log_dir(),
            self.audit_dir(),
            self.tokens_dir(),
            self.tmp_dir(),
        ];

        #[cfg(windows)]
        {
            crate::platform_fs::ensure_private_directory(&self.root)?;
            crate::platform_fs::ensure_private_directory(&self.root.join(".local"))?;
            crate::platform_fs::ensure_private_directory(&self.root.join(".config"))?;
        }

        for dir in &dirs {
            #[cfg(windows)]
            crate::platform_fs::ensure_private_directory(dir)?;
            #[cfg(not(windows))]
            std::fs::create_dir_all(dir)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&self.root, perms.clone())?;
            // Secure the two top-level dot-dirs.
            std::fs::set_permissions(self.root.join(".local"), perms.clone())?;
            // `.config/` is retained only when a legacy migration left it in
            // place. Fresh homes do not create it merely for env storage.
            let config_dir = self.config_dir();
            match std::fs::symlink_metadata(&config_dir) {
                Ok(metadata) if metadata.is_dir() => {
                    std::fs::set_permissions(config_dir, perms)?;
                },
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "principal .config path is not a regular directory",
                    ));
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    // ── Path accessors ───────────────────────────────────────────────

    /// Principal home root (`home/{principal}/`).
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// User-installed capsules (`.local/capsules/`).
    #[must_use]
    pub fn capsules_dir(&self) -> PathBuf {
        self.root.join(".local").join("capsules")
    }

    /// Capsule KV data (`.local/kv/`).
    #[must_use]
    pub fn kv_dir(&self) -> PathBuf {
        self.root.join(".local").join("kv")
    }

    /// Capsule logs (`.local/log/`).
    #[must_use]
    pub fn log_dir(&self) -> PathBuf {
        self.root.join(".local").join("log")
    }

    /// Audit chain (`.local/audit/`).
    #[must_use]
    pub fn audit_dir(&self) -> PathBuf {
        self.root.join(".local").join("audit")
    }

    /// Capability tokens (`.local/tokens/`).
    #[must_use]
    pub fn tokens_dir(&self) -> PathBuf {
        self.root.join(".local").join("tokens")
    }

    /// Legacy temporary source path (`.local/tmp/`). Runtime `/tmp` uses the
    /// disposable UID-scoped `run/principals/<uid>/tmp` tree instead.
    #[must_use]
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join(".local").join("tmp")
    }

    /// Configuration directory (`.config/`).
    #[must_use]
    pub fn config_dir(&self) -> PathBuf {
        self.root.join(".config")
    }

    /// Legacy capsule environment path (`.config/env/`), used only by an
    /// explicit layout migration. Principal creation never creates it.
    #[must_use]
    pub fn env_dir(&self) -> PathBuf {
        self.root.join(".config").join("env")
    }
}

#[cfg(test)]
#[path = "dirs_tests.rs"]
mod tests;
