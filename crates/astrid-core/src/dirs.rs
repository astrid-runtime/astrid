//! Directory scaffolding for Astrid home and workspace directories.
//!
//! Two key directory structures:
//!
//! - [`AstridHome`]: Global state at `~/.astrid/` (or `$ASTRID_HOME`).
//!   Linux FHS-aligned layout with `etc/`, `var/`, `run/`, `log/`, `keys/`,
//!   `bin/`, `lib/`, and `home/` for multi-principal isolation.
//!
//! - [`WorkspaceDir`]: Selected per-project state directory.
//!   Holds project configuration, capsules, hooks, and instructions.
//!   Contains a `workspace-id` UUID that links the project to its global state.
//!
//! - [`PrincipalHome`]: Per-principal home directory under `~/.astrid/home/{id}/`.
//!   Each principal gets isolated capsules, KV data, audit chain, tokens, and
//!   config — portable across deployments.
//!
//! # Layout
//!
//! ```text
//! ~/.astrid/                           (AstridHome)
//! ├── etc/
//! │   ├── config.toml                    deployment config
//! │   ├── servers.toml                   MCP server config
//! │   ├── gateway.toml                   daemon config
//! │   ├── hooks/                         system hooks
//! │   └── layout-version                 layout version sentinel
//! ├── var/
//! │   └── state.db/                      system KV (SurrealKV, persistent)
//! ├── run/                               ephemeral runtime state
//! │   ├── system.sock
//! │   ├── system.token
//! │   ├── system.ready
//! │   └── deferred.db/                   deferred queue (ephemeral)
//! ├── log/                               system logs
//! ├── keys/                              runtime signing key
//! ├── bin/                               content-addressed compiled WASM binaries
//! ├── lib/                               shared WASM component libraries (WIT, future)
//! └── home/
//!     └── {principal}/                   per-principal home
//!         ├── .local/
//!         │   ├── capsules/              user-installed capsules
//!         │   ├── kv/                    capsule KV data
//!         │   ├── log/                   capsule logs
//!         │   ├── audit/                 user's audit chain
//!         │   ├── tokens/                capability tokens
//!         │   └── tmp/                   VFS mounts as /tmp
//!         └── .config/
//!             └── env/                   capsule config overrides
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

use blake3::Hasher;
use uuid::Uuid;

use crate::principal::PrincipalId;

/// Current layout version. Written to `etc/layout-version` on first boot.
pub const LAYOUT_VERSION: &str = "1";

/// Default per-project runtime state directory.
pub const DEFAULT_WORKSPACE_STATE_DIR: &str = ".astrid";

/// Validated per-project runtime layout.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceLayout {
    state_dir_name: String,
}

/// A checked project workspace selection.
///
/// The project root is canonical and the selected state directory is either
/// absent or a real directory directly beneath that root. Symlinks, junctions,
/// and other redirects are rejected by requiring an existing directory to
/// canonicalize to the exact direct-child path selected here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSelection {
    project_root: PathBuf,
    state_dir: PathBuf,
    layout: WorkspaceLayout,
}

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

impl WorkspaceSelection {
    fn resolve(project_root: &Path, layout: WorkspaceLayout) -> io::Result<Self> {
        let project_root = std::fs::canonicalize(project_root).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to resolve workspace root {}: {error}",
                    project_root.display()
                ),
            )
        })?;
        if !std::fs::metadata(&project_root)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "workspace root is not a directory: {}",
                    project_root.display()
                ),
            ));
        }

        let state_dir = project_root.join(layout.state_dir_name());
        verify_state_dir_path(&project_root, &state_dir)?;
        Ok(Self {
            project_root,
            state_dir,
            layout,
        })
    }

    /// Canonical project root used by every workspace filesystem consumer.
    #[must_use]
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    /// Checked selected state directory.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Selected workspace layout.
    #[must_use]
    pub fn layout(&self) -> &WorkspaceLayout {
        &self.layout
    }

    /// Checked capsule directory under selected project state.
    ///
    /// # Errors
    ///
    /// Returns an error if an existing path component is redirected or is not
    /// a directory.
    pub fn capsules_dir(&self) -> io::Result<PathBuf> {
        self.resolve_directory("capsules")
    }

    /// Checked configuration path under selected project state.
    ///
    /// # Errors
    ///
    /// Returns an error if the existing file or one of its parents is
    /// redirected or has the wrong type.
    pub fn config_path(&self) -> io::Result<PathBuf> {
        self.resolve_file("config.toml")
    }

    /// Checked hooks directory under selected project state.
    ///
    /// # Errors
    ///
    /// Returns an error if an existing path component is redirected or is not
    /// a directory.
    pub fn hooks_dir(&self) -> io::Result<PathBuf> {
        self.resolve_directory("hooks")
    }

    /// Resolve a relative directory beneath selected project state without
    /// following an existing redirect.
    ///
    /// Missing components are allowed so callers can validate before creation.
    ///
    /// # Errors
    ///
    /// Returns an error for non-normal relative components, redirects, or an
    /// existing non-directory component.
    pub fn resolve_directory(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        self.resolve_descendant(relative.as_ref(), DescendantKind::Directory)
    }

    /// Resolve a relative file beneath selected project state without following
    /// an existing redirect.
    ///
    /// Missing components are allowed so callers can validate before creation.
    ///
    /// # Errors
    ///
    /// Returns an error for non-normal relative components, redirects, a
    /// non-directory parent, or an existing non-file target.
    pub fn resolve_file(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        self.resolve_descendant(relative.as_ref(), DescendantKind::File)
    }

    /// Verify every existing entry in a workspace-relative tree without
    /// following redirects.
    ///
    /// # Errors
    ///
    /// Returns an error if the root is unsafe, any descendant is a symlink,
    /// reparse redirect, or special file, or the tree changes while walking.
    pub fn verify_tree(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        let relative = relative.as_ref();
        let root = self.resolve_directory(relative)?;
        if !root.exists() {
            return Ok(root);
        }
        let mut pending = vec![root.clone()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink()
                    || (!metadata.is_dir() && !metadata.is_file())
                    || std::fs::canonicalize(&path)? != path
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "workspace tree contains a redirected or special entry: {}",
                            path.display()
                        ),
                    ));
                }
                if metadata.is_dir() {
                    pending.push(path);
                }
            }
        }
        self.resolve_directory(relative)?;
        Ok(root)
    }

    fn resolve_descendant(&self, relative: &Path, kind: DescendantKind) -> io::Result<PathBuf> {
        self.verify()?;
        let components = relative.components().collect::<Vec<_>>();
        if components.is_empty()
            || components
                .iter()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "workspace descendant must be a non-empty relative path without traversal",
            ));
        }

        let mut current = self.state_dir.clone();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(component) = component else {
                unreachable!("components validated above")
            };
            current.push(component);
            let metadata = match std::fs::symlink_metadata(&current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let final_component = index == components.len().saturating_sub(1);
            let expected_file = final_component && kind == DescendantKind::File;
            if metadata.file_type().is_symlink()
                || (expected_file && !metadata.is_file())
                || (!expected_file && !metadata.is_dir())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "workspace path must not contain redirects or unexpected file types: {}",
                        current.display()
                    ),
                ));
            }
            if std::fs::canonicalize(&current)? != current {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "workspace path redirects from its selected target: {}",
                        current.display()
                    ),
                ));
            }
        }
        Ok(self.state_dir.join(relative))
    }

    /// Re-check that the selected state path has not been redirected.
    ///
    /// A missing state directory remains valid. This permits a checked
    /// selection to be created before initialization while still rejecting a
    /// later symlink or non-directory replacement.
    ///
    /// # Errors
    ///
    /// Returns an error if the project root or state path no longer satisfies
    /// the original selection.
    pub fn verify(&self) -> io::Result<()> {
        let current = Self::resolve(&self.project_root, self.layout.clone())?;
        if current.project_root != self.project_root || current.state_dir != self.state_dir {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "workspace selection changed after validation",
            ));
        }
        Ok(())
    }

    /// Create the selected state directory and verify it again afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if creation fails or the path is redirected before or
    /// after creation.
    pub fn ensure_state_dir(&self) -> io::Result<()> {
        self.verify()?;
        match std::fs::create_dir(&self.state_dir) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => return Err(error),
        }
        self.verify()
    }

    /// Create a checked relative directory and verify the full path afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if a component is unsafe, creation fails, or a redirect
    /// appears during creation.
    pub fn ensure_directory(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        let relative = relative.as_ref();
        let path = self.resolve_directory(relative)?;
        self.ensure_state_dir()?;
        std::fs::create_dir_all(&path)?;
        let checked = self.resolve_directory(relative)?;
        self.verify()?;
        Ok(checked)
    }

    /// Stable opaque identity for the checked root and state-directory target.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(b"astrid-workspace-selection-v2\0");
        hash_path(&mut hasher, &self.project_root);
        hasher.update(b"\0");
        hash_path(&mut hasher, &self.state_dir);
        hasher.update(b"\0");
        hasher.update(self.layout.state_dir_name().as_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DescendantKind {
    Directory,
    File,
}

fn verify_state_dir_path(project_root: &Path, state_dir: &Path) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(state_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "workspace state path must be a real directory, not a redirect or file: {}",
                state_dir.display()
            ),
        ));
    }

    let canonical = std::fs::canonicalize(state_dir)?;
    if canonical != state_dir || canonical.parent() != Some(project_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "workspace state directory escapes or redirects outside its selected path: {}",
                state_dir.display()
            ),
        ));
    }
    Ok(())
}

/// Stable identity for one project root and workspace layout selection.
///
/// The identity is suitable for detecting whether a CLI and an already-running
/// daemon selected the same project. It does not expose the project path.
#[must_use]
pub fn workspace_selection_fingerprint(
    project_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> String {
    if let Ok(selection) = workspace_layout.resolve(project_root) {
        return selection.fingerprint();
    }
    let root = std::fs::canonicalize(project_root).unwrap_or_else(|_| {
        if project_root.is_absolute() {
            project_root.to_path_buf()
        } else {
            std::env::current_dir()
                .map_or_else(|_| project_root.to_path_buf(), |cwd| cwd.join(project_root))
        }
    });
    let mut hasher = Hasher::new();
    hasher.update(b"astrid-workspace-selection-v1\0");
    hash_path(&mut hasher, &root);
    hasher.update(b"\0");
    hasher.update(workspace_layout.state_dir_name().as_bytes());
    hex::encode(hasher.finalize().as_bytes())
}

/// Resolve a workspace safely and derive its opaque selection identity.
///
/// Security-sensitive callers must use this fallible form rather than relying
/// on a lexical path fingerprint.
///
/// # Errors
///
/// Returns an error if the workspace root or selected state path is unsafe.
pub fn checked_workspace_selection_fingerprint(
    project_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> io::Result<String> {
    Ok(workspace_layout.resolve(project_root)?.fingerprint())
}

fn hash_path(hasher: &mut Hasher, path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        hasher.update(path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        for unit in path.as_os_str().encode_wide() {
            hasher.update(&unit.to_le_bytes());
        }
    }
    #[cfg(not(any(unix, windows)))]
    hasher.update(path.as_os_str().to_string_lossy().as_bytes());
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

/// Global Astrid home directory (`~/.astrid/` or `$ASTRID_HOME`).
///
/// FHS-aligned system layout. Contains config (`etc/`), persistent state
/// (`var/`), ephemeral runtime (`run/`), logs (`log/`), keys (`keys/`),
/// shared WASM modules (`lib/`), system capsules (`capsules/`), and
/// per-principal home directories (`home/`).
#[derive(Debug, Clone)]
pub struct AstridHome {
    root: PathBuf,
}

impl AstridHome {
    /// Resolve the home directory.
    ///
    /// Checks `$ASTRID_HOME` first, then falls back to `$HOME/.astrid/`.
    ///
    /// # Errors
    ///
    /// Returns an error if neither `$ASTRID_HOME` nor `$HOME` is set.
    pub fn resolve() -> io::Result<Self> {
        let astrid_home = std::env::var("ASTRID_HOME").ok();
        let home = if astrid_home.is_none() {
            std::env::var("HOME").ok()
        } else {
            None
        };
        Self::resolve_with_env(astrid_home, home)
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

    /// Ensure the system directory structure exists with secure permissions.
    ///
    /// Creates `etc/`, `var/`, `run/`, `log/`, `keys/`, `secrets/`, `lib/`, and `home/`.
    /// Writes `etc/layout-version` with the current version.
    /// Sets all directories to `0o700` on Unix.
    ///
    /// Note: `capsules/` (system/distro capsules) is NOT created eagerly.
    /// Nothing writes there yet — user installs go to principal home.
    /// It will be created when an operator install mechanism lands.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or permission setting fails.
    pub fn ensure(&self) -> io::Result<()> {
        let dirs = [
            self.etc_dir(),
            self.hooks_dir(),
            self.var_dir(),
            self.run_dir(),
            self.log_dir(),
            self.keys_dir(),
            self.secrets_dir(),
            self.bin_dir(),
            self.wit_dir(),
            self.wit_store_dir(),
            self.home_dir(),
        ];
        for dir in &dirs {
            std::fs::create_dir_all(dir)?;
        }

        // Write layout version sentinel (idempotent).
        let version_path = self.etc_dir().join("layout-version");
        if !version_path.exists() {
            std::fs::write(&version_path, LAYOUT_VERSION)?;
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
        Ok(())
    }

    // ── Path accessors ───────────────────────────────────────────────

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

    /// Path to the system KV database (`var/state.db/`).
    #[must_use]
    pub fn state_db_path(&self) -> PathBuf {
        self.var_dir().join("state.db")
    }

    /// Root directory for OS-level copy-on-write workspace clones (`cow/`).
    ///
    /// Each non-git capsule workspace gets a per-workspace subdirectory here
    /// holding the copy-on-write working tree (an APFS `clonefile` clone on
    /// macOS, an `overlayfs` upper/work/merged triple on Linux). This tree is
    /// the directory a spawned process and the fs host both write to; the
    /// pristine workspace is only touched by an explicit promote.
    ///
    /// One workspace's clone is kept from reaching another's by the OS
    /// sandbox's default-deny-write: only a child's own `merged` tree is a
    /// writable root, so sibling clones under this `cow/` root are unwritable.
    /// This depends on `cow/` living under `~/.astrid` (not a world-writable
    /// location) — which is why the capsule loader fails closed to No-CoW
    /// rather than clone into a temp dir when the home is unresolvable. (The
    /// `cow/` root itself is NOT added to the sandbox mask: on macOS Seatbelt a
    /// mask that is an ancestor of the writable `merged` root is dropped; the
    /// mask instead covers the pristine workspace / overlay upper dirs.) See
    /// `astrid_vfs::workspace_cow`.
    #[must_use]
    pub fn cow_dir(&self) -> PathBuf {
        self.root.join("cow")
    }

    /// Ephemeral runtime directory (`run/`).
    #[must_use]
    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    /// Path to the kernel's Unix domain socket (`run/system.sock`).
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

    /// Secrets directory (`secrets/`).
    ///
    /// File-per-secret store keyed by
    /// `secrets/<scope>/<capsule>/<key>`. `<scope>` is either an
    /// agent principal name (per-agent override) or `__host__` (the
    /// shared / operator-wide value the kernel's secret-resolve path
    /// falls back to). Files are written `0600`, parent dirs `0700`.
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

/// Per-principal home directory (`~/.astrid/home/{principal}/`).
///
/// Each principal gets isolated storage following the XDG-like convention:
/// `.local/` for data and `.config/` for configuration.
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

    /// Ensure the full principal directory tree exists with secure permissions.
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
            self.env_dir(),
        ];
        for dir in &dirs {
            std::fs::create_dir_all(dir)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&self.root, perms.clone())?;
            // Secure the two top-level dot-dirs.
            std::fs::set_permissions(self.root.join(".local"), perms.clone())?;
            std::fs::set_permissions(self.root.join(".config"), perms)?;
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

    /// Temporary files, VFS-mounted as `/tmp` (`.local/tmp/`).
    #[must_use]
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join(".local").join("tmp")
    }

    /// Configuration directory (`.config/`).
    #[must_use]
    pub fn config_dir(&self) -> PathBuf {
        self.root.join(".config")
    }

    /// Capsule environment config overrides (`.config/env/`).
    #[must_use]
    pub fn env_dir(&self) -> PathBuf {
        self.root.join(".config").join("env")
    }
}

// ── WorkspaceDir (per-project) ───────────────────────────────────────────

/// Selected per-project workspace state directory.
///
/// Contains project-local runtime state. A `workspace-id` UUID links the
/// project to its global state in `~/.astrid/`.
#[derive(Debug, Clone)]
pub struct WorkspaceDir {
    /// The project root containing the selected state directory.
    project_root: PathBuf,
    layout: WorkspaceLayout,
}

impl WorkspaceDir {
    /// Detect the workspace directory by walking up from `start_dir`.
    ///
    /// Detection order:
    /// 1. Directory containing the selected state directory
    /// 2. Directory containing `.git`
    /// 3. Directory containing `ASTRID.md`
    /// 4. Fallback to `start_dir` itself
    #[must_use]
    pub fn detect(start_dir: &Path) -> Self {
        Self::detect_with_layout(start_dir, WorkspaceLayout::default())
    }

    /// Detect the workspace directory using `layout`.
    #[must_use]
    pub fn detect_with_layout(start_dir: &Path, layout: WorkspaceLayout) -> Self {
        let start = if start_dir.is_absolute() {
            start_dir.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(start_dir)
        };

        let mut current = start.as_path();

        loop {
            if layout.state_dir(current).is_dir() {
                return Self {
                    project_root: current.to_path_buf(),
                    layout,
                };
            }
            if current.join(".git").exists() {
                return Self {
                    project_root: current.to_path_buf(),
                    layout,
                };
            }
            if current.join("ASTRID.md").exists() {
                return Self {
                    project_root: current.to_path_buf(),
                    layout,
                };
            }
            match current.parent() {
                Some(parent) if parent != current => current = parent,
                _ => break,
            }
        }

        Self {
            project_root: start,
            layout,
        }
    }

    /// Create from an explicit project root (useful for testing).
    #[must_use]
    pub fn from_path(project_root: impl Into<PathBuf>) -> Self {
        Self::from_path_with_layout(project_root, WorkspaceLayout::default())
    }

    /// Create from an explicit project root and layout.
    #[must_use]
    pub fn from_path_with_layout(
        project_root: impl Into<PathBuf>,
        layout: WorkspaceLayout,
    ) -> Self {
        Self {
            project_root: project_root.into(),
            layout,
        }
    }

    /// Ensure the selected state directory exists and generate a workspace ID
    /// if one does not already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or workspace ID generation fails.
    pub fn ensure(&self) -> io::Result<()> {
        let selection = self.layout.resolve(&self.project_root)?;
        selection.ensure_state_dir()?;
        let _ = self.workspace_id()?;
        selection.verify()?;
        Ok(())
    }

    /// Resolve this workspace through the checked filesystem boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if the project root or selected state path is unsafe.
    pub fn selection(&self) -> io::Result<WorkspaceSelection> {
        self.layout.resolve(&self.project_root)
    }

    /// Project root directory containing the selected state directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.project_root
    }

    /// The selected project state directory.
    #[must_use]
    pub fn dot_astrid(&self) -> PathBuf {
        self.layout.state_dir(&self.project_root)
    }

    /// The active per-project runtime state directory.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.layout.state_dir(&self.project_root)
    }

    /// The active workspace layout.
    #[must_use]
    pub fn layout(&self) -> &WorkspaceLayout {
        &self.layout
    }

    /// Capsules under the selected project state directory.
    #[must_use]
    pub fn capsules_dir(&self) -> PathBuf {
        self.dot_astrid().join("capsules")
    }

    /// Path to the workspace-id file under selected project state.
    #[must_use]
    pub fn workspace_id_path(&self) -> PathBuf {
        self.dot_astrid().join("workspace-id")
    }

    /// Read or generate the workspace ID.
    ///
    /// If the file exists (e.g. cloned from a repo), its UUID is adopted.
    /// Otherwise a new UUID is generated and written.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or written.
    pub fn workspace_id(&self) -> io::Result<Uuid> {
        let selection = self.selection()?;
        selection.ensure_state_dir()?;
        let path = selection.resolve_file("workspace-id")?;
        if let Ok(content) = std::fs::read_to_string(&path) {
            let trimmed = content.trim();
            if let Ok(id) = Uuid::parse_str(trimmed) {
                selection.verify()?;
                return Ok(id);
            }
        }
        let id = Uuid::new_v4();
        selection.verify()?;
        std::fs::write(&path, id.to_string())?;
        selection.resolve_file("workspace-id")?;
        selection.verify()?;
        Ok(id)
    }

    /// Path to project instructions under selected project state.
    #[must_use]
    pub fn instructions_path(&self) -> PathBuf {
        self.dot_astrid().join("ASTRID.md")
    }
}

#[cfg(test)]
#[path = "dirs_tests.rs"]
mod tests;
