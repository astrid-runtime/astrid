//! Directory scaffolding for Astrid home and workspace directories.
//!
//! Two key directory structures:
//!
//! - [`AstridHome`]: Global state at `~/.astrid/` (or `$ASTRID_HOME`).
//!   Linux FHS-aligned layout with `etc/`, `var/`, `run/`, `log/`, `keys/`,
//!   `bin/`, `lib/`, and `home/` for multi-principal isolation.
//!
//! - [`WorkspaceDir`]: Per-project directory at `<project>/.astrid/`.
//!   Holds only committable project-level config (like `.astrid/ASTRID.md`).
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
//! <project>/.astrid/                   (WorkspaceDir)
//! ├── workspace-id                       UUID linking project to global state
//! └── ASTRID.md                        project-level instructions
//! ```

use std::io;
use std::path::{Component, Path, PathBuf};

use uuid::Uuid;

use crate::principal::PrincipalId;

/// Current layout version. Written to `etc/layout-version` on first boot.
pub const LAYOUT_VERSION: &str = "1";

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
    /// Creates `etc/`, `var/`, `run/`, `log/`, `keys/`, `lib/`, and `home/`.
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

/// Per-project workspace directory (`<project>/.astrid/`).
///
/// Contains only committable project-level config. A `workspace-id` UUID
/// links the project to its global state in `~/.astrid/`.
#[derive(Debug, Clone)]
pub struct WorkspaceDir {
    /// The project root (parent of `.astrid/`).
    project_root: PathBuf,
}

impl WorkspaceDir {
    /// Detect the workspace directory by walking up from `start_dir`.
    ///
    /// Detection order:
    /// 1. Directory containing `.astrid/`
    /// 2. Directory containing `.git`
    /// 3. Directory containing `ASTRID.md`
    /// 4. Fallback to `start_dir` itself
    #[must_use]
    pub fn detect(start_dir: &Path) -> Self {
        let start = if start_dir.is_absolute() {
            start_dir.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(start_dir)
        };

        let mut current = start.as_path();

        loop {
            if current.join(".astrid").is_dir() {
                return Self {
                    project_root: current.to_path_buf(),
                };
            }
            if current.join(".git").exists() {
                return Self {
                    project_root: current.to_path_buf(),
                };
            }
            if current.join("ASTRID.md").exists() {
                return Self {
                    project_root: current.to_path_buf(),
                };
            }
            match current.parent() {
                Some(parent) if parent != current => current = parent,
                _ => break,
            }
        }

        Self {
            project_root: start,
        }
    }

    /// Create from an explicit project root (useful for testing).
    #[must_use]
    pub fn from_path(project_root: impl Into<PathBuf>) -> Self {
        Self {
            project_root: project_root.into(),
        }
    }

    /// Ensure the `.astrid/` directory exists and generate a workspace ID
    /// if one does not already exist.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or workspace ID generation fails.
    pub fn ensure(&self) -> io::Result<()> {
        std::fs::create_dir_all(self.dot_astrid())?;
        let _ = self.workspace_id()?;
        Ok(())
    }

    /// Project root directory (parent of `.astrid/`).
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.project_root
    }

    /// The `.astrid/` directory itself.
    #[must_use]
    pub fn dot_astrid(&self) -> PathBuf {
        self.project_root.join(".astrid")
    }

    /// Workspace capsules directory (`.astrid/capsules/`).
    #[must_use]
    pub fn capsules_dir(&self) -> PathBuf {
        self.dot_astrid().join("capsules")
    }

    /// Path to the workspace-id file (`.astrid/workspace-id`).
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
        let path = self.workspace_id_path();
        if let Ok(content) = std::fs::read_to_string(&path) {
            let trimmed = content.trim();
            if let Ok(id) = Uuid::parse_str(trimmed) {
                return Ok(id);
            }
        }
        std::fs::create_dir_all(self.dot_astrid())?;
        let id = Uuid::new_v4();
        std::fs::write(&path, id.to_string())?;
        Ok(id)
    }

    /// Path to the project-level instructions file (`.astrid/ASTRID.md`).
    #[must_use]
    pub fn instructions_path(&self) -> PathBuf {
        self.dot_astrid().join("ASTRID.md")
    }
}

/// Directories skipped while scanning a workspace's immediate children for a
/// nested repository. These are obviously-huge or noise trees (build output,
/// dependency caches) and the repo's own `.git`; descending them would make
/// the shallow scan expensive without changing the outcome.
const GIT_SCAN_SKIP_DIRS: &[&str] = &["target", "node_modules", "dist", ".git"];

/// Returns `true` when `workspace_root` is under, or itself contains, git
/// version control.
///
/// A git-managed workspace must NOT use the in-process copy-on-write overlay:
/// its writes have to land on the real workspace so spawned processes (e.g.
/// `cargo`) and the user see them, with git providing the rollback. A
/// workspace counts as git-managed when ANY of:
///
/// 1. **Inside a work tree:** `workspace_root` or any ancestor (walking up to
///    the filesystem root) contains a `.git` entry. A submodule or linked
///    worktree records `.git` as a *file*, so both files and directories
///    count — [`Path::exists`] matches either.
/// 2. **Contains a repo:** `workspace_root` itself (depth 1, covered by the
///    first ancestor-walk iteration), or any of its immediate child
///    directories (shallow, depth <= 2), contains a `.git` entry. Obviously
///    huge / noise directories are skipped while scanning (see
///    [`GIT_SCAN_SKIP_DIRS`]).
///
/// The check is bounded and cheap — an ancestor walk plus a single shallow
/// read of the immediate children, no recursive tree walk — so it is safe to
/// run on every capsule load. Reuses the walk-up idiom of
/// [`WorkspaceDir::detect`].
#[must_use]
pub fn workspace_is_git_managed(workspace_root: &Path) -> bool {
    // Case 1: `workspace_root` or any ancestor is a git work tree. The first
    // iteration also covers "the workspace root itself is a repo" (depth 1).
    let mut current = workspace_root;
    loop {
        if current.join(".git").exists() {
            return true;
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent,
            _ => break,
        }
    }

    // Case 2: an immediate child directory of `workspace_root` is a repo
    // (depth <= 2). Shallow, single-level scan — no recursion.
    if let Ok(entries) = std::fs::read_dir(workspace_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && GIT_SCAN_SKIP_DIRS.contains(&name)
            {
                continue;
            }
            if path.is_dir() && path.join(".git").exists() {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
#[path = "dirs_tests.rs"]
mod tests;
