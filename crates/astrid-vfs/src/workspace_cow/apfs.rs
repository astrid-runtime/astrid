//! macOS APFS copy-on-write backend using the `clonefile(2)` syscall.
//!
//! [`prepare`](ApfsCow::prepare) clones the pristine workspace into a
//! per-workspace working directory under the copy-on-write root
//! (`~/.astrid/cow/<id>/merged`) with a single `clonefile(2)` syscall — an
//! O(1), copy-on-write clone that shares storage until a block is written. The
//! agent and any spawned process write to that clone;
//! [`promote`](ApfsCow::promote) atomically swaps the clone back over the
//! pristine workspace (`renamex_np` with `RENAME_SWAP`);
//! [`rollback`](ApfsCow::rollback) discards the clone and re-clones from
//! pristine.

#![allow(unsafe_code)] // Isolated FFI to clonefile(2) / renamex_np(2); every call is documented + argument-checked.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{CowCapability, PreparedWorkspace, WorkspaceCow};

/// Process-unique counter so two concurrent loads of the same workspace path
/// get distinct working directories (a `clonefile` destination must not exist).
static WORKSPACE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Paths fixed at [`ApfsCow::prepare`] time.
#[derive(Debug, Clone)]
struct ApfsPaths {
    /// The real workspace — only ever mutated by [`ApfsCow::promote`].
    pristine: PathBuf,
    /// The `clonefile` clone: the merged working tree the agent + spawns write.
    merged: PathBuf,
    /// The per-workspace directory (`<cow_root>/<id>`) removed at teardown.
    workspace_dir: PathBuf,
}

/// APFS `clonefile(2)` copy-on-write backend (macOS).
#[derive(Debug)]
pub struct ApfsCow {
    /// Root under which per-workspace clones live (`~/.astrid/cow`).
    cow_root: PathBuf,
    /// Set once by [`prepare`](Self::prepare); read by promote/rollback/teardown.
    paths: OnceLock<ApfsPaths>,
}

impl ApfsCow {
    /// Construct an APFS backend that stores its clones under `cow_root`.
    #[must_use]
    pub fn new(cow_root: PathBuf) -> Self {
        Self {
            cow_root,
            paths: OnceLock::new(),
        }
    }

    /// The paths fixed at prepare time, or an error if prepare has not run
    /// (or failed).
    fn paths(&self) -> io::Result<&ApfsPaths> {
        self.paths
            .get()
            .ok_or_else(|| io::Error::other("APFS workspace CoW: prepare() has not run"))
    }
}

impl WorkspaceCow for ApfsCow {
    fn capability(&self) -> CowCapability {
        CowCapability::Apfs
    }

    fn prepare(&self, pristine: &Path) -> io::Result<PreparedWorkspace> {
        // Derive a stable-ish, collision-free per-workspace directory name.
        let seq = WORKSPACE_SEQ.fetch_add(1, Ordering::Relaxed);
        let id = format!("{}-{seq}", path_hash(pristine));
        let workspace_dir = self.cow_root.join(&id);
        let merged = workspace_dir.join("merged");

        // The clonefile destination's PARENT must exist and the destination
        // itself must NOT (clonefile fails EEXIST otherwise). A fresh `<id>`
        // directory guarantees a clean `merged` slot.
        std::fs::create_dir_all(&workspace_dir)?;
        if merged.exists() {
            std::fs::remove_dir_all(&merged)?;
        }

        // The clone: O(1) copy-on-write. Fails (and we fall back to No-CoW)
        // if `pristine` is missing or lives on a different volume than the
        // Astrid home (clonefile requires one APFS volume).
        clonefile(pristine, &merged)?;

        let paths = ApfsPaths {
            pristine: pristine.to_path_buf(),
            merged: merged.clone(),
            workspace_dir,
        };
        // prepare() runs exactly once; if a second call races, keep the first.
        let _ = self.paths.set(paths);

        Ok(PreparedWorkspace {
            merged_path: merged,
            // Mask the PRISTINE workspace from spawned children. It is the
            // target of `promote`; a child that wrote it directly would smuggle
            // changes past the gate. On macOS Seatbelt this last-match deny bites
            // even where the clone lives under a broadly-writable location
            // (`/var/folders`, `/private/tmp`). We deliberately do NOT mask the
            // `cow/` root: it is an ANCESTOR of the writable `merged` clone, and
            // Seatbelt drops ancestor masks (they would deny lstat on the
            // writable root's own parents). Sibling clones are instead protected
            // by Seatbelt's default-deny-write — only `merged` is a writable
            // root — so a child cannot write another workspace's clone.
            mask_from_children: vec![pristine.to_path_buf()],
        })
    }

    fn promote(&self) -> io::Result<()> {
        let paths = self.paths()?;
        // The swap IS the commit point: atomically exchange the clone and the
        // pristine workspace (single volume, so atomic). After it, `pristine`
        // holds the working changes and the old `merged` path holds the old
        // pristine contents. A failure HERE means nothing committed.
        renamex_swap(&paths.merged, &paths.pristine)?;

        // Past the swap the commit has ALREADY landed. Re-establishing the
        // working clone (discard the old contents now at `merged`, re-clone from
        // the promoted pristine) is best-effort: if it fails, the merged tree is
        // left needing a re-prepare, but we must NOT report the promote as
        // failed — the changes are in the pristine workspace.
        if let Err(e) = std::fs::remove_dir_all(&paths.merged)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(
                merged = %paths.merged.display(),
                error = %e,
                "workspace CoW: promote committed, but clearing the stale merged \
                 tree failed; the merged tree needs a re-prepare"
            );
            return Ok(());
        }
        if let Err(e) = clonefile(&paths.pristine, &paths.merged) {
            tracing::warn!(
                merged = %paths.merged.display(),
                error = %e,
                "workspace CoW: promote committed, but re-establishing the merged \
                 clone failed; the merged tree needs a re-prepare"
            );
            return Ok(());
        }
        tracing::info!(
            pristine = %paths.pristine.display(),
            "workspace CoW: promoted APFS clone into the pristine workspace"
        );
        Ok(())
    }

    fn rollback(&self) -> io::Result<()> {
        let paths = self.paths()?;
        if paths.merged.exists() {
            std::fs::remove_dir_all(&paths.merged)?;
        }
        clonefile(&paths.pristine, &paths.merged)?;
        tracing::info!(
            pristine = %paths.pristine.display(),
            "workspace CoW: rolled back APFS clone to the pristine workspace"
        );
        Ok(())
    }

    fn teardown(&self) {
        if let Some(paths) = self.paths.get()
            && let Err(e) = std::fs::remove_dir_all(&paths.workspace_dir)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(
                dir = %paths.workspace_dir.display(),
                error = %e,
                "workspace CoW: APFS teardown could not remove clone directory"
            );
        }
    }
}

impl Drop for ApfsCow {
    fn drop(&mut self) {
        // RAII backstop: if the explicit `teardown()` on capsule unload was
        // missed, still remove the clone when the last handle drops.
        self.teardown();
    }
}

/// A short, deterministic hex digest of a path, used only as a directory name.
fn path_hash(path: &Path) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Canonicalize when possible so the same workspace maps to the same digest
    // regardless of how it was addressed; fall back to the raw path otherwise.
    let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// `clonefile(src, dst, 0)` — copy-on-write clone of a whole directory tree.
/// `dst` must not already exist.
fn clonefile(src: &Path, dst: &Path) -> io::Result<()> {
    let src_c = CString::new(src.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "clone source path has NUL"))?;
    let dst_c = CString::new(dst.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "clone dest path has NUL"))?;
    // SAFETY: `src_c`/`dst_c` are valid, NUL-terminated C strings that outlive
    // the call; `clonefile` reads them and returns a status code, retaining no
    // pointers. Flag `0` = default (clone contents, don't follow the final
    // symlink).
    let rc = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `renamex_np(a, b, RENAME_SWAP)` — atomically swap two existing paths on the
/// same volume.
fn renamex_swap(a: &Path, b: &Path) -> io::Result<()> {
    let a_c = CString::new(a.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "swap path a has NUL"))?;
    let b_c = CString::new(b.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "swap path b has NUL"))?;
    // SAFETY: both are valid, NUL-terminated C strings outliving the call;
    // `renamex_np` reads them and returns a status code, retaining no pointers.
    let rc = unsafe { libc::renamex_np(a_c.as_ptr(), b_c.as_ptr(), libc::RENAME_SWAP) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
