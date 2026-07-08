//! Linux `overlayfs` copy-on-write backend.
//!
//! [`prepare`](OverlayfsCow::prepare) mounts an `overlayfs` with the pristine
//! workspace as a read-only `lowerdir`, a fresh `upperdir` for the diff, a
//! `workdir`, and a `merged` mountpoint the agent + spawns write to. It first
//! tries a native kernel `mount(2)`, then falls back to `fuse-overlayfs`.
//! [`rollback`](OverlayfsCow::rollback) discards the upper and remounts.
//!
//! # PARTIAL promote (char-dev whiteouts only — TODO)
//! [`promote`](OverlayfsCow::promote) copies the upper into the pristine
//! workspace and translates only **plain whiteouts** (char device `0:0` → a
//! real delete of the lower entry). It does NOT yet handle **opaque
//! directories** (`trusted.overlay.opaque` — set when a dir is replaced
//! wholesale, e.g. `rm -rf d && mkdir d && touch d/new`) or `redirect_dir`
//! renames, so in those cases the lower's stale children silently survive the
//! commit. This is a known gap to close before the Linux path is production-
//! ready; it is not the "no-whiteout" gap of the in-process `OverlayVfs`
//! (which handled neither) but a narrower opaque-dir gap.
//!
//! # Privilege / runtime validation
//! This backend is compiled and type-checked on every platform's CI but its
//! mount path is exercised only on Linux. The macOS development host cannot run
//! it; see the `#[ignore]`d integration test noted in the crate tests.
//!
//! The native `mount(2)` path here does NOT itself create a user namespace, so
//! it succeeds only when the daemon already holds mount authority for overlayfs
//! (`CAP_SYS_ADMIN` — e.g. a root daemon, or an outer userns already set up with
//! uid/gid maps). Otherwise it fails and `fuse-overlayfs` is the working path.
//! TODO: `unshare(CLONE_NEWUSER | CLONE_NEWNS)` + uid/gid-map setup before the
//! mount so the native path works unprivileged (on Ubuntu 24.04+ that also needs
//! `kernel.apparmor_restrict_unprivileged_userns=0`, the same knob `bwrap`
//! needs — see `astrid_workspace::sandbox`).

#![allow(unsafe_code)] // Isolated FFI to mount(2) / umount2(2); documented + argument-checked.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::{CowCapability, PreparedWorkspace, WorkspaceCow};

/// Process-unique counter so concurrent loads of the same workspace path get
/// distinct mount directories.
static WORKSPACE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Paths fixed at [`OverlayfsCow::prepare`] time.
#[derive(Debug, Clone)]
struct OverlayfsPaths {
    /// The real workspace (overlayfs `lowerdir`, read-only).
    pristine: PathBuf,
    /// The overlayfs `upperdir` — holds the diff; masked from children.
    upper: PathBuf,
    /// The overlayfs `workdir` — kernel scratch; masked from children.
    work: PathBuf,
    /// The overlayfs mountpoint the agent + spawns write to.
    merged: PathBuf,
    /// The per-workspace directory removed at teardown.
    workspace_dir: PathBuf,
}

/// Linux `overlayfs` copy-on-write backend.
#[derive(Debug)]
pub struct OverlayfsCow {
    cow_root: PathBuf,
    paths: OnceLock<OverlayfsPaths>,
    /// Which mechanism actually mounted (native kernel vs `fuse-overlayfs`),
    /// so teardown unmounts the right way.
    capability: OnceLock<CowCapability>,
    mounted: AtomicBool,
}

impl OverlayfsCow {
    /// Construct an overlayfs backend that stores its upper/work/merged dirs
    /// under `cow_root`.
    #[must_use]
    pub fn new(cow_root: PathBuf) -> Self {
        Self {
            cow_root,
            paths: OnceLock::new(),
            capability: OnceLock::new(),
            mounted: AtomicBool::new(false),
        }
    }

    fn paths(&self) -> io::Result<&OverlayfsPaths> {
        self.paths
            .get()
            .ok_or_else(|| io::Error::other("overlayfs workspace CoW: prepare() has not run"))
    }

    /// Mount the overlay: try native `mount(2)` first, then `fuse-overlayfs`.
    /// Records which mechanism succeeded so teardown matches.
    fn mount(&self, p: &OverlayfsPaths) -> io::Result<CowCapability> {
        let data = format!(
            "lowerdir={},upperdir={},workdir={}",
            p.pristine.display(),
            p.upper.display(),
            p.work.display()
        );
        match mount_overlay(&p.merged, &data) {
            Ok(()) => Ok(CowCapability::Overlayfs),
            Err(native_err) => {
                tracing::warn!(
                    error = %native_err,
                    "workspace CoW: native overlayfs mount failed; trying fuse-overlayfs"
                );
                let status = std::process::Command::new("fuse-overlayfs")
                    .arg("-o")
                    .arg(&data)
                    .arg(&p.merged)
                    .status()?;
                if status.success() {
                    Ok(CowCapability::FuseOverlayfs)
                } else {
                    Err(io::Error::other(format!(
                        "fuse-overlayfs exited with {status}"
                    )))
                }
            },
        }
    }

    fn unmount(&self) {
        if !self.mounted.swap(false, Ordering::SeqCst) {
            return;
        }
        let Some(p) = self.paths.get() else { return };
        match self.capability.get() {
            Some(CowCapability::FuseOverlayfs) => {
                let _ = std::process::Command::new("fusermount")
                    .arg("-u")
                    .arg(&p.merged)
                    .status();
            },
            _ => {
                if let Err(e) = umount(&p.merged) {
                    tracing::debug!(
                        merged = %p.merged.display(),
                        error = %e,
                        "workspace CoW: overlayfs unmount failed"
                    );
                }
            },
        }
    }
}

impl WorkspaceCow for OverlayfsCow {
    fn capability(&self) -> CowCapability {
        self.capability
            .get()
            .copied()
            .unwrap_or(CowCapability::Overlayfs)
    }

    fn prepare(&self, pristine: &Path) -> io::Result<PreparedWorkspace> {
        let seq = WORKSPACE_SEQ.fetch_add(1, Ordering::Relaxed);
        let id = format!("{}-{seq}", path_hash(pristine));
        let workspace_dir = self.cow_root.join(&id);
        let upper = workspace_dir.join("upper");
        let work = workspace_dir.join("work");
        let merged = workspace_dir.join("merged");

        for dir in [&upper, &work, &merged] {
            std::fs::create_dir_all(dir)?;
        }

        let paths = OverlayfsPaths {
            pristine: pristine.to_path_buf(),
            upper: upper.clone(),
            work: work.clone(),
            merged: merged.clone(),
            workspace_dir,
        };

        let capability = self.mount(&paths)?;
        self.mounted.store(true, Ordering::SeqCst);
        let _ = self.capability.set(capability);
        let _ = self.paths.set(paths);

        Ok(PreparedWorkspace {
            merged_path: merged,
            // A child that wrote the upper/work dirs directly would corrupt the
            // overlay's copy-up/whiteout state and stage changes the gate never
            // approved. Both are SIBLINGS of `merged` (not ancestors), so the
            // sandbox masks them cleanly.
            mask_from_children: vec![upper, work],
        })
    }

    fn promote(&self) -> io::Result<()> {
        let p = self.paths()?;
        copy_upper_into_lower(&p.upper, &p.pristine)?;
        tracing::info!(
            pristine = %p.pristine.display(),
            "workspace CoW: promoted overlayfs upper into the pristine workspace"
        );
        Ok(())
    }

    fn rollback(&self) -> io::Result<()> {
        let p = self.paths()?;
        // Discard the diff: unmount, clear the upper + work, remount clean.
        self.unmount();
        for dir in [&p.upper, &p.work] {
            if dir.exists() {
                std::fs::remove_dir_all(dir)?;
            }
            std::fs::create_dir_all(dir)?;
        }
        let capability = self.mount(p)?;
        self.mounted.store(true, Ordering::SeqCst);
        let _ = self.capability.set(capability);
        tracing::info!(
            pristine = %p.pristine.display(),
            "workspace CoW: rolled back overlayfs upper"
        );
        Ok(())
    }

    fn teardown(&self) {
        self.unmount();
        if let Some(p) = self.paths.get()
            && let Err(e) = std::fs::remove_dir_all(&p.workspace_dir)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(
                dir = %p.workspace_dir.display(),
                error = %e,
                "workspace CoW: overlayfs teardown could not remove directory"
            );
        }
    }
}

impl Drop for OverlayfsCow {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Recursively copy `upper` into `lower`, translating plain overlayfs whiteouts
/// (char device `0:0`) into deletes of the corresponding `lower` entry.
///
/// TODO (Linux production-readiness): this does NOT handle opaque directories
/// (`trusted.overlay.opaque`) or `redirect_dir`, so a wholesale directory
/// replacement in the upper leaves the lower's stale children in place. Closing
/// that needs reading the overlay xattrs per directory.
fn copy_upper_into_lower(upper: &Path, lower: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(upper)? {
        let entry = entry?;
        let src = entry.path();
        let dst = lower.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&src)?;
        let ft = meta.file_type();

        // Whiteout: a char device with rdev 0:0 marks a deleted path.
        if ft.is_char_device() && meta.rdev() == 0 {
            if dst.exists() || std::fs::symlink_metadata(&dst).is_ok() {
                remove_any(&dst)?;
            }
            continue;
        }

        if ft.is_dir() {
            std::fs::create_dir_all(&dst)?;
            copy_upper_into_lower(&src, &dst)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&src)?;
            if dst.exists() || std::fs::symlink_metadata(&dst).is_ok() {
                remove_any(&dst)?;
            }
            std::os::unix::fs::symlink(target, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// Remove a path whether it is a file, symlink, or directory.
fn remove_any(path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// A short, deterministic hex digest of a path, used only as a directory name.
fn path_hash(path: &Path) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// `mount("overlay", target, "overlay", 0, data)`.
fn mount_overlay(target: &Path, data: &str) -> io::Result<()> {
    let src = CString::new("overlay")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mount source has NUL"))?;
    let fstype = CString::new("overlay")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mount fstype has NUL"))?;
    let target_c = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mount target has NUL"))?;
    let data_c = CString::new(data)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mount data has NUL"))?;
    // SAFETY: all four pointers are valid, NUL-terminated C strings that outlive
    // the call; `mount` reads them and returns a status code, retaining no
    // pointers. `data` is the overlayfs option string.
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            0,
            data_c.as_ptr().cast(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `umount2(target, MNT_DETACH)` — lazy unmount so a busy mountpoint still
/// detaches.
fn umount(target: &Path) -> io::Result<()> {
    let target_c = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "umount target has NUL"))?;
    // SAFETY: `target_c` is a valid, NUL-terminated C string outliving the call.
    let rc = unsafe { libc::umount2(target_c.as_ptr(), libc::MNT_DETACH) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
