//! Linux `overlayfs` copy-on-write backend.
//!
//! [`prepare`](OverlayfsCow::prepare) mounts an `overlayfs` with the pristine
//! workspace as a read-only `lowerdir`, a fresh `upperdir` for the diff, a
//! `workdir`, and a `merged` mountpoint the agent + spawns write to. It first
//! tries a native kernel `mount(2)`, then falls back to `fuse-overlayfs`.
//! [`rollback`](OverlayfsCow::rollback) discards the upper and remounts.
//!
//! # PARTIAL promote (char-dev whiteouts; opaque dirs refused)
//! [`promote`](OverlayfsCow::promote) copies the upper into the pristine
//! workspace and translates **plain whiteouts** (char device `0:0` → a real
//! delete of the lower entry). It does NOT yet translate **opaque directories**
//! (`trusted.overlay.opaque` — set when a dir is replaced wholesale, e.g.
//! `rm -rf d && mkdir d && touch d/new`) or `redirect_dir` renames. Rather than
//! silently leave the lower's stale children behind (an incorrect commit),
//! promote DETECTS those markers up front and REFUSES — failing closed so the
//! caller rolls back instead of committing a wrong tree. Translating them (so
//! such a promote can succeed) is the gap to close before the Linux path is
//! production-ready; it is a narrower gap than the in-process `OverlayVfs`,
//! which translated no whiteouts at all.
//!
//! # Privilege / runtime validation
//! This backend compiles only on Linux (`#[cfg(target_os = "linux")]`); its
//! mount path is exercised only on Linux CI (ubuntu-latest). The macOS
//! development host neither compiles nor runs it; see the `#[ignore]`d
//! integration test noted in the crate tests.
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
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

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
    /// Which mechanism currently holds the mount (native kernel vs
    /// `fuse-overlayfs`), so teardown unmounts the right way. Stored as a
    /// [`CowCapability`] discriminant ([`CAP_UNSET`] until the first mount) and
    /// updated by BOTH `prepare` and `rollback`, since a re-mount may resolve via
    /// a different mechanism than the original — a `OnceLock` would go stale and
    /// send `unmount` down the wrong teardown path.
    capability: AtomicU8,
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
            capability: AtomicU8::new(CAP_UNSET),
            mounted: AtomicBool::new(false),
        }
    }

    fn paths(&self) -> io::Result<&OverlayfsPaths> {
        self.paths
            .get()
            .ok_or_else(|| io::Error::other("overlayfs workspace CoW: prepare() has not run"))
    }

    /// The mechanism currently holding the mount (native default before the
    /// first mount, matching the old `unwrap_or(Overlayfs)`).
    fn load_capability(&self) -> CowCapability {
        cap_from_u8(self.capability.load(Ordering::SeqCst))
    }

    /// Record the mechanism a (re)mount resolved to, so `unmount` tears it down
    /// the matching way. Called by both `prepare` and `rollback`.
    fn store_capability(&self, capability: CowCapability) {
        self.capability
            .store(cap_to_u8(capability), Ordering::SeqCst);
    }

    /// Mount the overlay: try native `mount(2)` first, then `fuse-overlayfs`.
    /// Returns which mechanism succeeded so the caller records it for teardown.
    fn mount(p: &OverlayfsPaths) -> io::Result<CowCapability> {
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
        unmount_path(&p.merged, self.load_capability());
    }
}

impl WorkspaceCow for OverlayfsCow {
    fn capability(&self) -> CowCapability {
        self.load_capability()
    }

    fn prepare(&self, pristine: &Path) -> io::Result<PreparedWorkspace> {
        // prepare() must run exactly once per backend. Fail fast on an
        // accidental repeat before mounting anything; the `set` below is the
        // authoritative guard that also closes a concurrent race.
        if self.paths.get().is_some() {
            return Err(prepared_twice());
        }

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

        let capability = Self::mount(&paths)?;
        // Commit the tracked state. If a concurrent prepare() raced past the
        // guard above and set first, unmount + remove the overlay WE just built
        // so it does not leak, then report the double-prepare.
        if self.paths.set(paths.clone()).is_err() {
            unmount_path(&paths.merged, capability);
            let _ = std::fs::remove_dir_all(&paths.workspace_dir);
            return Err(prepared_twice());
        }
        self.mounted.store(true, Ordering::SeqCst);
        self.store_capability(capability);

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
        // Fail closed: refuse to promote an upper that contains an opaque or
        // redirect directory. `copy_upper_into_lower` cannot yet translate those
        // into deletes of the shadowed lower entries, so committing anyway would
        // silently leave stale lower children in place (an incorrect tree). The
        // caller rolls back instead of committing a wrong tree.
        ensure_no_opaque_markers(&p.upper)?;
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
        // A re-mount may resolve via a different mechanism than the original
        // (e.g. native now fails and fuse takes over); record the new one so
        // `unmount` tears it down correctly rather than via the stale mechanism.
        let capability = Self::mount(p)?;
        self.mounted.store(true, Ordering::SeqCst);
        self.store_capability(capability);
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
/// This does NOT translate opaque directories (`trusted.overlay.opaque`) or
/// `redirect_dir` — a wholesale directory replacement in the upper would leave
/// the lower's stale children in place. [`OverlayfsCow::promote`] guards against
/// that by refusing an upper that carries those markers
/// ([`ensure_no_opaque_markers`]), so this function is only ever reached for the
/// translatable cases. Making it TRANSLATE them (rather than the caller refusing)
/// is the Linux production-readiness follow-up.
fn copy_upper_into_lower(upper: &Path, lower: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(upper)? {
        let entry = entry?;
        let src = entry.path();
        let dst = lower.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&src)?;
        let ft = meta.file_type();

        // Whiteout: a char device with rdev 0:0 marks a deleted path.
        if ft.is_char_device() && meta.rdev() == 0 {
            if dst_symlink_metadata(&dst)?.is_some() {
                remove_any(&dst)?;
            }
            continue;
        }

        if ft.is_dir() {
            // A file or symlink already occupying `dst` must go before it can
            // become a directory (`create_dir_all` would fail on it).
            if let Some(dmeta) = dst_symlink_metadata(&dst)?
                && !dmeta.is_dir()
            {
                remove_any(&dst)?;
            }
            std::fs::create_dir_all(&dst)?;
            copy_upper_into_lower(&src, &dst)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&src)?;
            if dst_symlink_metadata(&dst)?.is_some() {
                remove_any(&dst)?;
            }
            std::os::unix::fs::symlink(target, &dst)?;
        } else {
            // Replace a directory or symlink at `dst` first: `fs::copy` would
            // fail on a directory, and on a symlink it would FOLLOW the link and
            // overwrite its target (possibly outside the workspace) instead of
            // replacing the link. An existing regular file it may overwrite.
            if let Some(dmeta) = dst_symlink_metadata(&dst)?
                && (dmeta.is_dir() || dmeta.file_type().is_symlink())
            {
                remove_any(&dst)?;
            }
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// `symlink_metadata` for a copy destination, distinguishing "absent" from a
/// real I/O error. `Ok(None)` = the path does not exist (or the platform cannot
/// stat it, e.g. wasm `Unsupported`); `Ok(Some(meta))` = the existing entry (NOT
/// following symlinks); any other error propagates rather than being silently
/// treated as absent.
fn dst_symlink_metadata(dst: &Path) -> io::Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(dst) {
        Ok(meta) => Ok(Some(meta)),
        Err(ref e)
            if e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::Unsupported =>
        {
            Ok(None)
        },
        Err(e) => Err(e),
    }
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

/// [`OverlayfsCow::capability`] is stored as a `u8` so both `prepare` and
/// `rollback` can update it (a re-mount may resolve via a different mechanism).
/// These map the two overlayfs mechanisms to/from that discriminant.
const CAP_UNSET: u8 = 0;
const CAP_NATIVE: u8 = 1;
const CAP_FUSE: u8 = 2;

fn cap_to_u8(capability: CowCapability) -> u8 {
    match capability {
        CowCapability::FuseOverlayfs => CAP_FUSE,
        // Any non-fuse overlay (including the `Overlayfs` default) is native.
        _ => CAP_NATIVE,
    }
}

fn cap_from_u8(value: u8) -> CowCapability {
    match value {
        CAP_FUSE => CowCapability::FuseOverlayfs,
        // CAP_UNSET (pre-mount) falls through to the native default, matching the
        // previous `unwrap_or(Overlayfs)` behaviour.
        _ => CowCapability::Overlayfs,
    }
}

/// Unmount a specific merged mountpoint with the mechanism that mounted it.
/// Shared by [`OverlayfsCow::unmount`] and the race-loser cleanup in
/// [`OverlayfsCow::prepare`], which must unmount ITS OWN overlay rather than the
/// winner's tracked one.
fn unmount_path(merged: &Path, capability: CowCapability) {
    match capability {
        CowCapability::FuseOverlayfs => {
            // FUSE3's `fusermount3` is the default on modern distros; fall back to
            // the FUSE2 `fusermount` only where `fusermount3` is absent or fails.
            let unmounted = std::process::Command::new("fusermount3")
                .arg("-u")
                .arg(merged)
                .status()
                .is_ok_and(|s| s.success());
            if !unmounted {
                let _ = std::process::Command::new("fusermount")
                    .arg("-u")
                    .arg(merged)
                    .status();
            }
        },
        _ => {
            if let Err(e) = umount(merged) {
                tracing::debug!(
                    merged = %merged.display(),
                    error = %e,
                    "workspace CoW: overlayfs unmount failed"
                );
            }
        },
    }
}

/// The error [`OverlayfsCow::prepare`] returns when called more than once on the
/// same backend — an accidental repeat (caught by the fast `paths.get()` check)
/// or a lost race with a concurrent call (caught by the `paths.set()` result).
fn prepared_twice() -> io::Error {
    io::Error::other("overlayfs workspace CoW: prepare() called more than once on the same backend")
}

/// overlayfs / fuse-overlayfs "this directory was replaced or renamed wholesale"
/// markers. Native kernel overlayfs stores them as `trusted.overlay.*` xattrs;
/// `fuse-overlayfs` uses the `user.fuseoverlayfs.*` namespace.
const OPAQUE_MARKER_XATTRS: [&str; 4] = [
    "trusted.overlay.opaque",
    "trusted.overlay.redirect",
    "user.fuseoverlayfs.opaque",
    "user.fuseoverlayfs.redirect",
];

/// Walk `dir` and error if any directory carries an opaque/redirect marker.
/// [`copy_upper_into_lower`] cannot yet translate those into deletes of the
/// shadowed lower entries, so [`OverlayfsCow::promote`] refuses rather than
/// commit a tree with stale lower children. Fails closed: an xattr that exists
/// but cannot be read (e.g. `EACCES` on a `trusted.*` name) is treated as
/// present.
fn ensure_no_opaque_markers(dir: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !std::fs::symlink_metadata(&path)?.file_type().is_dir() {
            continue;
        }
        for name in OPAQUE_MARKER_XATTRS {
            if has_xattr(&path, name)? {
                return Err(io::Error::other(format!(
                    "workspace CoW: overlayfs upper has an opaque/redirect directory \
                     ({name} on {}); promoting it would leave stale lower entries. This \
                     case is not yet supported, so the promote is refused — roll back \
                     instead of committing an incorrect tree.",
                    path.display()
                )));
            }
        }
        ensure_no_opaque_markers(&path)?;
    }
    Ok(())
}

/// Presence check for a single extended attribute via `lgetxattr(2)`.
/// `Ok(true)` = the attribute exists; `ENODATA`/`ENOTSUP` → `Ok(false)` (no such
/// marker, or a filesystem without xattrs); any other error propagates so the
/// caller fails closed.
fn has_xattr(path: &Path, name: &str) -> io::Result<bool> {
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "xattr path has NUL"))?;
    let name_c = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "xattr name has NUL"))?;
    // SAFETY: both C strings are NUL-terminated and outlive the call; a null
    // value pointer with size 0 asks only for the current value size and writes
    // nothing. `lgetxattr` does not follow a final symlink.
    let rc = unsafe { libc::lgetxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0) };
    if rc >= 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENODATA | libc::ENOTSUP) => Ok(false),
        _ => Err(err),
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
