//! OS-level copy-on-write for non-git agent workspaces.
//!
//! The in-process [`OverlayVfs`](crate::OverlayVfs) diverts a capsule's writes
//! into a temporary upper directory that only the fs host can see. A spawned
//! process (`cargo`, `git`, a `build.rs`) opens the workspace through the OS,
//! not through the VFS, so it reads the pristine lower and never the overlay's
//! upper — the copy-on-write is invisible to exactly the tools that matter.
//!
//! This module replaces that in-process overlay for the non-git branch with a
//! *real* OS-level copy-on-write, so the fs host AND spawned processes see one
//! merged filesystem at a single real path ([`PreparedWorkspace::merged_path`]).
//! Writes are live where `cargo` and the user look; the pristine workspace is
//! only mutated by an explicit [`promote`](WorkspaceCow::promote) (the gate's
//! "approve"), and discarded by [`rollback`](WorkspaceCow::rollback) (the gate's
//! "reject").
//!
//! Backends, chosen by [`detect_cow_backend`]:
//! * **macOS** — [`ApfsCow`](apfs::ApfsCow): an APFS `clonefile(2)` clone.
//! * **Linux** — `OverlayfsCow`: an unprivileged `overlayfs` mount (with
//!   `fuse-overlayfs` as the fallback).
//! * **everywhere / fallback** — [`NoCow`]: writes go direct to the pristine
//!   workspace, no rollback. This is the *fail-closed* default whenever a real
//!   backend cannot be established — never a silently faked copy-on-write.
//!
//! # Security: masking the upper from children
//!
//! [`PreparedWorkspace::mask_from_children`] lists the copy-on-write bookkeeping
//! directories (the overlayfs `upper`/`work`, the APFS clone root) that the OS
//! sandbox MUST hide from spawned children. Without the mask a child could write
//! the upper directly and bypass promote/rollback — the gate would then approve
//! a set of changes the child had already smuggled past it. The wiring threads
//! this list into the sandbox's hidden-path set (see
//! `astrid_workspace::sandbox`).

use std::io;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
pub mod apfs;
#[cfg(target_os = "linux")]
pub mod overlayfs;

#[cfg(test)]
mod tests;

#[cfg(target_os = "macos")]
pub use apfs::ApfsCow;
#[cfg(target_os = "linux")]
pub use overlayfs::OverlayfsCow;

/// The copy-on-write mechanism a [`WorkspaceCow`] backend provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowCapability {
    /// Linux kernel `overlayfs` (a real merged mount).
    Overlayfs,
    /// Linux `fuse-overlayfs` fallback (userspace merged mount).
    FuseOverlayfs,
    /// macOS APFS `clonefile(2)` copy-on-write clone.
    Apfs,
    /// No copy-on-write: writes go directly to the pristine workspace and
    /// promote/rollback are unsupported.
    None,
}

/// The outcome of preparing a workspace for copy-on-write.
#[derive(Debug, Clone)]
pub struct PreparedWorkspace {
    /// The single real directory the principal writes to AND spawned processes
    /// run in. For a real backend this is the merged/clone tree; for
    /// [`NoCow`] it is the pristine workspace itself.
    pub merged_path: PathBuf,
    /// Paths the OS sandbox MUST mask from spawned children — the copy-on-write
    /// upper/work directories (or the clone root) — so a child cannot write
    /// them directly and bypass [`promote`](WorkspaceCow::promote) /
    /// [`rollback`](WorkspaceCow::rollback). Empty for [`NoCow`].
    pub mask_from_children: Vec<PathBuf>,
}

/// A copy-on-write backend for a single workspace.
///
/// A backend is constructed for the workspace it will manage, then
/// [`prepare`](Self::prepare)d once. [`promote`](Self::promote) commits the
/// working changes into the pristine workspace; [`rollback`](Self::rollback)
/// discards them; [`teardown`](Self::teardown) unmounts / removes the working
/// tree and MUST run when the owning capsule unloads.
pub trait WorkspaceCow: Send + Sync {
    /// The copy-on-write mechanism this backend provides.
    fn capability(&self) -> CowCapability;

    /// Establish the copy-on-write working tree over `pristine` and return the
    /// merged path plus the child-mask set. Called exactly once.
    ///
    /// # Errors
    /// Returns an error if the mount/clone cannot be established. The caller
    /// (see [`prepare_workspace_cow`]) treats any error as a signal to
    /// fail closed to [`NoCow`] — it never proceeds with a half-built backend.
    fn prepare(&self, pristine: &Path) -> io::Result<PreparedWorkspace>;

    /// Commit the working changes into the pristine workspace (the gate's
    /// "approve"). After a successful promote the pristine workspace reflects
    /// every write made under `merged_path`.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::Unsupported`] for [`NoCow`] (there is nothing to
    /// commit — writes already went direct), or an I/O error if the commit
    /// fails.
    fn promote(&self) -> io::Result<()>;

    /// Discard the working changes, restoring the working tree to the pristine
    /// contents (the gate's "reject").
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::Unsupported`] for [`NoCow`], or an I/O error if
    /// the discard fails.
    fn rollback(&self) -> io::Result<()>;

    /// Unmount / remove the working tree. MUST run on capsule unload. Idempotent
    /// and best-effort: teardown errors are logged, not propagated, because a
    /// capsule unload cannot be failed by a stale mount.
    fn teardown(&self);
}

/// No-CoW baseline: correct on every platform, no isolation.
///
/// [`prepare`](WorkspaceCow::prepare) returns the pristine workspace as the
/// merged path with no masks — writes land directly on the real workspace.
/// [`promote`](WorkspaceCow::promote) / [`rollback`](WorkspaceCow::rollback)
/// are unsupported (there is no upper to commit or discard). This is the
/// fail-closed fallback whenever a real backend cannot be established.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCow;

impl WorkspaceCow for NoCow {
    fn capability(&self) -> CowCapability {
        CowCapability::None
    }

    fn prepare(&self, pristine: &Path) -> io::Result<PreparedWorkspace> {
        Ok(PreparedWorkspace {
            merged_path: pristine.to_path_buf(),
            mask_from_children: Vec::new(),
        })
    }

    fn promote(&self) -> io::Result<()> {
        tracing::warn!(
            "workspace CoW: promote requested on a No-CoW workspace — writes already \
             went direct to the workspace, there is nothing to commit"
        );
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "No-CoW workspace does not support promote",
        ))
    }

    fn rollback(&self) -> io::Result<()> {
        tracing::warn!(
            "workspace CoW: rollback requested on a No-CoW workspace — writes already \
             went direct to the workspace and cannot be rolled back"
        );
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "No-CoW workspace does not support rollback",
        ))
    }

    fn teardown(&self) {}
}

/// Construct the preferred copy-on-write backend for this host, storing its
/// working trees under `cow_root` (normally
/// [`AstridHome::cow_dir`](astrid_core::dirs::AstridHome::cow_dir)).
///
/// The factory only *selects* a backend; the mount/clone happens in
/// [`prepare`](WorkspaceCow::prepare). Selection order:
/// * macOS → [`ApfsCow`](apfs::ApfsCow).
/// * Linux → `OverlayfsCow` (which tries a native `overlayfs` mount, then
///   `fuse-overlayfs`, at prepare time).
/// * any other platform → [`NoCow`], with a `warn` naming the reason.
///
/// This never returns a backend that fakes copy-on-write: an unsupported
/// platform (or, at prepare time, a failed mount) fails closed to [`NoCow`].
#[must_use]
pub fn detect_cow_backend(cow_root: &Path) -> Box<dyn WorkspaceCow> {
    #[cfg(target_os = "macos")]
    {
        Box::new(apfs::ApfsCow::new(cow_root.to_path_buf()))
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(overlayfs::OverlayfsCow::new(cow_root.to_path_buf()))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = cow_root;
        tracing::warn!(
            "workspace CoW: no OS-level copy-on-write backend on this platform; \
             falling back to No-CoW (writes go direct, no rollback)"
        );
        Box::new(NoCow)
    }
}

/// Detect the preferred backend and [`prepare`](WorkspaceCow::prepare) it over
/// `pristine`, **failing closed to [`NoCow`]** — with a loud `warn` naming the
/// reason — if the mount/clone cannot be established.
///
/// This is the single entry point the capsule load path uses: it returns the
/// backend to keep alive for promote/rollback/teardown together with the
/// [`PreparedWorkspace`] (merged path + child masks) to wire into the VFS,
/// the spawn root, and the sandbox. It never surfaces an error, because a
/// copy-on-write that cannot be established must degrade to direct writes, not
/// abort the capsule.
#[must_use]
pub fn prepare_workspace_cow(
    cow_root: &Path,
    pristine: &Path,
) -> (Box<dyn WorkspaceCow>, PreparedWorkspace) {
    prepare_with_fallback(detect_cow_backend(cow_root), pristine)
}

/// The fail-closed [`NoCow`] result for `pristine`: writes go direct to the
/// workspace, no rollback, no masks. Use this whenever a copy-on-write root
/// cannot even be established (e.g. the Astrid home is unresolvable) — it keeps
/// writes on the real workspace instead of scattering a clone into a
/// world-writable location where a sibling child could reach another
/// workspace's clone and smuggle changes past its promote gate.
#[must_use]
pub fn no_cow_workspace(pristine: &Path) -> (Box<dyn WorkspaceCow>, PreparedWorkspace) {
    (
        Box::new(NoCow),
        PreparedWorkspace {
            merged_path: pristine.to_path_buf(),
            mask_from_children: Vec::new(),
        },
    )
}

/// Prepare `primary`, degrading to [`NoCow`] on any error. Split out so the
/// fail-closed path is unit-testable with an injected backend that fails
/// (no dependency on the host platform or `$ASTRID_HOME`).
fn prepare_with_fallback(
    primary: Box<dyn WorkspaceCow>,
    pristine: &Path,
) -> (Box<dyn WorkspaceCow>, PreparedWorkspace) {
    match primary.prepare(pristine) {
        Ok(prepared) => (primary, prepared),
        Err(e) => {
            tracing::warn!(
                capability = ?primary.capability(),
                error = %e,
                pristine = %pristine.display(),
                "workspace CoW: prepare failed; failing closed to No-CoW \
                 (writes go direct to the workspace, no rollback)"
            );
            no_cow_workspace(pristine)
        },
    }
}
