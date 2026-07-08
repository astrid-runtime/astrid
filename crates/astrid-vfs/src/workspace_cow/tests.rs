//! Unit tests for the workspace copy-on-write backends.
//!
//! No-CoW and the fail-closed degrade path run everywhere. The APFS clone /
//! promote / rollback test runs on macOS. The overlayfs mount test is
//! `#[cfg(target_os = "linux")]` + `#[ignore]` — it needs a Linux runtime with
//! unprivileged user namespaces (validated in CI, not on the macOS dev host).

use super::*;
use std::io;
use std::path::Path;

/// A backend whose `prepare` always fails — drives the fail-closed path in a
/// platform-independent way.
#[derive(Debug)]
struct AlwaysFailCow;

impl WorkspaceCow for AlwaysFailCow {
    fn capability(&self) -> CowCapability {
        CowCapability::Apfs
    }
    fn prepare(&self, _pristine: &Path) -> io::Result<PreparedWorkspace> {
        Err(io::Error::other("synthetic prepare failure"))
    }
    fn promote(&self) -> io::Result<()> {
        Ok(())
    }
    fn rollback(&self) -> io::Result<()> {
        Ok(())
    }
    fn teardown(&self) {}
}

#[test]
fn nocow_merges_to_pristine_and_refuses_promote() {
    let pristine = Path::new("/some/workspace");
    let prepared = NoCow
        .prepare(pristine)
        .expect("NoCow prepare is infallible");
    assert_eq!(prepared.merged_path, pristine);
    assert!(prepared.mask_from_children.is_empty());
    assert_eq!(NoCow.capability(), CowCapability::None);

    // promote / rollback are unsupported (writes already went direct).
    let promote = NoCow.promote().unwrap_err();
    assert_eq!(promote.kind(), io::ErrorKind::Unsupported);
    let rollback = NoCow.rollback().unwrap_err();
    assert_eq!(rollback.kind(), io::ErrorKind::Unsupported);
}

#[test]
fn prepare_fails_closed_to_nocow_on_backend_error() {
    // A backend that cannot establish CoW must degrade to No-CoW (merged ==
    // pristine, no masks) rather than abort or fake copy-on-write.
    let pristine = Path::new("/some/workspace");
    let (backend, prepared) = prepare_with_fallback(Box::new(AlwaysFailCow), pristine);
    assert_eq!(backend.capability(), CowCapability::None);
    assert_eq!(prepared.merged_path, pristine);
    assert!(prepared.mask_from_children.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_clone_isolates_then_promote_and_rollback() {
    use std::fs;

    let cow_root = tempfile::tempdir().expect("cow root");
    let pristine = tempfile::tempdir().expect("pristine");
    fs::write(pristine.path().join("orig.txt"), b"orig").expect("seed pristine");

    let backend = ApfsCow::new(cow_root.path().to_path_buf());
    let prepared = backend.prepare(pristine.path()).expect("apfs prepare");
    let merged = prepared.merged_path.clone();

    assert_eq!(backend.capability(), CowCapability::Apfs);
    // The clone carries the pristine contents.
    assert_eq!(
        fs::read(merged.join("orig.txt")).expect("read cloned orig"),
        b"orig"
    );
    // The mask hides the pristine workspace from spawned children.
    assert_eq!(
        prepared.mask_from_children,
        vec![pristine.path().to_path_buf()]
    );

    // A write in the clone is present in `merged` but ABSENT from pristine.
    fs::write(merged.join("new.txt"), b"new").expect("write in clone");
    assert!(merged.join("new.txt").exists());
    assert!(
        !pristine.path().join("new.txt").exists(),
        "clone write must not leak into pristine before promote"
    );

    // Promote commits the clone into pristine.
    backend.promote().expect("promote");
    assert_eq!(
        fs::read(pristine.path().join("new.txt")).expect("promoted new.txt"),
        b"new"
    );
    // The clone is re-established from the promoted pristine, so it still has
    // the committed file.
    assert!(merged.join("new.txt").exists());

    // A further clone write, then rollback, is discarded — pristine keeps only
    // the committed state.
    fs::write(merged.join("scratch.txt"), b"tmp").expect("scratch write");
    backend.rollback().expect("rollback");
    assert!(
        !merged.join("scratch.txt").exists(),
        "rollback must discard uncommitted clone writes"
    );
    assert!(
        merged.join("new.txt").exists(),
        "committed file survives rollback"
    );
    assert!(
        !pristine.path().join("scratch.txt").exists(),
        "rollback scratch never reached pristine"
    );

    // Teardown removes the working directory.
    backend.teardown();
    assert!(!merged.exists(), "teardown removes the clone");
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_prepare_twice_errors_without_leaking_a_second_clone() {
    // A second prepare() on the same backend must fail fast rather than clone
    // again: the second clone would be untracked (teardown/promote/rollback
    // still point at the first) and leak disk. Guards the double-prepare fix.
    let cow_root = tempfile::tempdir().expect("cow root");
    let pristine = tempfile::tempdir().expect("pristine");

    let backend = ApfsCow::new(cow_root.path().to_path_buf());
    let first = backend.prepare(pristine.path()).expect("first prepare");

    let err = backend
        .prepare(pristine.path())
        .expect_err("second prepare must error");
    assert_eq!(err.kind(), io::ErrorKind::Other);

    // The refused call created no second clone: exactly one working dir exists.
    let dirs = std::fs::read_dir(cow_root.path())
        .expect("read cow root")
        .filter_map(Result::ok)
        .count();
    assert_eq!(dirs, 1, "second prepare must not create a second clone dir");
    assert!(
        first.merged_path.exists(),
        "the first (tracked) clone is untouched"
    );

    backend.teardown();
}

/// Linux overlayfs prepare → write → promote. Ignored: needs a Linux runtime
/// with unprivileged user namespaces (CI-validated, not runnable on macOS).
#[cfg(target_os = "linux")]
#[test]
#[ignore = "overlayfs mount needs a Linux runtime with unprivileged userns; CI-validated"]
fn overlayfs_prepare_write_promote() {
    use std::fs;

    let cow_root = tempfile::tempdir().expect("cow root");
    let pristine = tempfile::tempdir().expect("pristine");
    fs::write(pristine.path().join("orig.txt"), b"orig").expect("seed pristine");

    let backend = OverlayfsCow::new(cow_root.path().to_path_buf());
    let prepared = backend.prepare(pristine.path()).expect("overlayfs prepare");
    let merged = prepared.merged_path.clone();

    // Merged shows the lower (pristine) contents.
    assert_eq!(
        fs::read(merged.join("orig.txt")).expect("read lower"),
        b"orig"
    );
    // upper + work are masked from children (siblings of merged).
    assert_eq!(prepared.mask_from_children.len(), 2);

    // A write lands in the upper, not the pristine lower, until promote.
    fs::write(merged.join("new.txt"), b"new").expect("write in merged");
    assert!(!pristine.path().join("new.txt").exists());

    backend.promote().expect("promote");
    assert_eq!(
        fs::read(pristine.path().join("new.txt")).expect("promoted"),
        b"new"
    );

    backend.teardown();
}
