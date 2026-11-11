//! Rollback preserves exact prior generations using anonymous scratch storage.

use std::io::{self, Read};
use std::path::Path;

use astrid_core::platform_fs::PrivateFileProjection;

use super::rollback::RollbackSpool;

fn private_root() -> (tempfile::TempDir, PrivateFileProjection) {
    let root = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let projection = PrivateFileProjection::open(root.path()).unwrap();
    (root, projection)
}

#[test]
fn rollback_distinguishes_absent_and_empty_without_scratch_bytes() {
    let (root, projection) = private_root();
    let mut spool = RollbackSpool::default();
    let missing = spool.capture(&projection, Path::new("missing")).unwrap();
    projection.write(Path::new("empty"), &[]).unwrap();
    let empty = spool.capture(&projection, Path::new("empty")).unwrap();
    assert!(
        !spool.has_scratch_file(),
        "absent and empty generations need no scratch file"
    );
    projection.write(Path::new("missing"), b"new").unwrap();
    projection.write(Path::new("empty"), b"new").unwrap();
    spool
        .restore(&projection, Path::new("missing"), missing)
        .unwrap();
    spool
        .restore(&projection, Path::new("empty"), empty)
        .unwrap();
    assert!(!root.path().join("missing").exists());
    assert_eq!(std::fs::read(root.path().join("empty")).unwrap(), b"");
    assert!(!spool.has_scratch_file());
}

#[test]
fn multi_generation_rollback_restores_exact_bytes() {
    let (root, projection) = private_root();
    let mut spool = RollbackSpool::default();
    projection.write(Path::new("a"), b"A0").unwrap();
    projection.write(Path::new("b"), b"B000").unwrap();
    projection.write(Path::new("c"), &[]).unwrap();

    let prev_a = spool.capture(&projection, Path::new("a")).unwrap();
    let prev_b = spool.capture(&projection, Path::new("b")).unwrap();
    let prev_c = spool.capture(&projection, Path::new("c")).unwrap();
    let prev_d = spool.capture(&projection, Path::new("d")).unwrap();
    assert!(spool.has_scratch_file());

    projection.write(Path::new("a"), b"A1").unwrap();
    projection.write(Path::new("b"), b"B1").unwrap();
    projection.write(Path::new("c"), b"C1").unwrap();
    projection.write(Path::new("d"), b"D1").unwrap();

    spool.restore(&projection, Path::new("d"), prev_d).unwrap();
    spool.restore(&projection, Path::new("c"), prev_c).unwrap();
    spool.restore(&projection, Path::new("b"), prev_b).unwrap();
    spool.restore(&projection, Path::new("a"), prev_a).unwrap();

    assert_eq!(std::fs::read(root.path().join("a")).unwrap(), b"A0");
    assert_eq!(std::fs::read(root.path().join("b")).unwrap(), b"B000");
    assert_eq!(std::fs::read(root.path().join("c")).unwrap(), b"");
    assert!(!root.path().join("d").exists());
}

/// Reader that fails after `ok_bytes` to exercise midstream cleanup.
struct FailAfter {
    ok_bytes: usize,
    read: usize,
}

impl Read for FailAfter {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.read >= self.ok_bytes {
            return Err(io::Error::other("injected midstream failure"));
        }
        let want = self.ok_bytes.strict_sub(self.read).min(buffer.len()).min(1);
        buffer[..want].fill(b'x');
        self.read = self.read.strict_add(want);
        Ok(want)
    }
}

#[cfg(unix)]
#[test]
fn write_from_midstream_failure_cleans_temporary() {
    let (root, projection) = private_root();
    std::fs::write(root.path().join("state"), b"previous").unwrap();
    let mut source = FailAfter {
        ok_bytes: 3,
        read: 0,
    };
    let error = projection
        .write_from(Path::new("state"), &mut source, 16)
        .unwrap_err();
    assert!(error.to_string().contains("injected midstream failure"));
    assert_eq!(
        std::fs::read(root.path().join("state")).unwrap(),
        b"previous"
    );
    for entry in std::fs::read_dir(root.path()).unwrap() {
        let name = entry.unwrap().file_name();
        assert!(
            !name.to_string_lossy().starts_with(".astrid-private-"),
            "temporary survived midstream failure: {name:?}"
        );
    }
}
