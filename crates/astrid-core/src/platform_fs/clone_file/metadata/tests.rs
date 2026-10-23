#![allow(unsafe_code)]
use super::*;
use crate::platform_fs::try_clone_file;
use std::ffi::CString;

fn attributed(file: &File) {
    let name = CString::new("user.astrid-clone-test").unwrap();
    let value = b"untrusted side data";
    // SAFETY: valid descriptor and live buffers; no data escapes the call.
    assert_eq!(
        unsafe {
            nix::libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        },
        0
    );
}

#[test]
fn attributed_sources_fall_back_without_creating_a_target() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source");
    std::fs::write(&path, b"verified data fork").unwrap();
    let source = File::open(path).unwrap();
    attributed(&source);
    let target = root.path().join("target");
    assert!(!try_clone_file(&source, &target).unwrap());
    assert!(!target.exists());
}

#[test]
fn flagged_sources_fall_back_without_creating_a_target() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source");
    std::fs::write(&path, b"verified data fork").unwrap();
    let source = File::open(path).unwrap();
    // SAFETY: an open fixture descriptor; restore flags before any assertion.
    assert_eq!(
        unsafe { nix::libc::fchflags(source.as_raw_fd(), nix::libc::UF_APPEND) },
        0
    );
    let target = root.path().join("target");
    let result = try_clone_file(&source, &target);
    let cleared = unsafe { nix::libc::fchflags(source.as_raw_fd(), 0) };
    assert_eq!(cleared, 0);
    assert!(!result.unwrap());
    assert!(!target.exists());
}

#[test]
fn read_only_sources_produce_private_writable_clones() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source");
    std::fs::write(&path, b"verified").unwrap();
    let source = File::open(&path).unwrap();
    std::fs::set_permissions(path, Permissions::from_mode(0o400)).unwrap();
    let target = root.path().join("target");
    if try_clone_file(&source, &target).unwrap() {
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::write(target, b"independent mutation").unwrap();
    }
}

#[test]
fn captured_clone_attributes_are_rechecked_and_discarded() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    std::fs::write(&target, b"captured clone").unwrap();
    attributed(&File::open(&target).unwrap());
    assert!(!prepare(&target).unwrap());
    assert!(!target.exists());
}

#[test]
fn captured_clone_flags_are_cleared_before_discard() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    std::fs::write(&target, b"captured clone").unwrap();
    let opened = File::open(&target).unwrap();
    // SAFETY: the fixture descriptor remains live until after discard.
    assert_eq!(
        unsafe { nix::libc::fchflags(opened.as_raw_fd(), nix::libc::UF_APPEND) },
        0
    );
    let result = prepare(&target);
    let cleared = unsafe { nix::libc::fchflags(opened.as_raw_fd(), 0) };
    assert_eq!(cleared, 0);
    assert!(!result.unwrap());
    assert!(!target.exists());
}
