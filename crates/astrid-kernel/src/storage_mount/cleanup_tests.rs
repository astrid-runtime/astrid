use super::*;

#[test]
fn cleanup_preserves_parent_opened_by_another_lease() {
    use nix::sys::stat::{Mode, mkdirat};

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("mounts");
    let retiring = root.join("retiring");
    astrid_core::platform_fs::ensure_private_directory(&retiring).unwrap();
    let callback = retiring.join("control.sock");
    let listener = std::os::unix::net::UnixListener::bind(&callback).unwrap();
    std::fs::write(retiring.join(LEASE_MANIFEST_NAME), b"test lease").unwrap();

    // The private-directory walker holds the parent open while creating the
    // next lease. Retiring the last existing lease must not unlink that parent.
    let parent = std::fs::File::open(&root).unwrap();
    drop(listener);
    cleanup_resource(&retiring, &callback);
    assert!(!retiring.exists());
    mkdirat(&parent, "arriving", Mode::S_IRWXU).unwrap();
    assert!(root.join("arriving").is_dir());
    astrid_core::platform_fs::validate_private_directory(&root).unwrap();
}
