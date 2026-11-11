//! Windows regressions for private file birth without path-based restrict reopen.

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt as _;

use super::{create_private_file, private_file_identity};

fn private_temp() -> tempfile::TempDir {
    let local = directories::BaseDirs::new()
        .expect("local app data")
        .data_local_dir()
        .to_path_buf();
    let root = tempfile::Builder::new()
        .prefix("astrid-native-io-")
        .tempdir_in(local)
        .expect("tempdir");
    astrid_core::platform_fs::ensure_private_directory(root.path()).expect("private root");
    root
}

#[test]
fn create_private_file_keeps_live_rw_handle_with_acl_at_birth() {
    let root = private_temp();
    let path = root.path().join("staging.open");
    let mut file = create_private_file(&path).expect("create private file");
    // Birth ACL must hold on the live constructor handle before any payload.
    astrid_core::platform_fs::validate_private_file_handle(&file).expect("ACL by handle");
    let identity = private_file_identity(&file).expect("handle identity");
    file.write_all(b"payload-v1")
        .expect("write through live constructor");
    file.flush().expect("flush writer");
    astrid_core::platform_fs::validate_private_file_handle(&file)
        .expect("ACL by handle after write");

    // Prove payload through the same live RW handle; birth share is FILE_SHARE_READ,
    // so a path reopen that omits FILE_SHARE_WRITE would conflict with this writer.
    file.seek(SeekFrom::Start(0))
        .expect("seek live constructor");
    let mut bytes = [0_u8; 10];
    file.read_exact(&mut bytes)
        .expect("read back through live constructor");
    assert_eq!(&bytes, b"payload-v1");

    // Original SHARE_READ birth still denies a second writer while RW is held.
    let second_writer = std::fs::OpenOptions::new()
        .write(true)
        .share_mode(
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
        )
        .open(&path);
    let error = second_writer.expect_err("second writer must conflict with live RW");
    assert_eq!(error.raw_os_error(), Some(32), "{error}");

    assert_eq!(
        private_file_identity(&file).expect("identity stable"),
        identity
    );
}

#[test]
fn create_private_file_create_new_never_overwrites() {
    let root = private_temp();
    let path = root.path().join("existing.open");
    std::fs::write(&path, b"original").unwrap();
    astrid_core::platform_fs::restrict_private_file(&path).unwrap();
    let error = create_private_file(&path).expect_err("create_new must not overwrite");
    assert!(error.to_string().contains("create private file"), "{error}");
    assert_eq!(std::fs::read(&path).unwrap(), b"original");
}
