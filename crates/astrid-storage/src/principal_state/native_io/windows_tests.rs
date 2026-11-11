//! Windows regressions for private file birth, directory flush, and exclusive rename.

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use super::{PrivateDirectory, create_private_file, private_file_identity};

/// Owned tempfile parent plus `ExactPrivate` child used for birth tests.
///
/// `tempfile` roots inherit host ACLs that are not `ExactPrivate`; never call
/// `ensure_private_directory` on that root. Create a private child beneath it.
struct PrivateTemp {
    _parent: tempfile::TempDir,
    path: PathBuf,
}

impl PrivateTemp {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn private_temp() -> PrivateTemp {
    let local = directories::BaseDirs::new()
        .expect("local app data")
        .data_local_dir()
        .to_path_buf();
    let parent = tempfile::Builder::new()
        .prefix("astrid-native-io-")
        .tempdir_in(local)
        .expect("tempdir");
    let path = parent.path().join("private");
    astrid_core::platform_fs::create_private_directory(&path).expect("exact private child");
    PrivateTemp {
        _parent: parent,
        path,
    }
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

#[test]
fn private_directory_sync_is_not_a_noop_and_honors_fault_injection() {
    let root = private_temp();
    let directory = PrivateDirectory::open(root.path()).expect("open ambient private directory");
    directory
        .sync()
        .expect("NTFS directory flush through cached capability");

    let _arm = astrid_core::platform_fs::directory_capability::DirectoryFlushCapability::arm_flush_failures(1);
    let error = directory
        .sync()
        .expect_err("fault-injected flush must surface");
    assert!(
        error
            .to_string()
            .contains("injected directory flush failure")
            || error.to_string().contains("flush directory"),
        "{error}"
    );
}

#[test]
fn rename_no_replace_refuses_existing_destination() {
    let root = private_temp();
    let directory = PrivateDirectory::open(root.path()).expect("open");
    let source = Path::new("writing.open");
    let destination = Path::new("sealed.open");
    std::fs::write(root.path().join(source), b"source-bytes").unwrap();
    astrid_core::platform_fs::restrict_private_file(&root.path().join(source)).unwrap();
    std::fs::write(root.path().join(destination), b"dest-bytes").unwrap();
    astrid_core::platform_fs::restrict_private_file(&root.path().join(destination)).unwrap();
    let expected = private_file_identity(&directory.open_file(source).unwrap()).unwrap();
    let error = directory
        .rename_with_identity(source, destination, expected)
        .expect_err("existing destination must refuse");
    assert!(
        error.to_string().contains("already exists") || error.to_string().contains("rename"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(root.path().join(source)).unwrap(),
        b"source-bytes"
    );
    assert_eq!(
        std::fs::read(root.path().join(destination)).unwrap(),
        b"dest-bytes"
    );
}

#[test]
fn rename_no_replace_keeps_both_names_when_destination_appears_before_nt() {
    let root = private_temp();
    let directory = PrivateDirectory::open(root.path()).expect("open");
    let source = Path::new("writing.open");
    let destination = Path::new("sealed.open");
    std::fs::write(root.path().join(source), b"source-bytes").unwrap();
    astrid_core::platform_fs::restrict_private_file(&root.path().join(source)).unwrap();
    let expected = private_file_identity(&directory.open_file(source).unwrap()).unwrap();
    assert!(!directory.contains(destination).unwrap());
    // Simulate arrival after the caller's absence check and drive the exact
    // production NT boundary without repeating that check.
    std::fs::write(root.path().join(destination), b"racer-bytes").unwrap();
    astrid_core::platform_fs::restrict_private_file(&root.path().join(destination)).unwrap();
    let error = super::windows_staging::rename_no_replace_windows(
        &directory.directory,
        source,
        &directory.directory,
        destination,
        super::windows_staging::ExpectedRenameIdentity::File(expected),
    )
    .expect_err("raced destination must not replace");
    assert!(
        error.to_string().contains("already exists")
            || error.to_string().contains("exclusive rename")
            || error.to_string().contains("rename"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(root.path().join(source)).unwrap(),
        b"source-bytes"
    );
    assert_eq!(
        std::fs::read(root.path().join(destination)).unwrap(),
        b"racer-bytes"
    );
}

#[cfg(feature = "legacy-surrealkv")]
#[test]
fn from_std_readonly_sync_fails_closed_without_ambient_escalation() {
    let root = private_temp();
    let child = root.path().join("captured");
    astrid_core::platform_fs::create_private_directory(&child).unwrap();
    std::fs::write(child.join("LOCK"), b"lock").unwrap();
    let captured = astrid_core::platform_fs::CapturedDirectory::open(&child).unwrap();
    let clone = captured.try_clone_directory_file().unwrap();
    let capability = PrivateDirectory::from_std_directory_file(clone, child.clone()).unwrap();
    let error = capability
        .sync()
        .expect_err("readonly from_std must not publish flush authority");
    assert!(
        error.to_string().contains("no published flush authority"),
        "{error}"
    );
    // Still usable for readonly enumeration.
    let mut names = capability.entries().unwrap();
    names.sort();
    assert_eq!(names, [std::ffi::OsString::from("LOCK")]);
}

#[cfg(feature = "legacy-surrealkv")]
#[test]
fn from_std_mutating_flush_syncs_through_paired_relative_capability() {
    let root = private_temp();
    let child = root.path().join("captured");
    astrid_core::platform_fs::create_private_directory(&child).unwrap();
    std::fs::write(child.join("payload"), b"x").unwrap();
    let captured = astrid_core::platform_fs::CapturedDirectory::open(&child).unwrap();
    let flush = captured.open_paired_flush().expect("relative paired flush");
    let clone = captured.try_clone_directory_file().unwrap();
    let capability =
        PrivateDirectory::from_std_directory_file_with_flush(clone, child.clone(), Some(flush))
            .unwrap();
    capability.sync().expect("mutating captured flush");
}

#[test]
fn validate_relative_component_rejects_escape_syntax_before_host_touch() {
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::OsStringExt as _;

    let rejected = ["", ".", "..", "\\", "C:", "x:y", "../x", "a\\b", "a/b"];
    for name in rejected {
        let error = astrid_core::platform_fs::directory_capability::validate_relative_component(
            OsStr::new(name),
        )
        .expect_err(name);
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{name}: {error}"
        );
    }
    let with_nul = OsString::from_wide(&[u16::from(b'a'), 0, u16::from(b'b')]);
    let error =
        astrid_core::platform_fs::directory_capability::validate_relative_component(&with_nul)
            .expect_err("embedded NUL");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
    astrid_core::platform_fs::directory_capability::validate_relative_component(OsStr::new("café"))
        .expect("non-ASCII leaf");
}

#[test]
fn free_directory_sync_surfaces_native_flush_failure() {
    let root = private_temp();
    super::sync_directory(root.path()).expect("real directory fence");
    let _fault = astrid_core::platform_fs::directory_capability::DirectoryFlushCapability::arm_flush_failures(1);
    let error = super::sync_directory(root.path()).expect_err("flush failure must surface");
    assert!(
        error
            .to_string()
            .contains("injected directory flush failure"),
        "{error}"
    );
}
