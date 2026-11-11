//! Native NTFS directory-flush access fixture (ordinary-user effective token).

use std::fs::File;
use std::io::{self, Write as _};

use super::super::directory_durability::{DirectoryFlushHandle, OrdinaryUserImpersonation};
use super::{private_temp, serial_test_guard};

#[test]
fn ordinary_user_ntfs_directory_flush_before_and_after_child_delete() {
    let _lock = serial_test_guard();
    let _ordinary = OrdinaryUserImpersonation::enter().unwrap_or_else(|error| {
        panic!("cannot prove ordinary-user effective token for flush fixture: {error:?}");
    });

    let root = private_temp();
    let child = root.path().join("pre-flush-child.txt");
    std::fs::write(&child, b"delete-then-flush").unwrap();

    // Regression: ambient File::open + sync_all is not a Windows directory barrier.
    let old_err = File::open(root.path())
        .and_then(|file| file.sync_all())
        .expect_err("File::open(root).sync_all must fail on a Windows directory");
    println!("legacy_file_open_sync_all_error={old_err:?}");

    let (handle, observation) =
        DirectoryFlushHandle::open_verified(root.path()).unwrap_or_else(|error| {
            panic!("pre-delete NTFS directory flush verification failed: {error:?}");
        });
    println!(
        "directory_flush_probe filesystem={} desired_access=0x{:08X} syscall_ntstatus=0x{:08X} iosb_ntstatus=0x{:08X} identity={:?}",
        observation.filesystem.to_string_lossy(),
        observation.desired_access,
        observation.syscall_ntstatus.cast_unsigned(),
        observation.iosb_ntstatus.cast_unsigned(),
        observation.identity,
    );
    assert!(
        observation
            .filesystem
            .to_string_lossy()
            .eq_ignore_ascii_case("NTFS"),
        "probe host volume must be NTFS for MS-FSA <80> barrier claim"
    );
    assert_eq!(observation.syscall_ntstatus, 0);
    assert_eq!(observation.iosb_ntstatus, 0);

    std::fs::remove_file(&child).unwrap();
    handle.flush_after_delete().unwrap_or_else(|error| {
        panic!("post-delete NtFlushBuffersFileEx(0) failed: {error:?}");
    });
    println!("directory_flush_probe post_delete_ok=1");
    let _ = io::stdout().flush();
}
