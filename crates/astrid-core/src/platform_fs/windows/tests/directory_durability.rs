//! Native NTFS directory-flush access fixture (ordinary-user effective token).
//!
//! Exercises the shared production opener/flush (`ntfs_directory_flush`), not a
//! probe-local NtFlush/FileId/NTFS protocol.

use std::fs::File;
use std::io::{self, Write as _};

use super::super::directory_durability::{DirectoryFlushHandle, OrdinaryUserImpersonation};
use super::super::ntfs_directory_flush::DIRECTORY_FLUSH_ACCESS;
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
            panic!("pre-delete shared NTFS directory flush verification failed: {error:?}");
        });
    assert!(
        observation.shared_production_flush,
        "observation must record PASS only after shared flush Ok"
    );
    assert_eq!(observation.desired_access, DIRECTORY_FLUSH_ACCESS);
    println!(
        "directory_flush_probe shared_production_flush=PASS desired_access=0x{:08X} identity={:?}",
        observation.desired_access, observation.identity,
    );

    // Child delete stays under the retained TrustedPathGuard (no ambient path
    // rebind between identity-bound open and post-delete flush).
    handle
        .remove_child_file(&child)
        .unwrap_or_else(|error| panic!("authority-relative child delete failed: {error:?}"));
    handle.flush_after_delete().unwrap_or_else(|error| {
        panic!("post-delete shared production directory flush failed: {error:?}");
    });
    println!("directory_flush_probe post_delete_shared_production_flush=PASS");
    let _ = io::stdout().flush();
}
