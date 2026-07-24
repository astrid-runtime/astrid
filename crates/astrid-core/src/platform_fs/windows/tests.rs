//! Native Windows filesystem security and crash-recovery regressions.

use std::io::BufRead as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Stdio;

use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, NO_PROPAGATE_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
    UNPROTECTED_DACL_SECURITY_INFORMATION, WinWorldSid,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_GENERIC_READ};

use super::acl::*;
use super::error::*;
use super::executable::*;
use super::io::*;
use super::path::*;
use super::prelude::*;
use super::private_file::*;
use crate::groups::{BUILTIN_ADMIN, GroupConfig};
use crate::profile::PrincipalProfile;
use crate::session_token::SessionToken;

static NATIVE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial_test_guard() -> std::sync::MutexGuard<'static, ()> {
    NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn private_temp() -> tempfile::TempDir {
    let local = BaseDirs::new().unwrap().data_local_dir().to_path_buf();
    let root = tempfile::Builder::new()
        .prefix("astrid-platform-fs-")
        .tempdir_in(local)
        .unwrap();
    apply_private_acl(root.path(), true).unwrap();
    validate_private_acl(root.path(), true).unwrap();
    root
}

fn update_tree() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = private_temp();
    let install = root.path().join("install");
    let extract = root.path().join("extract");
    std::fs::create_dir(&install).unwrap();
    std::fs::create_dir(&extract).unwrap();
    apply_private_acl(&install, true).unwrap();
    apply_private_acl(&extract, true).unwrap();
    std::fs::write(install.join("astrid.exe"), b"old-cli").unwrap();
    std::fs::write(install.join("astrid-daemon.exe"), b"old-daemon").unwrap();
    std::fs::write(extract.join("astrid.exe"), b"new-cli").unwrap();
    std::fs::write(extract.join("astrid-daemon.exe"), b"new-daemon").unwrap();
    (root, install, extract)
}

fn assert_old_set(install: &Path) {
    assert_eq!(
        std::fs::read(install.join("astrid.exe")).unwrap(),
        b"old-cli"
    );
    assert_eq!(
        std::fs::read(install.join("astrid-daemon.exe")).unwrap(),
        b"old-daemon"
    );
    assert!(!install.join(TRANSACTION_JOURNAL).exists());
}

fn assert_no_executable_transaction_artifacts(install: &Path) {
    let mut unexpected = Vec::new();
    for entry in std::fs::read_dir(install).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if !matches!(
            name.as_str(),
            "astrid.exe" | "astrid-daemon.exe" | TRANSACTION_LOCK
        ) {
            unexpected.push(name);
        }
    }
    assert!(
        unexpected.is_empty(),
        "unexpected transaction artifacts: {unexpected:?}"
    );
}

fn abort_private_write(file: &Path) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("platform_fs::windows::native_tests::child_aborts_inside_private_file_replace")
        .arg("--ignored")
        .arg("--nocapture")
        .env("ASTRID_TEST_PRIVATE_FILE", file)
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(
        file.parent()
            .unwrap()
            .join(PRIVATE_FILE_TRANSACTION_JOURNAL)
            .exists()
    );
}

fn set_world_entry(path: &Path, mask: u32, protected: bool) {
    set_world_entry_with_flags(path, mask, protected, 0);
}

fn set_world_entry_with_flags(path: &Path, mask: u32, protected: bool, inheritance: u32) {
    let world = WellKnownSid::get(WinWorldSid).unwrap();
    let mut entries = [explicit_access(
        world.as_ptr(),
        TRUSTEE_IS_WELL_KNOWN_GROUP,
        inheritance,
    )];
    entries[0].grfAccessPermissions = mask;
    let mut acl: *mut ACL = null_mut();
    // SAFETY: the entry owns a live world SID and the out pointer is valid.
    let status = unsafe { SetEntriesInAclW(1, entries.as_mut_ptr(), null(), &raw mut acl) };
    assert_eq!(status, ERROR_SUCCESS);
    let allocation = LocalAllocation(acl.cast());
    let mut wide = wide_path(path).unwrap();
    let protection = if protected {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    // SAFETY: path and ACL are live for the call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | protection,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    drop(allocation);
    assert_eq!(status, ERROR_SUCCESS);
}

fn set_required_directory_acl_flags(path: &Path, extra_flags: u32) {
    let required = RequiredSids::get().unwrap();
    let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | extra_flags;
    let mut entries = [
        explicit_access(required.current_user.as_ptr(), TRUSTEE_IS_USER, inheritance),
        explicit_access(
            required.local_system.as_ptr(),
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            inheritance,
        ),
        explicit_access(
            required.administrators.as_ptr(),
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            inheritance,
        ),
    ];
    let mut acl: *mut ACL = null_mut();
    // SAFETY: all entries retain live SID storage and the out pointer is valid.
    let status = unsafe {
        SetEntriesInAclW(
            u32::try_from(entries.len()).unwrap(),
            entries.as_mut_ptr(),
            null(),
            &raw mut acl,
        )
    };
    assert_eq!(status, ERROR_SUCCESS);
    let allocation = LocalAllocation(acl.cast());
    let mut wide = wide_path(path).unwrap();
    // SAFETY: path and ACL remain live for the call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    drop(allocation);
    assert_eq!(status, ERROR_SUCCESS);
}

fn set_trusted_directory_acl_with_world_read_inheritance(path: &Path) {
    let required = RequiredSids::get().unwrap();
    let world = WellKnownSid::get(WinWorldSid).unwrap();
    let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    let mut entries = [
        explicit_access(required.current_user.as_ptr(), TRUSTEE_IS_USER, inheritance),
        explicit_access(
            required.local_system.as_ptr(),
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            inheritance,
        ),
        explicit_access(
            required.administrators.as_ptr(),
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            inheritance,
        ),
        explicit_access(world.as_ptr(), TRUSTEE_IS_WELL_KNOWN_GROUP, inheritance),
    ];
    entries[3].grfAccessPermissions = FILE_GENERIC_READ;
    let mut acl: *mut ACL = null_mut();
    // SAFETY: every entry points to live SID storage and the out pointer is
    // valid. SetEntriesInAclW copies the SID bytes into the returned ACL.
    let status = unsafe {
        SetEntriesInAclW(
            u32::try_from(entries.len()).unwrap(),
            entries.as_mut_ptr(),
            null(),
            &raw mut acl,
        )
    };
    assert_eq!(status, ERROR_SUCCESS);
    let allocation = LocalAllocation(acl.cast());
    let mut wide = wide_path(path).unwrap();
    // SAFETY: the NUL-terminated path and ACL remain live for the call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    drop(allocation);
    assert_eq!(status, ERROR_SUCCESS);
}

#[test]
fn private_create_and_atomic_write_are_acl_validated() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let directory = root.path().join("private");
    ensure_private_directory(&directory).unwrap();
    let file = directory.join("token");
    atomic_write_private_file(&file, b"secret").unwrap();
    validate_private_file(&file).unwrap();
    assert_eq!(std::fs::read(file).unwrap(), b"secret");
}

#[test]
fn private_objects_are_exact_at_namespace_creation() {
    let _serial = serial_test_guard();
    let root = private_temp();
    set_trusted_directory_acl_with_world_read_inheritance(root.path());
    let guard = TrustedPathGuard::capture(root.path()).unwrap();
    guard
        .verify_contract(BoundaryContract::TrustedForCreate)
        .unwrap();
    assert!(
        guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)
            .is_err(),
        "test parent unexpectedly has the exact private ACL"
    );

    let child = root.path().join("child");
    TEST_PROBE_DIR_CREATE_ACL.store(true, std::sync::atomic::Ordering::SeqCst);
    ensure_private_directory(&child).unwrap();
    assert!(TEST_SAW_DIR_CREATE_ACL.swap(false, std::sync::atomic::Ordering::SeqCst));
    validate_private_acl(&child, true).unwrap();

    TEST_PROBE_FILE_CREATE_ACL.store(true, std::sync::atomic::Ordering::SeqCst);
    let _lock = acquire_private_file_transaction_lock(root.path(), &guard).unwrap();
    assert!(TEST_SAW_FILE_CREATE_ACL.swap(false, std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn failed_private_directory_sequence_removes_partial_descendants() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let first = root.path().join("first");
    let target = first.join("second");
    TEST_DIRECTORY_CREATE_COMPONENTS.store(0, std::sync::atomic::Ordering::SeqCst);
    *TEST_FAIL_DIRECTORY_CREATE_AFTER_COMPONENT.lock().unwrap() = Some(0);

    let error = ensure_private_directory(&target).unwrap_err();

    assert_eq!(native_error_code(&error), Some(5));
    assert!(
        TEST_FAIL_DIRECTORY_CREATE_AFTER_COMPONENT
            .lock()
            .unwrap()
            .is_none(),
        "directory-create fault hook was not exercised"
    );
    assert_eq!(
        TEST_DIRECTORY_CREATE_COMPONENTS.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(!first.exists(), "partial first component was not removed");
    assert!(!target.exists(), "partial target was not removed");
}

#[test]
fn private_reader_revalidates_exact_file_acl_on_its_open_handle() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let file = root.path().join("token");
    atomic_write_private_file(&file, b"secret").unwrap();
    set_world_entry(&file, FILE_GENERIC_READ, true);

    assert!(read_private_file_to_string(&file).is_err());
}

#[test]
fn trusted_parent_rejects_permissive_extra_inherited_and_null_dacls() {
    let _serial = serial_test_guard();
    for (mask, protected) in [(FILE_ALL_ACCESS, true), (FILE_ALL_ACCESS, false)] {
        let root = private_temp();
        set_world_entry(root.path(), mask, protected);
        assert!(TrustedPathGuard::capture(root.path()).is_err());
    }

    let root = private_temp();
    let file = root.path().join("private");
    std::fs::write(&file, b"secret").unwrap();
    apply_private_acl(&file, false).unwrap();
    set_world_entry(&file, FILE_GENERIC_READ, true);
    assert!(validate_private_file(&file).is_err());

    let root = private_temp();
    let mut wide = wide_path(root.path()).unwrap();
    // SAFETY: a null DACL is intentionally installed for this adversarial
    // test; the temporary directory remains owned by the test process.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null(),
        )
    };
    assert_eq!(status, ERROR_SUCCESS);
    assert!(TrustedPathGuard::capture(root.path()).is_err());

    for unexpected in [INHERIT_ONLY_ACE, NO_PROPAGATE_INHERIT_ACE] {
        let root = private_temp();
        set_required_directory_acl_flags(root.path(), unexpected);
        assert!(validate_private_acl(root.path(), true).is_err());
    }
}

#[test]
fn trusted_parent_lock_blocks_path_swap() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let guarded = root.path().join("guarded");
    std::fs::create_dir(&guarded).unwrap();
    apply_private_acl(&guarded, true).unwrap();
    let guard = TrustedPathGuard::capture(&guarded).unwrap();
    let moved = root.path().join("moved");
    assert!(std::fs::rename(&guarded, &moved).is_err());
    guard.verify().unwrap();
}

#[test]
fn handle_relative_mutation_cannot_be_redirected_by_boundary_swap() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let guarded = root.path().join("guarded");
    std::fs::create_dir(&guarded).unwrap();
    apply_private_acl(&guarded, true).unwrap();
    let source = guarded.join("source");
    let destination = guarded.join("destination");
    std::fs::write(&source, b"locked-content").unwrap();
    apply_private_acl(&source, false).unwrap();
    let guard = TrustedPathGuard::capture(&guarded).unwrap();
    let moved = root.path().join("moved");

    guard
        .with_verified_mutation(
            "handle-relative rename test",
            BoundaryContract::ExactPrivateDirectory,
            || {
                assert!(std::fs::rename(&guarded, &moved).is_err());
                move_guarded_file(&guard, &source, &destination)
            },
        )
        .unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), b"locked-content");
    assert!(!moved.exists());
}

#[test]
fn handle_relative_move_and_replacement_succeed() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let moved_source = root.path().join("move-source");
    let moved_destination = root.path().join("move-destination");
    let live = root.path().join("live");
    let replacement = root.path().join("replacement");
    for (path, bytes) in [
        (&moved_source, b"moved".as_slice()),
        (&live, b"old".as_slice()),
        (&replacement, b"new".as_slice()),
    ] {
        std::fs::write(path, bytes).unwrap();
        apply_private_acl(path, false).unwrap();
    }
    let guard = TrustedPathGuard::capture(root.path()).unwrap();

    move_guarded_file(&guard, &moved_source, &moved_destination).unwrap();
    assert_eq!(std::fs::read(&moved_destination).unwrap(), b"moved");
    assert!(!moved_source.exists());

    replace_file_checked(&guard, &live, &replacement).unwrap();
    assert_eq!(std::fs::read(&live).unwrap(), b"new");
    assert!(!replacement.exists());
}

#[test]
fn handle_relative_mutation_stays_bound_during_ancestor_move() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let ancestor = root.path().join("ancestor");
    let guarded = ancestor.join("guarded");
    std::fs::create_dir(&ancestor).unwrap();
    std::fs::create_dir(&guarded).unwrap();
    apply_private_acl(&ancestor, true).unwrap();
    apply_private_acl(&guarded, true).unwrap();
    let source = guarded.join("source");
    let destination = guarded.join("destination");
    std::fs::write(&source, b"authority-bound-content").unwrap();
    apply_private_acl(&source, false).unwrap();
    let guard = TrustedPathGuard::capture(&guarded).unwrap();
    let moved_ancestor = root.path().join("moved-ancestor");

    let result = guard.with_verified_mutation(
        "ancestor-move handle-relative test",
        BoundaryContract::ExactPrivateDirectory,
        || {
            std::fs::rename(&ancestor, &moved_ancestor)?;
            move_guarded_file(&guard, &source, &destination)
        },
    );

    assert!(result.is_err());
    assert_eq!(
        std::fs::read(moved_ancestor.join("guarded").join("destination")).unwrap(),
        b"authority-bound-content"
    );
    assert!(!destination.exists());
}

#[test]
fn private_directory_creation_blocks_ancestor_move_and_cleans_partial_child() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let ancestor = root.path().join("ancestor");
    let parent = ancestor.join("parent");
    std::fs::create_dir(&ancestor).unwrap();
    std::fs::create_dir(&parent).unwrap();
    apply_private_acl(&ancestor, true).unwrap();
    apply_private_acl(&parent, true).unwrap();

    let target = parent.join("first").join("second");
    let moved_ancestor = root.path().join("moved-ancestor");
    TEST_DIRECTORY_CREATE_COMPONENTS.store(0, std::sync::atomic::Ordering::SeqCst);
    *TEST_MOVE_ANCESTOR_DURING_DIRECTORY_CREATE.lock().unwrap() =
        Some((ancestor.clone(), moved_ancestor.clone()));

    let result = ensure_private_directory(&target);

    assert!(result.is_err());
    assert!(
        TEST_MOVE_ANCESTOR_DURING_DIRECTORY_CREATE
            .lock()
            .unwrap()
            .is_none(),
        "ancestor-move hook was not exercised"
    );
    assert!(
        !moved_ancestor.exists(),
        "ancestor moved despite a retained non-delete-sharing child handle"
    );
    assert!(ancestor.exists());
    assert_eq!(
        TEST_DIRECTORY_CREATE_COMPONENTS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "ancestor move was not attempted immediately after the first component"
    );
    assert!(
        !parent.join("first").exists(),
        "failed creation left the first component behind"
    );
    assert!(!target.exists(), "failed creation left the target behind");
}

#[test]
fn verified_mutation_checks_success_error_and_panic_paths() {
    let _serial = serial_test_guard();
    let root = private_temp();
    apply_private_acl(root.path(), true).unwrap();
    let guard = TrustedPathGuard::capture(root.path()).unwrap();

    assert_eq!(
        guard
            .with_verified_mutation(
                "successful test mutation",
                BoundaryContract::ExactPrivateDirectory,
                || Ok(17),
            )
            .unwrap(),
        17
    );

    let error = guard
        .with_verified_mutation(
            "failing test mutation",
            BoundaryContract::ExactPrivateDirectory,
            || Err::<(), _>(io::Error::from_raw_os_error(5)),
        )
        .unwrap_err();
    assert_eq!(native_error_code(&error), Some(5));

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _: io::Result<()> = guard.with_verified_mutation(
            "panicking test mutation",
            BoundaryContract::ExactPrivateDirectory,
            || panic!("original mutation panic"),
        );
    }));
    assert!(panic.is_err());
    guard
        .verify_contract(BoundaryContract::ExactPrivateDirectory)
        .unwrap();
}

#[test]
fn verified_mutation_retains_commit_record_when_contract_changes() {
    let _serial = serial_test_guard();
    let root = private_temp();
    apply_private_acl(root.path(), true).unwrap();
    let journal = root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL);
    std::fs::write(&journal, b"commit-record").unwrap();
    apply_private_acl(&journal, false).unwrap();
    let guard = TrustedPathGuard::capture(root.path()).unwrap();

    let result = guard.with_verified_mutation(
        "contract-changing test mutation",
        BoundaryContract::ExactPrivateDirectory,
        || {
            set_world_entry(root.path(), FILE_ALL_ACCESS, true);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(journal.exists());

    apply_private_acl(root.path(), true).unwrap();
    std::fs::remove_file(journal).unwrap();
}

#[test]
fn verified_mutation_preserves_native_error_when_postcheck_also_fails() {
    let _serial = serial_test_guard();
    let root = private_temp();
    apply_private_acl(root.path(), true).unwrap();
    let guard = TrustedPathGuard::capture(root.path()).unwrap();

    let error = guard
        .with_verified_mutation(
            "native-error contract-changing mutation",
            BoundaryContract::ExactPrivateDirectory,
            || {
                set_world_entry(root.path(), FILE_ALL_ACCESS, true);
                Err::<(), _>(io::Error::from_raw_os_error(5))
            },
        )
        .unwrap_err();
    assert_eq!(native_error_code(&error), Some(5));
    assert!(
        error
            .to_string()
            .contains("authority-boundary verification also failed")
    );

    apply_private_acl(root.path(), true).unwrap();
}

#[test]
fn verified_mutation_resumes_original_panic_after_failed_postcheck() {
    let _serial = serial_test_guard();
    let root = private_temp();
    apply_private_acl(root.path(), true).unwrap();
    let guard = TrustedPathGuard::capture(root.path()).unwrap();

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _: io::Result<()> = guard.with_verified_mutation(
            "panicking contract-changing mutation",
            BoundaryContract::ExactPrivateDirectory,
            || {
                set_world_entry(root.path(), FILE_ALL_ACCESS, true);
                panic!("original mutation panic");
            },
        );
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"original mutation panic")
    );

    apply_private_acl(root.path(), true).unwrap();
}

#[test]
fn transaction_lock_excludes_a_second_process() {
    let _serial = serial_test_guard();
    let (_root, install, _extract) = update_tree();
    let guard = TrustedPathGuard::capture(&install).unwrap();
    drop(acquire_transaction_lock(&install, &guard).unwrap());
    let lock_path = install.join(TRANSACTION_LOCK);
    let script = concat!(
        "$f=[IO.File]::Open($env:ASTRID_LOCK_TEST_PATH,",
        "[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite);",
        "$f.Lock(0,[Int64]::MaxValue);",
        "[Console]::Out.WriteLine('ready');",
        "[Console]::Out.Flush();",
        "Start-Sleep -Seconds 30"
    );
    let mut child = std::process::Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(script)
        .env("ASTRID_LOCK_TEST_PATH", &lock_path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "ready");
    let error = acquire_transaction_lock(&install, &guard).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    child.kill().unwrap();
    child.wait().unwrap();
    acquire_transaction_lock(&install, &guard).unwrap();
}

#[test]
fn dangerous_inherit_only_ace_and_untrusted_source_are_rejected() {
    let _serial = serial_test_guard();
    let (_root, install, extract) = update_tree();
    set_world_entry_with_flags(
        &install,
        FILE_ALL_ACCESS,
        true,
        OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE,
    );
    assert!(
        replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]).is_err()
    );

    let (_root, install, extract) = update_tree();
    let source = extract.join("astrid.exe");
    set_world_entry(&source, FILE_ALL_ACCESS, true);
    assert!(
        replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]).is_err()
    );
    assert_old_set(&install);
}

#[test]
fn locked_source_handle_blocks_concurrent_mutation() {
    let _serial = serial_test_guard();
    let (_root, _install, extract) = update_tree();
    let source = extract.join("astrid.exe");
    let locked = open_locked_regular_file(&source).unwrap();
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .is_err()
    );
    assert_eq!(file_identity(&locked.file).unwrap(), locked.identity);
}

#[test]
fn redirecting_directory_component_is_rejected() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let target = root.path().join("target");
    let redirect = root.path().join("redirect");
    std::fs::create_dir(&target).unwrap();
    apply_private_acl(&target, true).unwrap();
    std::os::windows::fs::symlink_dir(&target, &redirect).unwrap();
    assert!(TrustedPathGuard::capture(&redirect).is_err());
}

#[test]
fn junction_directory_component_is_rejected() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let target = root.path().join("junction-target");
    let redirect = root.path().join("junction");
    std::fs::create_dir(&target).unwrap();
    apply_private_acl(&target, true).unwrap();
    let status = std::process::Command::new("cmd.exe")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(&redirect)
        .arg(&target)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(TrustedPathGuard::capture(&redirect).is_err());
}

#[test]
fn handle_relative_rename_failure_restores_complete_old_set() {
    let _serial = serial_test_guard();
    let (_root, install, extract) = update_tree();
    *TEST_RENAME_FAULT.lock().unwrap() = Some(ERROR_SHARING_VIOLATION);
    assert!(
        replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]).is_err()
    );
    assert_old_set(&install);
}

#[test]
fn second_entry_preparation_failure_cleans_every_staged_artifact() {
    let _serial = serial_test_guard();
    let (_root, install, extract) = update_tree();
    *TEST_PREPARATION_FAIL_AT_ENTRY.lock().unwrap() = Some(1);

    assert!(
        replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]).is_err()
    );
    assert_old_set(&install);
    assert_no_executable_transaction_artifacts(&install);
}

#[test]
fn journal_publication_failure_cleans_journal_temp_and_prepared_files() {
    let _serial = serial_test_guard();
    let (_root, install, extract) = update_tree();
    TEST_JOURNAL_RENAME_FAULT.store(true, std::sync::atomic::Ordering::SeqCst);

    assert!(
        replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]).is_err()
    );
    assert_old_set(&install);
    assert_no_executable_transaction_artifacts(&install);
}

#[test]
fn private_journal_publication_failure_cleans_every_prepared_file() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let file = root.path().join("session-token");
    atomic_write_private_file(&file, b"old-private-value").unwrap();
    TEST_JOURNAL_RENAME_FAULT.store(true, std::sync::atomic::Ordering::SeqCst);

    assert!(atomic_write_private_file(&file, b"new-private-value").is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"old-private-value");
    let unexpected = std::fs::read_dir(root.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".astrid-private") && name != PRIVATE_FILE_TRANSACTION_LOCK)
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "unexpected private transaction artifacts: {unexpected:?}"
    );
}

#[test]
fn private_write_rename_failure_restores_old_file() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let file = root.path().join("session-token");
    atomic_write_private_file(&file, b"old-private-value").unwrap();
    *TEST_RENAME_FAULT.lock().unwrap() = Some(ERROR_SHARING_VIOLATION);
    assert!(atomic_write_private_file(&file, b"new-private-value").is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"old-private-value");
    validate_private_file(&file).unwrap();
    assert!(!root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());
}

#[test]
fn backup_update_error_immediately_recovers_the_old_set() {
    let _serial = serial_test_guard();
    let (_root, install, extract) = update_tree();
    let backup = install.join("astrid.exe.bak");
    std::fs::write(&backup, b"older-cli").unwrap();
    let _locked_backup = open_locked_regular_file(&backup).unwrap();
    assert!(
        replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]).is_err()
    );
    assert_old_set(&install);
}

#[test]
#[ignore = "invoked only as a subprocess by process_abort_recovers_on_next_run"]
fn child_aborts_after_first_replacement() {
    let install = PathBuf::from(std::env::var_os("ASTRID_TEST_INSTALL").unwrap());
    let extract = PathBuf::from(std::env::var_os("ASTRID_TEST_EXTRACT").unwrap());
    TEST_ABORT_AFTER_REPLACE.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]);
    panic!("replacement unexpectedly survived the abort hook");
}

#[test]
fn process_abort_recovers_on_next_run() {
    let _serial = serial_test_guard();
    let (_root, install, extract) = update_tree();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("platform_fs::windows::native_tests::child_aborts_after_first_replacement")
        .arg("--ignored")
        .arg("--nocapture")
        .env("ASTRID_TEST_INSTALL", &install)
        .env("ASTRID_TEST_EXTRACT", &extract)
        .status()
        .unwrap();
    assert!(!status.success());
    recover_executable_transaction(&install).unwrap();
    assert_old_set(&install);
}

#[test]
#[ignore = "invoked only as a subprocess by private-file reader recovery tests"]
fn child_aborts_inside_private_file_replace() {
    let file = PathBuf::from(std::env::var_os("ASTRID_TEST_PRIVATE_FILE").unwrap());
    TEST_ABORT_INSIDE_REPLACE.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = atomic_write_private_file(&file, b"new-private-value");
    panic!("private-file replacement unexpectedly survived the abort hook");
}

#[test]
fn real_private_file_readers_recover_old_state_after_process_abort() {
    let _serial = serial_test_guard();
    let root = private_temp();

    let profile_path = root.path().join("alice.toml");
    PrincipalProfile::default()
        .save_to_path(&profile_path)
        .unwrap();
    abort_private_write(&profile_path);
    assert_eq!(
        PrincipalProfile::load_from_path(&profile_path).unwrap(),
        PrincipalProfile::default()
    );
    assert!(!root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());

    let groups_path = root.path().join("groups.toml");
    GroupConfig::builtin_only()
        .save_to_path(&groups_path)
        .unwrap();
    abort_private_write(&groups_path);
    let groups = GroupConfig::load_from_path(&groups_path).unwrap();
    assert!(groups.get(BUILTIN_ADMIN).is_some());
    assert!(!root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());

    let token_path = root.path().join("system.token");
    let token = SessionToken::generate();
    let expected_token = token.to_hex();
    token.write_to_file(&token_path).unwrap();
    abort_private_write(&token_path);
    assert_eq!(
        SessionToken::read_from_file(&token_path).unwrap().to_hex(),
        expected_token
    );
    assert!(!root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());
}

#[test]
#[ignore = "invoked only as a subprocess by concurrent_reader_rejects_uncommitted_private_write"]
fn child_pauses_inside_private_file_replace() {
    let file = PathBuf::from(std::env::var_os("ASTRID_TEST_PRIVATE_FILE").unwrap());
    TEST_PAUSE_INSIDE_REPLACE.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = atomic_write_private_file(&file, b"new-private-value");
    panic!("private-file replacement unexpectedly survived the pause hook");
}

#[test]
fn concurrent_reader_rejects_uncommitted_private_write() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let token_path = root.path().join("system.token");
    let token = SessionToken::generate();
    let expected_token = token.to_hex();
    token.write_to_file(&token_path).unwrap();

    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("platform_fs::windows::native_tests::child_pauses_inside_private_file_replace")
        .arg("--ignored")
        .arg("--nocapture")
        .env("ASTRID_TEST_PRIVATE_FILE", &token_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(output.read_line(&mut line).unwrap(), 0);
        if line.contains("astrid-private-replace-ready") {
            break;
        }
    }
    assert!(root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());
    let error = SessionToken::read_from_file(&token_path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(
        SessionToken::read_from_file(&token_path).unwrap().to_hex(),
        expected_token
    );
    assert!(!root.path().join(PRIVATE_FILE_TRANSACTION_JOURNAL).exists());
}

#[test]
fn interrupted_replacement_recovers_at_each_mutation_phase() {
    let _serial = serial_test_guard();
    for crash_after in [0, 1] {
        let (_root, install, extract) = update_tree();
        *TEST_CRASH_AFTER_REPLACE.lock().unwrap() = Some(crash_after);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = replace_executable_set(
                    &install,
                    &extract,
                    &["astrid.exe", "astrid-daemon.exe"],
                );
            }))
            .is_err()
        );
        *TEST_CRASH_AFTER_REPLACE.lock().unwrap() = None;
        recover_executable_transaction(&install).unwrap();
        assert_old_set(&install);
        replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]).unwrap();
        assert_eq!(
            std::fs::read(install.join("astrid.exe")).unwrap(),
            b"new-cli"
        );
        assert_eq!(
            std::fs::read(install.join("astrid-daemon.exe")).unwrap(),
            b"new-daemon"
        );
        assert!(!install.join(TRANSACTION_JOURNAL).exists());
    }

    let (_root, install, extract) = update_tree();
    *TEST_CRASH_BEFORE_COMMIT.lock().unwrap() = true;
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ =
                replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]);
        }))
        .is_err()
    );
    *TEST_CRASH_BEFORE_COMMIT.lock().unwrap() = false;
    recover_executable_transaction(&install).unwrap();
    assert_old_set(&install);
    replace_executable_set(&install, &extract, &["astrid.exe", "astrid-daemon.exe"]).unwrap();
    assert_eq!(
        std::fs::read(install.join("astrid.exe")).unwrap(),
        b"new-cli"
    );
    assert_eq!(
        std::fs::read(install.join("astrid-daemon.exe")).unwrap(),
        b"new-daemon"
    );
}
