//! Windows append authority reuses existing native identity and birth fixtures.

use super::*;
use crate::platform_fs::PrivateProjectionInspection;

fn capture(root: &Path) -> crate::platform_fs::PrivateAppendRoot {
    PrivateProjectionInspection::try_open(root)
        .unwrap()
        .capture_append_root()
        .unwrap()
}

#[test]
fn append_rejects_changed_ancestor_or_os_denies_its_rename() {
    let _serial = serial_test_guard();
    let dir = private_temp();
    let ancestor = dir.path().join("ancestor");
    let home = ancestor.join("home");
    crate::platform_fs::ensure_private_directory(&home).unwrap();
    let append = capture(&home);
    if std::fs::rename(&ancestor, dir.path().join("parked")).is_ok() {
        crate::platform_fs::ensure_private_directory(&home).unwrap();
        assert!(
            append
                .open_private_append(Path::new("log/day.log"))
                .is_err()
        );
        assert!(!home.join("log/day.log").exists());
    } else {
        append
            .open_private_append(Path::new("log/day.log"))
            .unwrap()
            .write_all(b"bound")
            .unwrap();
        assert_eq!(std::fs::read(home.join("log/day.log")).unwrap(), b"bound");
    }
}

#[test]
fn append_midwalk_parent_swap_cannot_adopt_replacement() {
    let _serial = serial_test_guard();
    let dir = private_temp();
    let home = dir.path().join("home");
    let mid = home.join("mid");
    crate::platform_fs::ensure_private_directory(&mid.join("nested")).unwrap();
    let append = capture(&home);
    let replacement = dir.path().join("replacement");
    crate::platform_fs::ensure_private_directory(&replacement.join("nested")).unwrap();
    let leaf = replacement.join("nested/day.log");
    std::fs::write(&leaf, b"outside").unwrap();
    apply_private_acl(&leaf, false).unwrap();
    *TEST_MOVE_DESCENDANT_DURING_CAPTURE.lock().unwrap() =
        Some((mid, dir.path().join("parked"), replacement));
    assert!(
        append
            .open_private_append(Path::new("mid/nested/day.log"))
            .is_err()
    );
    assert!(
        TEST_MOVE_DESCENDANT_DURING_CAPTURE
            .lock()
            .unwrap()
            .is_none()
    );
    let original = home.join("mid/nested/day.log");
    let outside = if original.exists() { original } else { leaf };
    assert_eq!(std::fs::read(outside).unwrap(), b"outside");
}

#[test]
fn append_reports_native_child_birth_fence_failure() {
    let _serial = serial_test_guard();
    let dir = private_temp();
    let append = capture(dir.path());
    let _fault = install_descendant_namespace_flush_failures(1);
    assert!(
        append
            .open_private_append(Path::new("log/day.log"))
            .is_err()
    );
    assert!(!dir.path().join("log/day.log").exists());
}

#[test]
fn shared_home_authority_does_not_pin_removable_log_directories() {
    let _serial = serial_test_guard();
    let dir = private_temp();
    let append = capture(dir.path());
    let mut file = append
        .open_private_append(Path::new("log/day.log"))
        .unwrap();
    file.write_all(b"history").unwrap();
    drop(file);
    std::fs::remove_file(dir.path().join("log/day.log")).unwrap();
    std::fs::remove_dir(dir.path().join("log")).unwrap();
    assert!(!dir.path().join("log").exists());
    append
        .open_private_append(Path::new("log/day.log"))
        .unwrap()
        .write_all(b"new")
        .unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("log/day.log")).unwrap(),
        b"new"
    );
}

#[test]
fn append_create_has_private_acl_before_any_post_open_repair() {
    let _serial = serial_test_guard();
    let dir = private_temp();
    let append = capture(dir.path());
    TEST_APPLY_PRIVATE_ACL_COUNT.with(|count| count.set(0));
    let file = append.open_private_append(Path::new("day.log")).unwrap();
    assert_eq!(TEST_APPLY_PRIVATE_ACL_COUNT.with(std::cell::Cell::get), 0);
    validate_private_acl_handle(file.as_raw_handle().cast(), false, "appended daily log").unwrap();
}

#[test]
fn append_write_and_sync_all_succeed_on_new_and_existing_leaves() {
    let _serial = serial_test_guard();
    let dir = private_temp();
    let append = capture(dir.path());
    let mut created = append.open_private_append(Path::new("day.log")).unwrap();
    created.write_all(b"one").unwrap();
    created.sync_all().unwrap();
    drop(created);
    assert_eq!(std::fs::read(dir.path().join("day.log")).unwrap(), b"one");
    let mut existing = append.open_private_append(Path::new("day.log")).unwrap();
    existing.write_all(b"two").unwrap();
    existing.sync_all().unwrap();
    drop(existing);
    assert_eq!(
        std::fs::read(dir.path().join("day.log")).unwrap(),
        b"onetwo"
    );
}

#[test]
fn append_repairs_existing_leaf_acl_without_rewriting_birth_acl() {
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

    let _serial = serial_test_guard();
    let dir = private_temp();
    let append = capture(dir.path());
    TEST_APPLY_PRIVATE_ACL_COUNT.with(|count| count.set(0));
    let mut file = append.open_private_append(Path::new("day.log")).unwrap();
    file.write_all(b"kept").unwrap();
    drop(file);
    assert_eq!(TEST_APPLY_PRIVATE_ACL_COUNT.with(std::cell::Cell::get), 0);

    super::super::set_world_entry(&dir.path().join("day.log"), FILE_GENERIC_READ, true);
    let mut file = append.open_private_append(Path::new("day.log")).unwrap();
    assert!(TEST_APPLY_PRIVATE_ACL_COUNT.with(std::cell::Cell::get) >= 1);
    validate_private_acl_handle(file.as_raw_handle().cast(), false, "repaired daily log").unwrap();
    assert_eq!(std::fs::read(dir.path().join("day.log")).unwrap(), b"kept");
    file.seek(std::io::SeekFrom::Start(0)).unwrap();
    file.write_all(b" appended").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(
        std::fs::read(dir.path().join("day.log")).unwrap(),
        b"kept appended"
    );
}

#[test]
fn append_refuses_a_junction_parent_without_touching_target() {
    let _serial = serial_test_guard();
    let dir = private_temp();
    let home = dir.path().join("home");
    let target = dir.path().join("target");
    crate::platform_fs::ensure_private_directory(&home).unwrap();
    crate::platform_fs::ensure_private_directory(&target).unwrap();
    let append = capture(&home);
    let status = std::process::Command::new("cmd.exe")
        .args(["/C", "mklink", "/J"])
        .arg(home.join("log"))
        .arg(&target)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        append
            .open_private_append(Path::new("log/day.log"))
            .is_err()
    );
    assert!(!target.join("day.log").exists());
}

#[test]
fn append_leaf_birth_does_not_add_a_projection_namespace_flush() {
    let _serial = serial_test_guard();
    let dir = private_temp();
    let append = capture(dir.path());
    let fault = install_namespace_flush_failures(1);
    let mut file = append.open_private_append(Path::new("day.log")).unwrap();
    drop(fault);
    file.write_all(b"line").unwrap();
    assert_eq!(std::fs::read(dir.path().join("day.log")).unwrap(), b"line");
}

#[test]
fn append_capture_rejects_an_existing_nonprivate_root_without_repair() {
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

    let _serial = serial_test_guard();
    let dir = private_temp();
    super::super::set_world_entry(dir.path(), FILE_GENERIC_READ, true);
    assert!(crate::platform_fs::ensure_private_directory(dir.path()).is_err());
    assert!(PrivateProjectionInspection::try_open(dir.path()).is_err());
    assert!(validate_private_acl(dir.path(), true).is_err());
    assert!(!dir.path().join("day.log").exists());
}
