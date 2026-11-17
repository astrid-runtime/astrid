//! Error boundaries use real filesystem operations followed by injected errors.

use std::cell::RefCell;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::rc::Rc;

use super::hooks::{self, Event};
use crate::platform_fs::PrivateFileProjection;

#[test]
fn failed_root_preparation_fences_the_captured_root_before_returning() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let events = Rc::new(RefCell::new(Vec::new()));
    let recorded = Rc::clone(&events);
    let _hook = hooks::install(move |event| {
        recorded.borrow_mut().push(event);
        if event == Event::RootRepairSynced {
            return Err(io::Error::other("injected after real root repair fsync"));
        }
        Ok(())
    });
    let error = PrivateFileProjection::open(root.path()).err().unwrap();
    assert!(error.to_string().contains("root repair fsync"));
    assert_eq!(
        fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        &*events.borrow(),
        &[Event::RootRepairSynced, Event::RootSynced]
    );
}

#[test]
fn failed_temporary_cleanup_is_retried_before_terminal_success() {
    failed_cleanup(false);
}

#[test]
fn persistent_temporary_cleanup_failure_still_fences_and_prevents_success() {
    failed_cleanup(true);
}

fn failed_cleanup(persistent: bool) {
    let root = tempfile::tempdir().unwrap();
    let writer = PrivateFileProjection::open(root.path()).unwrap();
    let events = Rc::new(RefCell::new(Vec::new()));
    let recorded = Rc::clone(&events);
    let mut write_failed = false;
    let mut cleanup_failed = false;
    let hook = hooks::install(move |event| {
        recorded.borrow_mut().push(event);
        if event == Event::FileSynced && !write_failed {
            write_failed = true;
            return Err(io::Error::other("injected after real file fsync"));
        }
        if event == Event::BeforeTemporaryCleanup && (!cleanup_failed || persistent) {
            cleanup_failed = true;
            return Err(io::Error::other("injected cleanup failure"));
        }
        Ok(())
    });
    let error = writer
        .write(Path::new("destination"), b"authoritative")
        .unwrap_err();
    assert!(error.to_string().contains("temporary cleanup failed"));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    let result = writer.sync();
    if persistent {
        assert!(result.unwrap_err().to_string().contains("cleanup failure"));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    } else {
        result.unwrap();
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
    assert!(events.borrow().contains(&Event::RootSynced));
    drop(hook);
    writer.sync().unwrap();
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    assert!(!root.path().join("destination").exists());
}

#[test]
fn cleanup_retries_parent_fsync_after_the_temporary_name_was_unlinked() {
    let root = tempfile::tempdir().unwrap();
    let writer = PrivateFileProjection::open(root.path()).unwrap();
    let events = Rc::new(RefCell::new(Vec::new()));
    let recorded = Rc::clone(&events);
    let mut failed_write = false;
    let mut failed_cleanup = false;
    let hook = hooks::install(move |event| {
        recorded.borrow_mut().push(event);
        if event == Event::FileSynced && !failed_write {
            failed_write = true;
            return Err(io::Error::other(
                "injected write failure after real file fsync",
            ));
        }
        if event == Event::TemporaryUnlinked && !failed_cleanup {
            failed_cleanup = true;
            return Err(io::Error::other(
                "injected error after unlink before parent fsync",
            ));
        }
        Ok(())
    });
    let error = writer
        .write(Path::new("destination"), b"authoritative")
        .unwrap_err();
    assert!(error.to_string().contains("temporary cleanup failed"));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    assert!(writer.platform.pending_temporary.borrow().is_some());
    writer.sync().unwrap();
    assert!(writer.platform.pending_temporary.borrow().is_none());
    assert_eq!(
        events
            .borrow()
            .iter()
            .filter(|&&event| event == Event::TemporaryUnlinked)
            .count(),
        1
    );
    assert!(events.borrow().contains(&Event::RootSynced));
    drop(hook);
    assert!(!root.path().join("destination").exists());
}
