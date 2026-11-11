//! Observational native probe for ancestor rename while root authority is held.
//!
//! Either ancestor outcome is recorded; the direct-root fence, held-object
//! usability and post-drop control are asserted.

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::BorrowedHandle;
use std::path::Path;

use super::super::acl::{apply_private_acl, validate_private_acl_handle};
use super::super::captured_directory::query_directory_identity;
use super::super::directory_capability::{DirectoryFlushCapability, open_directory_flush};
use super::super::path::{BoundaryContract, TrustedPathGuard, create_private_directory};
use super::{private_temp, serial_test_guard};
use crate::platform_fs::DirectoryIdentity;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

const CHILD_BEFORE: &[u8] = b"probe-before";
const CHILD_AFTER: &[u8] = b"/after-ancestor-attempt";

#[derive(Clone, Copy)]
enum ProbeCase {
    GuardHeld,
    PairedAfterGuardDrop,
    PairedAndShareDeleteChildAfterGuardDrop,
}

impl ProbeCase {
    fn label(self) -> &'static str {
        match self {
            Self::GuardHeld => "guard-held",
            Self::PairedAfterGuardDrop => "paired-after-guard-drop",
            Self::PairedAndShareDeleteChildAfterGuardDrop => {
                "paired-share-delete-child-after-guard-drop"
            }
        }
    }
}

enum HeldAuthority {
    Guard(TrustedPathGuard),
    Paired(DirectoryFlushCapability),
    PairedWithChild {
        // Windows cleanup must release the ordinary child before its root cap.
        child: File,
        capability: DirectoryFlushCapability,
    },
}

impl HeldAuthority {
    fn capture(case: ProbeCase, root: &Path) -> Self {
        let guard = TrustedPathGuard::capture(root).unwrap();
        guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)
            .unwrap();
        if matches!(case, ProbeCase::GuardHeld) {
            return Self::Guard(guard);
        }
        // SAFETY: the guard owns this live directory handle throughout paired
        // capture. The borrowed view transfers no ownership; the paired API
        // duplicates its own authority before the guard is explicitly dropped.
        let borrowed = unsafe { BorrowedHandle::borrow_raw(guard.authority_handle().cast()) };
        let capability = open_directory_flush(root, borrowed).unwrap();
        drop(guard);
        if matches!(case, ProbeCase::PairedAfterGuardDrop) {
            return Self::Paired(capability);
        }
        let child = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(root.join("ordinary-child"))
            .unwrap();
        Self::PairedWithChild { child, capability }
    }

    fn identity(&self) -> DirectoryIdentity {
        match self {
            Self::Guard(guard) => {
                // SAFETY: this borrowed view ends before the retained guard.
                let borrowed =
                    unsafe { BorrowedHandle::borrow_raw(guard.authority_handle().cast()) };
                query_directory_identity(&borrowed).unwrap()
            }
            Self::Paired(capability) | Self::PairedWithChild { capability, .. } => {
                query_directory_identity(capability.file()).unwrap()
            }
        }
    }

    fn prove_owned_object_usable(&mut self, expected: DirectoryIdentity) {
        assert_eq!(self.identity(), expected);
        match self {
            Self::Guard(guard) => {
                // Validate the retained object, without verifying its old label.
                validate_private_acl_handle(guard.authority_handle(), true, "probe held root")
                    .unwrap();
            }
            Self::Paired(capability) | Self::PairedWithChild { capability, .. } => {
                assert_eq!(capability.identity(), expected);
                capability.flush().unwrap();
            }
        }
        if let Self::PairedWithChild { child, .. } = self {
            child.seek(SeekFrom::End(0)).unwrap();
            child.write_all(CHILD_AFTER).unwrap();
            child.sync_all().unwrap();
            child.seek(SeekFrom::Start(0)).unwrap();
            let mut bytes = Vec::new();
            child.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, [CHILD_BEFORE, CHILD_AFTER].concat());
        }
    }
}

fn record(case: ProbeCase, operation: &str, result: &io::Result<()>) {
    let raw_error = result.as_ref().err().and_then(io::Error::raw_os_error);
    // Write directly so markers survive successful libtest capture without any
    // changes to the existing native command's flags or required test set.
    let mut output = io::stdout().lock();
    writeln!(output,
        "ASTRID_WINDOWS_ANCESTOR_PROBE case={} operation={operation} succeeded={} raw_os_error={raw_error:?}",
        case.label(), result.is_ok(),
    ).unwrap();
    output.flush().unwrap();
}

fn probe(case: ProbeCase) {
    let _serial = serial_test_guard();
    // Declared before all native handles, so unwinding also drops handles before
    // TempDir recursively cleans up the owned fixture.
    let temporary = private_temp();
    let ancestor = temporary.path().join("ancestor");
    let root = ancestor.join("runtime");
    create_private_directory(&ancestor).unwrap();
    create_private_directory(&root).unwrap();
    if matches!(case, ProbeCase::PairedAndShareDeleteChildAfterGuardDrop) {
        let child = root.join("ordinary-child");
        std::fs::write(&child, CHILD_BEFORE).unwrap();
        apply_private_acl(&child, false).unwrap();
    }
    let mut held = HeldAuthority::capture(case, &root);
    let identity = held.identity();
    let direct_destination = ancestor.join("direct-root-rename");
    let direct_result = std::fs::rename(&root, &direct_destination);
    record(case, "direct-root-rename-held", &direct_result);
    assert!(
        direct_result.is_err(),
        "retained root authority must deny a direct root rename"
    );
    assert!(root.is_dir());
    assert!(!direct_destination.exists());

    let moved = temporary.path().join("moved-ancestor");
    let ancestor_result = std::fs::rename(&ancestor, &moved);
    record(case, "ancestor-rename-held", &ancestor_result);
    if ancestor_result.is_ok() {
        assert!(!ancestor.exists());
        assert!(!root.exists());
        assert!(moved.join("runtime").is_dir());
    } else {
        assert!(root.is_dir());
        assert!(!moved.exists());
    }
    held.prove_owned_object_usable(identity);
    drop(held);
    if ancestor_result.is_ok() {
        // Restore the starting names only after releasing every native handle,
        // then exercise the identical source/destination positive control.
        let reset = std::fs::rename(&moved, &ancestor);
        record(case, "reset-after-drop", &reset);
        reset.unwrap();
    }
    let control = std::fs::rename(&ancestor, &moved);
    record(case, "same-ancestor-rename-after-drop", &control);
    control.unwrap();
    assert!(!ancestor.exists());
    assert!(moved.join("runtime").is_dir());
}

#[test]
fn existing_guard_observes_ancestor_rename_with_positive_control() {
    probe(ProbeCase::GuardHeld);
}

#[test]
fn paired_capability_after_guard_drop_observes_ancestor_rename_with_positive_control() {
    probe(ProbeCase::PairedAfterGuardDrop);
}

#[test]
fn paired_capability_and_share_delete_child_observe_ancestor_rename_with_positive_control() {
    probe(ProbeCase::PairedAndShareDeleteChildAfterGuardDrop);
}
