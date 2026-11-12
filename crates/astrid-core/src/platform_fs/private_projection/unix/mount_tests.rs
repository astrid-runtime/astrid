//! Real mount substitutions exercised by the native Linux private-namespace job.

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use super::hooks::{self, Event};
use crate::platform_fs::PrivateFileProjection;
use crate::platform_fs::mount_fixtures::{BindMount, require_private_namespace};

#[test]
#[ignore = "requires CAP_SYS_ADMIN in a caller-owned private mount namespace; run by native Linux CI"]
fn bind_mount_projection_operations_reject_existing_file_and_parent_mounts() {
    require_private_namespace();
    for directory in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let writer = PrivateFileProjection::open(root.path()).unwrap();
        let relative = if directory { "mounted/leaf" } else { "mounted" };
        writer.write(Path::new(relative), b"original").unwrap();
        writer.sync().unwrap();
        let target = root.path().join("mounted");
        let mut mounted = BindMount::attach(&target).unwrap();
        for result in [
            writer.snapshot(Path::new(relative)).map(|_| ()),
            writer.write(Path::new(relative), b"replacement"),
            writer.remove(Path::new(relative)),
        ] {
            let error = result.unwrap_err();
            assert!(error.to_string().contains("mount boundary"), "{error}");
        }
        mounted.unmount().unwrap();
        assert_eq!(
            std::fs::read(root.path().join(relative)).unwrap(),
            b"original"
        );
    }
}

#[test]
#[ignore = "requires CAP_SYS_ADMIN in a caller-owned private mount namespace; run by native Linux CI"]
fn bind_mount_projection_rechecks_leaf_after_capture_before_mutation() {
    require_private_namespace();
    for operation in [Event::BeforeRename, Event::BeforeUnlink] {
        let root = tempfile::tempdir().unwrap();
        let writer = PrivateFileProjection::open(root.path()).unwrap();
        let relative = Path::new("staging");
        writer
            .write(relative, b"unadmitted sentinel staging")
            .unwrap();
        writer.sync().unwrap();
        let target = root.path().join(relative);
        let mounted = Rc::new(RefCell::new(None));
        let captured = Rc::clone(&mounted);
        let mount_path = target.clone();
        let hook = hooks::install(move |event| {
            if event == operation {
                assert!(captured.borrow().is_none(), "mount hook must run once");
                *captured.borrow_mut() = Some(BindMount::attach(&mount_path)?);
            }
            Ok(())
        });
        let result = if operation == Event::BeforeRename {
            writer.write(relative, b"replacement")
        } else {
            writer.remove(relative)
        };
        drop(hook);
        let error = result.unwrap_err();
        assert!(error.to_string().contains("mount boundary"), "{error}");
        mounted
            .borrow_mut()
            .as_mut()
            .expect("real bind mount reached")
            .unmount()
            .unwrap();
        assert_eq!(
            std::fs::read(target).unwrap(),
            b"unadmitted sentinel staging"
        );
    }
}

#[test]
#[ignore = "requires CAP_SYS_ADMIN in a caller-owned private mount namespace; run by native Linux CI"]
fn bind_mount_inspection_rejects_matching_directory_and_file() {
    require_private_namespace();
    let root = tempfile::tempdir().unwrap();
    let writer = PrivateFileProjection::open(root.path()).unwrap();
    writer.ensure_directory(Path::new("mounted")).unwrap();
    writer
        .write(Path::new("mounted/leaf"), b"catalog-identical")
        .unwrap();
    writer.sync().unwrap();

    let inspection =
        crate::platform_fs::PrivateProjectionInspection::try_open(root.path()).unwrap();
    assert!(
        inspection
            .matches_private_directory(Path::new("mounted"))
            .unwrap()
    );
    assert!(
        inspection
            .matches_private_file(Path::new("mounted/leaf"), b"catalog-identical")
            .unwrap()
    );

    let target = root.path().join("mounted");
    let mut mounted = BindMount::attach(&target).unwrap();
    assert!(
        !inspection
            .matches_private_directory(Path::new("mounted"))
            .unwrap(),
        "same-device directory bind must not satisfy inspection"
    );
    assert!(
        !inspection
            .matches_private_file(Path::new("mounted/leaf"), b"catalog-identical")
            .unwrap(),
        "same-device file bind must not satisfy inspection"
    );
    mounted.unmount().unwrap();
}

#[test]
#[ignore = "requires CAP_SYS_ADMIN in a caller-owned private mount namespace; run by native Linux CI"]
fn bind_mount_inspection_bound_writer_keeps_original_mount_authority() {
    require_private_namespace();
    let root = tempfile::tempdir().unwrap();
    let writer = PrivateFileProjection::open(root.path()).unwrap();
    writer.write(Path::new("sentinel"), b"original").unwrap();
    writer.sync().unwrap();
    let inspection =
        crate::platform_fs::PrivateProjectionInspection::try_open(root.path()).unwrap();
    let mut mounted = BindMount::attach(root.path()).unwrap();
    let error = match inspection.open_writer() {
        Ok(_) => panic!("root bind mount must not rebase captured authority"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("mount boundary"), "{error}");
    mounted.unmount().unwrap();
    assert_eq!(
        std::fs::read(root.path().join("sentinel")).unwrap(),
        b"original"
    );
    inspection.open_writer().unwrap().sync().unwrap();
}
