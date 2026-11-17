//! Child and parent namespace barriers for private directory creation.

use super::*;

#[test]
fn ensure_nested_directory_birth_requires_namespace_flush() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();

    let nested = projection_root.join("a").join("b");
    assert!(!nested.exists(), "precondition: nested dirs absent");

    // Child flush runs before parent flush; fail the first flush point.
    let fault = install_descendant_namespace_flush_failures(1);
    let error = projection
        .ensure_directory(&rel(&["a", "b"]))
        .expect_err("created directory namespace flush must be required");
    assert!(
        error
            .to_string()
            .contains("injected descendant namespace flush failure"),
        "{error}"
    );
    // Partial creates are cleaned up on failure (CreatedPrivateDirectories).
    assert!(
        !nested.exists(),
        "failed birth must not leave durable nested leaf after cleanup"
    );
    drop(fault);

    projection.ensure_directory(&rel(&["a", "b"])).unwrap();
    assert!(
        nested.is_dir(),
        "successful ensure must materialize nested dirs"
    );
    projection.sync().unwrap();
}

#[test]
fn ensure_nested_directory_parent_flush_required_after_child_flush() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();

    // Pre-create the intermediate so the next birth's parent is an existing
    // non-leaf component (may allow FILE_SHARE_DELETE) while still requiring
    // the parent namespace fence after a successful child flush.
    projection.ensure_directory(&rel(&["existing-a"])).unwrap();
    let nested = projection_root.join("existing-a").join("new-b");
    assert!(!nested.exists(), "precondition: new-b absent");

    let fault = install_descendant_parent_namespace_flush_failure();
    let error = projection
        .ensure_directory(&rel(&["existing-a", "new-b"]))
        .expect_err("parent namespace flush after successful child flush must be required");
    assert!(
        error
            .to_string()
            .contains("injected descendant parent namespace flush failure"),
        "{error}"
    );
    assert!(
        !nested.exists(),
        "failed parent fence must clean up the newly created child"
    );
    assert!(
        projection_root.join("existing-a").is_dir(),
        "pre-existing intermediate must remain after child cleanup"
    );
    drop(fault);

    projection
        .ensure_directory(&rel(&["existing-a", "new-b"]))
        .unwrap();
    assert!(
        nested.is_dir(),
        "cleared parent-fault arm must create new-b"
    );
    projection.sync().unwrap();
}

#[test]
fn missing_projection_root_create_requires_namespace_flush() {
    let _serial = serial_test_guard();
    for parent_only in [false, true] {
        let root = private_temp();
        let projection_root = root.path().join("missing-root");
        assert!(
            !projection_root.exists(),
            "projection root must start absent"
        );

        // Exercise both fences in the missing-root creation path. The parent
        // arm reaches a successful child flush before rejecting publication.
        let (fault, expected) = if parent_only {
            (
                install_descendant_parent_namespace_flush_failure(),
                "injected descendant parent namespace flush failure",
            )
        } else {
            (
                install_descendant_namespace_flush_failures(1),
                "injected descendant namespace flush failure",
            )
        };
        let Err(error) = ProjectionRoot::open_writer(&projection_root, None) else {
            panic!("missing-root creation requires both namespace fences");
        };
        assert!(error.to_string().contains(expected), "{error}");
        assert!(
            !projection_root.exists(),
            "failed missing-root fence must clean up the new root"
        );
        drop(fault);

        let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();
        assert!(projection_root.is_dir());
        projection.sync().unwrap();
    }
}
