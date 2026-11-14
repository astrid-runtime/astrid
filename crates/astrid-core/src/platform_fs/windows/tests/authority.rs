//! Retained-authority behavior while an ancestor namespace entry changes.

use super::*;

#[test]
fn handle_relative_mutation_fails_closed_or_stays_bound_during_ancestor_move() {
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
    assert!(!destination.exists());
    let moved_guarded = moved_ancestor.join("guarded");
    let outcomes = [
        std::fs::read(&source),
        std::fs::read(moved_guarded.join("source")),
        std::fs::read(moved_guarded.join("destination")),
    ];
    let valid = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Ok(bytes) if bytes == b"authority-bound-content"))
        .count()
        == 1
        && outcomes.iter().all(|outcome| {
            outcome
                .as_ref()
                .is_ok_and(|bytes| bytes == b"authority-bound-content")
                || outcome
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        });
    assert!(
        valid,
        "ancestor move must preserve exactly one authority-bound copy: {outcomes:?}"
    );
}

#[test]
fn exclusive_private_directory_is_exact_at_creation_and_refuses_reuse() {
    let root = private_temp();
    let path = root.path().join("exclusive-private");
    crate::platform_fs::create_private_directory(&path).unwrap();
    crate::platform_fs::validate_private_directory(&path).unwrap();
    assert_eq!(
        crate::platform_fs::create_private_directory(&path)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
}

#[test]
fn captured_directory_handle_moves_without_adopting_a_late_source_name() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let sources = root.path().join("sources");
    let targets = root.path().join("targets");
    crate::platform_fs::create_private_directory(&sources).unwrap();
    crate::platform_fs::create_private_directory(&targets).unwrap();
    let source = sources.join("source");
    let staged = targets.join("staged");
    crate::platform_fs::create_private_directory(&source).unwrap();
    std::fs::write(source.join("data"), b"captured bytes").unwrap();
    let source_parent = TrustedPathGuard::capture(&sources).unwrap();
    let target_parent = TrustedPathGuard::capture(&targets).unwrap();
    // One DELETE-capable handle also denies delete sharing. A second handle
    // requesting DELETE would itself conflict with that namespace fence.
    let (captured, expected) = open_directory_identity_relative_with_access(
        source_parent.authority_handle(),
        OsStr::new("source"),
        true,
        DELETE,
    )
    .unwrap();
    let replacement = sources.join("replacement");
    assert!(std::fs::rename(&source, &replacement).is_err());
    assert!(source.is_dir());
    assert!(!replacement.exists());
    rename_guarded_handle(&captured, &target_parent, &staged, false).unwrap();
    assert!(!source.exists());
    assert_eq!(
        std::fs::read(staged.join("data")).unwrap(),
        b"captured bytes"
    );
    drop(captured);
    let (confirmation, installed) = open_directory_identity_relative_with_access(
        target_parent.authority_handle(),
        OsStr::new("staged"),
        false,
        0,
    )
    .unwrap();
    assert_eq!(installed, expected);
    drop(confirmation);

    crate::platform_fs::create_private_directory(&source).unwrap();
    std::fs::write(source.join("sentinel"), b"new source must survive").unwrap();
    let (captured, _) = open_directory_identity_relative_with_access(
        source_parent.authority_handle(),
        OsStr::new("source"),
        true,
        DELETE,
    )
    .unwrap();
    // A destination collision must neither replace the existing tree nor
    // remove the captured source. No pathname replacement fallback is allowed.
    assert!(rename_guarded_handle(&captured, &target_parent, &staged, false).is_err());
    assert_eq!(
        std::fs::read(source.join("sentinel")).unwrap(),
        b"new source must survive"
    );
    assert_eq!(
        std::fs::read(staged.join("data")).unwrap(),
        b"captured bytes"
    );
}

#[test]
fn stopped_volume_metadata_observation_preserves_live_writer() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let path = root.path().join("astrid.volume");
    let mut writer = create_new_private_file_shared(&path).unwrap();
    writer.try_lock().unwrap();
    // A content reader must still refuse concurrent writable media.
    let error = validate_private_file(&path).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(32));
    super::super::validate_private_file_metadata(&path).unwrap();
    let competing = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(
        competing.try_lock().is_err(),
        "observation released the live owner lock"
    );
    // Observation neither reads locked payload bytes nor releases the owner.
    writer.write_all(b"owned volume").unwrap();
    writer.sync_all().unwrap();
    drop(writer);
    competing.try_lock().unwrap();
    drop(competing);
    validate_private_file(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"owned volume");
}

#[test]
fn stopped_volume_metadata_observation_rejects_nonprivate_file_and_parent() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let path = root.path().join("astrid.volume");
    drop(create_new_private_file_shared(&path).unwrap());
    set_world_entry(&path, FILE_GENERIC_READ, true);
    assert!(super::super::validate_private_file_metadata(&path).is_err());
    apply_private_acl(&path, false).unwrap();
    set_world_entry(root.path(), FILE_GENERIC_READ, true);
    assert!(super::super::validate_private_file_metadata(&path).is_err());
    // Validation must not repair either ACL.
    assert!(validate_private_directory(root.path()).is_err());
    apply_private_acl(root.path(), true).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
}
