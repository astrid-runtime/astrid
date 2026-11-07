use super::CapturedDirectory;

#[test]
fn cleanup_refuses_a_replaced_database_child_without_deleting_either_tree() {
    let temporary = tempfile::tempdir().unwrap();
    let workspace = temporary.path().join("workspace");
    let database = workspace.join("database");
    let saved = temporary.path().join("saved-database");
    std::fs::create_dir_all(&database).unwrap();
    std::fs::write(database.join("copied"), b"original copy").unwrap();
    let captured = CapturedDirectory::open(&workspace).unwrap();
    std::fs::rename(&database, &saved).unwrap();
    std::fs::create_dir(&database).unwrap();
    std::fs::write(database.join("sentinel"), b"replacement must survive").unwrap();
    let result = captured.remove();
    assert!(result.is_err(), "cleanup adopted a replacement database");
    assert_eq!(
        std::fs::read(database.join("sentinel")).unwrap(),
        b"replacement must survive"
    );
    assert_eq!(
        std::fs::read(saved.join("copied")).unwrap(),
        b"original copy"
    );
}

#[test]
fn cleanup_refuses_an_empty_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("workspace");
    let saved = temporary.path().join("saved");
    std::fs::create_dir(&original).unwrap();
    let captured = CapturedDirectory::open(&original).unwrap();
    std::fs::rename(&original, &saved).unwrap();
    std::fs::create_dir(&original).unwrap();
    assert!(captured.remove().is_err());
    assert!(original.is_dir());
    assert!(saved.is_dir());
}

#[test]
fn cleanup_refuses_foreign_outer_content_before_deleting_the_database() {
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("workspace");
    let database = original.join("database");
    std::fs::create_dir_all(&database).unwrap();
    std::fs::write(database.join("copied"), b"copy").unwrap();
    let captured = CapturedDirectory::open(&original).unwrap();
    std::fs::write(original.join("late"), b"must survive").unwrap();
    assert!(captured.remove().is_err());
    assert_eq!(
        std::fs::read(original.join("late")).unwrap(),
        b"must survive"
    );
    assert_eq!(std::fs::read(database.join("copied")).unwrap(), b"copy");
}

#[test]
fn final_empty_unlink_preserves_a_late_nonempty_replacement_at_its_name() {
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("workspace");
    let saved = temporary.path().join("saved");
    std::fs::create_dir(&original).unwrap();
    let captured = CapturedDirectory::open(&original).unwrap();
    captured.verify_empty().unwrap();
    // Interleave after the final identity/empty check and before the actual
    // destructive primitive. A staging rename would move this foreign root.
    std::fs::rename(&original, &saved).unwrap();
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("sentinel"), b"must stay here").unwrap();
    assert!(captured.unlink_empty().is_err());
    assert_eq!(
        std::fs::read(original.join("sentinel")).unwrap(),
        b"must stay here"
    );
    assert!(saved.is_dir());
    let names = std::fs::read_dir(temporary.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 2, "cleanup must not invent a staging name");
}
