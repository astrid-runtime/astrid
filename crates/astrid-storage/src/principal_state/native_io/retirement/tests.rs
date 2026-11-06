use super::CapturedDirectory;

#[test]
fn final_removal_preserves_reused_original_name() {
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("workspace");
    std::fs::create_dir(&original).unwrap();
    let captured = CapturedDirectory::open(&original).unwrap();
    let staged = captured.stage_empty().unwrap();
    assert!(!original.try_exists().unwrap());
    std::fs::create_dir(&original).unwrap();
    // Even an empty replacement must not be mistaken for the captured root.
    staged.remove_empty().unwrap();
    assert!(original.is_dir());
}

#[test]
fn staging_refuses_an_empty_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("workspace");
    let saved = temporary.path().join("saved");
    std::fs::create_dir(&original).unwrap();
    let captured = CapturedDirectory::open(&original).unwrap();
    std::fs::rename(&original, &saved).unwrap();
    std::fs::create_dir(&original).unwrap();
    assert!(captured.stage_empty().is_err());
    assert!(original.is_dir());
    assert!(saved.is_dir());
}

#[test]
fn staging_refuses_late_content_without_deleting_it() {
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("workspace");
    std::fs::create_dir(&original).unwrap();
    let captured = CapturedDirectory::open(&original).unwrap();
    std::fs::write(original.join("late"), b"must survive").unwrap();
    assert!(captured.stage_empty().is_err());
    assert_eq!(
        std::fs::read(original.join("late")).unwrap(),
        b"must survive"
    );
}
