use super::rollback::{collect_remove_dir, collect_remove_file};

#[test]
fn cleanup_collectors_preserve_every_reclamation_error() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("directory");
    let file = temp.path().join("file");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&file, b"state").unwrap();
    let mut errors = Vec::new();

    collect_remove_file(&directory, "profile", &mut errors);
    collect_remove_dir(&file, "home", &mut errors);

    assert_eq!(errors.len(), 2, "both independent failures must survive");
    assert!(errors[0].contains("profile"));
    assert!(errors[1].contains("home"));
}
