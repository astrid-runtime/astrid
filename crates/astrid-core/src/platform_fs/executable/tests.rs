use super::*;

#[test]
fn replacement_input_validation_rejects_partial_or_ambiguous_sets() {
    let root = tempfile::tempdir().unwrap();
    let install = root.path().join("install");
    let extract = root.path().join("extract");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&extract).unwrap();
    std::fs::write(extract.join("astrid"), b"new").unwrap();

    assert!(validate_replacement_inputs(&install, &extract, &[]).is_err());
    assert!(validate_replacement_inputs(&install, &extract, &["../astrid"]).is_err());
    assert!(validate_replacement_inputs(&install, &extract, &["astrid", "astrid"]).is_err());
    assert!(validate_replacement_inputs(&install, &extract, &["astrid", "astrid-daemon"]).is_err());
}

#[cfg(unix)]
#[test]
fn unix_replacement_preserves_backups_and_cleans_staging() {
    let root = tempfile::tempdir().unwrap();
    let install = root.path().join("install");
    let extract = root.path().join("extract");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&extract).unwrap();
    std::fs::write(install.join("astrid"), b"old").unwrap();
    std::fs::write(install.join("astrid-daemon"), b"old-daemon").unwrap();
    std::fs::write(extract.join("astrid"), b"new").unwrap();
    std::fs::write(extract.join("astrid-daemon"), b"new-daemon").unwrap();

    replace_executable_set(&install, &extract, &["astrid", "astrid-daemon"]).unwrap();

    assert_eq!(std::fs::read(install.join("astrid")).unwrap(), b"new");
    assert_eq!(std::fs::read(install.join("astrid.bak")).unwrap(), b"old");
    assert!(!install.join(".astrid.new").exists());
}

#[cfg(unix)]
#[test]
fn unix_replacement_staging_failure_cleans_partial_new_files() {
    let root = tempfile::tempdir().unwrap();
    let install = root.path().join("install");
    let extract = root.path().join("extract");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&extract).unwrap();
    std::fs::write(extract.join("astrid"), b"new").unwrap();
    std::fs::write(extract.join("astrid-daemon"), b"new-daemon").unwrap();
    std::fs::create_dir(install.join(".astrid-daemon.new")).unwrap();

    let error = replace_executable_set(&install, &extract, &["astrid", "astrid-daemon"])
        .expect_err("a directory at a staging path must prevent replacement");

    assert!(error.to_string().contains("failed to stage"));
    assert!(!install.join("astrid").exists());
    assert!(!install.join("astrid-daemon").exists());
    assert!(!install.join(".astrid.new").exists());
    assert!(install.join(".astrid-daemon.new").is_dir());
}
