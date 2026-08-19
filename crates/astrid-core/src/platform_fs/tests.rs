use super::*;

fn rule(principal: AclPrincipal, directory: bool) -> AclRule {
    AclRule {
        principal,
        access: AclAccess::AllowFullControl,
        inheritance: if directory {
            AclInheritance::Children
        } else {
            AclInheritance::None
        },
    }
}

#[test]
fn private_acl_requires_exact_principal_set_and_protection() {
    let rules = [
        rule(AclPrincipal::CurrentUser, true),
        rule(AclPrincipal::LocalSystem, true),
        rule(AclPrincipal::Administrators, true),
    ];
    assert!(acl_rules_are_private(true, true, true, &rules));
    assert!(!acl_rules_are_private(true, false, true, &rules));
    assert!(!acl_rules_are_private(true, true, false, &rules));
}

#[test]
fn private_acl_rejects_extra_or_weakened_entries() {
    let mut rules = vec![
        rule(AclPrincipal::CurrentUser, false),
        rule(AclPrincipal::LocalSystem, false),
        rule(AclPrincipal::Administrators, false),
    ];
    assert!(acl_rules_are_private(false, true, true, &rules));

    rules.push(rule(AclPrincipal::Other, false));
    assert!(!acl_rules_are_private(false, true, true, &rules));
    rules.pop();

    rules[0].access = AclAccess::Other;
    assert!(!acl_rules_are_private(false, true, true, &rules));
    rules[0].access = AclAccess::AllowFullControl;
    rules[0].inheritance = AclInheritance::InheritedOrOther;
    assert!(!acl_rules_are_private(false, true, true, &rules));
}

#[test]
fn private_acl_distinguishes_file_and_directory_inheritance() {
    let directory_rules = [
        rule(AclPrincipal::CurrentUser, true),
        rule(AclPrincipal::LocalSystem, true),
        rule(AclPrincipal::Administrators, true),
    ];
    assert!(!acl_rules_are_private(false, true, true, &directory_rules));

    let file_rules = [
        rule(AclPrincipal::CurrentUser, false),
        rule(AclPrincipal::LocalSystem, false),
        rule(AclPrincipal::Administrators, false),
    ];
    assert!(!acl_rules_are_private(true, true, true, &file_rules));
}

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

#[cfg(unix)]
#[test]
fn unix_private_atomic_write_repairs_permissive_replacement() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("secret");
    std::fs::write(&path, b"old").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(validate_private_file(&path).is_err());

    atomic_write_private_file(&path, b"new").unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(validate_private_file(&path).is_ok());
}

#[cfg(unix)]
#[test]
fn unix_private_directory_validation_rejects_permissive_modes() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(validate_private_directory(root.path()).is_err());

    ensure_private_directory(root.path()).unwrap();
    assert!(validate_private_directory(root.path()).is_ok());
    assert_eq!(
        std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_private_paths_do_not_use_macos_system_aliases() {
    let path = PathBuf::from("/tmp/astrid-private");

    assert_eq!(normalize_unix_system_alias(path.clone()), path);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_private_paths_resolve_system_tmp_alias() {
    assert_eq!(
        normalize_unix_system_alias(PathBuf::from("/tmp/astrid-private")),
        PathBuf::from("/private/tmp/astrid-private")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_private_file_validation_rejects_and_restriction_removes_extended_acl() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("secret");
    std::fs::write(&path, b"secret").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let status = std::process::Command::new("/bin/chmod")
        .arg("+a")
        .arg("everyone allow read")
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());

    assert!(validate_private_file(&path).is_err());
    restrict_private_file(&path).unwrap();
    assert!(validate_private_file(&path).is_ok());
}

#[cfg(unix)]
#[test]
fn unix_private_directory_creation_rejects_redirected_components() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let redirect = root.path().join("redirect");
    symlink(outside.path(), &redirect).unwrap();

    assert!(ensure_private_directory(&redirect.join("private")).is_err());
    assert!(verify_no_redirects(&redirect).is_err());
    assert!(!outside.path().join("private").exists());
}

#[cfg(unix)]
#[test]
fn unix_redirect_validation_accepts_regular_leaf_files_but_not_symlinks() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("intent");
    let redirect = root.path().join("redirect");
    std::fs::write(&file, b"intent").unwrap();
    symlink(&file, &redirect).unwrap();

    verify_no_redirects(&file).unwrap();
    assert!(verify_no_redirects(&redirect).is_err());
}
