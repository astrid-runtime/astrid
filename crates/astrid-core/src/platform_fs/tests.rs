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
