use super::{preflight_legacy_audit_sources, require_audit_integrity, retire_legacy_audit_dir};
use astrid_audit::ChainVerificationResult;
use astrid_core::SessionId;
use astrid_core::dirs::AstridHome;

#[test]
fn audit_retirement_validates_tree_and_removes_only_verified_source() {
    let directory = tempfile::tempdir().expect("temporary home");
    let home = AstridHome::from_path(directory.path().join(".astrid"));
    home.ensure().expect("home layout");
    let principal_home = home.principal_home(&astrid_core::PrincipalId::default());
    principal_home.ensure().expect("legacy principal layout");
    std::fs::write(principal_home.audit_dir().join("entry"), b"audit").expect("audit fixture");

    retire_legacy_audit_dir(&home, &principal_home.audit_dir()).expect("retire audit source");
    assert!(!principal_home.audit_dir().exists());
    assert!(
        !home
            .migrations_dir()
            .join("audit-principal-home.retired")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn audit_retirement_rejects_redirects_before_removal() {
    let directory = tempfile::tempdir().expect("temporary home");
    let home = AstridHome::from_path(directory.path().join(".astrid"));
    home.ensure().expect("home layout");
    let principal_home = home.principal_home(&astrid_core::PrincipalId::default());
    principal_home.ensure().expect("legacy principal layout");
    let outside = directory.path().join("outside");
    std::fs::create_dir(&outside).expect("outside fixture");
    std::os::unix::fs::symlink(&outside, principal_home.audit_dir().join("redirect"))
        .expect("redirect fixture");

    assert!(retire_legacy_audit_dir(&home, &principal_home.audit_dir()).is_err());
    assert!(principal_home.audit_dir().exists());
}

#[test]
fn audit_boot_integrity_barrier_rejects_tampered_history() {
    let valid = vec![(
        SessionId::new(),
        ChainVerificationResult {
            valid: true,
            entries_verified: 1,
            issues: Vec::new(),
        },
    )];
    require_audit_integrity(&valid).expect("valid history permits boot");

    let invalid = vec![(
        SessionId::new(),
        ChainVerificationResult {
            valid: false,
            entries_verified: 1,
            issues: Vec::new(),
        },
    )];
    assert!(require_audit_integrity(&invalid).is_err());
}

#[test]
fn audit_boot_rejects_unhandled_non_default_source() {
    let directory = tempfile::tempdir().expect("temporary home");
    let home = AstridHome::from_path(directory.path().join(".astrid"));
    home.ensure().expect("home layout");
    let other = astrid_core::PrincipalId::new("other".to_owned()).expect("principal id");
    let other_home = home.principal_home(&other);
    other_home.ensure().expect("legacy principal layout");
    std::fs::write(other_home.audit_dir().join("entry"), b"audit").expect("non-empty audit");
    let default_source = home
        .principal_home(&astrid_core::PrincipalId::default())
        .audit_dir();

    let error = preflight_legacy_audit_sources(&home, &default_source)
        .expect_err("unhandled non-empty source must block boot");
    assert!(
        error
            .to_string()
            .contains("only the default principal source")
    );
    assert!(other_home.audit_dir().exists());
    assert_eq!(
        std::fs::read(other_home.audit_dir().join("entry")).expect("preserved"),
        b"audit"
    );
}

#[test]
fn audit_boot_allows_empty_non_default_audit_directory() {
    let directory = tempfile::tempdir().expect("temporary home");
    let home = AstridHome::from_path(directory.path().join(".astrid"));
    home.ensure().expect("home layout");
    let other = astrid_core::PrincipalId::new("other".to_owned()).expect("principal id");
    let other_home = home.principal_home(&other);
    other_home.ensure().expect("legacy principal layout");
    let default_source = home
        .principal_home(&astrid_core::PrincipalId::default())
        .audit_dir();
    preflight_legacy_audit_sources(&home, &default_source)
        .expect("empty non-default audit must not refuse cutover");
    assert!(other_home.audit_dir().exists());
}
