use std::fs;

use astrid_capsule::manifest::{CapabilitiesDef, CapsuleManifest};
use astrid_core::dirs::AstridHome;

use super::{quarantine_legacy_authority_receipt, rebind_relocated_legacy_authority_receipt};
use crate::authority::{
    AuthorityDecision, AuthorityReceiptTransaction, AuthoritySource, InstallInspection,
    InstalledAuthority, authority_paths, authorize_install, digest_manifest,
};

fn inspection(capsule_id: &str, digest: &str, manifest_digest: &str) -> InstallInspection {
    InstallInspection {
        capsule_id: astrid_capsule::capsule::CapsuleId::new(capsule_id).unwrap(),
        version: "1.0.0".into(),
        content_digest: digest.into(),
        provenance: crate::authority::ArtifactProvenance::Unsigned,
        capability_expansions: Vec::new(),
        manifest_digest: manifest_digest.into(),
        requested_capabilities: CapabilitiesDef::default(),
    }
}

fn write_manifest(dir: &std::path::Path, name: &str) -> (CapsuleManifest, String) {
    fs::create_dir_all(dir).unwrap();
    let body = format!("[package]\nname = \"{name}\"\nversion = \"1.0.0\"\n");
    fs::write(dir.join("Capsule.toml"), &body).unwrap();
    let manifest = astrid_capsule::discovery::load_manifest(&dir.join("Capsule.toml")).unwrap();
    (manifest, digest_manifest(body.as_bytes()))
}

#[test]
fn rebind_copies_unique_path_hashed_leftover_onto_current_target() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    let previous = temp.path().join("previous-prefix/released-capsule");
    let current = temp.path().join("current-prefix/released-capsule");
    let (manifest, manifest_digest) = write_manifest(&current, "released-capsule");
    let authority = authorize_install(
        &inspection("released-capsule", "abc", &manifest_digest),
        &AuthorityDecision::ExplicitApproval {
            content_digest: "abc".into(),
        },
    )
    .unwrap();
    AuthorityReceiptTransaction::stage(&home, &previous, &authority)
        .unwrap()
        .commit()
        .unwrap();
    let previous_paths = authority_paths(&home, &previous).unwrap();
    let current_paths = authority_paths(&home, &current).unwrap();
    assert!(previous_paths.active.exists());
    assert!(!current_paths.active.exists());
    assert_ne!(previous_paths.active, current_paths.active);

    rebind_relocated_legacy_authority_receipt(&home, &current, &manifest).unwrap();

    assert!(
        current_paths.active.exists(),
        "current target must receive the rebound receipt"
    );
    assert!(
        previous_paths.active.exists(),
        "original leftover must stay until sweep"
    );
    let rebound: InstalledAuthority =
        serde_json::from_slice(&fs::read(&current_paths.active).unwrap()).unwrap();
    assert_eq!(rebound.source, AuthoritySource::ExplicitApproval);
    assert_eq!(rebound.capsule_id, "released-capsule");
}

#[test]
fn duplicate_capsule_id_leftovers_are_not_rebound() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    let current = temp.path().join("current-prefix/released-capsule");
    let (manifest, manifest_digest) = write_manifest(&current, "released-capsule");
    let authority = authorize_install(
        &inspection("released-capsule", "abc", &manifest_digest),
        &AuthorityDecision::ExplicitApproval {
            content_digest: "abc".into(),
        },
    )
    .unwrap();
    AuthorityReceiptTransaction::stage(
        &home,
        &temp.path().join("old-a/released-capsule"),
        &authority,
    )
    .unwrap()
    .commit()
    .unwrap();
    AuthorityReceiptTransaction::stage(
        &home,
        &temp.path().join("old-b/released-capsule"),
        &authority,
    )
    .unwrap()
    .commit()
    .unwrap();

    rebind_relocated_legacy_authority_receipt(&home, &current, &manifest).unwrap();

    let current_paths = authority_paths(&home, &current).unwrap();
    assert!(
        !current_paths.active.exists(),
        "ambiguous leftovers must not be assigned"
    );
}

#[test]
fn quarantine_preserves_original_receipt_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    home.ensure().unwrap();
    let previous = temp.path().join("previous-prefix/ghost-capsule");
    let authority = authorize_install(
        &inspection("ghost-capsule", "abc", "manifest"),
        &AuthorityDecision::ExplicitApproval {
            content_digest: "abc".into(),
        },
    )
    .unwrap();
    AuthorityReceiptTransaction::stage(&home, &previous, &authority)
        .unwrap()
        .commit()
        .unwrap();
    let paths = authority_paths(&home, &previous).unwrap();
    let original = fs::read(&paths.active).unwrap();

    let quarantined = quarantine_legacy_authority_receipt(&home, &paths.active).unwrap();

    assert!(!paths.active.exists());
    assert_eq!(fs::read(&quarantined).unwrap(), original);
}
