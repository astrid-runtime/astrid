use std::fs;

use super::*;

fn inspection(provenance: ArtifactProvenance) -> InstallInspection {
    InstallInspection {
        capsule_id: CapsuleId::new("example").unwrap(),
        version: "1.0.0".into(),
        content_digest: "abc".into(),
        provenance,
        capability_expansions: Vec::new(),
        manifest_digest: "manifest".into(),
        requested_capabilities: CapabilitiesDef::default(),
    }
}

#[test]
fn automatic_accepts_only_same_runtime_signature() {
    let local = inspection(ArtifactProvenance::LocalRuntime {
        signer: "key".into(),
        signature: "sig".into(),
    });
    assert_eq!(
        authorize_install(&local, &AuthorityDecision::Automatic)
            .unwrap()
            .source,
        AuthoritySource::LocalRuntimeBuild
    );
    assert!(
        authorize_install(
            &inspection(ArtifactProvenance::ForeignRuntime {
                signer: "key".into(),
                signature: "sig".into(),
            }),
            &AuthorityDecision::Automatic,
        )
        .is_err()
    );
    assert!(
        authorize_install(
            &inspection(ArtifactProvenance::Unsigned),
            &AuthorityDecision::Automatic,
        )
        .is_err()
    );
}

#[test]
fn explicit_approval_is_bound_to_digest() {
    let input = inspection(ArtifactProvenance::Unsigned);
    assert!(
        authorize_install(
            &input,
            &AuthorityDecision::ExplicitApproval {
                content_digest: "wrong".into(),
            },
        )
        .is_err()
    );
    assert_eq!(
        authorize_install(
            &input,
            &AuthorityDecision::ExplicitApproval {
                content_digest: "abc".into(),
            },
        )
        .unwrap()
        .source,
        AuthoritySource::ExplicitApproval
    );
}

#[test]
fn pending_authority_transaction_fails_closed_and_cleans_up_on_error() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    let target = temp.path().join("installed/example");
    let authority = authorize_install(
        &inspection(ArtifactProvenance::Unsigned),
        &AuthorityDecision::ExplicitApproval {
            content_digest: "abc".into(),
        },
    )
    .unwrap();
    let transaction = AuthorityReceiptTransaction::stage(&home, &target, &authority).unwrap();
    assert!(read_installed_authority(&home, &target).is_err());
    drop(transaction);
    assert!(read_installed_authority(&home, &target).unwrap().is_none());
}

#[test]
fn legacy_authority_retirement_removes_only_the_exact_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    let target = temp.path().join("installed/example");
    let authority = authorize_install(
        &inspection(ArtifactProvenance::Unsigned),
        &AuthorityDecision::ExplicitApproval {
            content_digest: "abc".into(),
        },
    )
    .unwrap();
    AuthorityReceiptTransaction::stage(&home, &target, &authority)
        .unwrap()
        .commit()
        .unwrap();
    let bytes = read_installed_authority_bytes(&home, &target)
        .unwrap()
        .expect("active receipt");
    let paths = authority_paths(&home, &target).unwrap();
    retire_legacy_authority_receipt(&home, &target, &bytes).unwrap();
    assert!(!paths.active.exists(), "exact active receipt is retired");
    assert!(paths.directory.exists(), "authority parent remains durable");
}

#[test]
fn legacy_authority_retirement_preserves_mutated_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    let target = temp.path().join("installed/example");
    let authority = authorize_install(
        &inspection(ArtifactProvenance::Unsigned),
        &AuthorityDecision::ExplicitApproval {
            content_digest: "abc".into(),
        },
    )
    .unwrap();
    AuthorityReceiptTransaction::stage(&home, &target, &authority)
        .unwrap()
        .commit()
        .unwrap();
    let paths = authority_paths(&home, &target).unwrap();
    let expected = fs::read(&paths.active).unwrap();
    fs::write(&paths.active, b"mutated").unwrap();
    assert!(retire_legacy_authority_receipt(&home, &target, &expected).is_err());
    assert_eq!(fs::read(&paths.active).unwrap(), b"mutated");
}

#[test]
fn legacy_authority_pending_artifact_blocks_and_is_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    let target = temp.path().join("installed/example");
    let authority = authorize_install(
        &inspection(ArtifactProvenance::Unsigned),
        &AuthorityDecision::ExplicitApproval {
            content_digest: "abc".into(),
        },
    )
    .unwrap();
    let transaction = AuthorityReceiptTransaction::stage(&home, &target, &authority).unwrap();
    let paths = authority_paths(&home, &target).unwrap();
    let error = retire_legacy_authority_receipt(&home, &target, b"expected").unwrap_err();
    assert!(error.to_string().contains("pending"));
    assert!(paths.pending.exists());
    drop(transaction);
}

#[test]
fn authority_status_blocks_unknown_but_preserves_workspace_portal_receipts() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    let workspace_target = temp.path().join("project/.astrid/capsules/example");
    let workspace_parent = workspace_target.parent().unwrap();
    fs::create_dir_all(workspace_parent).unwrap();
    let authority = authorize_install(
        &inspection(ArtifactProvenance::Unsigned),
        &AuthorityDecision::ExplicitApproval {
            content_digest: "abc".into(),
        },
    )
    .unwrap();
    AuthorityReceiptTransaction::stage(&home, &workspace_target, &authority)
        .unwrap()
        .commit()
        .unwrap();
    let portal =
        legacy_authority_receipt_status(&home, std::slice::from_ref(&workspace_target)).unwrap();
    assert!(portal.unknown_active.is_empty());
    let paths = authority_paths(&home, &workspace_target).unwrap();
    assert!(paths.active.exists());
    let unknown = paths.directory.join("unknown.json");
    fs::write(&unknown, b"unknown").unwrap();
    let status =
        legacy_authority_receipt_status(&home, std::slice::from_ref(&workspace_target)).unwrap();
    assert_eq!(status.unknown_active, vec![unknown]);
}
