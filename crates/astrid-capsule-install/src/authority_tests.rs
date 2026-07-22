use std::fs::File;
use std::io::Read;
use std::path::Path;

use astrid_build::artifact::{self, sign_archive};
use astrid_core::PrincipalId;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use astrid_crypto::KeyPair;

use crate::{
    ArtifactProvenance, AuthorityDecision, AuthoritySource, InstallOptions, authorize_install,
    inspect_archive_for_principal_in_workspace, inspect_archive_for_principal_with_layout,
    read_installed_authority, resolve_target_dir_for,
    unpack_and_install_authorized_for_principal_in_workspace,
    unpack_and_install_authorized_for_principal_with_layout, verify_installed_authority,
};

fn write_archive(path: &Path, name: &str, version: &str, capabilities: &str) {
    let manifest =
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n\n{capabilities}");
    let file = File::create(path).unwrap();
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, "Capsule.toml", manifest.as_bytes())
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap();
}

fn install_home(root: &Path, key: &KeyPair) -> AstridHome {
    let home = AstridHome::from_path(root);
    std::fs::create_dir_all(home.keys_dir()).unwrap();
    std::fs::write(home.runtime_key_path(), key.secret_key_bytes()).unwrap();
    home
}

#[test]
fn same_runtime_build_installs_automatically_and_records_authority() {
    let temp = tempfile::tempdir().unwrap();
    let key = KeyPair::generate();
    let home = install_home(&temp.path().join("runtime-a"), &key);
    let archive = temp.path().join("example.capsule");
    write_archive(
        &archive,
        "example",
        "1.0.0",
        "[capabilities]\nnet_connect = [\"api.example:443\"]\n",
    );
    sign_archive(&archive, &key).unwrap();
    let principal = PrincipalId::new("alice").unwrap();

    let inspection = inspect_archive_for_principal_with_layout(
        &archive,
        &home,
        &principal,
        false,
        &WorkspaceLayout::default(),
    )
    .unwrap();
    assert!(matches!(
        inspection.provenance,
        ArtifactProvenance::LocalRuntime { .. }
    ));
    let output = unpack_and_install_authorized_for_principal_with_layout(
        &archive,
        &home,
        InstallOptions::default(),
        &principal,
        &AuthorityDecision::Automatic,
        &WorkspaceLayout::default(),
    )
    .unwrap();
    let authority = read_installed_authority(&home, &output.target_dir)
        .unwrap()
        .unwrap();
    assert_eq!(authority.source, AuthoritySource::LocalRuntimeBuild);
    assert_eq!(authority.capsule_id, "example");
    assert_eq!(authority.version, "1.0.0");
    assert_eq!(authority.content_digest, inspection.content_digest);
    assert_eq!(
        authority.approved_capabilities.net_connect,
        vec!["api.example:443"]
    );
    assert!(
        output.target_dir.read_dir().unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("authority")),
        "kernel authority metadata must stay outside capsule-writable storage"
    );

    std::fs::write(
        output.target_dir.join("Capsule.toml"),
        "[package]\nname = \"example\"\nversion = \"1.0.0\"\n\
         [capabilities]\nnet_connect = [\"api.example:443\"]\n# changed after install\n",
    )
    .unwrap();
    let changed =
        astrid_capsule::discovery::load_manifest(&output.target_dir.join("Capsule.toml")).unwrap();
    let error = verify_installed_authority(&home, &output.target_dir, &changed).unwrap_err();
    assert!(error.to_string().contains("exact manifest approved"));

    std::fs::write(
        output.target_dir.join("Capsule.toml"),
        "[package]\nname = \"example\"\nversion = \"1.0.0\"\n\
         [capabilities]\nnet_connect = [\"api.example:443\", \"db.example:5432\"]\n",
    )
    .unwrap();
    let expanded =
        astrid_capsule::discovery::load_manifest(&output.target_dir.join("Capsule.toml")).unwrap();
    let error = verify_installed_authority(&home, &output.target_dir, &expanded).unwrap_err();
    assert!(error.to_string().contains("net_connect=[db.example:5432]"));
}

#[test]
fn foreign_runtime_signature_needs_digest_bound_approval() {
    let temp = tempfile::tempdir().unwrap();
    let builder_key = KeyPair::generate();
    let home = install_home(&temp.path().join("runtime-b"), &KeyPair::generate());
    let archive = temp.path().join("example.capsule");
    write_archive(&archive, "example", "1.0.0", "");
    sign_archive(&archive, &builder_key).unwrap();
    let principal = PrincipalId::new("alice").unwrap();
    let layout = WorkspaceLayout::default();
    let inspection =
        inspect_archive_for_principal_with_layout(&archive, &home, &principal, false, &layout)
            .unwrap();
    assert!(matches!(
        inspection.provenance,
        ArtifactProvenance::ForeignRuntime { .. }
    ));
    assert!(authorize_install(&inspection, &AuthorityDecision::Automatic).is_err());
    assert!(
        unpack_and_install_authorized_for_principal_with_layout(
            &archive,
            &home,
            InstallOptions::default(),
            &principal,
            &AuthorityDecision::ExplicitApproval {
                content_digest: "wrong".into(),
            },
            &layout,
        )
        .is_err()
    );
    let output = unpack_and_install_authorized_for_principal_with_layout(
        &archive,
        &home,
        InstallOptions::default(),
        &principal,
        &AuthorityDecision::ExplicitApproval {
            content_digest: inspection.content_digest,
        },
        &layout,
    )
    .unwrap();
    assert_eq!(
        read_installed_authority(&home, &output.target_dir)
            .unwrap()
            .unwrap()
            .source,
        AuthoritySource::ExplicitApproval
    );
}

#[test]
fn tampered_signature_fails_even_with_explicit_approval() {
    let temp = tempfile::tempdir().unwrap();
    let key = KeyPair::generate();
    let home = install_home(&temp.path().join("runtime"), &KeyPair::generate());
    let signed = temp.path().join("signed.capsule");
    write_archive(&signed, "example", "1.0.0", "");
    sign_archive(&signed, &key).unwrap();

    let tampered = temp.path().join("tampered.capsule");
    let input = File::open(&signed).unwrap();
    let mut source = tar::Archive::new(flate2::read::GzDecoder::new(input));
    let output = File::create(&tampered).unwrap();
    let encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
    let mut target = tar::Builder::new(encoder);
    for entry in source.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        if path == Path::new("Capsule.toml") {
            bytes.extend_from_slice(b"\n[capabilities]\nallow_prompt_injection = true\n");
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        target
            .append_data(&mut header, path, bytes.as_slice())
            .unwrap();
    }
    target.into_inner().unwrap().finish().unwrap();

    assert!(artifact::verify_archive(&tampered).is_err());
    let principal = PrincipalId::new("alice").unwrap();
    assert!(
        inspect_archive_for_principal_with_layout(
            &tampered,
            &home,
            &principal,
            false,
            &WorkspaceLayout::default(),
        )
        .is_err()
    );
    assert!(
        !resolve_target_dir_for(&home, &principal, "example", false)
            .unwrap()
            .exists()
    );
}

#[test]
fn upgrade_inspection_reports_only_new_capability_authority() {
    let temp = tempfile::tempdir().unwrap();
    let home = install_home(&temp.path().join("runtime"), &KeyPair::generate());
    let principal = PrincipalId::new("alice").unwrap();
    let layout = WorkspaceLayout::default();
    let v1 = temp.path().join("v1.capsule");
    write_archive(
        &v1,
        "example",
        "1.0.0",
        "[capabilities]\nnet_connect = [\"api.example:443\"]\n",
    );
    let first =
        inspect_archive_for_principal_with_layout(&v1, &home, &principal, false, &layout).unwrap();
    unpack_and_install_authorized_for_principal_with_layout(
        &v1,
        &home,
        InstallOptions::default(),
        &principal,
        &AuthorityDecision::ExplicitApproval {
            content_digest: first.content_digest,
        },
        &layout,
    )
    .unwrap();

    let v2 = temp.path().join("v2.capsule");
    write_archive(
        &v2,
        "example",
        "2.0.0",
        "[capabilities]\nnet_connect = [\"api.example:443\", \"db.example:5432\"]\nallow_prompt_injection = true\n",
    );
    let upgrade =
        inspect_archive_for_principal_with_layout(&v2, &home, &principal, false, &layout).unwrap();
    assert_eq!(upgrade.capability_expansions.len(), 2);
    assert_eq!(
        upgrade.capability_expansions[0].name,
        "allow_prompt_injection"
    );
    assert_eq!(
        upgrade.capability_expansions[1].added,
        vec!["db.example:5432"]
    );
}

#[test]
fn legacy_install_is_snapshotted_once_then_enforced() {
    let temp = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(temp.path().join("home"));
    let target = temp.path().join("legacy");
    std::fs::create_dir_all(&target).unwrap();
    let manifest_path = target.join("Capsule.toml");
    std::fs::write(
        &manifest_path,
        "[package]\nname = \"legacy\"\nversion = \"1.0.0\"\n\
         [capabilities]\nnet_connect = [\"api.example:443\"]\n",
    )
    .unwrap();
    let original = astrid_capsule::discovery::load_manifest(&manifest_path).unwrap();
    verify_installed_authority(&home, &target, &original).unwrap();
    assert_eq!(
        read_installed_authority(&home, &target)
            .unwrap()
            .unwrap()
            .source,
        AuthoritySource::LegacyMigration
    );

    std::fs::write(
        &manifest_path,
        "[package]\nname = \"legacy\"\nversion = \"1.0.0\"\n\
         [capabilities]\nnet_connect = [\"api.example:443\", \"db.example:5432\"]\n",
    )
    .unwrap();
    let expanded = astrid_capsule::discovery::load_manifest(&manifest_path).unwrap();
    let error = verify_installed_authority(&home, &target, &expanded).unwrap_err();
    assert!(error.to_string().contains("db.example:5432"));
}

#[test]
fn authorized_workspace_install_uses_explicit_kernel_root() {
    let temp = tempfile::tempdir().unwrap();
    let key = KeyPair::generate();
    let home = install_home(&temp.path().join("home"), &key);
    let workspace = temp.path().join("selected-workspace");
    std::fs::create_dir(&workspace).unwrap();
    let archive = temp.path().join("workspace.capsule");
    write_archive(&archive, "workspace-cap", "1.0.0", "");
    sign_archive(&archive, &key).unwrap();
    let principal = PrincipalId::new("alice").unwrap();
    let layout = WorkspaceLayout::default();
    let inspection = inspect_archive_for_principal_in_workspace(
        &archive,
        &home,
        &principal,
        true,
        Some(&workspace),
        &layout,
    )
    .unwrap();
    let output = unpack_and_install_authorized_for_principal_in_workspace(
        &archive,
        &home,
        InstallOptions {
            workspace: true,
            ..Default::default()
        },
        &principal,
        Some(&workspace),
        &AuthorityDecision::Automatic,
        &layout,
    )
    .unwrap();
    assert_eq!(inspection.capsule_id.as_str(), "workspace-cap");
    let selected = layout.resolve(&workspace).unwrap();
    assert!(output.target_dir.starts_with(selected.state_dir()));
}
