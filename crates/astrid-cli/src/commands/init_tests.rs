//! Tests for [`super`] — the `astrid init` distro-provisioning path. Kept
//! in a sibling file (referenced via `#[path]`) so `init.rs` stays under
//! the per-file CI line cap.

use super::*;

struct CurrentDirGuard(std::path::PathBuf);

impl CurrentDirGuard {
    fn set(path: &std::path::Path) -> Self {
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(path).unwrap();
        Self(original)
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.0).unwrap();
    }
}

fn run_bare_cwd_child(child_name: &str, marker: &str) {
    let result_dir = tempfile::tempdir().unwrap();
    let result_path = result_dir.path().join("result");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "--nocapture", child_name])
        .env("ASTRID_BARE_CWD_TEST", "1")
        .env("ASTRID_BARE_CWD_RESULT", &result_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(result_path).unwrap(), marker);
}

#[test]
fn batch_install_rejects_reported_identity_mismatch() {
    let expected = astrid_capsule::capsule::CapsuleId::new("expected-capsule").unwrap();
    let err = validate_batch_install(
        &expected,
        "1.0.0",
        None,
        super::super::capsule::install::BatchInstallOutcome {
            installed: vec![super::super::capsule::install::InstalledCapsuleOutcome {
                id: astrid_capsule::capsule::CapsuleId::new("wrong-capsule").unwrap(),
                version: "1.0.0".to_string(),
                wasm_hash: Some("abcd".to_string()),
            }],
            resolved_ref: Some("v1.0.0".to_string()),
        },
    )
    .unwrap_err();

    assert!(err.to_string().contains("expected-capsule"), "got: {err:#}");
}

#[test]
fn batch_install_accepts_actual_version_hash_and_ref() {
    let expected = astrid_capsule::capsule::CapsuleId::new("expected-capsule").unwrap();
    let verified = validate_batch_install(
        &expected,
        "1.0.0",
        None,
        super::super::capsule::install::BatchInstallOutcome {
            installed: vec![super::super::capsule::install::InstalledCapsuleOutcome {
                id: expected.clone(),
                version: "1.0.0".to_string(),
                wasm_hash: Some("abcd".to_string()),
            }],
            resolved_ref: Some("v1.0.0".to_string()),
        },
    )
    .unwrap();
    assert_eq!(verified.version, "1.0.0");
    assert_eq!(verified.wasm_hash.as_deref(), Some("abcd"));
    assert_eq!(verified.resolved_ref.as_deref(), Some("v1.0.0"));
}

#[test]
fn batch_install_rejects_multiple_reported_capsules() {
    let expected = astrid_capsule::capsule::CapsuleId::new("expected-capsule").unwrap();
    let err = validate_batch_install(
        &expected,
        "1.0.0",
        None,
        super::super::capsule::install::BatchInstallOutcome {
            installed: vec![
                super::super::capsule::install::InstalledCapsuleOutcome {
                    id: expected.clone(),
                    version: "1.0.0".to_string(),
                    wasm_hash: None,
                },
                super::super::capsule::install::InstalledCapsuleOutcome {
                    id: astrid_capsule::capsule::CapsuleId::new("wrong-capsule").unwrap(),
                    version: "1.0.0".to_string(),
                    wasm_hash: None,
                },
            ],
            resolved_ref: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("checked installer reported"));
}

#[test]
fn batch_install_rejects_declared_version_mismatch() {
    let expected = astrid_capsule::capsule::CapsuleId::new("expected-capsule").unwrap();
    let err = validate_batch_install(
        &expected,
        "1.0.0",
        None,
        super::super::capsule::install::BatchInstallOutcome {
            installed: vec![super::super::capsule::install::InstalledCapsuleOutcome {
                id: expected.clone(),
                version: "2.0.0".to_string(),
                wasm_hash: None,
            }],
            resolved_ref: None,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("installed manifest reports 2.0.0"));
}

#[test]
fn provider_selection_parses_multi_select() {
    assert_eq!(parse_provider_selection("1,2", 3), vec![1, 2]);
    assert_eq!(parse_provider_selection(" 2 , 3 ", 3), vec![2, 3]);
    assert_eq!(parse_provider_selection("1", 3), vec![1]);
}

#[test]
fn provider_selection_drops_out_of_range_and_garbage() {
    assert_eq!(parse_provider_selection("0,4,2,abc", 3), vec![2]);
    assert!(parse_provider_selection("", 3).is_empty());
    assert!(parse_provider_selection("9,10", 3).is_empty());
}

#[test]
fn provider_selection_dedupes_preserving_order() {
    assert_eq!(parse_provider_selection("2,1,2,1", 3), vec![2, 1]);
}

#[test]
fn provider_selection_preserves_entry_order() {
    // User order is honoured (3 then 1), not numeric-sorted.
    assert_eq!(parse_provider_selection("3,1", 3), vec![3, 1]);
}

#[test]
fn extract_var_refs_finds_all() {
    assert_eq!(extract_var_refs("{{ foo }}"), vec!["foo"]);
    assert_eq!(extract_var_refs("{{ a }}-{{ b }}"), vec!["a", "b"],);
    assert!(extract_var_refs("no vars").is_empty());
}

#[test]
fn resolve_template_replaces_vars() {
    let mut vars = HashMap::new();
    vars.insert("key".to_string(), "secret123".to_string());
    vars.insert("url".to_string(), "https://api.example.com".to_string());

    assert_eq!(resolve_template("{{ key }}", &vars), "secret123",);
    assert_eq!(
        resolve_template("prefix-{{ url }}-suffix", &vars),
        "prefix-https://api.example.com-suffix",
    );
}

#[test]
fn resolve_template_handles_missing_var() {
    let vars = HashMap::new();
    // Unresolved template stays as-is.
    assert_eq!(resolve_template("{{ missing }}", &vars), "{{ missing }}",);
}

#[test]
fn distro_source_resolution_rejects_bare_names_without_a_network_default() {
    let error = resolve_distro_url("example-distro").expect_err("bare name has no provenance");
    assert!(error.to_string().contains("@owner/repo"));
    assert!(error.to_string().contains("local Distro.toml path"));
}

#[test]
fn distro_source_resolution_rejects_non_repository_at_paths() {
    for source in ["@", "@owner", "@/repo", "@owner/", "@owner/repo/extra"] {
        assert!(resolve_distro_url(source).is_err(), "must reject {source}");
    }
}

#[test]
fn distro_source_resolution_at_prefix() {
    assert_eq!(
        resolve_distro_url("@myorg/mydistro").unwrap(),
        "https://raw.githubusercontent.com/myorg/mydistro/main/Distro.toml",
    );
}

#[test]
fn distro_source_resolution_full_url() {
    let url = "https://example.com/Distro.toml";
    assert_eq!(resolve_distro_url(url).unwrap(), url);
}

// ---- Part A: headless selection / variable resolution ----

use super::super::distro::manifest::{DistroCapsule, VariableDef};

fn signed_source_fixture(
    dir: &std::path::Path,
) -> (std::path::PathBuf, Vec<u8>, String, astrid_crypto::KeyPair) {
    let keypair = astrid_crypto::KeyPair::generate();
    let pubkey = super::super::distro::sign::pubkey_to_wire(&keypair.export_public_key());
    let bytes = format!(
        "schema-version = 1\n\n\
         [distro]\nid = \"test\"\nname = \"Test\"\nversion = \"0.1.0\"\n\n\
         [distro.signing]\npubkey = \"{pubkey}\"\n\n\
         [[capsule]]\nname = \"cli\"\nsource = \"@org/cli\"\nversion = \"0.1.0\"\nrole = \"uplink\"\n"
    )
    .into_bytes();
    let manifest_hash = manifest_hash(&bytes);
    let lock = super::super::distro::lock::DistroLock {
        schema_version: 1,
        distro: super::super::distro::lock::DistroLockMeta {
            id: "test".into(),
            version: "0.1.0".into(),
            resolved_at: "2026-01-01T00:00:00Z".into(),
        },
        capsules: vec![super::super::distro::lock::LockedCapsule {
            name: "cli".into(),
            version: "0.1.0".into(),
            source: "@org/cli".into(),
            hash: format!("blake3:{}", "a".repeat(64)),
            resolved_ref: Some("v0.1.0".into()),
        }],
        manifest_hash: Some(manifest_hash.clone()),
    };
    let sig = super::super::distro::sign::sign_lock(&lock, &keypair).unwrap();
    std::fs::write(dir.join("Distro.toml"), &bytes).unwrap();
    std::fs::write(
        dir.join("Distro.lock"),
        toml::to_string_pretty(&lock).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("Distro.sig"), sig).unwrap();
    (dir.join("Distro.toml"), bytes, manifest_hash, keypair)
}

fn seed_distro_pin(home: &AstridHome, distro_id: &str, keypair: &astrid_crypto::KeyPair) {
    let trust_dir = home.root().join("trust");
    std::fs::create_dir_all(&trust_dir).unwrap();
    let pubkey = super::super::distro::sign::pubkey_to_wire(&keypair.export_public_key());
    std::fs::write(
        trust_dir.join(format!("{distro_id}.pub")),
        format!("{pubkey}\n"),
    )
    .unwrap();
}

fn seed_pin(home: &AstridHome, keypair: &astrid_crypto::KeyPair) {
    seed_distro_pin(home, "test", keypair);
}

fn signed_local_source_fixture(
    dir: &std::path::Path,
    capsule_bytes: &[u8],
) -> (std::path::PathBuf, Vec<u8>, String, astrid_crypto::KeyPair) {
    std::fs::create_dir_all(dir.join("capsules")).unwrap();
    std::fs::write(dir.join("capsules/member.capsule"), capsule_bytes).unwrap();
    let keypair = astrid_crypto::KeyPair::generate();
    let pubkey = super::super::distro::sign::pubkey_to_wire(&keypair.export_public_key());
    let bytes = format!(
        "schema-version = 1\n\n\
         [distro]\nid = \"local-test\"\nname = \"Local Test\"\nversion = \"0.1.0\"\n\n\
         [distro.signing]\npubkey = \"{pubkey}\"\n\n\
         [[capsule]]\nname = \"member\"\nsource = \"capsules/member.capsule\"\n\
         version = \"1.0.0\"\nrole = \"uplink\"\n"
    )
    .into_bytes();
    let capsule_hash = format!("blake3:{}", blake3::hash(capsule_bytes).to_hex());
    let manifest_hash = manifest_hash(&bytes);
    let lock = super::super::distro::lock::DistroLock {
        schema_version: 1,
        distro: super::super::distro::lock::DistroLockMeta {
            id: "local-test".into(),
            version: "0.1.0".into(),
            resolved_at: "2026-01-01T00:00:00Z".into(),
        },
        capsules: vec![super::super::distro::lock::LockedCapsule {
            name: "member".into(),
            version: "1.0.0".into(),
            source: "capsules/member.capsule".into(),
            hash: capsule_hash,
            resolved_ref: None,
        }],
        manifest_hash: Some(manifest_hash.clone()),
    };
    let sig = super::super::distro::sign::sign_lock(&lock, &keypair).unwrap();
    std::fs::write(dir.join("Distro.toml"), &bytes).unwrap();
    std::fs::write(
        dir.join("Distro.lock"),
        toml::to_string_pretty(&lock).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("Distro.sig"), sig).unwrap();
    (dir.join("Distro.toml"), bytes, manifest_hash, keypair)
}

async fn prepared_local_signed_fixture(
    dir: &std::path::Path,
    capsule_bytes: &[u8],
) -> (super::signed_source::SignedDistroBundle, Vec<u8>, String) {
    prepared_local_signed_fixture_with_source(
        dir,
        capsule_bytes,
        dir.join("Distro.toml").to_str().unwrap(),
    )
    .await
}

async fn prepared_local_signed_fixture_with_source(
    dir: &std::path::Path,
    capsule_bytes: &[u8],
    source: &str,
) -> (super::signed_source::SignedDistroBundle, Vec<u8>, String) {
    let home = AstridHome::from_path(dir.join("home"));
    let (_, bytes, expected_hash, keypair) = signed_local_source_fixture(dir, capsule_bytes);
    seed_distro_pin(&home, "local-test", &keypair);
    let opts = InitOpts {
        require_signed: true,
        offline: true,
        ..Default::default()
    };
    let super::PreparedDistro::Signed(bundle) =
        super::signed_source::prepare_distro_source(source, &opts, &home)
            .await
            .unwrap()
    else {
        panic!("signed local Distro.toml must prepare a signed bundle");
    };
    (*bundle, bytes, expected_hash)
}

#[test]
fn signed_apply_prepares_and_resolves_bare_manifest_path_in_cwd() {
    run_bare_cwd_child(
        "commands::init::tests::signed_apply_bare_manifest_path_child",
        "BARE_MANIFEST_APPLY_OK",
    );
}

#[test]
fn signed_apply_bare_manifest_path_child() {
    if std::env::var("ASTRID_BARE_CWD_TEST").as_deref() != Ok("1") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let capsule_bytes = b"local signed capsule".to_vec();

    let _current_dir = CurrentDirGuard::set(dir.path());
    let prepared = futures::executor::block_on(prepared_local_signed_fixture_with_source(
        dir.path(),
        &capsule_bytes,
        "Distro.toml",
    ));
    let (bundle, bytes, expected_hash) = prepared;
    assert_eq!(bundle.manifest_hash, expected_hash);
    assert_eq!(bundle.manifest_hash, manifest_hash(&bytes));
    assert_eq!(
        bundle.manifest_path.as_deref(),
        Some(
            dir.path()
                .canonicalize()
                .unwrap()
                .join("Distro.toml")
                .as_path()
        )
    );

    let staging = tempfile::tempdir().unwrap();
    let resolved = futures::executor::block_on(super::signed_source::resolve_signed_capsules(
        &bundle.manifest.capsules,
        &bundle,
        staging.path(),
    ))
    .unwrap();
    let staged = staging.path().join("member.capsule");
    assert_eq!(std::fs::read(&staged).unwrap(), capsule_bytes);
    assert_eq!(resolved[0].source, staged.to_string_lossy());
    std::fs::write(
        std::env::var("ASTRID_BARE_CWD_RESULT").unwrap(),
        "BARE_MANIFEST_APPLY_OK",
    )
    .unwrap();
}

#[test]
fn signed_apply_resolves_relative_member_from_manifest_parent() {
    let dir = tempfile::tempdir().unwrap();
    let capsule_bytes = b"local signed capsule".to_vec();
    let (bundle, _, expected_hash) =
        futures::executor::block_on(prepared_local_signed_fixture(dir.path(), &capsule_bytes));
    assert_eq!(
        bundle.manifest_path.as_deref(),
        Some(dir.path().join("Distro.toml").as_path())
    );

    let staging = tempfile::tempdir().unwrap();
    let resolved = futures::executor::block_on(super::signed_source::resolve_signed_capsules(
        &bundle.manifest.capsules,
        &bundle,
        staging.path(),
    ))
    .unwrap();
    let staged = staging.path().join("member.capsule");
    assert_eq!(resolved[0].source, staged.to_string_lossy());
    assert_eq!(std::fs::read(&staged).unwrap(), capsule_bytes);
    assert_eq!(bundle.manifest_hash, expected_hash);
}

#[test]
fn signed_apply_resolves_member_from_parent_manifest_path() {
    run_bare_cwd_child(
        "commands::init::tests::signed_apply_resolves_member_from_parent_manifest_path_child",
        "PARENT_MANIFEST_APPLY_OK",
    );
}

#[test]
fn signed_apply_resolves_member_from_parent_manifest_path_child() {
    if std::env::var("ASTRID_BARE_CWD_TEST").as_deref() != Ok("1") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("bundle");
    let cwd = dir.path().join("cwd");
    let capsule_bytes = b"local signed capsule".to_vec();
    std::fs::create_dir_all(&cwd).unwrap();

    let _current_dir = CurrentDirGuard::set(&cwd);
    let (bundle_state, bytes, expected_hash) = futures::executor::block_on(
        prepared_local_signed_fixture_with_source(&bundle, &capsule_bytes, "../bundle/Distro.toml"),
    );
    let expected_manifest_path = std::env::current_dir()
        .unwrap()
        .join("../bundle/Distro.toml");

    assert_eq!(bundle_state.manifest_hash, expected_hash);
    assert_eq!(bundle_state.manifest_hash, manifest_hash(&bytes));
    assert_eq!(
        bundle_state.manifest_path.as_deref(),
        Some(expected_manifest_path.as_path())
    );

    let staging = tempfile::tempdir().unwrap();
    let resolved = futures::executor::block_on(super::signed_source::resolve_signed_capsules(
        &bundle_state.manifest.capsules,
        &bundle_state,
        staging.path(),
    ))
    .unwrap();
    let staged = staging.path().join("member.capsule");
    assert_eq!(std::fs::read(&staged).unwrap(), capsule_bytes);
    assert_eq!(resolved[0].source, staged.to_string_lossy());
    std::fs::write(
        std::env::var("ASTRID_BARE_CWD_RESULT").unwrap(),
        "PARENT_MANIFEST_APPLY_OK",
    )
    .unwrap();
}

#[test]
fn signed_apply_fails_closed_on_missing_relative_member() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle, _, _) =
        futures::executor::block_on(prepared_local_signed_fixture(dir.path(), b"member"));
    std::fs::remove_file(dir.path().join("capsules/member.capsule")).unwrap();
    let staging = tempfile::tempdir().unwrap();

    let err = futures::executor::block_on(super::signed_source::resolve_signed_capsules(
        &bundle.manifest.capsules,
        &bundle,
        staging.path(),
    ))
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("member.capsule"),
        "got: {err:#}"
    );
    assert!(!staging.path().join("member.capsule").exists());
}

#[cfg(unix)]
#[test]
fn signed_apply_fails_closed_on_member_escape() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle, _, _) =
        futures::executor::block_on(prepared_local_signed_fixture(dir.path(), b"member"));
    std::fs::remove_file(dir.path().join("capsules/member.capsule")).unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("outside.capsule"), b"outside").unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("outside.capsule"),
        dir.path().join("capsules/member.capsule"),
    )
    .unwrap();
    let staging = tempfile::tempdir().unwrap();

    let err = futures::executor::block_on(super::signed_source::resolve_signed_capsules(
        &bundle.manifest.capsules,
        &bundle,
        staging.path(),
    ))
    .unwrap_err();
    assert!(format!("{err:#}").contains("escapes"), "got: {err:#}");
    assert!(!staging.path().join("member.capsule").exists());
}

#[test]
fn signed_apply_rejects_post_verification_substitution() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle, _, _) =
        futures::executor::block_on(prepared_local_signed_fixture(dir.path(), b"member"));
    std::fs::write(dir.path().join("capsules/member.capsule"), b"substituted").unwrap();
    let staging = tempfile::tempdir().unwrap();

    let err = futures::executor::block_on(super::signed_source::resolve_signed_capsules(
        &bundle.manifest.capsules,
        &bundle,
        staging.path(),
    ))
    .unwrap_err();
    assert!(err.to_string().contains("hash mismatch"), "got: {err}");
    assert!(!staging.path().join("member.capsule").exists());
}

#[test]
fn product_source_prepares_signed_distro_toml_without_shuttle_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path().join("home"));
    let (source, bytes, expected_hash, keypair) = signed_source_fixture(dir.path());
    seed_pin(&home, &keypair);
    let opts = InitOpts {
        require_signed: true,
        offline: true,
        ..Default::default()
    };

    let prepared = futures::executor::block_on(super::signed_source::prepare_distro_source(
        source.to_str().unwrap(),
        &opts,
        &home,
    ))
    .unwrap();
    let super::PreparedDistro::Signed(bundle) = prepared else {
        panic!("signed Distro.toml must use the source bundle path");
    };
    assert_eq!(bundle.manifest_hash, expected_hash);
    assert_eq!(bundle.manifest_hash, manifest_hash(&bytes));
    assert_eq!(
        bundle.lock.manifest_hash.as_deref(),
        Some(expected_hash.as_str())
    );
}

#[test]
fn product_source_missing_pin_fails_closed_without_writing_a_pin() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path().join("home"));
    let (source, _, _, _) = signed_source_fixture(dir.path());

    for accept_new_key in [false, true] {
        let opts = InitOpts {
            require_signed: true,
            offline: true,
            accept_new_key,
            ..Default::default()
        };

        let error = futures::executor::block_on(super::signed_source::prepare_distro_source(
            source.to_str().unwrap(),
            &opts,
            &home,
        ))
        .unwrap_err();
        assert!(
            error.to_string().contains("no signing-key pin"),
            "got: {error:#}"
        );
    }
    assert!(!home.root().join("trust").join("test.pub").exists());
}

#[test]
fn product_source_rotates_only_an_existing_differing_pin() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path().join("home"));
    let (source, _, _, keypair) = signed_source_fixture(dir.path());
    seed_pin(&home, &astrid_crypto::KeyPair::generate());
    let opts = InitOpts {
        require_signed: true,
        offline: true,
        accept_new_key: true,
        ..Default::default()
    };

    futures::executor::block_on(super::signed_source::prepare_distro_source(
        source.to_str().unwrap(),
        &opts,
        &home,
    ))
    .unwrap();

    let rotated = std::fs::read_to_string(home.root().join("trust").join("test.pub")).unwrap();
    assert_eq!(
        rotated,
        format!(
            "{}\n",
            super::super::distro::sign::pubkey_to_wire(&keypair.export_public_key())
        )
    );
}

#[test]
fn product_source_rejects_unsigned_distro_toml_before_install_state() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path().join("home"));
    std::fs::write(
        dir.path().join("Distro.toml"),
        "schema-version = 1\n\n[distro]\nid = \"test\"\nname = \"Test\"\nversion = \"0.1.0\"\n\n\
         [[capsule]]\nname = \"cli\"\nsource = \"@org/cli\"\nversion = \"0.1.0\"\nrole = \"uplink\"\n",
    )
    .unwrap();
    let opts = InitOpts {
        require_signed: true,
        offline: true,
        ..Default::default()
    };

    let error = futures::executor::block_on(super::signed_source::prepare_distro_source(
        dir.path().join("Distro.toml").to_str().unwrap(),
        &opts,
        &home,
    ))
    .unwrap_err();
    assert!(error.to_string().contains("Distro.lock"), "got: {error:#}");
}

#[test]
fn product_source_rejects_tampered_distro_toml_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path().join("home"));
    let (source, bytes, _, _) = signed_source_fixture(dir.path());
    let mut tampered = bytes.clone();
    tampered.extend_from_slice(b"\n# tampered after sealing\n");
    std::fs::write(&source, tampered).unwrap();
    let opts = InitOpts {
        require_signed: true,
        offline: true,
        ..Default::default()
    };

    let error = futures::executor::block_on(super::signed_source::prepare_distro_source(
        source.to_str().unwrap(),
        &opts,
        &home,
    ))
    .unwrap_err();
    assert!(
        error.to_string().contains("manifest_hash"),
        "got: {error:#}"
    );
}

#[test]
fn product_source_rejects_tampered_signature() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path().join("home"));
    let (source, _, _, _) = signed_source_fixture(dir.path());
    std::fs::write(dir.path().join("Distro.sig"), "00").unwrap();
    let opts = InitOpts {
        require_signed: true,
        offline: true,
        ..Default::default()
    };

    let error = futures::executor::block_on(super::signed_source::prepare_distro_source(
        source.to_str().unwrap(),
        &opts,
        &home,
    ))
    .unwrap_err();
    assert!(error.to_string().contains("signature"));
}

#[test]
fn signed_lock_cannot_add_undeclared_member() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path().join("home"));
    let (source, bytes, expected_hash, _) = signed_source_fixture(dir.path());
    let keypair = astrid_crypto::KeyPair::generate();
    let lock = super::super::distro::lock::DistroLock {
        schema_version: 1,
        distro: super::super::distro::lock::DistroLockMeta {
            id: "test".into(),
            version: "0.1.0".into(),
            resolved_at: "2026-01-01T00:00:00Z".into(),
        },
        capsules: vec![super::super::distro::lock::LockedCapsule {
            name: "undeclared".into(),
            version: "0.1.0".into(),
            source: "@org/undeclared".into(),
            hash: format!("blake3:{}", "a".repeat(64)),
            resolved_ref: None,
        }],
        manifest_hash: Some(expected_hash),
    };
    let sig = super::super::distro::sign::sign_lock(&lock, &keypair).unwrap();
    std::fs::write(
        dir.path().join("Distro.lock"),
        toml::to_string_pretty(&lock).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.path().join("Distro.sig"), sig).unwrap();
    let opts = InitOpts {
        require_signed: true,
        offline: true,
        ..Default::default()
    };

    let error = futures::executor::block_on(super::signed_source::prepare_distro_source(
        source.to_str().unwrap(),
        &opts,
        &home,
    ))
    .unwrap_err();
    assert!(error.to_string().contains("undeclared capsule"));
    assert_eq!(super::manifest_hash(&bytes), lock.manifest_hash.unwrap());
}

fn cap(name: &str, group: Option<&str>, default: bool) -> DistroCapsule {
    DistroCapsule {
        name: name.to_string(),
        source: format!("@org/{name}"),
        version: "0.1.0".to_string(),
        tag: None,
        branch: None,
        rev: None,
        default,
        group: group.map(String::from),
        role: None,
        env: HashMap::new(),
    }
}

#[test]
fn parse_cli_vars_splits_first_equals() {
    let raw = vec!["A=1".to_string(), "URL=https://x?y=z".to_string()];
    let map = parse_cli_vars(&raw).unwrap();
    assert_eq!(map["A"], "1");
    assert_eq!(map["URL"], "https://x?y=z");
}

#[test]
fn parse_cli_vars_rejects_no_equals() {
    assert!(parse_cli_vars(&["NOEQ".to_string()]).is_err());
    assert!(parse_cli_vars(&["=value".to_string()]).is_err());
}

#[test]
fn headless_select_takes_defaults_and_ungrouped() {
    let caps = vec![
        cap("cli", None, false),
        cap("openai", Some("llm"), true),
        cap("anthropic", Some("llm"), false),
    ];
    let selected = select_capsules(caps, true).unwrap();
    let names: std::collections::HashSet<&str> = selected.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains("cli"), "ungrouped always selected");
    assert!(names.contains("openai"), "group default selected");
    assert!(!names.contains("anthropic"), "non-default not selected");
}

#[test]
fn headless_select_falls_back_to_first_when_no_default() {
    let caps = vec![
        cap("cli", None, false),
        cap("alpha", Some("llm"), false),
        cap("beta", Some("llm"), false),
    ];
    let selected = select_capsules(caps, true).unwrap();
    let names: std::collections::HashSet<&str> = selected.iter().map(|c| c.name.as_str()).collect();
    // First in manifest order within the group is "alpha".
    assert!(names.contains("alpha"));
    assert!(!names.contains("beta"));
}

fn var(secret: bool, default: Option<&str>) -> VariableDef {
    VariableDef {
        secret,
        description: None,
        default: default.map(String::from),
    }
}

fn cap_with_env(name: &str, key: &str, template: &str) -> DistroCapsule {
    let mut c = cap(name, None, false);
    c.env.insert(key.to_string(), template.to_string());
    c
}

#[test]
fn headless_collect_uses_cli_var_override() {
    let mut variables = HashMap::new();
    variables.insert("api_key".to_string(), var(true, Some("from-default")));
    let selected = vec![cap_with_env("llm", "API_KEY", "{{ api_key }}")];
    let mut cli = HashMap::new();
    cli.insert("api_key".to_string(), "from-cli".to_string());

    let vars = collect_variables(&variables, &selected, true, &cli).unwrap();
    assert_eq!(vars["api_key"], "from-cli");
}

#[test]
fn headless_collect_uses_env_then_default() {
    let mut variables = HashMap::new();
    variables.insert("base_url".to_string(), var(false, Some("https://default")));
    let mut needed = std::collections::HashSet::new();
    needed.insert("base_url".to_string());

    // No CLI var, no env → default.
    let vars = collect_variables_headless(&variables, &needed, &HashMap::new(), |_| None).unwrap();
    assert_eq!(vars["base_url"], "https://default");

    // Env (ASTRID_VAR_BASE_URL) beats default — injected lookup, no
    // process-global state.
    let vars = collect_variables_headless(&variables, &needed, &HashMap::new(), |k| {
        (k == "ASTRID_VAR_BASE_URL").then(|| "https://from-env".to_string())
    })
    .unwrap();
    assert_eq!(vars["base_url"], "https://from-env");
}

#[tokio::test]
async fn offline_refuses_remote_capsule_source() {
    // A local Distro.toml with a remote @org/repo capsule must not
    // silently fetch under --offline.
    let selected = vec![cap("llm", None, false)]; // source "@org/llm"
    let err = install_capsules(&selected, true, &astrid_core::PrincipalId::default(), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("--offline"), "got: {err}");
    assert!(err.to_string().contains("network/GitHub"), "got: {err}");
}

#[test]
fn offline_guard_blocks_only_github_sources() {
    // GitHub-backed shapes are network sources (rejected under --offline).
    assert!(is_network_capsule_source("@org/repo"));
    assert!(is_network_capsule_source("@org/repo@1.2.0"));
    assert!(is_network_capsule_source("github.com/org/repo"));
    assert!(is_network_capsule_source("https://github.com/org/repo"));

    // Local paths are NOT network sources — including a bare relative
    // path like `capsules/cli.capsule`, which the old guard wrongly
    // rejected because it didn't start with `.` or `/`.
    assert!(!is_network_capsule_source("capsules/cli.capsule"));
    assert!(!is_network_capsule_source("./capsules/cli.capsule"));
    assert!(!is_network_capsule_source("/abs/path/cli.capsule"));
    assert!(!is_network_capsule_source("cli.capsule"));
}

#[test]
fn headless_collect_errors_on_missing_required_var() {
    let mut variables = HashMap::new();
    variables.insert("api_key".to_string(), var(true, None)); // no default
    let mut needed = std::collections::HashSet::new();
    needed.insert("api_key".to_string());

    let err =
        collect_variables_headless(&variables, &needed, &HashMap::new(), |_| None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("api_key"), "got: {msg}");
    assert!(msg.contains("ASTRID_VAR_API_KEY"), "got: {msg}");
}

// Durable env writes are exercised through the daemon admin API and the
// storage-control namespace tests.  No test creates or inspects a native
// `.env.json` path: those files are now an explicit migration input only.

/// A `Distro.lock` is written ONLY on a full success (or an empty
/// selection). A partial or wholly-failed run writes no lock so a re-run
/// re-attempts the missing capsules instead of short-circuiting at the
/// freshness gate (`is_lock_fresh` can't diff the capsule set).
#[test]
fn should_write_lock_gates_on_success() {
    // Full success → write.
    assert!(should_write_lock(5, 5));
    // Empty selection is not a failure → write (marks the run done).
    assert!(should_write_lock(0, 0));
    // Partial success → do NOT write: a version-matched lock would make the
    // next `init` short-circuit and never retry the failures.
    assert!(!should_write_lock(5, 3));
    // Every install failed → do NOT write.
    assert!(!should_write_lock(5, 0));
    assert!(!should_write_lock(1, 0));
}

/// Regression: a PARTIAL run must leave no `Distro.lock` on disk, so a
/// later `run_init` reloads nothing at the freshness gate and re-provisions
/// the missing capsules. Before the fix (which wrote a lock whenever
/// `succeeded > 0`), a partial run persisted a version-matched lock and the
/// retry was silently wedged. Exercised through `persist_lock_if_earned`,
/// the exact seam `run_init` uses to decide.
#[test]
fn partial_run_leaves_no_lock_for_retry() {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join("distro.lock");
    let lock = create_lock_from_parts(
        1,
        "example-distro",
        "1.0.0",
        "blake3:manifest-bytes",
        Vec::new(),
    );
    assert_eq!(lock.manifest_hash.as_deref(), Some("blake3:manifest-bytes"));

    // Partial (3 of 5): no lock written, returns false.
    let wrote = persist_lock_if_earned(&lock_path, 5, 3, &lock).unwrap();
    assert!(!wrote, "partial run must not write a lock");
    assert!(
        load_lock(&lock_path).unwrap().is_none(),
        "partial run must leave no Distro.lock on disk, else the retry is wedged"
    );

    // Full (5 of 5): lock written, returns true — a re-run then correctly
    // short-circuits at the freshness gate.
    let wrote = persist_lock_if_earned(&lock_path, 5, 5, &lock).unwrap();
    assert!(wrote, "full success must write the lock");
    assert!(
        load_lock(&lock_path).unwrap().is_some(),
        "full success must persist the lock"
    );
}
