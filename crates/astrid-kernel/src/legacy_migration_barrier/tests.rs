use std::collections::BTreeMap;
use std::fs;
#[cfg(target_os = "macos")]
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::*;

fn test_home() -> (tempfile::TempDir, AstridHome) {
    let root = tempfile::tempdir().expect("temporary home");
    make_private_dir(root.path());
    let home = AstridHome::from_path(root.path());
    fs::create_dir_all(home.etc_dir()).expect("etc");
    fs::create_dir_all(home.migrations_dir()).expect("migrations");
    (root, home)
}

fn make_private_dir(path: &std::path::Path) {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private directory");
    #[cfg(not(unix))]
    let _ = path;
}

fn make_private_file(path: &std::path::Path) {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private file");
    #[cfg(not(unix))]
    let _ = path;
}

#[test]
fn layout_v2_without_ledger_is_rejected_before_home_ensure() {
    let (_root, home) = test_home();
    fs::write(home.layout_version_path(), b"2").expect("layout sentinel");

    let error = reject_incomplete_layout_v2(&home).expect_err("missing ledger must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("ledger is missing"));
}

#[test]
fn origin_is_captured_before_fresh_home_ensure() {
    let (_root, home) = test_home();
    fs::remove_dir_all(home.etc_dir()).expect("remove test etc");
    fs::remove_dir_all(home.migrations_dir()).expect("remove test migrations");
    // `migrations/` is nested below `var/`; remove the now-empty parent so
    // `AstridHome::ensure` sees the same empty root as a brand-new install.
    fs::remove_dir_all(home.var_dir()).expect("remove test var");
    let origin = capture_layout_origin(&home).expect("fresh origin");
    assert_eq!(origin, LayoutOrigin::Fresh);
    home.ensure().expect("initialize fresh home");
    assert_eq!(
        home.layout_version().expect("layout version").as_deref(),
        Some("2")
    );
    // The origin remains Fresh even though ensure has now written v2. The
    // native composition root carries this captured value through boot so it
    // can write the explicit fresh-layout ledger instead of treating the home
    // as a failed upgrade.
    assert_eq!(origin, LayoutOrigin::Fresh);
    assert_eq!(
        capture_layout_origin(&home).expect("v2 origin"),
        LayoutOrigin::ExistingV2
    );
}

#[test]
fn layout_v2_incomplete_ledger_is_rejected() {
    let (_root, home) = test_home();
    fs::write(home.layout_version_path(), b"2").expect("layout sentinel");
    let ledger = MigrationLedger {
        schema: LEDGER_SCHEMA,
        complete: false,
        components: Vec::new(),
    };
    let ledger_path = ledger_path(&home);
    let bytes = canonical_json(&ledger).expect("canonical ledger");
    fs::write(&ledger_path, bytes).expect("ledger");
    make_private_file(&ledger_path);

    let error = reject_incomplete_layout_v2(&home).expect_err("incomplete ledger must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("ledger is incomplete"));
}

#[cfg(any(unix, windows))]
#[test]
fn completion_ledger_redirect_is_rejected_without_following_or_mutating_target() {
    let (_root, home) = test_home();
    fs::write(home.layout_version_path(), b"2").expect("layout sentinel");
    let outside = tempfile::tempdir().expect("outside target");
    let outside_ledger = outside.path().join("ledger.json");
    let ledger = fresh_retirement_ledger(SourceIdentity::absent());
    let bytes = canonical_json(&ledger).expect("canonical ledger");
    fs::write(&outside_ledger, &bytes).expect("outside ledger");
    let completion = ledger_path(&home);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_ledger, &completion).expect("ledger symlink");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&outside_ledger, &completion).expect("ledger reparse point");

    let error = reject_incomplete_layout_v2(&home)
        .expect_err("completion ledger redirects must fail closed");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        fs::read(&outside_ledger).expect("outside ledger remains"),
        bytes
    );
    assert!(
        fs::symlink_metadata(&completion)
            .expect("completion entry remains")
            .file_type()
            .is_symlink(),
        "the redirected completion entry must not be replaced or followed"
    );
}

#[test]
fn canonical_complete_ledger_is_admitted() {
    let (_root, home) = test_home();
    fs::write(home.layout_version_path(), b"2").expect("layout sentinel");
    let mut ledger = MigrationLedger {
        schema: LEDGER_SCHEMA,
        complete: true,
        components: vec![
            MigrationComponent {
                name: "system:cow".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::parse("verified-discard-v1:source-digest=absent:layout-receipt=layout-v1-to-v2.complete").expect("proof"),
            },
            MigrationComponent {
                name: "system:state-db".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
            MigrationComponent {
                name: "system:capsule-authority".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
            MigrationComponent {
                name: "system:fresh-layout".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::fresh_layout(),
            },
            MigrationComponent {
                name: "system:gateway-revocations".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
            MigrationComponent {
                name: "system:host-secrets".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
            MigrationComponent {
                name: "system:invites".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
            MigrationComponent {
                name: "system:pair-tokens".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
        ],
    };
    ledger
        .components
        .sort_by(|left, right| left.name.cmp(&right.name));
    let ledger_path = ledger_path(&home);
    let bytes = canonical_json(&ledger).expect("canonical ledger");
    fs::write(&ledger_path, bytes).expect("ledger");
    make_private_file(&ledger_path);
    reject_incomplete_layout_v2(&home).expect("complete canonical ledger is valid");
}

#[test]
fn canonical_ledger_without_layout_provenance_is_rejected() {
    let (_root, home) = test_home();
    fs::write(home.layout_version_path(), b"2").expect("layout sentinel");
    let mut ledger = MigrationLedger {
        schema: LEDGER_SCHEMA,
        complete: true,
        components: vec![
            MigrationComponent {
                name: "system:cow".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::parse("verified-discard-v1:source-digest=absent:layout-receipt=layout-v1-to-v2.complete").expect("proof"),
            },
            MigrationComponent {
                name: "system:state-db".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
            MigrationComponent {
                name: "system:capsule-authority".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
            MigrationComponent {
                name: "system:gateway-revocations".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
            MigrationComponent {
                name: "system:host-secrets".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
            MigrationComponent {
                name: "system:invites".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
            MigrationComponent {
                name: "system:pair-tokens".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: DestinationProof::absent(),
            },
        ],
    };
    ledger
        .components
        .sort_by(|left, right| left.name.cmp(&right.name));
    fs::write(
        ledger_path(&home),
        canonical_json(&ledger).expect("canonical ledger"),
    )
    .expect("ledger");
    assert!(reject_incomplete_layout_v2(&home).is_err());
}

#[test]
fn ledger_rejects_tampered_or_incomplete_component_sets() {
    let (_root, home) = test_home();
    fs::write(home.layout_version_path(), b"2").expect("layout sentinel");
    let ledger = MigrationLedger {
        schema: LEDGER_SCHEMA,
        complete: true,
        components: vec![MigrationComponent {
            name: "system:cow".to_owned(),
            source: SourceIdentity::absent(),
            destination_proof: DestinationProof::parse("verified-discard-v1:source-digest=not-absent:layout-receipt=layout-v1-to-v2.complete").expect("proof"),
        }],
    };
    fs::write(
        ledger_path(&home),
        canonical_json(&ledger).expect("canonical ledger"),
    )
    .expect("ledger");
    assert!(reject_incomplete_layout_v2(&home).is_err());
}

#[test]
fn existing_layout_requires_receipts_for_live_immutable_components() {
    let directory = PrincipalDirectory::default();
    let alias = PrincipalId::new("default").expect("alias");
    let uid = PrincipalUid::from_bytes([0x42; 32]);
    directory.register(alias, uid).expect("binding");
    let home_component = MigrationComponent {
        name: format!("principal:{uid}:home"),
        source: SourceIdentity::absent(),
        destination_proof: DestinationProof::absent(),
    };
    let component = MigrationComponent {
        name: format!("principal:{uid}:logs"),
        source: SourceIdentity::present(
            super::source::SourceDigest::from_hex("a".repeat(64)).expect("digest"),
            super::source::SourceCount::new(1),
            super::source::SourceCount::new(1),
        )
        .expect("present source"),
        destination_proof: DestinationProof::parse(format!("blake3:{}", "b".repeat(64)))
            .expect("proof"),
    };
    let ledger = MigrationLedger {
        schema: LEDGER_SCHEMA,
        complete: true,
        components: vec![home_component, component],
    };
    let (_root, home) = test_home();
    let error = validate_existing_proofs(&home, &ledger, &BTreeMap::new(), &directory)
        .expect_err("live immutable receipt cannot disappear");
    assert!(
        error
            .to_string()
            .contains("live principal migration receipt")
    );
}

#[tokio::test]
async fn existing_ledger_allows_principal_admitted_after_cutover() {
    let root = tempfile::tempdir().expect("temporary home");
    make_private_dir(root.path());
    let home = AstridHome::from_path(root.path());
    home.ensure().expect("fresh home");
    let directory = PrincipalDirectory::default();
    let default_uid = PrincipalUid::from_bytes([0x31; 32]);
    directory
        .register(PrincipalId::default(), default_uid)
        .expect("default binding");
    let quota: std::sync::Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>> =
        std::sync::Arc::new(|_: &astrid_storage::StateOwner| Ok(None));
    let store = astrid_storage::open_runtime_principal_store_with_directory(
        &home,
        quota,
        directory.clone(),
    )
    .await
    .expect("runtime store");

    let mut sources = BTreeMap::new();
    sources.insert("system:cow".to_owned(), SourceIdentity::absent());
    for kind in ["home", "secrets", "audit", "tmp"] {
        sources.insert(
            format!("principal:{default_uid}:{kind}"),
            SourceIdentity::absent(),
        );
    }

    let later_uid = PrincipalUid::from_bytes([0x52; 32]);
    directory
        .register(
            PrincipalId::new("later-agent").expect("later alias"),
            later_uid,
        )
        .expect("post-cutover binding");
    let proofs = collect_destination_proofs(&home, &store, &directory, &sources, false)
        .await
        .expect("post-cutover principal is not legacy inventory");

    assert!(
        proofs
            .keys()
            .all(|name| !name.starts_with(&format!("principal:{later_uid}:")))
    );
    assert!(proofs.contains_key(&format!("principal:{default_uid}:home")));
}

#[test]
fn existing_layout_rejects_reappeared_secret_alias_without_current_binding() {
    let (_root, home) = test_home();
    let legacy_alias = home.secrets_dir().join("deleted-alias");
    astrid_core::platform_fs::ensure_private_directory(&legacy_alias).expect("legacy secrets");

    let error = ensure_no_unretired_component_sources(&home, &PrincipalDirectory::default(), false)
        .expect_err("historical secret alias must not be silently cleaned");
    assert!(error.to_string().contains("secret source reappeared"));
    assert!(legacy_alias.is_dir(), "reappeared source must be preserved");
}

#[test]
fn first_migration_retires_empty_unsupported_kv_and_token_directories() {
    let (_root, home) = test_home();
    let alias = PrincipalId::default();
    let directory = PrincipalDirectory::default();
    directory
        .register(alias.clone(), PrincipalUid::from_bytes([0x51; 32]))
        .expect("default binding");
    let principal_home = home.principal_home(&alias);
    astrid_core::platform_fs::ensure_private_directory(&principal_home.kv_dir())
        .expect("empty legacy KV directory");
    astrid_core::platform_fs::ensure_private_directory(&principal_home.tokens_dir())
        .expect("empty legacy token directory");

    ensure_no_unretired_component_sources(&home, &directory, true)
        .expect("empty unsupported directories are safe to retire before ordinary home cleanup");

    assert!(!principal_home.kv_dir().exists());
    assert!(!principal_home.tokens_dir().exists());
}

fn fresh_retirement_ledger(cow: SourceIdentity) -> MigrationLedger {
    let mut components = vec![
        MigrationComponent {
            name: "system:cow".to_owned(),
            destination_proof: DestinationProof::parse(format!(
                "verified-discard-v1:source-digest={}:layout-receipt=layout-v1-to-v2.complete",
                cow.digest
            ))
            .expect("proof"),
            source: cow,
        },
        MigrationComponent {
            name: "system:fresh-layout".to_owned(),
            source: SourceIdentity::absent(),
            destination_proof: DestinationProof::fresh_layout(),
        },
    ];
    for name in [
        "system:state-db",
        "system:capsule-authority",
        "system:gateway-revocations",
        "system:host-secrets",
        "system:invites",
        "system:pair-tokens",
    ] {
        components.push(MigrationComponent {
            name: name.to_owned(),
            source: SourceIdentity::absent(),
            destination_proof: DestinationProof::absent(),
        });
    }
    components.sort_by(|left, right| left.name.cmp(&right.name));
    MigrationLedger {
        schema: LEDGER_SCHEMA,
        complete: true,
        components,
    }
}

#[test]
fn empty_secret_root_requires_an_exact_source_bound_proof() {
    let uid = PrincipalUid::from_bytes([0x61; 32]);
    let source = SourceIdentity::present(
        super::source::SourceDigest::from_hex("a".repeat(64)).expect("digest"),
        super::source::SourceCount::ZERO,
        super::source::SourceCount::ZERO,
    )
    .expect("present empty source");
    let mut ledger = fresh_retirement_ledger(SourceIdentity::absent());
    ledger.components.extend([
        MigrationComponent {
            name: format!("principal:{uid}:home"),
            source: SourceIdentity::absent(),
            destination_proof: DestinationProof::absent(),
        },
        MigrationComponent {
            name: format!("principal:{uid}:secrets"),
            destination_proof: DestinationProof::parse(format!(
                "verified-empty-v1:source-digest={}",
                source.digest
            ))
            .expect("proof"),
            source,
        },
    ]);
    ledger
        .components
        .sort_by(|left, right| left.name.cmp(&right.name));

    validate_ledger_shape(&ledger).expect("empty secret proof is source-bound");
    let secret = ledger
        .components
        .iter_mut()
        .find(|component| component.name.ends_with(":secrets"))
        .expect("secret component");
    secret.source.entries = super::source::SourceCount::new(1);
    assert!(validate_ledger_shape(&ledger).is_err());
}

#[test]
fn migrated_capsule_scopes_are_added_to_the_frozen_source_inventory() {
    let (_root, home) = test_home();
    let alias = PrincipalId::default();
    let uid = PrincipalUid::from_bytes([0x62; 32]);
    let capsule = "legacy-provider".to_owned();
    let principal_home = home.principal_home(&alias);
    astrid_core::platform_fs::ensure_private_directory(&principal_home.env_dir())
        .expect("legacy env root");
    let env = principal_home.env_dir().join("legacy-provider.env.json");
    fs::write(&env, b"{}\n").expect("legacy env");
    make_private_file(&env);
    let secret = home.secrets_dir().join(alias.as_ref()).join(&capsule);
    astrid_core::platform_fs::ensure_private_directory(&secret).expect("legacy secret scope");
    let secret_value = secret.join("api-key");
    fs::write(&secret_value, b"secret\n").expect("legacy secret");
    make_private_file(&secret_value);

    let mut sources = BTreeMap::new();
    add_principal_scope_sources(&mut sources, &home, &alias, uid, &[capsule])
        .expect("scope inventory");

    assert!(sources[&format!("principal:{uid}:env:legacy-provider")].present);
    assert!(sources[&format!("principal:{uid}:secret:legacy-provider")].present);
}

#[tokio::test]
async fn post_barrier_retirement_resumes_after_crash_and_rejects_reappeared_cow() {
    let root = tempfile::tempdir().expect("temporary home");
    make_private_dir(root.path());
    let home = AstridHome::from_path(root.path());
    home.ensure().expect("fresh home");
    let quota: std::sync::Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>> =
        std::sync::Arc::new(|_: &astrid_storage::StateOwner| Ok(None));
    let store = astrid_storage::open_runtime_principal_store(&home, quota)
        .await
        .expect("runtime store");

    let cow_file = home.cow_dir().join("workspace").join("merged");
    astrid_core::platform_fs::ensure_private_directory(&home.cow_dir()).expect("cow root");
    astrid_core::platform_fs::ensure_private_directory(cow_file.parent().expect("cow parent"))
        .expect("cow directory");
    fs::write(&cow_file, b"discardable workspace").expect("cow file");
    make_private_file(&cow_file);
    let cow = snapshot_path(&home.cow_dir()).expect("cow identity");
    let ledger = fresh_retirement_ledger(cow);
    fs::write(
        ledger_path(&home),
        canonical_json(&ledger).expect("canonical ledger"),
    )
    .expect("ledger");

    assert!(home.principal_store_path().is_dir());
    retire_post_barrier_sources(&home, &store).expect("first retirement");
    assert!(!home.principal_store_path().exists());
    assert!(!home.cow_dir().exists());

    // A crash after unlink but before the caller advances is idempotent.
    retire_post_barrier_sources(&home, &store).expect("restart retirement");

    // A later, different source cannot borrow the historical authorization.
    astrid_core::platform_fs::ensure_private_directory(&home.cow_dir()).expect("reappeared cow");
    let reappeared = home.cow_dir().join("new-bytes");
    fs::write(&reappeared, b"must survive").expect("reappeared bytes");
    make_private_file(&reappeared);
    let error = retire_post_barrier_sources(&home, &store)
        .expect_err("changed reappeared cow must fail closed");
    assert!(error.to_string().contains("changed before retirement"));
    assert_eq!(
        fs::read(reappeared).expect("retained bytes"),
        b"must survive"
    );
}

#[test]
fn tmp_retirement_interruption_preserves_source_or_durable_component_proof() {
    let (_root, home) = test_home();
    fs::write(home.layout_version_path(), b"2").expect("layout sentinel");
    home.ensure().expect("fresh home");
    let alias = PrincipalId::default();
    let uid = PrincipalUid::from_bytes([0x73; 32]);
    let directory = PrincipalDirectory::default();
    directory.register(alias.clone(), uid).expect("binding");
    let source = home.principal_home(&alias).tmp_dir();
    astrid_core::platform_fs::ensure_private_directory(&source).expect("tmp root");
    let entry = source.join("leftover");
    fs::write(&entry, b"disposable bytes").expect("tmp source");
    make_private_file(&entry);
    let expected = snapshot_path(&source).expect("tmp identity");
    let name = format!("principal:{uid}:tmp");
    let mut snapshots = BTreeMap::new();
    snapshots.insert(name.clone(), expected.clone());
    let mut ledger = fresh_retirement_ledger(SourceIdentity::absent());
    ledger.components.push(MigrationComponent {
        name: name.clone(),
        source: expected.clone(),
        destination_proof: DestinationProof::parse(format!(
            "verified-discard-v1:source-digest={}:disposable=tmp",
            expected.digest
        ))
        .expect("proof"),
    });
    ledger
        .components
        .sort_by(|left, right| left.name.cmp(&right.name));
    let ledger_bytes = canonical_json(&ledger).expect("canonical durable tmp proof");
    astrid_core::platform_fs::atomic_write_private_file(&ledger_path(&home), &ledger_bytes)
        .expect("durable tmp proof");

    inject_tmp_retirement_interruption_once(&home);
    retire_disposable_tmp_sources(&home, &directory, &snapshots).expect("tmp source retirement");
    let error = interrupt_after_tmp_retirement_if_requested(&home)
        .expect_err("injected crash must stop before the global ledger write");
    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);

    let source_preserved =
        source.exists() && snapshot_path(&source).is_ok_and(|actual| actual == expected);
    let durable_proof = fs::read(ledger_path(&home))
        .ok()
        .and_then(|bytes| decode_canonical::<MigrationLedger>(&bytes, &ledger_path(&home)).ok())
        .is_some_and(|ledger| {
            ledger.components.iter().any(|component| {
                component.name == name
                    && component.source == expected
                    && component
                        .destination_proof
                        .starts_with("verified-discard-v1:")
            })
        });
    assert!(
        source_preserved || durable_proof,
        "an interrupted tmp retirement must retain the exact source or a canonical proof"
    );
}

#[test]
fn retirement_rejects_source_mutation_and_preserves_data() {
    let root = tempfile::tempdir().expect("temporary root");
    make_private_dir(root.path());
    let file = root.path().join("note.txt");
    fs::write(&file, b"before").expect("source");
    make_private_file(&file);
    let expected = snapshot_path(root.path()).expect("snapshot");
    fs::write(&file, b"after").expect("mutation");

    let error = retire_tree(root.path(), &expected, &[]).expect_err("mutation must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&file).expect("source remains"), b"after");
}

#[test]
fn retirement_never_sweeps_a_component_owned_directory() {
    let root = tempfile::tempdir().expect("temporary root");
    make_private_dir(root.path());
    let capsules = root.path().join(".local").join("capsules");
    fs::create_dir_all(&capsules).expect("capsules");
    make_private_dir(&root.path().join(".local"));
    make_private_dir(&capsules);
    let package = capsules.join("example");
    fs::write(&package, b"package").expect("package");
    make_private_file(&package);
    let expected = snapshot_path(root.path()).expect("snapshot");

    let error = retire_tree(root.path(), &expected, std::slice::from_ref(&capsules))
        .expect_err("protected component source must not be swept");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        package.exists(),
        "component source must remain for its importer"
    );
}

#[test]
fn ordinary_tree_retirement_is_bottom_up_and_idempotent_at_call_site() {
    let root = tempfile::tempdir().expect("temporary root");
    make_private_dir(root.path());
    let nested = root.path().join("a").join("b");
    fs::create_dir_all(&nested).expect("nested source");
    make_private_dir(&root.path().join("a"));
    make_private_dir(&nested);
    let value = nested.join("value");
    fs::write(&value, b"value").expect("source");
    make_private_file(&value);
    let expected = snapshot_path(root.path()).expect("snapshot");
    retire_tree(root.path(), &expected, &[]).expect("ordinary source retires");
    assert!(!root.path().exists());
    // A restart sees an absent principal source and therefore performs no
    // recursive cleanup. This mirrors `retire_principal_sources`'s idempotent
    // absent-path branch.
    assert_eq!(
        snapshot_path(root.path()).expect("absent snapshot"),
        SourceIdentity::absent()
    );
}

#[cfg(unix)]
#[test]
fn retirement_rejects_same_uid_symlink_swap_before_unlink() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary root");
    make_private_dir(root.path());
    let source = root.path().join("entry");
    fs::write(&source, b"source").expect("source");
    make_private_file(&source);
    let expected = snapshot_path(root.path()).expect("source identity");
    let outside = tempfile::tempdir().expect("outside target");
    let outside_file = outside.path().join("outside");
    fs::write(&outside_file, b"outside").expect("outside file");
    let outside_target = outside_file.clone();
    super::host_fs::set_test_retire_leaf_hook(
        source.clone(),
        Box::new(move |path| {
            fs::remove_file(path).expect("replace source");
            symlink(&outside_target, path).expect("same-uid symlink replacement");
        }),
    );

    let error = retire_tree(root.path(), &expected, &[])
        .expect_err("a symlink replacement must fail closed");

    assert!(error.to_string().contains("redirect") || error.to_string().contains("regular"));
    assert!(
        fs::symlink_metadata(&source)
            .expect("replacement remains")
            .file_type()
            .is_symlink(),
        "retirement must not unlink a replacement symlink"
    );
    assert_eq!(
        fs::read(&outside_file).expect("outside survives"),
        b"outside"
    );
}

#[cfg(unix)]
#[test]
fn retirement_rejects_same_uid_fifo_swap_before_unlink() {
    use std::os::unix::fs::FileTypeExt;

    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;

    let root = tempfile::tempdir().expect("temporary root");
    make_private_dir(root.path());
    let source = root.path().join("entry");
    fs::write(&source, b"source").expect("source");
    make_private_file(&source);
    let expected = snapshot_path(root.path()).expect("source identity");
    super::host_fs::set_test_retire_leaf_hook(
        source.clone(),
        Box::new(move |path| {
            fs::remove_file(path).expect("replace source");
            mkfifo(path, Mode::from_bits_truncate(0o600)).expect("same-uid fifo replacement");
        }),
    );

    let error =
        retire_tree(root.path(), &expected, &[]).expect_err("a FIFO replacement must fail closed");

    assert!(error.to_string().contains("special") || error.to_string().contains("regular"));
    assert!(
        fs::symlink_metadata(&source)
            .expect("replacement remains")
            .file_type()
            .is_fifo(),
        "retirement must not unlink a replacement FIFO"
    );
}

#[cfg(windows)]
#[test]
fn retirement_rejects_same_uid_reparse_swap_before_unlink() {
    let root = tempfile::tempdir().expect("temporary root");
    make_private_dir(root.path());
    let source = root.path().join("entry");
    fs::write(&source, b"source").expect("source");
    let expected = snapshot_path(root.path()).expect("source identity");
    let outside = tempfile::tempdir().expect("outside target");
    let outside_file = outside.path().join("outside");
    fs::write(&outside_file, b"outside").expect("outside file");
    super::host_fs::set_test_retire_leaf_hook(
        source.clone(),
        Box::new(move |path| {
            fs::remove_file(path).expect("replace source");
            std::os::windows::fs::symlink_file(&outside_file, path)
                .expect("same-uid reparse replacement");
        }),
    );

    let error = retire_tree(root.path(), &expected, &[])
        .expect_err("a reparse replacement must fail closed");

    assert!(error.to_string().contains("redirect") || error.to_string().contains("regular"));
    assert!(fs::symlink_metadata(&source).is_ok(), "replacement remains");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_source_root_is_recognized_as_a_mounted_volume() {
    assert!(
        super::host_fs::test_active_mountpoint(Path::new("/")).expect("inspect macOS mount table"),
        "the source-root mount must be treated as an active volume boundary"
    );
}

#[cfg(unix)]
#[test]
fn source_preflight_rejects_symlink_and_fifo() {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    let root = tempfile::tempdir().expect("temporary root");
    let target = tempfile::tempdir().expect("outside target");
    symlink(target.path(), root.path().join("redirect")).expect("symlink");
    assert!(snapshot_path(root.path()).is_err());

    let root = tempfile::tempdir().expect("temporary root");
    let socket_path = root.path().join("special");
    let _socket = UnixListener::bind(&socket_path).expect("socket");
    assert!(snapshot_path(root.path()).is_err());
}

#[cfg(unix)]
#[test]
fn owner_controlled_snapshot_accepts_historical_read_only_modes() {
    let root = tempfile::tempdir().expect("temporary root");
    make_private_dir(root.path());
    let state_db = root.path().join("state.db");
    let wal = state_db.join("wal");
    fs::create_dir_all(&wal).expect("legacy WAL directory");
    fs::set_permissions(&state_db, fs::Permissions::from_mode(0o755))
        .expect("released database mode");
    fs::set_permissions(&wal, fs::Permissions::from_mode(0o755)).expect("released WAL mode");
    let segment = wal.join("00000000000000000000.wal");
    fs::write(&segment, b"released WAL bytes").expect("legacy WAL segment");
    fs::set_permissions(&segment, fs::Permissions::from_mode(0o644))
        .expect("released WAL segment mode");

    assert!(
        snapshot_path(&state_db).is_err(),
        "ordinary component sources retain the owner-only contract"
    );
    let snapshot = snapshot_owner_controlled_path(&state_db)
        .expect("released read-only permissions are migration-compatible");
    assert!(snapshot.present);
    assert_eq!(snapshot.entries, 2);

    fs::set_permissions(&segment, fs::Permissions::from_mode(0o666))
        .expect("make legacy segment writable");
    let error = snapshot_owner_controlled_path(&state_db)
        .expect_err("externally writable database bytes must fail closed");
    assert!(error.to_string().contains("group/world writable"));
}

#[test]
fn prefixed_distro_init_digest_still_binds_discard_proof() {
    let uid = PrincipalUid::from_bytes([0x44; 32]);
    let digest = format!("blake3:{}", "c".repeat(64));
    let source =
        SourceIdentity::from_snapshot_fields(&digest, 1, 8, true).expect("prefixed source");
    assert_eq!(source.digest.as_ref(), digest);
    let mut ledger = fresh_retirement_ledger(SourceIdentity::absent());
    ledger.components.push(MigrationComponent {
        name: format!("principal:{uid}:home"),
        source: SourceIdentity::absent(),
        destination_proof: DestinationProof::absent(),
    });
    ledger.components.push(MigrationComponent {
        name: format!("principal:{uid}:distro-init"),
        source,
        destination_proof: DestinationProof::parse(format!(
            "verified-discard-v1:source-digest={digest}"
        ))
        .expect("proof"),
    });
    ledger
        .components
        .sort_by(|left, right| left.name.cmp(&right.name));
    validate_ledger_shape(&ledger).expect("prefixed distro-init digest binds the discard proof");
}

#[test]
fn destination_proof_rejects_unknown_prefix() {
    assert!(DestinationProof::parse("not-a-proof").is_err());
    assert!(serde_json::from_str::<DestinationProof>(r#""mystery:value""#).is_err());
}

#[test]
fn destination_proof_rejects_newline() {
    assert!(DestinationProof::parse("absent\n").is_err());
    assert!(DestinationProof::parse("verified-discard-v1:source-digest=absent\n").is_err());
}

#[test]
fn destination_proof_accepts_absent_and_canonical_blake3() {
    let absent = DestinationProof::parse("absent").expect("absent");
    assert_eq!(absent.as_ref(), "absent");
    assert_eq!(serde_json::to_string(&absent).expect("json"), r#""absent""#);
    assert_eq!(
        serde_json::from_str::<DestinationProof>(r#""absent""#).expect("parse"),
        absent
    );

    let hex = "b".repeat(64);
    let stored = format!("blake3:{hex}");
    let proof = DestinationProof::parse(stored.clone()).expect("blake3 proof");
    assert_eq!(proof.as_ref(), stored);
    assert_eq!(
        serde_json::to_string(&proof).expect("json"),
        serde_json::to_string(&stored).expect("string json")
    );
}

#[test]
fn destination_proof_rejects_uppercase_blake3_hex() {
    assert!(DestinationProof::parse(format!("blake3:{}", "B".repeat(64))).is_err());
}

#[test]
fn destination_proof_keeps_prefixed_source_digest_in_verified_discard() {
    let digest = format!("blake3:{}", "c".repeat(64));
    let stored = format!("verified-discard-v1:source-digest={digest}");
    let proof = DestinationProof::parse(stored.clone()).expect("prefixed discard");
    assert_eq!(proof.as_ref(), stored);
    assert!(proof.contains(&format!("source-digest={digest}")));
}
