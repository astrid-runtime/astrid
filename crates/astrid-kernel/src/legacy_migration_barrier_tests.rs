use std::collections::BTreeMap;
use std::fs;

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
    fs::write(
        ledger_path(&home),
        canonical_json(&ledger).expect("canonical ledger"),
    )
    .expect("ledger");

    let error = reject_incomplete_layout_v2(&home).expect_err("incomplete ledger must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("ledger is incomplete"));
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
                destination_proof:
                    "verified-discard-v1:source-digest=absent:layout-receipt=layout-v1-to-v2.complete"
                        .to_owned(),
            },
            MigrationComponent {
                name: "system:state-db".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
            },
            MigrationComponent {
                name: "system:capsule-authority".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
            },
            MigrationComponent {
                name: "system:fresh-layout".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof:
                    "fresh-layout-v1:initialized-without-legacy-sources".to_owned(),
            },
            MigrationComponent {
                name: "system:gateway-revocations".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
            },
            MigrationComponent {
                name: "system:host-secrets".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
            },
            MigrationComponent {
                name: "system:invites".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
            },
            MigrationComponent {
                name: "system:pair-tokens".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
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
                destination_proof:
                    "verified-discard-v1:source-digest=absent:layout-receipt=layout-v1-to-v2.complete"
                        .to_owned(),
            },
            MigrationComponent {
                name: "system:state-db".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
            },
            MigrationComponent {
                name: "system:capsule-authority".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
            },
            MigrationComponent {
                name: "system:gateway-revocations".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
            },
            MigrationComponent {
                name: "system:host-secrets".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
            },
            MigrationComponent {
                name: "system:invites".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
            },
            MigrationComponent {
                name: "system:pair-tokens".to_owned(),
                source: SourceIdentity::absent(),
                destination_proof: "absent".to_owned(),
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
            destination_proof:
                "verified-discard-v1:source-digest=not-absent:layout-receipt=layout-v1-to-v2.complete"
                    .to_owned(),
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
        destination_proof: "absent".to_owned(),
    };
    let component = MigrationComponent {
        name: format!("principal:{uid}:logs"),
        source: SourceIdentity {
            digest: "a".repeat(64),
            entries: 1,
            bytes: 1,
            present: true,
        },
        destination_proof: format!("blake3:{}", "b".repeat(64)),
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

fn fresh_retirement_ledger(cow: SourceIdentity) -> MigrationLedger {
    let mut components = vec![
        MigrationComponent {
            name: "system:cow".to_owned(),
            destination_proof: format!(
                "verified-discard-v1:source-digest={}:layout-receipt=layout-v1-to-v2.complete",
                cow.digest
            ),
            source: cow,
        },
        MigrationComponent {
            name: "system:fresh-layout".to_owned(),
            source: SourceIdentity::absent(),
            destination_proof: "fresh-layout-v1:initialized-without-legacy-sources".to_owned(),
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
            destination_proof: "absent".to_owned(),
        });
    }
    components.sort_by(|left, right| left.name.cmp(&right.name));
    MigrationLedger {
        schema: LEDGER_SCHEMA,
        complete: true,
        components,
    }
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
fn released_state_db_accepts_historical_read_only_modes() {
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
    let snapshot = snapshot_released_surrealkv(&state_db)
        .expect("released read-only permissions are migration-compatible");
    assert!(snapshot.present);
    assert_eq!(snapshot.entries, 2);

    fs::set_permissions(&segment, fs::Permissions::from_mode(0o666))
        .expect("make legacy segment writable");
    let error = snapshot_released_surrealkv(&state_db)
        .expect_err("externally writable database bytes must fail closed");
    assert!(error.to_string().contains("group/world writable"));
}
