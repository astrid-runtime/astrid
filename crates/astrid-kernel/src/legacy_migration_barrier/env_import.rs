//! Ledger-bound import of released principal env and secret scopes.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use astrid_capsule_install::legacy_env_secret_import_status;
use astrid_capsule_types::CapsuleId;
use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;
use astrid_storage::RuntimePrincipalStore;

use super::host_fs::{path_exists, snapshot_path, storage_io};
use super::ledger::import_legacy_system_secrets;
use super::source::SourceIdentity;

/// Keep retained settings tied to the principal's frozen source inventory,
/// including scopes without a currently installed capsule. Runtime capsule
/// lookups do not inherit other scopes, and values never become system-owned.
pub(super) fn include_legacy_scopes(
    capsules: &mut Vec<CapsuleId>,
    uid: PrincipalUid,
    snapshots: &BTreeMap<String, SourceIdentity>,
) -> io::Result<()> {
    let prefix = format!("principal:{uid}:env:");
    for name in snapshots.keys() {
        let Some(capsule) = name.strip_prefix(&prefix) else {
            continue;
        };
        let capsule = CapsuleId::new(capsule.to_owned()).map_err(storage_io)?;
        if !capsules.contains(&capsule) {
            capsules.push(capsule);
        }
    }
    Ok(())
}

pub(super) async fn import_env_and_secrets(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    bindings: &[(PrincipalId, PrincipalUid)],
    snapshots: &BTreeMap<String, SourceIdentity>,
    host_secret_source: &SourceIdentity,
) -> io::Result<()> {
    let handle = tokio::runtime::Handle::current();
    for (alias, uid) in bindings {
        let owner = astrid_storage::StateOwner::Principal(*uid);
        let summaries = store.capsules().list(&owner).map_err(storage_io)?;
        let env_root = home.principal_home(alias).env_dir();
        let secret_root = home.secrets_dir().join(alias.as_str());
        // Scope ownership comes from this principal's UID-bound inventory,
        // not from whether its capsule package is still installed.
        if path_exists(&env_root)? {
            let mut entries = fs::read_dir(&env_root).map_err(io::Error::other)?;
            while let Some(entry) = entries.next().transpose().map_err(io::Error::other)? {
                let metadata = fs::symlink_metadata(entry.path()).map_err(io::Error::other)?;
                if !metadata.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "legacy env source is not a regular file: {}",
                            entry.path().display()
                        ),
                    ));
                }
            }
        }
        let mut capsules = summaries
            .iter()
            .map(|summary| CapsuleId::new(summary.id()).map_err(storage_io))
            .collect::<io::Result<Vec<_>>>()?;
        include_legacy_scopes(&mut capsules, *uid, snapshots)?;
        let retained = super::env_inventory::record(home, *uid, &capsules, snapshots)?;
        for capsule in &capsules {
            let env = env_root.join(format!("{capsule}.env.json"));
            let secret = secret_root.join(capsule.as_str());
            require_scope_matches_ledger(
                snapshots,
                &format!("principal:{uid}:env:{capsule}"),
                &env,
            )?;
            require_scope_matches_ledger(
                snapshots,
                &format!("principal:{uid}:secret:{capsule}"),
                &secret,
            )?;
            let env_arg = path_exists(&env)?.then_some(env);
            let secret_arg = path_exists(&secret)?.then_some(secret);
            if env_arg.is_none() && secret_arg.is_none() && retained.contains(capsule) {
                let scope =
                    astrid_storage::env::principal_env_store(store.kv(), *uid, capsule.as_str())
                        .map_err(storage_io)?;
                if scope
                    .get(astrid_storage::env::LEGACY_IMPORT_MARKER_KEY)
                    .await
                    .map_err(storage_io)?
                    .is_none()
                {
                    return Err(io::Error::other(format!(
                        "retired legacy scope has no completion receipt: {alias}/{capsule}"
                    )));
                }
            }
            astrid_storage::env::import_legacy_scope(
                store.kv(),
                *uid,
                capsule.as_str(),
                env_arg,
                secret_arg,
                true,
                handle.clone(),
            )
            .await
            .map_err(storage_io)?;
        }
    }
    import_legacy_system_secrets(home, store, handle.clone(), host_secret_source).await?;
    let statuses = legacy_env_secret_import_status(store, home, &store.principal_directory())
        .await
        .map_err(|error| io::Error::other(format!("legacy env/secret status failed: {error}")))?;
    if let Some(status) = statuses.into_iter().find(|status| {
        status.native_env_present
            || status.native_secret_present
            || !status.unreceipted_capsules.is_empty()
    }) {
        return Err(io::Error::other(format!(
            "legacy env/secret sources remain for {} (uid {}); migration API did not retire every scope",
            status.alias, status.uid
        )));
    }
    Ok(())
}

fn require_scope_matches_ledger(
    snapshots: &BTreeMap<String, SourceIdentity>,
    name: &str,
    path: &Path,
) -> io::Result<()> {
    let expected = snapshots
        .get(name)
        .ok_or_else(|| io::Error::other(format!("migration source inventory is missing {name}")))?;
    let actual = snapshot_path(path)?;
    if actual != *expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy env/secret source changed before import: {name}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_scope_matches_ledger;
    use crate::legacy_migration_barrier::host_fs::snapshot_path;
    use std::collections::BTreeMap;
    use std::fs;

    fn make_private_file(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private file");
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    #[test]
    fn capsule_scope_import_rejects_source_that_changed_after_preflight() {
        let root = tempfile::tempdir().expect("temporary scope");
        let env = root.path().join("legacy-provider.env.json");
        fs::write(&env, b"{\"TOKEN\":\"one\"}\n").expect("env");
        make_private_file(&env);
        let expected = snapshot_path(&env).expect("preflight");
        let name = "principal:uid:env:legacy-provider";
        let mut snapshots = BTreeMap::new();
        snapshots.insert(name.to_owned(), expected);

        fs::write(&env, b"{\"TOKEN\":\"two\"}\n").expect("swap");
        make_private_file(&env);

        let error = require_scope_matches_ledger(&snapshots, name, &env)
            .expect_err("changed env must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("changed before import"));
        assert_eq!(
            fs::read(&env).expect("retained swapped bytes"),
            b"{\"TOKEN\":\"two\"}\n"
        );
    }

    #[test]
    fn capsule_scope_import_accepts_identical_preflight_identity() {
        let root = tempfile::tempdir().expect("temporary scope");
        let env = root.path().join("legacy-provider.env.json");
        fs::write(&env, b"{\"TOKEN\":\"one\"}\n").expect("env");
        make_private_file(&env);
        let expected = snapshot_path(&env).expect("preflight");
        let name = "principal:uid:env:legacy-provider";
        let mut snapshots = BTreeMap::new();
        snapshots.insert(name.to_owned(), expected);

        require_scope_matches_ledger(&snapshots, name, &env).expect("unchanged env");
        assert!(
            require_scope_matches_ledger(&snapshots, "principal:uid:env:missing", &env)
                .expect_err("missing inventory")
                .to_string()
                .contains("missing principal:uid:env:missing")
        );
        assert_eq!(
            require_scope_matches_ledger(&snapshots, name, &root.path().join("absent.env.json"))
                .expect_err("absent path must not match a present identity")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    async fn admitted_store() -> (
        tempfile::TempDir,
        super::AstridHome,
        super::RuntimePrincipalStore,
        super::PrincipalUid,
        super::PrincipalUid,
    ) {
        use astrid_core::{dirs::AstridHome, principal::PrincipalId};
        use astrid_storage::{
            IdentityStore as _, KvIdentityStore, KvQuotaResolver, ScopedKvStore, StateOwner,
        };
        use std::sync::Arc;

        let root = tempfile::tempdir().expect("temporary home");
        let home = AstridHome::from_path(root.path());
        home.ensure().expect("home");
        let alias = PrincipalId::default();
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
        let store = astrid_storage::open_runtime_principal_store(&home, quota)
            .await
            .expect("store");
        let identities = KvIdentityStore::with_principal_directory(
            ScopedKvStore::new(store.kv(), "system:identity").expect("identity scope"),
            store.principal_directory(),
        );
        let identity = identities
            .create_principal(alias.clone(), [0x81; 32])
            .await
            .expect("admit principal");
        let uid = identities
            .get_principal_identity(identity.id)
            .await
            .expect("identity read")
            .expect("identity")
            .uid;
        let foreign_identity = identities
            .create_principal(
                PrincipalId::new("foreign").expect("foreign alias"),
                [0x82; 32],
            )
            .await
            .expect("admit foreign principal");
        let foreign_uid = identities
            .get_principal_identity(foreign_identity.id)
            .await
            .expect("foreign identity read")
            .expect("foreign identity")
            .uid;
        (root, home, store, uid, foreign_uid)
    }

    #[tokio::test]
    async fn legacy_default_scope_is_imported_without_an_installed_default_capsule() {
        assert_scope_import("default").await;
    }

    #[tokio::test]
    async fn legacy_removed_capsule_scope_is_imported_without_a_local_package() {
        assert_scope_import("removed-provider").await;
    }

    async fn assert_scope_import(capsule: &str) {
        let (_root, home, store, uid, foreign_uid) = admitted_store().await;
        let alias = super::PrincipalId::default();
        let env_root = home.principal_home(&alias).env_dir();
        astrid_core::platform_fs::ensure_private_directory(&env_root).expect("env directory");
        let env = env_root.join(format!("{capsule}.env.json"));
        fs::write(&env, b"{\"LEGACY_VALUE\":\"preserved\"}\n").expect("legacy env");
        make_private_file(&env);
        let secret_root = home.secrets_dir().join(alias.as_str()).join(capsule);
        astrid_core::platform_fs::ensure_private_directory(&secret_root).expect("secret root");
        let secret = secret_root.join("legacy-token");
        fs::write(&secret, b"disposable-test-value").expect("legacy secret");
        make_private_file(&secret);
        let mut sources = BTreeMap::new();
        crate::legacy_migration_barrier::host_fs::add_principal_scope_sources(
            &mut sources,
            &home,
            &alias,
            uid,
            &[],
        )
        .expect("inventory");

        sources.insert(
            format!("principal:{uid}:secrets"),
            snapshot_path(&home.secrets_dir().join(alias.as_str()))
                .expect("aggregate secret identity"),
        );

        super::import_env_and_secrets(
            &home,
            &store,
            &[(alias.clone(), uid)],
            &sources,
            &super::SourceIdentity::absent(),
        )
        .await
        .expect("legacy scope must not block boot");
        assert!(!env.exists(), "retire only after durable import");
        assert!(!secret_root.exists());
        let scope = astrid_storage::env::principal_env_store(store.kv(), uid, capsule)
            .expect("principal scope");
        assert_eq!(
            astrid_storage::env::get_env(&scope, "LEGACY_VALUE")
                .await
                .expect("read env"),
            Some("preserved".to_owned())
        );
        assert!(
            scope
                .get(astrid_storage::env::LEGACY_IMPORT_MARKER_KEY)
                .await
                .expect("receipt")
                .is_some()
        );
        let foreign = astrid_storage::env::principal_env_store(store.kv(), foreign_uid, capsule)
            .expect("foreign scope");
        assert!(
            astrid_storage::env::read_env(&foreign)
                .await
                .expect("foreign read")
                .is_empty()
        );
        let system =
            astrid_storage::env::system_env_store(store.kv(), capsule).expect("system scope");
        assert!(
            astrid_storage::env::read_env(&system)
                .await
                .expect("system read")
                .is_empty()
        );
        let secrets = astrid_storage::env::principal_secret_store(store.kv(), uid, capsule)
            .expect("secret scope");
        assert_eq!(
            astrid_storage::env::get_secret(&secrets, "legacy-token")
                .await
                .expect("secret read"),
            Some("disposable-test-value".to_owned())
        );
        sources.insert("system:cow".to_owned(), super::SourceIdentity::absent());
        for kind in ["home", "tmp"] {
            sources.insert(
                format!("principal:{uid}:{kind}"),
                super::SourceIdentity::absent(),
            );
        }
        let proofs = crate::legacy_migration_barrier::ledger::collect_destination_proofs(
            &home,
            &store,
            &store.principal_directory(),
            &sources,
            true,
        )
        .await
        .expect("complete destination proofs");
        assert!(!proofs[&format!("principal:{uid}:env:{capsule}")].is_absent());
        assert!(!proofs[&format!("principal:{uid}:secret:{capsule}")].is_absent());
        assert_scope_retry(&home, &store, uid, capsule, &proofs).await;
    }

    async fn assert_scope_retry(
        home: &super::AstridHome,
        store: &super::RuntimePrincipalStore,
        uid: super::PrincipalUid,
        capsule: &str,
        proofs: &BTreeMap<String, crate::legacy_migration_barrier::DestinationProof>,
    ) {
        let alias = super::PrincipalId::default();
        let scope = astrid_storage::env::principal_env_store(store.kv(), uid, capsule)
            .expect("principal scope");
        // A later barrier stage fails after both native sources are retired.
        // Retry must rebuild discovery from durable state, not the old map.
        crate::legacy_migration_barrier::inject_tmp_retirement_interruption_once(home);
        let error =
            crate::legacy_migration_barrier::interrupt_after_tmp_retirement_if_requested(home)
                .expect_err("later barrier interruption");
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        let retry = crate::legacy_migration_barrier::preflight_sources(
            home,
            store,
            &[(alias.clone(), uid)],
        )
        .expect("retry inventory from retired sources");
        assert!(retry.contains_key(&format!("principal:{uid}:env:{capsule}")));
        assert!(retry.contains_key(&format!("principal:{uid}:secret:{capsule}")));
        super::import_env_and_secrets(
            home,
            store,
            &[(alias, uid)],
            &retry,
            &super::SourceIdentity::absent(),
        )
        .await
        .expect("resume completed scope");
        let retry_proofs = crate::legacy_migration_barrier::ledger::collect_destination_proofs(
            home,
            store,
            &store.principal_directory(),
            &retry,
            true,
        )
        .await
        .expect("retry includes orphan receipts");
        for kind in ["env", "secret"] {
            let name = format!("principal:{uid}:{kind}:{capsule}");
            assert_eq!(retry_proofs[&name], proofs[&name]);
        }
        scope
            .delete(astrid_storage::env::LEGACY_IMPORT_MARKER_KEY)
            .await
            .expect("remove completion receipt negative fixture");
        let error = super::import_env_and_secrets(
            home,
            store,
            &[(super::PrincipalId::default(), uid)],
            &retry,
            &super::SourceIdentity::absent(),
        )
        .await
        .expect_err("inventory must not replace a missing receipt");
        assert!(error.to_string().contains("no completion receipt"));
        assert!(
            scope
                .get(astrid_storage::env::LEGACY_IMPORT_MARKER_KEY)
                .await
                .expect("missing receipt remains missing")
                .is_none()
        );
    }

    #[tokio::test]
    async fn legacy_default_conflict_preserves_native_sources() {
        let (_root, home, store, uid, _) = admitted_store().await;
        let alias = super::PrincipalId::default();
        let env_root = home.principal_home(&alias).env_dir();
        astrid_core::platform_fs::ensure_private_directory(&env_root).expect("env root");
        let path = env_root.join("default.env.json");
        let bytes = b"{\"KEY\":\"legacy\"}\n";
        fs::write(&path, bytes).expect("native source");
        make_private_file(&path);
        let scope =
            astrid_storage::env::principal_env_store(store.kv(), uid, "default").expect("scope");
        astrid_storage::env::set_env(&scope, "KEY", "existing")
            .await
            .expect("existing value");
        let mut sources = BTreeMap::new();
        crate::legacy_migration_barrier::host_fs::add_principal_scope_sources(
            &mut sources,
            &home,
            &alias,
            uid,
            &[],
        )
        .expect("inventory");
        let error = super::import_env_and_secrets(
            &home,
            &store,
            &[(alias, uid)],
            &sources,
            &super::SourceIdentity::absent(),
        )
        .await
        .expect_err("conflict must fail");
        assert!(error.to_string().contains("conflicts with durable state"));
        assert_eq!(fs::read(&path).expect("retained source"), bytes);
        assert_eq!(
            astrid_storage::env::get_env(&scope, "KEY")
                .await
                .expect("existing read"),
            Some("existing".to_owned())
        );
        assert!(
            scope
                .get(astrid_storage::env::LEGACY_IMPORT_MARKER_KEY)
                .await
                .expect("receipt read")
                .is_none()
        );
    }

    #[test]
    fn legacy_default_inventory_is_optional_and_deduplicated() {
        let root = tempfile::tempdir().expect("temporary home");
        let home = super::AstridHome::from_path(root.path());
        let alias = super::PrincipalId::default();
        let uid = super::PrincipalUid::from_bytes([0x91; 32]);
        let mut sources = BTreeMap::new();
        crate::legacy_migration_barrier::host_fs::add_principal_scope_sources(
            &mut sources,
            &home,
            &alias,
            uid,
            &[],
        )
        .expect("absent inventory");
        assert!(
            sources.is_empty(),
            "old ledgers must not gain absent default scopes"
        );
        sources.insert(
            format!("principal:{uid}:env:default"),
            super::SourceIdentity::absent(),
        );
        let mut capsules = vec![super::CapsuleId::new("default").expect("scope id")];
        super::include_legacy_scopes(&mut capsules, uid, &sources).expect("frozen scopes");
        assert_eq!(capsules.len(), 1);
        assert_eq!(capsules[0].as_str(), "default");
    }
}
