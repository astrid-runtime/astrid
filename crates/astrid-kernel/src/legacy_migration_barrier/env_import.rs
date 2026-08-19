//! Ledger-bound import of released principal env and secret scopes.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use astrid_capsule_install::legacy_env_secret_import_status;
use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;
use astrid_storage::RuntimePrincipalStore;

use super::host_fs::{path_exists, snapshot_path, storage_io};
use super::ledger::import_legacy_system_secrets;
use super::source::SourceIdentity;

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
        // Unknown capsule-specific files cannot be assigned safely.  This is
        // deliberately a hard dependency rather than an alias-based guess.
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
        for summary in summaries {
            let capsule = summary.id();
            let env = env_root.join(format!("{capsule}.env.json"));
            let secret = secret_root.join(capsule);
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
            astrid_storage::env::import_legacy_scope(
                store.kv(),
                *uid,
                capsule,
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
}
