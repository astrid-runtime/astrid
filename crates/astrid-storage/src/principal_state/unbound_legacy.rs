//! Admit leftover layout-1 aliases before `SurrealKV` store import.
//!
//! `import_page` resolves host-stamped `alias:capsule:*` namespaces through
//! [`PrincipalDirectory::uid_for`]. Identity users and profiles do not cover
//! leftover homes that 0.10.4 allowed without a durable identity. Mint those
//! aliases first so store open does not fail closed on the leftover.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope, PrincipalProfile};

use super::super::native_io::sync_directory;
use crate::error::{StorageError, StorageResult};
use crate::identity::{IdentityStore, KvIdentityStore};
use crate::kv::{KvStore, ScopedKvStore};

const QUARANTINE_DIR: &str = "unbound-legacy-homes";

/// Mint leftover valid aliases from `home/*` and unmatched capsule namespaces.
///
/// Aliases already assigned by [`super::derive_bindings`] are left alone.
/// `home/default` is the admitted principal home, not a leftover.
pub(crate) async fn admit_unbound_legacy_aliases(
    home: &AstridHome,
    identity_kv: Arc<dyn KvStore>,
    capsule_aliases: &[PrincipalId],
) -> StorageResult<()> {
    let claimed = super::derive_bindings(home, Arc::clone(&identity_kv))
        .await?
        .into_iter()
        .map(|binding| binding.alias)
        .collect::<HashSet<_>>();
    let identities = KvIdentityStore::new(ScopedKvStore::new(identity_kv, "system:identity")?);
    let mut leftovers = HashSet::new();
    collect_home_leftovers(home, &mut leftovers)?;
    leftovers.extend(
        capsule_aliases
            .iter()
            .filter(|alias| !is_reserved_non_default(alias))
            .cloned(),
    );
    for alias in leftovers {
        if claimed.contains(&alias) {
            continue;
        }
        mint_leftover_identity(home, &identities, &alias).await?;
    }
    Ok(())
}

fn collect_home_leftovers(
    home: &AstridHome,
    leftovers: &mut HashSet<PrincipalId>,
) -> StorageResult<()> {
    let source_root = home.home_dir();
    let metadata = match fs::symlink_metadata(&source_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(StorageError::Connection(format!(
                "scan leftover principal homes {}: {error}",
                source_root.display()
            )));
        },
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::Connection(format!(
            "legacy principal home root is not a regular directory: {}",
            source_root.display()
        )));
    }
    astrid_core::platform_fs::validate_private_directory(&source_root)
        .map_err(|error| storage_io(&error))?;
    astrid_core::platform_fs::verify_no_redirects(&source_root)
        .map_err(|error| storage_io(&error))?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(&source_root).map_err(|error| {
        StorageError::Connection(format!("scan {}: {error}", source_root.display()))
    })? {
        entries.push(entry.map_err(|error| {
            StorageError::Connection(format!("scan {}: {error}", source_root.display()))
        })?);
    }
    for entry in entries {
        admit_or_quarantine_home_entry(home, leftovers, &entry.path(), &entry.file_name())?;
    }
    Ok(())
}

fn admit_or_quarantine_home_entry(
    home: &AstridHome,
    leftovers: &mut HashSet<PrincipalId>,
    path: &Path,
    file_name: &OsStr,
) -> StorageResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        StorageError::Connection(format!("stat leftover {}: {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return quarantine_entry(
            home,
            path,
            file_name,
            "legacy principal home entry is not a regular directory",
        );
    }
    let Some(alias_text) = file_name.to_str() else {
        return quarantine_entry(
            home,
            path,
            file_name,
            "legacy principal directory name is not UTF-8",
        );
    };
    let Ok(alias) = PrincipalId::new(alias_text.to_owned()) else {
        return quarantine_entry(
            home,
            path,
            file_name,
            "legacy principal directory name is not a valid PrincipalId",
        );
    };
    if is_reserved_non_default(&alias) {
        return quarantine_entry(
            home,
            path,
            file_name,
            alias
                .reserved_reason()
                .unwrap_or("reserved principal alias"),
        );
    }
    leftovers.insert(alias);
    Ok(())
}

async fn mint_leftover_identity(
    home: &AstridHome,
    identities: &KvIdentityStore,
    alias: &PrincipalId,
) -> StorageResult<()> {
    ensure_profile_with_genesis_key(home, alias)?;
    let public_key = super::load_initial_public_key(home, alias)?;
    identities
        .create_principal(alias.clone(), public_key)
        .await
        .map_err(|error| storage_identity(&error))?;
    tracing::info!(
        principal = %alias,
        "minted durable identity for unbound layout-1 principal before store import"
    );
    Ok(())
}

fn ensure_profile_with_genesis_key(home: &AstridHome, alias: &PrincipalId) -> StorageResult<()> {
    let path = PrincipalProfile::path_for(home, alias);
    let mut profile = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(StorageError::Connection(format!(
                "legacy principal profile is not a regular file: {}",
                path.display()
            )));
        },
        Ok(_) => PrincipalProfile::load_required(home, alias).map_err(|error| {
            StorageError::Connection(format!("load leftover profile for {alias}: {error}"))
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => PrincipalProfile::default(),
        Err(error) => {
            return Err(StorageError::Connection(format!(
                "stat leftover profile {}: {error}",
                path.display()
            )));
        },
    };
    let minted = mint_bootstrap_keypair(home, alias, &mut profile)?;
    if minted || !path.is_file() {
        profile.save(home, alias).map_err(|error| {
            StorageError::Connection(format!("save leftover profile for {alias}: {error}"))
        })?;
    }
    Ok(())
}

fn mint_bootstrap_keypair(
    home: &AstridHome,
    principal: &PrincipalId,
    profile: &mut PrincipalProfile,
) -> StorageResult<bool> {
    if !profile.auth.public_keys.is_empty() {
        return Ok(false);
    }
    let keys_dir = home.keys_dir();
    fs::create_dir_all(&keys_dir).map_err(|error| {
        StorageError::Connection(format!("create keys dir {}: {error}", keys_dir.display()))
    })?;
    let key_path = keys_dir.join(format!("{principal}.key"));
    let keypair = astrid_crypto::load_or_generate_keypair(&key_path).map_err(|error| {
        StorageError::Connection(format!(
            "mint leftover principal key {}: {error}",
            key_path.display()
        ))
    })?;
    let pubkey_hex = keypair.export_public_key().to_hex();
    if profile.auth.device_by_pubkey(&pubkey_hex).is_none() {
        profile.auth.public_keys.push(DeviceKey::new(
            pubkey_hex,
            DeviceScope::Full,
            None,
            chrono::Utc::now().timestamp().max(0),
        ));
    }
    if !profile.auth.methods.contains(&AuthMethod::Keypair) {
        profile.auth.methods.push(AuthMethod::Keypair);
    }
    Ok(true)
}

fn quarantine_entry(
    home: &AstridHome,
    source: &Path,
    file_name: &OsStr,
    reason: &str,
) -> StorageResult<()> {
    let quarantine_root = home.migrations_dir().join(QUARANTINE_DIR);
    astrid_core::platform_fs::ensure_private_directory(&quarantine_root)
        .map_err(|error| storage_io(&error))?;
    let destination = unique_quarantine_path(&quarantine_root, file_name)?;
    let source_parent = source.parent().map(Path::to_path_buf);
    fs::rename(source, &destination).map_err(|error| {
        StorageError::Connection(format!(
            "quarantine {} to {}: {error}",
            source.display(),
            destination.display()
        ))
    })?;
    if let Some(parent) = source_parent.as_deref() {
        sync_directory(parent)?;
    }
    sync_directory(destination.parent().unwrap_or(&quarantine_root))?;
    let sidecar = destination.with_file_name(format!(
        "{}.original-name",
        destination
            .file_name()
            .map_or("leftover", |name| name.to_str().unwrap_or("leftover"))
    ));
    astrid_core::platform_fs::atomic_write_private_file(&sidecar, &os_str_bytes(file_name))
        .map_err(|error| storage_io(&error))?;
    tracing::warn!(
        leftover = %file_name.to_string_lossy(),
        reason,
        destination = %destination.display(),
        "quarantined unbound layout-1 home directory before store import"
    );
    Ok(())
}

fn unique_quarantine_path(root: &Path, file_name: &OsStr) -> StorageResult<PathBuf> {
    let encoded = encoded_file_name(file_name);
    for index in 0_u32..1024 {
        let candidate = if index == 0 {
            root.join(&encoded)
        } else {
            root.join(format!("{encoded}-{index}"))
        };
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => {},
            Err(error) => {
                return Err(StorageError::Connection(format!(
                    "stat quarantine candidate {}: {error}",
                    candidate.display()
                )));
            },
        }
    }
    Err(StorageError::Connection(
        "exhausted unique names for quarantined legacy home directory".to_owned(),
    ))
}

fn encoded_file_name(name: &OsStr) -> String {
    const MAX_SAFE_NAME: usize = 64;
    match name.to_str() {
        Some(text)
            if !text.is_empty()
                && text.len() <= MAX_SAFE_NAME
                && text != "."
                && text != ".."
                && text
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') =>
        {
            text.to_owned()
        },
        _ => format!("invalid-{}", blake3::hash(&os_str_bytes(name)).to_hex()),
    }
}

fn os_str_bytes(name: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        name.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        name.to_string_lossy().as_bytes().to_vec()
    }
}

fn is_reserved_non_default(alias: &PrincipalId) -> bool {
    alias.reserved_reason().is_some() && *alias != PrincipalId::default()
}

fn storage_io(error: &std::io::Error) -> StorageError {
    StorageError::Connection(error.to_string())
}

fn storage_identity(error: &crate::identity::IdentityError) -> StorageError {
    StorageError::Connection(format!("unbound layout-1 principal identity: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrincipalDirectory;
    use crate::kv::{KvQuotaResolver, MemoryKvStore, SurrealKvStore};
    use crate::principal_state::{StateOwner, open_runtime_principal_store_with_directory};
    use astrid_core::profile::{DeviceKey, DeviceScope};

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        })
    }

    fn seed_legacy_layout(home: &AstridHome) {
        std::fs::create_dir_all(home.etc_dir()).unwrap();
        std::fs::write(
            home.layout_version_path(),
            astrid_core::dirs::LEGACY_LAYOUT_VERSION,
        )
        .unwrap();
    }

    fn write_admitted_profile(home: &AstridHome, alias: &PrincipalId, key: [u8; 32]) {
        let mut profile = PrincipalProfile::default();
        profile.auth.public_keys.push(DeviceKey::new(
            hex::encode(key),
            DeviceScope::Full,
            None,
            1_700_000_000,
        ));
        profile
            .save_to_path(&home.profile_path(alias))
            .expect("admitted profile");
    }

    #[tokio::test]
    async fn leftover_alias_home_and_capsule_kv_import_without_prior_identity() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        seed_legacy_layout(&home);
        let admitted = PrincipalId::new("default").unwrap();
        write_admitted_profile(&home, &admitted, [0x11; 32]);
        let leftover = PrincipalId::new("legacy-agent").unwrap();
        astrid_core::platform_fs::ensure_private_directory(&home.home_dir()).unwrap();
        astrid_core::platform_fs::ensure_private_directory(home.principal_home(&admitted).root())
            .unwrap();
        let leftover_home = home.principal_home(&leftover).root().to_path_buf();
        astrid_core::platform_fs::ensure_private_directory(&leftover_home).unwrap();
        astrid_core::platform_fs::ensure_private_directory(&leftover_home.join("documents"))
            .unwrap();
        fs::write(leftover_home.join("documents/note.txt"), b"leftover-home").unwrap();
        assert!(!home.profile_path(&leftover).is_file());

        let legacy = Arc::new(SurrealKvStore::open(home.state_db_path()).unwrap());
        let legacy_kv: Arc<dyn KvStore> = legacy.clone();
        let identities = KvIdentityStore::new(
            ScopedKvStore::new(Arc::clone(&legacy_kv), "system:identity").unwrap(),
        );
        // 0.10.4 CLI root is linked at cli/local; its user record principal
        // need not already be `default`. derive_bindings still claims default.
        let user = identities.create_user(Some("cli-root")).await.unwrap();
        identities
            .link("cli", "local", user.id, "system")
            .await
            .unwrap();
        legacy
            .set("default:capsule:shell", "cwd", b"/workspace".to_vec())
            .await
            .unwrap();
        legacy
            .set("legacy-agent:capsule:demo", "note", b"from-kv".to_vec())
            .await
            .unwrap();
        drop(identities);
        drop(legacy_kv);
        legacy.close().await.unwrap();

        let principals = PrincipalDirectory::default();
        let store = open_runtime_principal_store_with_directory(
            &home,
            unlimited_quota(),
            principals.clone(),
        )
        .await
        .expect("store open must survive leftover alias without identity");
        assert!(principals.uid_for(&admitted).is_ok());
        let leftover_uid = principals
            .uid_for(&leftover)
            .expect("leftover alias must be minted before import");
        assert_eq!(
            store
                .kv()
                .get("legacy-agent:capsule:demo", "note")
                .await
                .unwrap(),
            Some(b"from-kv".to_vec())
        );
        assert_eq!(
            store
                .kv()
                .get("default:capsule:shell", "cwd")
                .await
                .unwrap(),
            Some(b"/workspace".to_vec())
        );
        assert!(home.profile_path(&leftover).is_file());
        assert_ne!(leftover_uid, principals.uid_for(&admitted).unwrap());
        let migrated =
            KvIdentityStore::new(ScopedKvStore::new(store.kv(), "system:identity").unwrap());
        let users = migrated.list_users().await.unwrap();
        let default_users = users
            .iter()
            .filter(|user| user.principal == admitted)
            .count();
        assert_eq!(
            default_users, 1,
            "default must not be reminted when derive_bindings already claims it"
        );
        assert_eq!(users.len(), 2);
        store.kv().close().await.unwrap();
    }

    fn memory_identity_kv() -> Arc<dyn KvStore> {
        Arc::new(MemoryKvStore::new())
    }

    fn quarantined_payloads(home: &AstridHome) -> Vec<PathBuf> {
        fs::read_dir(home.migrations_dir().join("unbound-legacy-homes"))
            .expect("quarantine dir")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_none_or(|name| !name.ends_with(".original-name"))
            })
            .collect()
    }

    #[tokio::test]
    async fn storage_quarantines_invalid_leftover_home_entries() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        astrid_core::platform_fs::ensure_private_directory(&home.home_dir()).unwrap();

        let invalid = home.home_dir().join("not.valid");
        astrid_core::platform_fs::ensure_private_directory(&invalid).unwrap();
        fs::write(invalid.join("keep-me.txt"), b"preserved").unwrap();

        let long_name = "a".repeat(200);
        let long_path = home.home_dir().join(&long_name);
        astrid_core::platform_fs::ensure_private_directory(&long_path).unwrap();
        fs::write(long_path.join("keep-me.txt"), b"long-preserved").unwrap();

        let file_path = home.home_dir().join("legacy-agent");
        fs::write(&file_path, b"not-a-directory").unwrap();

        #[cfg(unix)]
        let symlink_path = {
            let target = home.root().join("symlink-target");
            fs::write(&target, b"target-bytes").unwrap();
            let path = home.home_dir().join("symlink-agent");
            std::os::unix::fs::symlink(&target, &path).unwrap();
            path
        };

        admit_unbound_legacy_aliases(&home, memory_identity_kv(), &[])
            .await
            .expect("quarantine invalid leftovers");
        assert!(!invalid.exists());
        assert!(!long_path.exists());
        assert!(!file_path.exists());
        #[cfg(unix)]
        assert!(symlink_path.symlink_metadata().is_err());

        let payloads = quarantined_payloads(&home);
        assert_eq!(payloads.len(), {
            #[cfg(unix)]
            {
                4
            }
            #[cfg(not(unix))]
            {
                3
            }
        });
        let names = payloads
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            names.iter().all(|name| name.len() <= 80),
            "quarantine names must stay bounded: {names:?}"
        );
        let sidecars = fs::read_dir(home.migrations_dir().join("unbound-legacy-homes"))
            .expect("quarantine dir")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".original-name"))
            })
            .collect::<Vec<_>>();
        assert!(
            sidecars
                .iter()
                .any(|path| fs::read(path).ok().as_deref() == Some(long_name.as_bytes())),
            "original long name must be preserved beside the bounded payload"
        );
    }
}
