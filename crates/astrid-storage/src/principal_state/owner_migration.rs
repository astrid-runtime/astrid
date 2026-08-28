//! Crash-recoverable migration from alias-keyed roots to stable principal UIDs.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::engine::{DurableEngine, DurableError, PrincipalCodec, RecoveryLimits};
use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalIdentity;
use astrid_core::principal::PrincipalId;

use super::format_amendment::{STORE_METADATA_FILE, is_supported_alias_owner_metadata};
use super::native_io::{atomic_write, rename_private_entry, sync_directory};
use super::staging;
use super::{
    Blake3ObjectIdentityV1, PrincipalDirectory, RuntimeEngine, RuntimeStore, StateOwner,
    StateOwnerCodecV2, StateOwnerResolver,
};
use crate::error::{StorageError, StorageResult};
use crate::identity::{IdentityStore, KvIdentityStore};
use crate::kv::{KvPrincipalResolver, KvStore, ScopedKvStore, TreeKvStore};

const MIGRATION_INTENT_FILE: &str = "principal-owner-migration.intent";
const ROOT_FILE: &str = "roots.journal";
const REPLACEMENT_ROOT_FILE: &str = "roots.principal-uid.replacement";
const PREVIOUS_ROOT_FILE: &str = "roots.alias.previous";
const MIGRATION_INTENT: &[u8] =
    b"migration=state-owner-alias-to-principal-uid\nfrom=state-owner-v1\nto=principal-uid-v1\n";

#[cfg(feature = "legacy-surrealkv")]
#[path = "unbound_legacy.rs"]
mod unbound_legacy;
#[cfg(feature = "legacy-surrealkv")]
pub(super) use unbound_legacy::admit_unbound_legacy_aliases;

#[derive(Clone, Debug, PartialEq, Eq)]
enum AliasStateOwner {
    System,
    Principal(PrincipalId),
}

impl Ord for AliasStateOwner {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::System, Self::System) => Ordering::Equal,
            (Self::System, Self::Principal(_)) => Ordering::Less,
            (Self::Principal(_), Self::System) => Ordering::Greater,
            (Self::Principal(left), Self::Principal(right)) => left.as_str().cmp(right.as_str()),
        }
    }
}

impl PartialOrd for AliasStateOwner {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug)]
struct AliasStateOwnerCodecV1;

impl PrincipalCodec<AliasStateOwner> for AliasStateOwnerCodecV1 {
    fn encode(&self, owner: &AliasStateOwner) -> Vec<u8> {
        match owner {
            AliasStateOwner::System => vec![0],
            AliasStateOwner::Principal(principal) => {
                let mut bytes = Vec::with_capacity(principal.as_str().len().saturating_add(1));
                bytes.push(1);
                bytes.extend_from_slice(principal.as_str().as_bytes());
                bytes
            },
        }
    }

    fn decode(&self, bytes: &[u8]) -> Option<AliasStateOwner> {
        match bytes.split_first()? {
            (0, []) => Some(AliasStateOwner::System),
            (1, principal) => std::str::from_utf8(principal)
                .ok()
                .and_then(|value| PrincipalId::new(value.to_owned()).ok())
                .map(AliasStateOwner::Principal),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct AliasStateOwnerResolver;

impl KvPrincipalResolver<AliasStateOwner> for AliasStateOwnerResolver {
    fn resolve(&self, namespace: &str) -> StorageResult<AliasStateOwner> {
        let Some((principal, capsule)) = namespace.split_once(":capsule:") else {
            return Ok(AliasStateOwner::System);
        };
        if capsule.is_empty() {
            return Err(StorageError::InvalidKey(
                "host-stamped capsule namespace has an empty capsule identifier".to_owned(),
            ));
        }
        PrincipalId::new(principal.to_owned())
            .map(AliasStateOwner::Principal)
            .map_err(|error| {
                StorageError::InvalidKey(format!(
                    "capsule namespace has invalid host-stamped principal: {error}"
                ))
            })
    }
}

type AliasRuntimeEngine =
    DurableEngine<AliasStateOwner, Blake3ObjectIdentityV1, AliasStateOwnerCodecV1>;
type AliasRuntimeStore = TreeKvStore<
    AliasStateOwner,
    Blake3ObjectIdentityV1,
    AliasStateOwnerResolver,
    AliasRuntimeEngine,
>;

#[derive(Clone)]
struct PrincipalBinding {
    alias: PrincipalId,
    user_id: uuid::Uuid,
    identity: PrincipalIdentity,
    initial_public_key: [u8; 32],
}

pub(super) async fn apply_if_required(
    home: &AstridHome,
    principals: &PrincipalDirectory,
    format_spec: &crate::storage_model::ObjectRecord,
    catalog_spec: &crate::storage_model::ObjectRecord,
    metadata: &[u8],
) -> StorageResult<()> {
    let store = home.principal_store_path();
    let metadata_path = store.join(STORE_METADATA_FILE);
    if !metadata_path.exists() {
        return Ok(());
    }
    let actual = std::fs::read(&metadata_path).map_err(|error| {
        StorageError::Connection(format!(
            "read principal owner metadata {}: {error}",
            metadata_path.display()
        ))
    })?;
    let intent = store.join(MIGRATION_INTENT_FILE);
    if actual == metadata && !intent.exists() {
        return Ok(());
    }
    if actual != metadata && !is_supported_alias_owner_metadata(&actual) && !intent.exists() {
        return Ok(());
    }

    recover_missing_active_root(&store)?;
    if resume_uid_store(
        home,
        principals,
        format_spec,
        catalog_spec,
        metadata,
        &store,
        &intent,
    )
    .await?
    {
        return Ok(());
    }

    if actual != metadata && !is_supported_alias_owner_metadata(&actual) {
        return Err(StorageError::Connection(
            "principal owner migration intent exists but neither its old metadata nor its UID journal is recoverable"
                .to_owned(),
        ));
    }
    migrate_alias_store(
        home,
        principals,
        format_spec,
        catalog_spec,
        metadata,
        &store,
        &intent,
    )
    .await
}

async fn resume_uid_store(
    home: &AstridHome,
    principals: &PrincipalDirectory,
    format_spec: &crate::storage_model::ObjectRecord,
    catalog_spec: &crate::storage_model::ObjectRecord,
    metadata: &[u8],
    store: &Path,
    intent: &Path,
) -> StorageResult<bool> {
    let Ok(engine) = RuntimeEngine::open(
        store,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    ) else {
        return Ok(false);
    };
    finish_uid_store(
        home,
        principals,
        Arc::new(engine),
        format_spec,
        catalog_spec,
        metadata,
    )
    .await?;
    cleanup(store, intent)?;
    Ok(true)
}

async fn migrate_alias_store(
    home: &AstridHome,
    principals: &PrincipalDirectory,
    format_spec: &crate::storage_model::ObjectRecord,
    catalog_spec: &crate::storage_model::ObjectRecord,
    metadata: &[u8],
    store: &Path,
    intent: &Path,
) -> StorageResult<()> {
    let legacy = Arc::new(
        AliasRuntimeEngine::open(
            store,
            Blake3ObjectIdentityV1,
            AliasStateOwnerCodecV1,
            RecoveryLimits::process_addressable(),
        )
        .map_err(|error| {
            StorageError::Connection(format!("open alias-keyed principal store: {error}"))
        })?,
    );
    let legacy_kv: Arc<dyn KvStore> = Arc::new(AliasRuntimeStore::from_engine(
        Arc::clone(&legacy),
        AliasStateOwnerResolver,
    ));
    let bindings = derive_bindings(home, legacy_kv).await?;
    install_directory(principals, &bindings)?;
    let by_alias = bindings
        .iter()
        .map(|binding| (binding.alias.clone(), binding.identity.uid))
        .collect::<HashMap<_, _>>();
    validate_mapped_roots(&legacy, &by_alias)?;

    legacy
        .persist_standalone_object(format_spec)
        .and_then(|_| legacy.persist_standalone_object(catalog_spec))
        .map_err(|error| {
            StorageError::Connection(format!(
                "persist UID migration format specifications: {error}"
            ))
        })?;
    atomic_write(intent, MIGRATION_INTENT)?;
    write_uid_root_snapshot(&legacy, store, &by_alias)?;
    legacy.close().map_err(|error| {
        StorageError::Connection(format!("close alias-keyed principal store: {error}"))
    })?;
    drop(legacy);

    promote_root_snapshot(store)?;
    let engine = Arc::new(
        RuntimeEngine::open(
            store,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .map_err(|error| {
            StorageError::Connection(format!("verify UID-keyed principal store: {error}"))
        })?,
    );
    finish_uid_store(
        home,
        principals,
        engine,
        format_spec,
        catalog_spec,
        metadata,
    )
    .await?;
    cleanup(store, intent)
}

fn validate_mapped_roots(
    legacy: &AliasRuntimeEngine,
    by_alias: &HashMap<PrincipalId, astrid_core::identity::PrincipalUid>,
) -> StorageResult<()> {
    for (owner, _) in legacy
        .roots()
        .map_err(|error| StorageError::Connection(error.to_string()))?
    {
        if let AliasStateOwner::Principal(alias) = owner
            && !by_alias.contains_key(&alias)
        {
            return Err(StorageError::Connection(format!(
                "durable principal {alias} has no authoritative identity record"
            )));
        }
    }
    Ok(())
}

fn write_uid_root_snapshot(
    legacy: &AliasRuntimeEngine,
    store: &Path,
    by_alias: &HashMap<PrincipalId, astrid_core::identity::PrincipalUid>,
) -> StorageResult<()> {
    let replacement = store.join(REPLACEMENT_ROOT_FILE);
    legacy
        .write_mapped_root_snapshot(&replacement, &StateOwnerCodecV2, |owner| match owner {
            AliasStateOwner::System => Ok(StateOwner::System),
            AliasStateOwner::Principal(alias) => {
                let uid = by_alias
                    .get(alias)
                    .copied()
                    .ok_or(DurableError::InvalidRestore(
                        "principal mapping is incomplete",
                    ))?;
                Ok(StateOwner::Principal(uid))
            },
        })
        .map_err(|error| {
            StorageError::Connection(format!("write UID-keyed root snapshot: {error}"))
        })
}

async fn finish_uid_store(
    home: &AstridHome,
    principals: &PrincipalDirectory,
    engine: Arc<RuntimeEngine>,
    format_spec: &crate::storage_model::ObjectRecord,
    catalog_spec: &crate::storage_model::ObjectRecord,
    metadata: &[u8],
) -> StorageResult<()> {
    engine
        .persist_standalone_object(format_spec)
        .and_then(|_| engine.persist_standalone_object(catalog_spec))
        .map_err(|error| {
            StorageError::Connection(format!("verify UID format specifications: {error}"))
        })?;
    let store: Arc<dyn KvStore> = Arc::new(RuntimeStore::from_engine(
        Arc::clone(&engine),
        StateOwnerResolver::new(principals.clone()),
    ));
    backfill_principal_identities(home, principals, store).await?;
    staging::migrate_alias_owner_intents(&home.content_staging_path(), |alias| {
        principals.uid_for(alias)
    })?;
    engine.close().map_err(|error| {
        StorageError::Connection(format!("close UID-keyed principal store: {error}"))
    })?;
    atomic_write(
        &home.principal_store_path().join(STORE_METADATA_FILE),
        metadata,
    )
}

#[cfg(feature = "legacy-surrealkv")]
pub(super) async fn populate_directory(
    home: &AstridHome,
    principals: &PrincipalDirectory,
    store: Arc<dyn KvStore>,
) -> StorageResult<()> {
    let bindings = derive_bindings(home, store).await?;
    install_directory(principals, &bindings)
}

pub(super) async fn backfill_principal_identities(
    home: &AstridHome,
    principals: &PrincipalDirectory,
    store: Arc<dyn KvStore>,
) -> StorageResult<()> {
    let bindings = derive_bindings(home, Arc::clone(&store)).await?;
    install_directory(principals, &bindings)?;
    let identities = KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(store, "system:identity")?,
        principals.clone(),
    );
    for binding in bindings {
        let persisted = identities
            .bind_principal_identity(
                binding.user_id,
                binding.alias.clone(),
                binding.initial_public_key,
            )
            .await
            .map_err(|error| identity_error(&error))?;
        if persisted != binding.identity {
            return Err(StorageError::Connection(format!(
                "principal identity changed while migrating alias {}",
                binding.alias
            )));
        }
    }
    Ok(())
}

async fn derive_bindings(
    home: &AstridHome,
    kv: Arc<dyn KvStore>,
) -> StorageResult<Vec<PrincipalBinding>> {
    let identities = KvIdentityStore::new(ScopedKvStore::new(kv, "system:identity")?);
    let users = identities
        .list_users()
        .await
        .map_err(|error| identity_error(&error))?;
    let cli_root = identities
        .resolve("cli", "local")
        .await
        .map_err(|error| identity_error(&error))?
        .map(|user| user.id);
    let mut bindings = Vec::new();
    for mut user in users {
        let persisted_identity = identities
            .get_principal_identity(user.id)
            .await
            .map_err(|error| identity_error(&error))?;
        let links = identities
            .list_links(user.id)
            .await
            .map_err(|error| identity_error(&error))?;
        let mut linked_aliases = links
            .iter()
            .filter(|link| {
                link.platform == "astrid-agent"
                    || (link.platform == "cli" && link.platform_user_id != "local")
            })
            .map(|link| PrincipalId::new(link.platform_user_id.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                StorageError::Connection(format!(
                    "identity link for user {} has an invalid principal alias: {error}",
                    user.id
                ))
            })?;
        linked_aliases.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
        linked_aliases.dedup();
        if linked_aliases.len() > 1 {
            return Err(StorageError::Connection(format!(
                "identity user {} names multiple Astrid principals",
                user.id
            )));
        }
        let alias = if cli_root == Some(user.id) {
            PrincipalId::default()
        } else if let Some(alias) = linked_aliases.into_iter().next() {
            alias
        } else if home.profile_path(&user.principal).exists() || persisted_identity.is_some() {
            user.principal.clone()
        } else {
            continue;
        };
        let initial_public_key = match &persisted_identity {
            Some(identity) => {
                identity.validate().map_err(|error| {
                    StorageError::Connection(format!(
                        "principal identity for {alias} is invalid: {error}"
                    ))
                })?;
                identity.genesis.initial_public_key
            },
            None => load_initial_public_key(home, &alias)?,
        };
        user.principal = alias.clone();
        let identity = match persisted_identity {
            Some(identity) => identity,
            None => PrincipalIdentity::from_genesis(
                astrid_core::identity::PrincipalGenesis::from_parts(
                    user.id,
                    user.created_at,
                    initial_public_key,
                ),
            )
            .map_err(|error| StorageError::Connection(error.to_string()))?,
        };
        bindings.push(PrincipalBinding {
            alias,
            user_id: user.id,
            identity,
            initial_public_key,
        });
    }
    bindings.sort_by(|left, right| left.alias.as_str().cmp(right.alias.as_str()));
    if bindings
        .windows(2)
        .any(|pair| pair[0].alias == pair[1].alias)
    {
        return Err(StorageError::Connection(
            "two identity users claim one principal alias".to_owned(),
        ));
    }
    Ok(bindings)
}

pub(super) fn load_initial_public_key(
    home: &AstridHome,
    alias: &PrincipalId,
) -> StorageResult<[u8; 32]> {
    let profile = astrid_core::PrincipalProfile::load(home, alias).map_err(|error| {
        StorageError::Connection(format!("load profile for principal {alias}: {error}"))
    })?;
    let device = profile
        .auth
        .public_keys
        .iter()
        .min_by_key(|device| (device.created_at, device.key_id.as_str()))
        .ok_or_else(|| {
            StorageError::Connection(format!(
                "principal {alias} has no Ed25519 key for genesis identity"
            ))
        })?;
    let decoded = hex::decode(&device.pubkey).map_err(|error| {
        StorageError::Connection(format!(
            "principal {alias} has an invalid genesis public key: {error}"
        ))
    })?;
    <[u8; 32]>::try_from(decoded).map_err(|_| {
        StorageError::Connection(format!(
            "principal {alias} genesis public key is not 32 bytes"
        ))
    })
}

fn identity_error(error: &crate::identity::IdentityError) -> StorageError {
    StorageError::Connection(format!("principal identity migration: {error}"))
}

fn install_directory(
    principals: &PrincipalDirectory,
    bindings: &[PrincipalBinding],
) -> StorageResult<()> {
    principals.replace_all(
        bindings
            .iter()
            .map(|binding| (binding.alias.clone(), binding.identity.uid)),
    )
}

fn recover_missing_active_root(store: &Path) -> StorageResult<()> {
    let active = store.join(ROOT_FILE);
    if active.exists() {
        return Ok(());
    }
    let replacement = store.join(REPLACEMENT_ROOT_FILE);
    let previous = store.join(PREVIOUS_ROOT_FILE);
    let source = if replacement.exists() {
        replacement
    } else if previous.exists() {
        previous
    } else {
        return Err(StorageError::Connection(
            "principal owner migration lost every root-journal candidate".to_owned(),
        ));
    };
    rename_private_entry(&source, &active)?;
    sync_directory(store)
}

fn promote_root_snapshot(store: &Path) -> StorageResult<()> {
    let active = store.join(ROOT_FILE);
    let replacement = store.join(REPLACEMENT_ROOT_FILE);
    let previous = store.join(PREVIOUS_ROOT_FILE);
    if previous.exists() {
        return Err(StorageError::Connection(format!(
            "principal owner migration backup already exists at {}",
            previous.display()
        )));
    }
    rename_private_entry(&active, &previous)?;
    sync_directory(store)?;
    rename_private_entry(&replacement, &active)?;
    sync_directory(store)
}

fn cleanup(store: &Path, intent: &Path) -> StorageResult<()> {
    match std::fs::remove_file(intent) {
        Ok(()) => sync_directory(store),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StorageError::Connection(format!(
            "remove principal owner migration intent {}: {error}",
            intent.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::storage_model::ObjectIdentity;
    use astrid_core::profile::{DeviceKey, DeviceScope, PrincipalProfile};

    use super::*;
    use crate::kv::{KvQuotaResolver, ScopedKvStore};
    use crate::principal_state::bootstrap;
    use crate::principal_state::format_amendment::{
        PRE_PRINCIPAL_UID_FORMAT_SPEC_ID, legacy_store_metadata,
    };
    use crate::principal_state::migrations::{CATALOG_TREE_MARKER, MIGRATION_MARKER_FILE};
    use crate::principal_state::{StateOwner, open_runtime_principal_store_with_directory};

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) | StateOwner::User(_) => {
                    Some(u64::MAX)
                },
            })
        })
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn alias_roots_migrate_without_changing_generation_or_commit() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let alias = PrincipalId::new("Alice").unwrap();
        let initial_public_key = [0x42; 32];
        let mut profile = PrincipalProfile::default();
        profile.auth.public_keys.push(DeviceKey::new(
            hex::encode(initial_public_key),
            DeviceScope::Full,
            None,
            1_700_000_000,
        ));
        profile.save_to_path(&home.profile_path(&alias)).unwrap();

        let store_path = home.principal_store_path();
        let legacy = Arc::new(
            AliasRuntimeEngine::open(
                &store_path,
                Blake3ObjectIdentityV1,
                AliasStateOwnerCodecV1,
                RecoveryLimits::process_addressable(),
            )
            .unwrap(),
        );
        let legacy_kv: Arc<dyn KvStore> = Arc::new(AliasRuntimeStore::from_engine(
            Arc::clone(&legacy),
            AliasStateOwnerResolver,
        ));
        let identities = KvIdentityStore::new(
            ScopedKvStore::new(Arc::clone(&legacy_kv), "system:identity").unwrap(),
        );
        // Legacy agent provisioning stored `cli/<principal>` while the user
        // record normalized its display name into a different alias.
        let user = identities.create_user(Some("Alice")).await.unwrap();
        assert_eq!(user.principal, PrincipalId::new("alice").unwrap());
        identities
            .link("cli", alias.as_str(), user.id, "system")
            .await
            .unwrap();
        let principal_kv =
            ScopedKvStore::new(Arc::clone(&legacy_kv), "Alice:capsule:demo").unwrap();
        principal_kv.set("answer", b"42".to_vec()).await.unwrap();
        let old_root = legacy
            .root(&AliasStateOwner::Principal(alias.clone()))
            .unwrap()
            .unwrap();
        legacy.close().unwrap();
        drop(legacy_kv);
        drop(legacy);

        atomic_write(
            &store_path.join(STORE_METADATA_FILE),
            &legacy_store_metadata(PRE_PRINCIPAL_UID_FORMAT_SPEC_ID),
        )
        .unwrap();
        atomic_write(&store_path.join(MIGRATION_MARKER_FILE), CATALOG_TREE_MARKER).unwrap();

        let principals = PrincipalDirectory::default();
        let migrated = open_runtime_principal_store_with_directory(
            &home,
            unlimited_quota(),
            principals.clone(),
        )
        .await
        .unwrap();
        let uid = principals.uid_for(&alias).unwrap();
        assert_eq!(
            migrated.engine.root(&StateOwner::Principal(uid)).unwrap(),
            Some(old_root)
        );
        let migrated_kv = ScopedKvStore::new(migrated.kv(), "Alice:capsule:demo").unwrap();
        assert_eq!(
            migrated_kv.get("answer").await.unwrap(),
            Some(b"42".to_vec())
        );
        let identity_store = KvIdentityStore::with_principal_directory(
            ScopedKvStore::new(migrated.kv(), "system:identity").unwrap(),
            principals.clone(),
        );
        let persisted = identity_store.get_user(user.id).await.unwrap().unwrap();
        let identity = identity_store
            .get_principal_identity(persisted.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(identity.uid, uid);
        assert_eq!(identity.genesis.initial_public_key, initial_public_key);
        assert_eq!(identity.genesis.identity_id, user.id);
        assert_eq!(
            identity.genesis.created_at_seconds,
            user.created_at.timestamp()
        );
        assert!(store_path.is_dir());
        assert!(home.storage_volume_path().is_file());

        let format_spec = bootstrap::format_specification().unwrap();
        let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
        assert_eq!(
            migrated
                .engine
                .object(Blake3ObjectIdentityV1.identify(&format_spec))
                .unwrap(),
            Some(format_spec)
        );
        assert_eq!(
            migrated
                .engine
                .object(Blake3ObjectIdentityV1.identify(&catalog_spec))
                .unwrap(),
            Some(catalog_spec)
        );
        migrated.kv().close().await.unwrap();
    }

    #[test]
    fn promotion_prefixes_recover_new_snapshot_or_old_journal() {
        let after_backup = tempfile::tempdir().unwrap();
        let store = after_backup.path();
        std::fs::write(store.join(PREVIOUS_ROOT_FILE), b"old").unwrap();
        std::fs::write(store.join(REPLACEMENT_ROOT_FILE), b"new").unwrap();
        recover_missing_active_root(store).unwrap();
        assert_eq!(std::fs::read(store.join(ROOT_FILE)).unwrap(), b"new");
        assert_eq!(
            std::fs::read(store.join(PREVIOUS_ROOT_FILE)).unwrap(),
            b"old"
        );

        let replacement_lost = tempfile::tempdir().unwrap();
        let store = replacement_lost.path();
        std::fs::write(store.join(PREVIOUS_ROOT_FILE), b"old").unwrap();
        recover_missing_active_root(store).unwrap();
        assert_eq!(std::fs::read(store.join(ROOT_FILE)).unwrap(), b"old");
        assert!(!store.join(PREVIOUS_ROOT_FILE).exists());

        let normal = tempfile::tempdir().unwrap();
        let store = normal.path();
        std::fs::write(store.join(ROOT_FILE), b"old").unwrap();
        std::fs::write(store.join(REPLACEMENT_ROOT_FILE), b"new").unwrap();
        promote_root_snapshot(store).unwrap();
        assert_eq!(std::fs::read(store.join(ROOT_FILE)).unwrap(), b"new");
        assert_eq!(
            std::fs::read(store.join(PREVIOUS_ROOT_FILE)).unwrap(),
            b"old"
        );
    }

    #[test]
    fn missing_every_root_candidate_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let error = recover_missing_active_root(directory.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("lost every root-journal candidate")
        );
    }
}
