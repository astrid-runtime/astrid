//! Ordered native store migration registry.
//!
//! Keep the executable upgrade window bounded. When the minimum supported
//! on-disk version advances, retired transforms move to the standalone
//! migrator while their specifications and golden fixtures remain in source
//! history.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;

use super::{NativePrincipalContentStore, RuntimeEngine, StateOwner, atomic_write};
#[cfg(feature = "legacy-surrealkv")]
use super::{RuntimeStore, StateOwnerResolver};
use crate::content::CatalogValidation;
use crate::error::{StorageError, StorageResult};
#[cfg(feature = "legacy-surrealkv")]
use crate::kv::{KvPrincipalResolver, SurrealKvStore};
use astrid_core::dirs::AstridHome;

pub(super) const MIGRATION_MARKER_FILE: &str = "migration.complete";
#[cfg(feature = "legacy-surrealkv")]
const MIGRATION_PAGE_ENTRIES: usize = 512;
const CURRENT_STORE_VERSION: u32 = 2;
const MINIMUM_SUPPORTED_STORE_VERSION: u32 = 1;
pub(super) const LEGACY_TO_V1_MARKER: &[u8] =
    b"migration=surrealkv-to-principal-store\nfrom=legacy\nto=1\n";
pub(super) const CATALOG_TREE_MARKER: &[u8] =
    b"migration=surrealkv-to-principal-store\nfrom=legacy\nto=1\n\
      migration=flat-content-catalog-to-radix-tree\nfrom=1\nto=2\n";

/// Human-auditable record of the transforms compiled into this binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MigrationDescriptor {
    id: &'static str,
    from: &'static str,
    to: u32,
    rollback: &'static str,
}

const MIGRATION_HISTORY: &[MigrationDescriptor] = &[
    MigrationDescriptor {
        id: "surrealkv-to-principal-store",
        from: "legacy",
        to: 1,
        rollback: "legacy source preserved; post-cutover writes require export",
    },
    MigrationDescriptor {
        id: "flat-content-catalog-to-radix-tree",
        from: "1",
        to: 2,
        rollback: "old root remains in commit lineage until retention removes it",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MigrationState {
    Uninitialized,
    PrincipalStore,
    CatalogTree,
}

fn migration_state(store_path: &Path) -> MigrationState {
    match std::fs::read(store_path.join(MIGRATION_MARKER_FILE)).as_deref() {
        Ok(bytes) if bytes == CATALOG_TREE_MARKER => MigrationState::CatalogTree,
        Ok(bytes) if bytes == LEGACY_TO_V1_MARKER => MigrationState::PrincipalStore,
        _ => MigrationState::Uninitialized,
    }
}

pub(super) fn is_complete(store_path: &Path) -> bool {
    migration_state(store_path) != MigrationState::Uninitialized
}

pub(super) async fn apply_required(
    home: &AstridHome,
    store_path: &Path,
    engine: &Arc<RuntimeEngine>,
    validated_catalogs: &Arc<Mutex<BTreeMap<StateOwner, CatalogValidation>>>,
) -> StorageResult<()> {
    let first = MIGRATION_HISTORY.first().ok_or_else(|| {
        StorageError::Internal("principal store has no compiled migration path".to_owned())
    })?;
    let last = MIGRATION_HISTORY.last().ok_or_else(|| {
        StorageError::Internal("principal store has no compiled migration path".to_owned())
    })?;
    if first.id != "surrealkv-to-principal-store"
        || first.from != "legacy"
        || first.to != MINIMUM_SUPPORTED_STORE_VERSION
        || last.id != "flat-content-catalog-to-radix-tree"
        || last.to != CURRENT_STORE_VERSION
    {
        return Err(StorageError::Internal(
            "principal store migration registry is inconsistent".to_owned(),
        ));
    }
    let state = migration_state(store_path);
    if state == MigrationState::CatalogTree {
        return Ok(());
    }
    let legacy_path = home.state_db_path();
    if state == MigrationState::Uninitialized {
        let path_to_check = legacy_path.clone();
        let legacy_exists = run_blocking_migration(move || Ok(path_to_check.exists())).await?;
        if legacy_exists {
            #[cfg(feature = "legacy-surrealkv")]
            migrate_legacy(&legacy_path, engine).await?;
            #[cfg(not(feature = "legacy-surrealkv"))]
            return Err(StorageError::Connection(format!(
                "legacy state exists at {}; rebuild with the legacy-surrealkv feature to migrate it",
                legacy_path.display()
            )));
        }
        if !legacy_exists {
            let engine = Arc::clone(engine);
            run_blocking_migration(move || {
                engine
                    .flush()
                    .map_err(|error| StorageError::Internal(error.to_string()))
            })
            .await?;
        }
    }
    migrate_content_catalogs(engine, validated_catalogs).await?;
    let marker = store_path.join(MIGRATION_MARKER_FILE);
    run_blocking_migration(move || atomic_write(&marker, CATALOG_TREE_MARKER)).await
}

async fn migrate_content_catalogs(
    engine: &Arc<RuntimeEngine>,
    validated_catalogs: &Arc<Mutex<BTreeMap<StateOwner, CatalogValidation>>>,
) -> StorageResult<()> {
    let engine = Arc::clone(engine);
    let validated_catalogs = Arc::clone(validated_catalogs);
    run_blocking_migration(move || {
        let principals = engine
            .roots()
            .map_err(|error| StorageError::Internal(error.to_string()))?;
        let content = NativePrincipalContentStore::from_engine_with_validation(
            Arc::clone(&engine),
            validated_catalogs,
        );
        for (principal, _) in principals {
            content
                .migrate_legacy_catalog(&principal)
                .map_err(|error| StorageError::Serialization(error.to_string()))?;
        }
        engine
            .flush()
            .map_err(|error| StorageError::Internal(error.to_string()))
    })
    .await
}

#[cfg(feature = "legacy-surrealkv")]
async fn migrate_legacy(legacy_path: &Path, engine: &Arc<RuntimeEngine>) -> StorageResult<()> {
    let legacy_path = legacy_path.to_path_buf();
    let engine = Arc::clone(engine);
    let legacy = run_blocking_migration(move || {
        let legacy = SurrealKvStore::open(legacy_path)?;
        migrate_legacy_blocking(&legacy, &engine)?;
        Ok(legacy)
    })
    .await?;
    legacy.close().await
}

#[cfg(feature = "legacy-surrealkv")]
fn migrate_legacy_blocking(
    legacy: &SurrealKvStore,
    engine: &Arc<RuntimeEngine>,
) -> StorageResult<()> {
    let migration = RuntimeStore::from_engine(Arc::clone(engine), StateOwnerResolver);
    let mut expected = BTreeMap::<StateOwner, MigrationDigest>::new();
    let mut cursor = None;
    loop {
        let (entries, next) = legacy.migration_page(cursor.as_deref(), MIGRATION_PAGE_ENTRIES)?;
        if entries.is_empty() {
            break;
        }
        import_page(&migration, &entries, &mut expected)?;
        cursor = next;
    }
    verify_migration(engine, &expected)?;
    engine
        .flush()
        .map_err(|error| StorageError::Internal(error.to_string()))?;
    Ok(())
}

async fn run_blocking_migration<T, F>(operation: F) -> StorageResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> StorageResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            StorageError::Internal(format!("principal store migration worker failed: {error}"))
        })?
}

#[cfg(feature = "legacy-surrealkv")]
fn import_page(
    store: &RuntimeStore,
    entries: &[crate::KvEntry],
    expected: &mut BTreeMap<StateOwner, MigrationDigest>,
) -> StorageResult<()> {
    let resolver = StateOwnerResolver;
    let mut start = 0;
    while start < entries.len() {
        let owner = resolver.resolve(&entries[start].namespace)?;
        let mut end = start.saturating_add(1);
        while end < entries.len() && resolver.resolve(&entries[end].namespace)? == owner {
            end = end.saturating_add(1);
        }
        store.import_entries_for_migration(&owner, &entries[start..end])?;
        let digest = expected.entry(owner).or_default();
        for entry in &entries[start..end] {
            digest.add(&entry.namespace, &entry.key, &entry.value)?;
        }
        start = end;
    }
    Ok(())
}

#[cfg(feature = "legacy-surrealkv")]
fn verify_migration(
    engine: &Arc<RuntimeEngine>,
    expected: &BTreeMap<StateOwner, MigrationDigest>,
) -> StorageResult<()> {
    for (owner, expected_digest) in expected {
        let mut actual = MigrationDigest::default();
        let store = RuntimeStore::from_engine(Arc::clone(engine), StateOwnerResolver);
        store.visit_entries_for_migration(owner, |namespace, key, value| {
            actual.add(namespace, key, value)
        })?;
        if actual.finish() != expected_digest.finish() {
            return Err(StorageError::Internal(format!(
                "legacy migration verification failed for {owner:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "legacy-surrealkv")]
#[derive(Clone, Debug)]
struct MigrationDigest {
    count: u64,
    hasher: blake3::Hasher,
}

#[cfg(feature = "legacy-surrealkv")]
impl Default for MigrationDigest {
    fn default() -> Self {
        Self {
            count: 0,
            hasher: blake3::Hasher::new_derive_key(
                "astrid legacy principal migration verification v1",
            ),
        }
    }
}

#[cfg(feature = "legacy-surrealkv")]
impl MigrationDigest {
    fn add(&mut self, namespace: &str, key: &str, value: &[u8]) -> StorageResult<()> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| StorageError::Internal("migration entry count overflow".to_owned()))?;
        hash_field(&mut self.hasher, namespace.as_bytes())?;
        hash_field(&mut self.hasher, key.as_bytes())?;
        hash_field(&mut self.hasher, value)
    }

    fn finish(&self) -> (u64, [u8; 32]) {
        (self.count, *self.hasher.clone().finalize().as_bytes())
    }
}

#[cfg(feature = "legacy-surrealkv")]
fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) -> StorageResult<()> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| StorageError::Internal("migration field length overflow".to_owned()))?;
    hasher.update(&length.to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn compiled_history_is_contiguous_and_bounded() {
        assert_eq!(MINIMUM_SUPPORTED_STORE_VERSION, 1);
        assert_eq!(CURRENT_STORE_VERSION, 2);
        assert_eq!(MIGRATION_HISTORY.len(), 2);
        assert_eq!(MIGRATION_HISTORY[0].from, "legacy");
        assert_eq!(MIGRATION_HISTORY[0].to, MINIMUM_SUPPORTED_STORE_VERSION);
        assert_eq!(MIGRATION_HISTORY[1].from, "1");
        assert_eq!(MIGRATION_HISTORY[1].to, CURRENT_STORE_VERSION);
        assert!(MIGRATION_HISTORY[0].rollback.contains("source preserved"));
        assert!(MIGRATION_HISTORY[1].rollback.contains("commit lineage"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_migration_work_does_not_stall_the_executor() {
        let entered = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::clone(&entered);
        let worker_released = Arc::clone(&released);
        let release_after_entry = tokio::spawn(async move {
            while !entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            released.store(true, Ordering::Release);
        });

        run_blocking_migration(move || {
            worker_entered.store(true, Ordering::Release);
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(500))
                .unwrap();
            while !worker_released.load(Ordering::Acquire) {
                if Instant::now() >= deadline {
                    return Err(StorageError::Internal(
                        "migration blocked its async executor".to_owned(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        })
        .await
        .unwrap();
        release_after_entry.await.unwrap();
    }
}
