//! Ordered native store migration registry.
//!
//! Keep the executable upgrade window bounded. When the minimum supported
//! on-disk version advances, retired transforms move to the standalone
//! migrator while their specifications and golden fixtures remain in source
//! history.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use super::{RuntimeEngine, RuntimeStore, StateOwner, StateOwnerResolver, atomic_write};
use crate::error::{StorageError, StorageResult};
use crate::kv::{KvPrincipalResolver, SurrealKvStore};
use astrid_core::dirs::AstridHome;

pub(super) const MIGRATION_MARKER_FILE: &str = "migration.complete";
const MIGRATION_PAGE_ENTRIES: usize = 512;
const CURRENT_STORE_VERSION: u32 = 1;
const MINIMUM_SUPPORTED_STORE_VERSION: u32 = 1;
const LEGACY_TO_V1_MARKER: &[u8] = b"migration=surrealkv-to-principal-store\nfrom=legacy\nto=1\n";

/// Human-auditable record of the transforms compiled into this binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MigrationDescriptor {
    id: &'static str,
    from: &'static str,
    to: u32,
    rollback: &'static str,
}

const MIGRATION_HISTORY: &[MigrationDescriptor] = &[MigrationDescriptor {
    id: "surrealkv-to-principal-store",
    from: "legacy",
    to: 1,
    rollback: "legacy source preserved; post-cutover writes require export",
}];

pub(super) fn is_complete(store_path: &Path) -> bool {
    std::fs::read(store_path.join(MIGRATION_MARKER_FILE))
        .is_ok_and(|bytes| bytes == LEGACY_TO_V1_MARKER)
}

pub(super) async fn apply_required(
    home: &AstridHome,
    store_path: &Path,
    engine: &Arc<RuntimeEngine>,
) -> StorageResult<()> {
    debug_assert_eq!(CURRENT_STORE_VERSION, MINIMUM_SUPPORTED_STORE_VERSION);
    let migration = MIGRATION_HISTORY.first().ok_or_else(|| {
        StorageError::Internal("principal store has no compiled migration path".to_owned())
    })?;
    if migration.id != "surrealkv-to-principal-store"
        || migration.from != "legacy"
        || migration.to != CURRENT_STORE_VERSION
    {
        return Err(StorageError::Internal(
            "principal store migration registry is inconsistent".to_owned(),
        ));
    }
    migrate_legacy(home, engine).await?;
    atomic_write(&store_path.join(MIGRATION_MARKER_FILE), LEGACY_TO_V1_MARKER)
}

async fn migrate_legacy(home: &AstridHome, engine: &Arc<RuntimeEngine>) -> StorageResult<()> {
    let legacy_path = home.state_db_path();
    if !legacy_path.exists() {
        engine
            .flush()
            .map_err(|error| StorageError::Internal(error.to_string()))?;
        return Ok(());
    }

    let legacy = SurrealKvStore::open(&legacy_path)?;
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
    legacy.close().await?;
    Ok(())
}

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

fn verify_migration(
    engine: &Arc<RuntimeEngine>,
    expected: &BTreeMap<StateOwner, MigrationDigest>,
) -> StorageResult<()> {
    for (owner, expected_digest) in expected {
        let mut actual = MigrationDigest::default();
        let store = RuntimeStore::from_engine(Arc::clone(engine), StateOwnerResolver);
        for entry in store.entries_for_migration(owner)? {
            actual.add(&entry.namespace, &entry.key, &entry.value)?;
        }
        if actual.finish() != expected_digest.finish() {
            return Err(StorageError::Internal(format!(
                "legacy migration verification failed for {owner:?}"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct MigrationDigest {
    count: u64,
    hasher: blake3::Hasher,
}

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

fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) -> StorageResult<()> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| StorageError::Internal("migration field length overflow".to_owned()))?;
    hasher.update(&length.to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_history_is_contiguous_and_bounded() {
        assert_eq!(MINIMUM_SUPPORTED_STORE_VERSION, 1);
        assert_eq!(CURRENT_STORE_VERSION, 1);
        assert_eq!(MIGRATION_HISTORY.len(), 1);
        assert_eq!(MIGRATION_HISTORY[0].from, "legacy");
        assert_eq!(MIGRATION_HISTORY[0].to, CURRENT_STORE_VERSION);
        assert!(MIGRATION_HISTORY[0].rollback.contains("source preserved"));
    }
}
