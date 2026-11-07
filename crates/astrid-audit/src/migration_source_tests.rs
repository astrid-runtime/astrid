//! Legacy files must survive every pre-retirement audit read.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;

use super::*;

fn published_legacy_source(path: &Path) {
    // The published state fixture uses the same 0.21 file format as audit.
    // Its unrelated namespaces deliberately form an empty audit projection.
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../astrid-storage/fixtures/v0.10.4-macos-aarch64/state-db.json"
    ))
    .unwrap();
    materialize_source(path, &fixture);
}

fn materialize_source(path: &Path, fixture: &serde_json::Value) {
    for file in fixture["files"].as_array().unwrap() {
        let target = path.join(file["path"].as_str().unwrap());
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(file["base64"].as_str().unwrap())
            .unwrap();
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, bytes).unwrap();
    }
}

fn source_files(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), files);
            } else {
                assert!(entry.file_type().unwrap().is_file());
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(path, path, &mut files);
    files
}

#[tokio::test]
async fn published_legacy_import_preserves_source_until_retirement() {
    let directory = super::legacy_test_directory::temporary().unwrap();
    let path = directory.path().join("audit-db");
    published_legacy_source(&path);
    let before = source_files(&path);
    let destination = AuditLog::open_with_kv_store(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        KeyPair::generate(),
    )
    .unwrap();
    let report = destination
        .import_legacy_audit(&path, "released-empty-audit")
        .await
        .unwrap();
    assert_eq!(report.source_entries, 0);
    assert!(report.marker_installed);
    assert_eq!(source_files(&path), before);
    destination
        .verify_legacy_source_digest(&path, "released-empty-audit", &report.source_digest)
        .await
        .unwrap();
    assert_eq!(source_files(&path), before);
}

#[tokio::test]
async fn rejected_legacy_digest_preserves_published_source() {
    let directory = super::legacy_test_directory::temporary().unwrap();
    let path = directory.path().join("audit-db");
    published_legacy_source(&path);
    let before = source_files(&path);
    let destination = AuditLog::in_memory(KeyPair::generate());
    let error = destination
        .verify_legacy_source_digest(&path, "released-empty-audit", "wrong-digest")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("changed before retirement"));
    assert_eq!(source_files(&path), before);
}

#[cfg(unix)]
struct ReplacingSourceCapacity {
    source: PathBuf,
    replacement: PathBuf,
    retained: PathBuf,
}

#[cfg(unix)]
impl AuditCapacityProvider for ReplacingSourceCapacity {
    fn available_bytes(&self) -> AuditResult<Option<u64>> {
        // Called after the importer captured its source, before copying payload.
        // Simulate a noncooperating source replacement during the MOVE.
        std::fs::rename(&self.source, &self.retained).unwrap();
        std::fs::rename(&self.replacement, &self.source).unwrap();
        Ok(Some(u64::MAX))
    }
}

async fn seed_audit(path: &Path, key: Arc<KeyPair>, entries: usize) {
    let source = AuditLog::open_legacy_source(path, key).unwrap();
    let session = SessionId::new();
    for index in 0..entries {
        source
            .append(
                session.clone(),
                AuditAction::McpToolCall {
                    server: "source-preservation".to_owned(),
                    tool: index.to_string(),
                    args_hash: ContentHash::zero(),
                },
                AuthorizationProof::NotRequired {
                    reason: "fixture".to_owned(),
                },
                AuditOutcome::success(),
            )
            .await
            .unwrap();
    }
    source.close().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn original_source_change_during_move_still_prevents_marker_publication() {
    let directory = super::legacy_test_directory::temporary().unwrap();
    let path = directory.path().join("source");
    let replacement = directory.path().join("replacement");
    let key = Arc::new(KeyPair::generate());
    seed_audit(&path, Arc::clone(&key), 1).await;
    seed_audit(&replacement, Arc::clone(&key), 2).await;
    let replacement_files = source_files(&replacement);
    let destination = AuditLog::open_with_kv_store_and_capacity(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        key,
        Some(Arc::new(ReplacingSourceCapacity {
            source: path.clone(),
            replacement,
            retained: directory.path().join("retained-original"),
        })),
    )
    .unwrap();
    let error = destination
        .import_legacy_audit(&path, "changing-audit-source")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("changed before retirement"));
    assert!(
        destination
            .storage
            .migration_marker()
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(source_files(&path), replacement_files);
}

struct ChangingPayloadCapacity {
    source: PathBuf,
    replacement: BTreeMap<PathBuf, Vec<u8>>,
}

impl AuditCapacityProvider for ChangingPayloadCapacity {
    fn available_bytes(&self) -> AuditResult<Option<u64>> {
        // Windows refuses a parent rename while the original LOCK is open.
        // A noncooperating writer can still replace closed data files without
        // replacing LOCK. Keep that same inode fenced throughout the mutation.
        let writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.source.join("LOCK"))
            .unwrap();
        assert!(matches!(
            writer.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(writer);
        for entry in std::fs::read_dir(&self.source).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == "LOCK" {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                std::fs::remove_dir_all(entry.path()).unwrap();
            } else {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }
        for (relative, bytes) in &self.replacement {
            if relative == Path::new("LOCK") {
                continue;
            }
            let target = self.source.join(relative);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, bytes).unwrap();
        }
        Ok(Some(u64::MAX))
    }
}

#[tokio::test]
async fn original_payload_change_under_shared_lock_prevents_marker_publication() {
    let directory = super::legacy_test_directory::temporary().unwrap();
    let path = directory.path().join("source");
    let replacement = directory.path().join("replacement");
    let key = Arc::new(KeyPair::generate());
    seed_audit(&path, Arc::clone(&key), 1).await;
    seed_audit(&replacement, Arc::clone(&key), 2).await;
    let original_lock = std::fs::read(path.join("LOCK")).unwrap();
    let mut replacement_files = source_files(&replacement);
    replacement_files.insert(PathBuf::from("LOCK"), original_lock);
    let destination = AuditLog::open_with_kv_store_and_capacity(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        key,
        Some(Arc::new(ChangingPayloadCapacity {
            source: path.clone(),
            replacement: replacement_files.clone(),
        })),
    )
    .unwrap();
    let error = destination
        .import_legacy_audit(&path, "changing-audit-payload")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("changed before retirement"));
    assert!(
        destination
            .storage
            .migration_marker()
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(source_files(&path), replacement_files);
}

struct FixedCapacity(u64);

impl AuditCapacityProvider for FixedCapacity {
    fn available_bytes(&self) -> AuditResult<Option<u64>> {
        Ok(Some(self.0))
    }
}

#[tokio::test]
async fn nonempty_old_format_import_preserves_source_on_refusal_and_success() {
    // Generated by actual SurrealKV 0.21.3 public APIs, not a release artifact.
    // An opaque historical payload proves the blind-MOVE byte contract; this
    // test does not claim to recertify historical signatures or chains.
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("../fixtures/surrealkv-0.21.3-audit.json")).unwrap();
    for available in [0, u64::MAX] {
        let directory = super::legacy_test_directory::temporary().unwrap();
        let path = directory.path().join("audit-db");
        materialize_source(&path, &fixture);
        let before = source_files(&path);
        let destination = AuditLog::open_with_kv_store_and_capacity(
            Arc::new(astrid_storage::MemoryKvStore::new()),
            KeyPair::generate(),
            Some(Arc::new(FixedCapacity(available))),
        )
        .unwrap();
        let result = destination
            .import_legacy_audit(&path, "old-nonempty-audit")
            .await;
        assert_eq!(source_files(&path), before);
        if available == 0 {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("insufficient destination capacity")
            );
            assert!(
                destination
                    .storage
                    .migration_marker()
                    .await
                    .unwrap()
                    .is_none()
            );
        } else {
            let report = result.unwrap();
            assert_eq!(report.source_entries, 1);
            assert_eq!(report.imported_entries, 1);
            assert!(report.marker_installed);
            let stored = destination
                .storage
                .as_kv_audit_storage()
                .unwrap()
                .kv_store()
                .get("audit:entries", "fixture-entry")
                .await
                .unwrap();
            assert_eq!(
                stored.as_deref(),
                Some(b"opaque-legacy-audit-entry".as_slice())
            );
            destination
                .verify_legacy_source_digest(&path, "old-nonempty-audit", &report.source_digest)
                .await
                .unwrap();
            assert_eq!(source_files(&path), before);
        }
    }
}

#[tokio::test]
async fn final_digest_keeps_original_writer_fenced_through_staged_retirement() {
    let directory = super::legacy_test_directory::temporary().unwrap();
    let path = directory.path().join("audit-db");
    published_legacy_source(&path);
    let before = source_files(&path);
    let staging_root = directory.path().join("retired");
    let destination = AuditLog::open_with_kv_store(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        KeyPair::generate(),
    )
    .unwrap();
    let report = destination
        .import_legacy_audit(&path, "fenced-retirement")
        .await
        .unwrap();
    destination
        .with_verified_legacy_source(
            &path,
            "fenced-retirement",
            &report.source_digest,
            async |source| {
                assert_eq!(
                    source.kind(),
                    astrid_storage::LegacySourceKind::LockedDatabase
                );
                assert_source_writer_excluded(&path);
                assert_eq!(source_files(&path), before);
                let intent = source.retirement_intent();
                source
                    .retire(&intent, &staging_root)
                    .await
                    .map_err(|error| AuditError::StorageError(error.to_string()))
            },
        )
        .await
        .unwrap();
    assert!(!path.exists());
    assert!(std::fs::read_dir(&staging_root).unwrap().next().is_none());
}

fn assert_source_writer_excluded(source: &std::path::Path) {
    let competing = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(source.join("LOCK"))
        .unwrap();
    assert!(
        matches!(competing.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "writer entered the digest-bound source fence"
    );
    // This checkpoint must close before a Windows parent move. Keeping a
    // separate path-open probe live would itself pin the source directory.
}

#[tokio::test]
async fn empty_source_retirement_atomically_refuses_new_files() {
    let directory = super::legacy_test_directory::temporary().unwrap();
    let path = directory.path().join("audit-db");
    std::fs::create_dir(&path).unwrap();
    let destination = AuditLog::open_with_kv_store(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        KeyPair::generate(),
    )
    .unwrap();
    let report = destination
        .import_legacy_audit(&path, "empty-retirement")
        .await
        .unwrap();
    let error = destination
        .with_verified_legacy_source(
            &path,
            "empty-retirement",
            &report.source_digest,
            async |source| {
                assert_eq!(
                    source.kind(),
                    astrid_storage::LegacySourceKind::EmptyDirectory
                );
                std::fs::write(path.join("late-writer"), b"must survive").unwrap();
                let intent = source.retirement_intent();
                source
                    .retire(&intent, &directory.path().join("retired"))
                    .await
                    .map_err(|error| AuditError::StorageError(error.to_string()))
            },
        )
        .await
        .unwrap_err();
    assert!(!error.to_string().is_empty());
    assert_eq!(
        std::fs::read(path.join("late-writer")).unwrap(),
        b"must survive"
    );
}

#[tokio::test]
async fn unchanged_empty_source_can_be_retired_without_creating_a_lock() {
    let directory = super::legacy_test_directory::temporary().unwrap();
    let path = directory.path().join("audit-db");
    std::fs::create_dir(&path).unwrap();
    let destination = AuditLog::open_with_kv_store(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        KeyPair::generate(),
    )
    .unwrap();
    let report = destination
        .import_legacy_audit(&path, "empty-retirement")
        .await
        .unwrap();
    destination
        .with_verified_legacy_source(
            &path,
            "empty-retirement",
            &report.source_digest,
            async |source| {
                assert_eq!(
                    source.kind(),
                    astrid_storage::LegacySourceKind::EmptyDirectory
                );
                assert!(std::fs::read_dir(&path).unwrap().next().is_none());
                let intent = source.retirement_intent();
                source
                    .retire(&intent, &directory.path().join("retired"))
                    .await
                    .map_err(|error| AuditError::StorageError(error.to_string()))
            },
        )
        .await
        .unwrap();
    assert!(!path.exists());
}

#[path = "migration_source_tests/retirement.rs"]
mod retirement;
