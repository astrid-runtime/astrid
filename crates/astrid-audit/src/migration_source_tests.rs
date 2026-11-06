//! Released legacy files must survive every pre-retirement audit read.

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
    let directory = tempfile::tempdir().unwrap();
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
    let directory = tempfile::tempdir().unwrap();
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

struct ReplacingSourceCapacity {
    source: PathBuf,
    replacement: PathBuf,
    retained: PathBuf,
}

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

#[tokio::test]
async fn original_source_change_during_move_still_prevents_marker_publication() {
    let directory = tempfile::tempdir().unwrap();
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
