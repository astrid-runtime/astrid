//! Exercise captured retirement and interrupted-stage recovery through the real API.

use super::*;
use crate::SurrealKvStore;

async fn seeded_source(path: &Path) {
    let store = SurrealKvStore::open(path).unwrap();
    store
        .set("test", "key", b"original".to_vec())
        .await
        .unwrap();
    store.close().await.unwrap();
}

async fn capture(path: &Path) -> LegacySource {
    with_legacy_kv_snapshot(path, async |store, source| {
        assert_eq!(
            store.get("test", "key").await.unwrap().unwrap(),
            b"original"
        );
        source
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn captured_retirement_removes_only_its_source_and_resume_is_idempotent() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let staging = root.path().join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    source.retire(&intent, &staging).await.unwrap();
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    resume_legacy_retirement(&path, &staging, &intent)
        .await
        .unwrap();
    astrid_core::platform_fs::create_private_directory(&path).unwrap();
    std::fs::write(path.join("sentinel"), b"fresh occupant").unwrap();
    assert!(
        resume_legacy_retirement(&path, &staging, &intent)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(path.join("sentinel")).unwrap(),
        b"fresh occupant"
    );
}

#[tokio::test]
async fn empty_capture_refuses_a_late_file_without_staging_it() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("empty");
    let staging = root.path().join("staging");
    astrid_core::platform_fs::create_private_directory(&path).unwrap();
    let source = with_legacy_kv_snapshot(&path, async |_, source| source)
        .await
        .unwrap();
    assert_eq!(source.kind(), LegacySourceKind::EmptyDirectory);
    let intent = source.retirement_intent();
    std::fs::write(path.join("late"), b"must survive").unwrap();
    assert!(source.retire(&intent, &staging).await.is_err());
    assert_eq!(std::fs::read(path.join("late")).unwrap(), b"must survive");
    assert!(!staging.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn replacement_before_retirement_is_preserved() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let retained = root.path().join("retained");
    let staging = root.path().join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    std::fs::rename(&path, &retained).unwrap();
    astrid_core::platform_fs::create_private_directory(&path).unwrap();
    std::fs::write(path.join("sentinel"), b"replacement").unwrap();
    assert!(source.retire(&intent, &staging).await.is_err());
    assert!(retained.join("LOCK").is_file());
    assert_eq!(
        std::fs::read(path.join("sentinel")).unwrap(),
        b"replacement"
    );
}

// Drop the real staged owner to model interruption before any deletion.
async fn stage_captured(
    source: LegacySource,
    staging: &Path,
    intent: &LegacyRetirementIntent,
) -> std::path::PathBuf {
    let stage = staging.join(intent.stage_name().unwrap());
    let owner = source.stage_retirement(intent, staging).await.unwrap();
    drop(owner);
    stage
}

#[tokio::test]
async fn interrupted_stage_without_lock_is_retired_without_reopening_the_database() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let staging = root.path().join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    let stage = stage_captured(source, &staging, &intent).await;
    // Removing LOCK makes this an incomplete database. A legacy engine open
    // would fabricate a new LOCK or fail instead of resuming authorized cleanup.
    std::fs::remove_file(stage.join("LOCK")).unwrap();
    resume_legacy_retirement(&path, &staging, &intent)
        .await
        .unwrap();
    assert!(!path.exists());
    assert!(!stage.exists());
    resume_legacy_retirement(&path, &staging, &intent)
        .await
        .unwrap();
}

#[tokio::test]
async fn unrelated_stage_is_never_adopted() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let staging = root.path().join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    let stage = stage_captured(source, &staging, &intent).await;
    let retained = root.path().join("retained");
    std::fs::rename(&stage, &retained).unwrap();
    astrid_core::platform_fs::create_private_directory(&stage).unwrap();
    std::fs::write(stage.join("sentinel"), b"unknown stage").unwrap();
    assert!(
        resume_legacy_retirement(&path, &staging, &intent)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(stage.join("sentinel")).unwrap(),
        b"unknown stage"
    );
    assert!(retained.join("LOCK").is_file());
}

#[tokio::test]
async fn replaced_stage_lock_is_refused_without_deleting_payload() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let staging = root.path().join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    let stage = stage_captured(source, &staging, &intent).await;
    // Retain the old inode/FileId so this test cannot accidentally reuse it.
    std::fs::rename(stage.join("LOCK"), root.path().join("retained-lock")).unwrap();
    std::fs::write(stage.join("LOCK"), b"replacement lock").unwrap();
    assert!(
        resume_legacy_retirement(&path, &staging, &intent)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(stage.join("LOCK")).unwrap(),
        b"replacement lock"
    );
    assert!(stage.is_dir());
}

#[tokio::test]
async fn staged_owner_keeps_writer_exclusion_and_preserves_a_fresh_original() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let staging = root.path().join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    let owner = source.stage_retirement(&intent, &staging).await.unwrap();
    let stage = staging.join(intent.stage_name().unwrap());
    assert!(!path.exists());
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(stage.join("LOCK"))
        .unwrap();
    assert!(matches!(
        writer.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(writer);
    astrid_core::platform_fs::create_private_directory(&path).unwrap();
    std::fs::write(path.join("sentinel"), b"fresh original").unwrap();
    owner.retire().await.unwrap();
    assert!(!stage.exists());
    assert_eq!(
        std::fs::read(path.join("sentinel")).unwrap(),
        b"fresh original"
    );
}

#[tokio::test]
async fn staged_resume_targets_only_the_stage_when_original_is_reoccupied() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let staging = root.path().join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    let stage = stage_captured(source, &staging, &intent).await;
    astrid_core::platform_fs::create_private_directory(&path).unwrap();
    std::fs::write(path.join("sentinel"), b"restored source").unwrap();
    // An Authorized caller has no permission to adopt this ambiguity.
    assert!(
        resume_legacy_retirement(&path, &staging, &intent)
            .await
            .is_err()
    );
    // A durable Staged caller has narrower authority: the UUID stage only.
    resume_staged_legacy_retirement(&staging, &intent)
        .await
        .unwrap();
    assert!(!stage.exists());
    assert_eq!(
        std::fs::read(path.join("sentinel")).unwrap(),
        b"restored source"
    );
}

#[tokio::test]
async fn missing_staging_ancestor_is_refused_before_source_move() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let absent = root.path().join("absent");
    let staging = absent.join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    assert!(source.stage_retirement(&intent, &staging).await.is_err());
    assert!(path.join("LOCK").exists());
    assert!(!absent.exists());
    let source = capture(&path).await;
    drop(source);
}

#[tokio::test]
async fn authorized_stage_capture_refuses_an_absent_stage() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let staging = root.path().join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    drop(source);
    assert!(
        capture_authorized_legacy_retirement_stage(&staging, &intent)
            .await
            .is_err()
    );
    assert!(path.join("LOCK").exists());
    assert!(!staging.exists());
}

#[tokio::test]
async fn authorized_stage_capture_holds_the_writer_fence_on_a_moved_stage() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let staging = root.path().join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    let stage = stage_captured(source, &staging, &intent).await;
    let owner = capture_authorized_legacy_retirement_stage(&staging, &intent)
        .await
        .unwrap();
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(stage.join("LOCK"))
        .unwrap();
    assert!(matches!(
        writer.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(writer);
    owner.retire().await.unwrap();
    assert!(!stage.exists());
    assert!(!path.exists());
}

#[tokio::test]
async fn authorized_stage_capture_refuses_a_missing_lock_while_staged_resume_cleans_up() {
    let root = test_directory::temporary().unwrap();
    let path = root.path().join("source");
    let staging = root.path().join("staging");
    seeded_source(&path).await;
    let source = capture(&path).await;
    let intent = source.retirement_intent();
    let stage = stage_captured(source, &staging, &intent).await;
    std::fs::remove_file(stage.join("LOCK")).unwrap();
    assert!(
        capture_authorized_legacy_retirement_stage(&staging, &intent)
            .await
            .is_err()
    );
    assert!(stage.is_dir());
    resume_staged_legacy_retirement(&staging, &intent)
        .await
        .unwrap();
    assert!(!stage.exists());
}
