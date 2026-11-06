use super::*;

pub(super) fn workspace_name_present(path: &std::path::Path) -> bool {
    // A Windows directory marked for deletion can reject child metadata opens
    // with ACCESS_DENIED before its name disappears. Observe the parent
    // namespace instead; enumeration errors remain failures, never absence.
    let name = path.file_name().unwrap();
    std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .any(|entry| entry.unwrap().file_name() == name)
}

async fn reader() -> (SnapshotReader, Arc<SnapshotStore>, std::path::PathBuf) {
    let workspace = tempfile::tempdir().unwrap();
    let path = workspace.path().to_path_buf();
    let store = SurrealKvStore::open(path.join("database")).unwrap();
    store.set("test", "key", b"value".to_vec()).await.unwrap();
    let store = Arc::new(SnapshotStore::new(store));
    let reader = SnapshotReader {
        store: Some(Arc::clone(&store)),
        workspace: Some(SnapshotWorkspace(Some(workspace.keep()))),
    };
    (reader, store, path)
}

#[tokio::test]
async fn explicit_close_closes_escaped_handles_before_removing_workspace() {
    let (mut reader, escaped, path) = reader().await;
    reader.close().await.unwrap();
    assert!(!path.try_exists().unwrap());
    assert!(escaped.get("test", "key").await.is_err());
}

#[tokio::test]
async fn cancellation_closes_reader_and_removes_only_owned_workspace() {
    let (reader, escaped, path) = reader().await;
    let source = tempfile::tempdir().unwrap();
    let source_file = source.path().join("untouched");
    std::fs::write(&source_file, b"source").unwrap();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _reader = reader;
        entered.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    ready.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while workspace_name_present(&path) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(escaped.get("test", "key").await.is_err());
    assert_eq!(std::fs::read(&source_file).unwrap(), b"source");
}

#[test]
fn unavailable_cleanup_runtime_retains_workspace_instead_of_unlinking() {
    let workspace = tempfile::tempdir().unwrap();
    let path = workspace.path().to_path_buf();
    drop(SnapshotWorkspace(Some(workspace.keep())));
    assert!(path.is_dir());
    std::fs::remove_dir(path).unwrap();
}

#[tokio::test]
async fn operation_error_still_closes_escaped_snapshot_handle() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let original = SurrealKvStore::open(&source).unwrap();
    original
        .set("test", "key", b"original".to_vec())
        .await
        .unwrap();
    original.close().await.unwrap();
    let result = with_legacy_kv_snapshot(&source, async |store, _| {
        assert_eq!(
            store.get("test", "key").await.unwrap().unwrap(),
            b"original"
        );
        Err::<(), Arc<dyn KvStore>>(store)
    })
    .await
    .unwrap();
    let escaped = result.unwrap_err();
    assert!(escaped.get("test", "key").await.is_err());
    let reopened = SurrealKvStore::open(&source).unwrap();
    assert_eq!(
        reopened.get("test", "key").await.unwrap().unwrap(),
        b"original"
    );
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn live_source_writer_is_refused_without_touching_lock() {
    let directory = tempfile::tempdir().unwrap();
    let original = SurrealKvStore::open(directory.path()).unwrap();
    original
        .set("test", "key", b"original".to_vec())
        .await
        .unwrap();
    let lock = directory.path().join("LOCK");
    // Windows byte-range locks also deny ordinary reads. Inspect the live
    // file identity and metadata without reading its locked bytes; verify the
    // pinned backend's PID payload only after the writer releases the lock.
    let before = std::fs::File::open(&lock).unwrap();
    let identity = super::super::native_io::private_file_identity(&before).unwrap();
    let metadata = before.metadata().unwrap();
    let expected = format!("{}\n", std::process::id()).into_bytes();
    assert_eq!(metadata.len(), expected.len() as u64);
    let result = with_legacy_kv_snapshot(directory.path(), async |_, _| {
        panic!("must not invoke operation while source writer holds LOCK");
    })
    .await;
    assert!(result.is_err());
    let after = std::fs::File::open(&lock).unwrap();
    assert_eq!(
        super::super::native_io::private_file_identity(&after).unwrap(),
        identity
    );
    assert_eq!(after.metadata().unwrap().len(), metadata.len());
    assert_eq!(
        after.metadata().unwrap().modified().unwrap(),
        metadata.modified().unwrap()
    );
    assert_eq!(
        original.get("test", "key").await.unwrap().unwrap(),
        b"original"
    );
    original.close().await.unwrap();
    assert_eq!(std::fs::read(&lock).unwrap(), expected);
}

#[tokio::test]
async fn source_writer_excluded_through_operation_without_rewriting_lock() {
    let directory = tempfile::tempdir().unwrap();
    let original = SurrealKvStore::open(directory.path()).unwrap();
    original
        .set("test", "key", b"original".to_vec())
        .await
        .unwrap();
    original.close().await.unwrap();
    drop(original);
    let lock = directory.path().join("LOCK");
    let before = std::fs::read(&lock).unwrap();
    let permissions = std::fs::metadata(&lock).unwrap().permissions();
    with_legacy_kv_snapshot(directory.path(), async |store, _| {
        assert_eq!(
            store.get("test", "key").await.unwrap().unwrap(),
            b"original"
        );
        // Do not call the engine opener: it truncates LOCK before attempting
        // its exclusive lock. This non-truncating handle models that lock.
        let competing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock)
            .unwrap();
        assert!(competing.try_lock().is_err());
        assert_eq!(std::fs::read(&lock).unwrap(), before);
    })
    .await
    .unwrap();
    assert_eq!(std::fs::read(&lock).unwrap(), before);
    assert_eq!(std::fs::metadata(&lock).unwrap().permissions(), permissions);
    let competing = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock)
        .unwrap();
    competing.try_lock().unwrap();
}

#[tokio::test]
async fn empty_source_stays_empty_and_nonempty_without_lock_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    with_legacy_kv_snapshot(directory.path(), async |store, _| {
        assert!(store.list_keys("test").await.unwrap().is_empty());
    })
    .await
    .unwrap();
    assert!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none()
    );
    std::fs::write(directory.path().join("unrecognized"), b"source").unwrap();
    let result = with_legacy_kv_snapshot(directory.path(), async |_, _| {
        panic!("a nonempty source must have its original LOCK");
    })
    .await;
    assert!(result.is_err());
    assert!(!directory.path().join("LOCK").exists());
}

#[tokio::test]
async fn directory_lock_is_refused_without_entering_operation() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("LOCK")).unwrap();
    let result = with_legacy_kv_snapshot(directory.path(), async |_, _| {
        panic!("directory LOCK must be refused");
    })
    .await;
    assert!(result.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn redirected_lock_is_refused_without_touching_target() {
    let directory = tempfile::tempdir().unwrap();
    let target = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(target.path(), b"untouched").unwrap();
    std::os::unix::fs::symlink(target.path(), directory.path().join("LOCK")).unwrap();
    let result = with_legacy_kv_snapshot(directory.path(), async |_, _| {
        panic!("redirected LOCK must be refused");
    })
    .await;
    assert!(result.is_err());
    assert_eq!(std::fs::read(target.path()).unwrap(), b"untouched");
}

#[tokio::test]
async fn snapshot_refuses_mutation_and_all_reads_after_close() {
    let (mut reader, escaped, path) = reader().await;
    assert!(
        escaped
            .set("test", "key", b"changed".to_vec())
            .await
            .is_err()
    );
    assert!(escaped.delete("test", "key").await.is_err());
    assert!(
        escaped
            .compare_and_swap("test", "key", None, vec![])
            .await
            .is_err()
    );
    assert!(escaped.clear_namespace("test").await.is_err());
    assert!(escaped.clear_prefix("test", "").await.is_err());
    assert!(!escaped.supports_atomic_batch());
    assert_eq!(escaped.get("test", "key").await.unwrap().unwrap(), b"value");
    reader.close().await.unwrap();
    assert!(!path.exists());
    assert!(escaped.exists("test", "key").await.is_err());
    assert!(escaped.list_keys("test").await.is_err());
    assert!(escaped.list_keys_with_prefix("test", "").await.is_err());
    assert!(
        escaped
            .list_keys_with_prefix_page("test", "", None, 1)
            .await
            .is_err()
    );
    assert!(escaped.close().await.is_err());
}
