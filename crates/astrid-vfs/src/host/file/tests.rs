use super::*;
use crate::Vfs;

fn operation() -> FileOperationGuard {
    FileOperationGuard::new(())
}

struct Fixture {
    root: tempfile::TempDir,
    handle: DirHandle,
    vfs: HostVfs,
}

impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file"), bytes).unwrap();
        let handle = DirHandle::new();
        let vfs = HostVfs::with_registered_dir(handle.clone(), root.path()).unwrap();
        Self { root, handle, vfs }
    }

    async fn open(&self, mode: OpenMode) -> Arc<dyn VfsFile> {
        self.vfs
            .open_file(&self.handle, "file", mode, operation())
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn owned_open_modes_preserve_creation_and_access_semantics() {
    let f = Fixture::new(b"initial");
    let capacity = f.vfs.fd_semaphore.available_permits();
    for mode in [OpenMode::Read, OpenMode::ReadWrite] {
        assert!(matches!(
            f.vfs
                .open_file(&f.handle, "missing", mode, operation())
                .await,
            Err(VfsError::NotFound(_))
        ));
    }
    assert!(!f.root.path().join("missing").exists());
    assert_eq!(f.vfs.fd_semaphore.available_permits(), capacity);
    let read = f.open(OpenMode::Read).await;
    assert!(matches!(
        read.write_at(FileOffset::new(0), b"bad", operation()).await,
        Err(VfsError::PermissionDenied(_))
    ));
    assert!(matches!(
        read.set_len(FileLength::new(0), operation()).await,
        Err(VfsError::PermissionDenied(_))
    ));
    let write = f.open(OpenMode::Write).await;
    assert_eq!(write.stat(operation()).await.unwrap().size, 0);
    assert_eq!(
        write
            .write_at(FileOffset::new(0), b"new", operation())
            .await
            .unwrap(),
        3
    );
    assert!(matches!(
        write
            .read_at(FileOffset::new(0), ReadLength::new(3), operation())
            .await,
        Err(VfsError::PermissionDenied(_))
    ));
    let append = f.open(OpenMode::Append).await;
    assert_eq!(
        append
            .write_at(FileOffset::new(u64::MAX), b"!", operation())
            .await
            .unwrap(),
        1
    );
    assert_eq!(std::fs::read(f.root.path().join("file")).unwrap(), b"new!");
}

#[tokio::test]
async fn positional_reads_and_concurrent_writes_do_not_share_a_cursor() {
    let f = Fixture::new(b"abcdefgh");
    let left = f.open(OpenMode::ReadWrite).await;
    let right = f.open(OpenMode::ReadWrite).await;
    let (a, b) = tokio::join!(
        left.write_at(FileOffset::new(0), b"LEFT", operation()),
        right.write_at(FileOffset::new(4), b"RGHT", operation()),
    );
    assert_eq!(a.unwrap(), 4);
    assert_eq!(b.unwrap(), 4);
    for (offset, expected) in [(4, b"RGHT".as_slice()), (0, b"LEFT"), (4, b"RGHT")] {
        assert_eq!(
            left.read_at(FileOffset::new(offset), ReadLength::new(4), operation())
                .await
                .unwrap(),
            expected
        );
    }
    // No handle-close publication is needed to expose an acknowledged write.
    assert_eq!(
        std::fs::read(f.root.path().join("file")).unwrap(),
        b"LEFTRGHT"
    );
}

#[tokio::test]
async fn truncate_extension_eof_and_overflow_use_bounded_offset_operations() {
    let f = Fixture::new(b"abc");
    let file = f.open(OpenMode::ReadWrite).await;
    file.set_len(FileLength::new(8), operation()).await.unwrap();
    assert_eq!(
        file.read_at(FileOffset::new(0), ReadLength::new(20), operation())
            .await
            .unwrap(),
        b"abc\0\0\0\0\0"
    );
    file.set_len(FileLength::new(2), operation()).await.unwrap();
    assert_eq!(file.stat(operation()).await.unwrap().size, 2);
    assert!(
        file.read_at(FileOffset::new(2), ReadLength::new(20), operation())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        file.read_at(FileOffset::new(u64::MAX), ReadLength::new(2), operation()).await,
        Err(VfsError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
    ));
    assert!(matches!(
        file.write_at(FileOffset::new(u64::MAX), b"bad", operation()).await,
        Err(VfsError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
    ));
    assert_eq!(file.stat(operation()).await.unwrap().size, 2);
}

#[tokio::test]
async fn sync_and_reopen_retain_acknowledged_bytes() {
    let f = Fixture::new(b"old");
    let file = f.open(OpenMode::ReadWrite).await;
    assert_eq!(
        file.write_at(FileOffset::new(0), b"NEW", operation())
            .await
            .unwrap(),
        3
    );
    file.sync_data(operation()).await.unwrap();
    file.sync_all(operation()).await.unwrap();
    drop(file);
    let reopened = f.open(OpenMode::Read).await;
    assert_eq!(
        reopened
            .read_at(FileOffset::new(0), ReadLength::new(3), operation())
            .await
            .unwrap(),
        b"NEW"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn rename_unlink_and_path_replacement_do_not_retarget_an_open_object() {
    let f = Fixture::new(b"original");
    let file = f.open(OpenMode::ReadWrite).await;
    std::fs::rename(f.root.path().join("file"), f.root.path().join("moved")).unwrap();
    std::fs::write(f.root.path().join("file"), b"replacement").unwrap();
    assert_eq!(file.stat(operation()).await.unwrap().size, 8);
    std::fs::remove_file(f.root.path().join("moved")).unwrap();
    assert_eq!(
        file.read_at(FileOffset::new(0), ReadLength::new(8), operation())
            .await
            .unwrap(),
        b"original"
    );
    file.set_len(FileLength::new(2), operation()).await.unwrap();
    assert_eq!(file.stat(operation()).await.unwrap().size, 2);
    drop(file);
    assert!(!f.root.path().join("moved").exists());
    assert_eq!(
        std::fs::read(f.root.path().join("file")).unwrap(),
        b"replacement"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn escaped_symlinks_and_nonregular_objects_are_not_admitted() {
    let f = Fixture::new(b"inside");
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret"), b"outside").unwrap();
    std::os::unix::fs::symlink(outside.path(), f.root.path().join("escape")).unwrap();
    for mode in [OpenMode::Read, OpenMode::Write, OpenMode::ReadWrite] {
        assert!(
            f.vfs
                .open_file(&f.handle, "escape/secret", mode, operation())
                .await
                .is_err()
        );
    }
    assert_eq!(
        std::fs::read(outside.path().join("secret")).unwrap(),
        b"outside"
    );
    assert!(
        f.vfs
            .open_file(&f.handle, "../outside", OpenMode::Read, operation())
            .await
            .is_err()
    );
    std::fs::create_dir(f.root.path().join("directory")).unwrap();
    assert!(matches!(
        f.vfs
            .open_file(&f.handle, "directory", OpenMode::Read, operation())
            .await,
        Err(VfsError::NotSupported(_))
    ));
}

#[tokio::test]
async fn owned_and_legacy_handles_share_the_existing_descriptor_quota() {
    let f = Fixture::new(b"quota");
    let capacity = f.vfs.fd_semaphore.available_permits();
    let mut files = Vec::new();
    for _ in 0..capacity {
        files.push(f.open(OpenMode::Read).await);
    }
    assert!(matches!(
        f.vfs.open(&f.handle, "file", false, false).await,
        Err(VfsError::PermissionDenied(_))
    ));
    files.pop();
    let legacy = f.vfs.open(&f.handle, "file", false, false).await.unwrap();
    assert!(matches!(
        f.vfs
            .open_file(&f.handle, "file", OpenMode::Read, operation())
            .await,
        Err(VfsError::PermissionDenied(_))
    ));
    f.vfs.close(&legacy).await.unwrap();
    files.clear();
    assert_eq!(f.vfs.fd_semaphore.available_permits(), capacity);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_waiter_does_not_release_admission_before_native_work_settles() {
    let f = Fixture::new(b"retained");
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let native = Arc::new(NativeFile {
        state: Arc::new(FileState {
            file: std::fs::File::open(f.root.path().join("file")).unwrap(),
            mode: OpenMode::Read,
            #[cfg(windows)]
            operation: std::sync::Mutex::new(()),
            _permit: Arc::clone(&semaphore).try_acquire_owned().unwrap(),
        }),
    });
    let (started, waiting) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel::<()>();
    let (settled, mut settlement) = tokio::sync::oneshot::channel();
    let guard = FileOperationGuard::new(DropSignal(Some(settled)));
    let owned = Arc::clone(&native);
    let job = tokio::spawn(async move {
        owned
            .run(guard, move |_| {
                let _ = started.send(());
                // Closing the sender also releases this work if the test unwinds.
                let _ = blocked.recv();
                Ok(())
            })
            .await
    });
    waiting.await.unwrap();
    job.abort();
    assert!(matches!(job.await, Err(error) if error.is_cancelled()));
    drop(native);
    assert_eq!(semaphore.available_permits(), 0);
    assert!(matches!(
        settlement.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    drop(release);
    tokio::time::timeout(std::time::Duration::from_secs(2), settlement)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while semaphore.available_permits() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(semaphore.available_permits(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn independent_append_handles_preserve_complete_records() {
    let f = Fixture::new(b"");
    let mut tasks = Vec::new();
    for writer in 0..8 {
        let file = f.open(OpenMode::Append).await;
        tasks.push(tokio::spawn(async move {
            for record in 0..16 {
                let bytes = format!("{writer:02}:{record:04}\n");
                assert_eq!(
                    file.write_at(FileOffset::new(0), bytes.as_bytes(), operation())
                        .await
                        .unwrap(),
                    8
                );
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let bytes = std::fs::read(f.root.path().join("file")).unwrap();
    assert_eq!(bytes.len(), 8 * 16 * 8);
    let records: std::collections::BTreeSet<_> = bytes.chunks_exact(8).collect();
    assert_eq!(records.len(), 8 * 16);
    for writer in 0..8 {
        for record in 0..16 {
            let expected = format!("{writer:02}:{record:04}\n");
            assert!(records.contains(expected.as_bytes()));
        }
    }
}

struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[test]
fn cancelled_queued_open_retains_authority_until_native_job_settles() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let f = Arc::new(Fixture::new(b"retained"));
        let capacity = f.vfs.fd_semaphore.available_permits();
        let semaphore = Arc::clone(&f.vfs.fd_semaphore);
        let (started, waiting) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let occupied_worker = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = blocked.recv();
        });
        waiting.await.unwrap();
        let (settled, mut settlement) = tokio::sync::oneshot::channel();
        let guard = FileOperationGuard::new(DropSignal(Some(settled)));
        let owned = Arc::clone(&f);
        let job = tokio::spawn(async move {
            owned
                .vfs
                .open_file(&owned.handle, "file", OpenMode::Read, guard)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while semaphore.available_permits() == capacity {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        job.abort();
        assert!(matches!(job.await, Err(error) if error.is_cancelled()));
        assert_eq!(semaphore.available_permits(), capacity - 1);
        assert!(matches!(
            settlement.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        drop(release);
        occupied_worker.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), settlement)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while semaphore.available_permits() != capacity {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    });
}

#[tokio::test]
async fn idle_file_does_not_retain_a_settled_operations_authority() {
    let f = Fixture::new(b"idle");
    let (settled, settlement) = tokio::sync::oneshot::channel();
    let file = f
        .vfs
        .open_file(
            &f.handle,
            "file",
            OpenMode::Read,
            FileOperationGuard::new(DropSignal(Some(settled))),
        )
        .await
        .unwrap();
    settlement.await.unwrap();
    let (settled, settlement) = tokio::sync::oneshot::channel();
    assert_eq!(
        file.stat(FileOperationGuard::new(DropSignal(Some(settled))))
            .await
            .unwrap()
            .size,
        4
    );
    settlement.await.unwrap();
    // The file remains usable after both operation guards have settled.
    assert_eq!(
        file.read_at(FileOffset::new(0), ReadLength::new(4), operation())
            .await
            .unwrap(),
        b"idle"
    );
}

#[tokio::test]
async fn create_modes_create_missing_files_without_implicitly_granting_reads() {
    let f = Fixture::new(b"preserve");
    for (path, mode) in [
        ("created-write", OpenMode::Write),
        ("created-append", OpenMode::Append),
    ] {
        let file = f
            .vfs
            .open_file(&f.handle, path, mode, operation())
            .await
            .unwrap();
        assert_eq!(
            file.write_at(FileOffset::new(0), b"new", operation())
                .await
                .unwrap(),
            3
        );
        assert!(matches!(
            file.read_at(FileOffset::new(0), ReadLength::new(3), operation())
                .await,
            Err(VfsError::PermissionDenied(_))
        ));
        drop(file);
        assert_eq!(std::fs::read(f.root.path().join(path)).unwrap(), b"new");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn admitted_symlink_and_closed_directory_do_not_retarget_owned_file() {
    let f = Fixture::new(b"original");
    std::os::unix::fs::symlink("file", f.root.path().join("link")).unwrap();
    let file = f
        .vfs
        .open_file(&f.handle, "link", OpenMode::Read, operation())
        .await
        .unwrap();
    std::fs::remove_file(f.root.path().join("link")).unwrap();
    std::fs::write(f.root.path().join("link"), b"replacement").unwrap();
    f.vfs.close_dir(&f.handle).await.unwrap();
    assert_eq!(
        file.read_at(FileOffset::new(0), ReadLength::new(8), operation())
            .await
            .unwrap(),
        b"original"
    );
    assert!(
        f.vfs
            .open_file(&f.handle, "file", OpenMode::Read, operation())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unsupported_overlay_open_has_no_copy_up_or_dirty_close_effect() {
    let lower = Fixture::new(b"lower");
    let upper = Fixture::new(b"upper");
    let handle = lower.handle.clone();
    let overlay = crate::OverlayVfs::new(Box::new(lower.vfs), Box::new(upper.vfs));
    for mode in [
        OpenMode::Read,
        OpenMode::Write,
        OpenMode::Append,
        OpenMode::ReadWrite,
    ] {
        let (settled, settlement) = tokio::sync::oneshot::channel();
        assert!(matches!(
            overlay
                .open_file(
                    &handle,
                    "file",
                    mode,
                    FileOperationGuard::new(DropSignal(Some(settled)))
                )
                .await,
            Err(VfsError::NotSupported(_))
        ));
        settlement.await.unwrap();
    }
    assert!(overlay.dirty_paths().is_empty());
    assert_eq!(
        std::fs::read(lower.root.path().join("file")).unwrap(),
        b"lower"
    );
    assert_eq!(
        std::fs::read(upper.root.path().join("file")).unwrap(),
        b"upper"
    );
}
