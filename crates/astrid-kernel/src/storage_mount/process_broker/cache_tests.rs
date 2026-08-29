//! Cached process projection reference-count regressions.

use super::*;

#[cfg(any(unix, windows))]
fn test_projection_key(
    actor: [u8; 32],
    workspace: [u8; 16],
) -> (ProcessProjectionBinding, ProcessProjectionKey) {
    let uid = astrid_core::PrincipalUid::from_bytes(actor);
    let owner = StateOwner::Principal(uid);
    let binding = ProcessProjectionBinding::new(
        owner,
        uid,
        ProjectionGeneration::capture().expect("test projection generation"),
        ProcessProjectionTargetSet::branch(
            owner,
            uid,
            astrid_core::WorkspaceUid::from_bytes(workspace),
            None,
        )
        .expect("valid target set"),
    )
    .expect("valid test projection binding");
    let key = ProcessProjectionKey {
        binding: binding.clone(),
        read_write: true,
    };
    (binding, key)
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn process_projection_cache_reuses_one_pair_until_last_close() {
    let cleanup_count = Arc::new(AtomicU64::new(0));
    let cleanup_count_for_projection = Arc::clone(&cleanup_count);
    let (binding, key) = test_projection_key([0xA1; 32], [0xB2; 16]);
    let projection = Arc::new(CachedProcessProjection {
        binding,
        workspace_mountpoint: PathBuf::from("/private/workspace"),
        home_mountpoint: PathBuf::from("/private/home"),
        fleet_shared_mountpoint: None,
        refs: AtomicU64::new(0),
        closing: AtomicBool::new(false),
        cleanup_failed: AtomicBool::new(false),
        cleanup: Arc::new(move || {
            let cleanup_count = Arc::clone(&cleanup_count_for_projection);
            Box::pin(async move {
                cleanup_count.fetch_add(1, Ordering::AcqRel);
                true
            })
        }),
    });
    let cache = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
    cache
        .lock()
        .await
        .insert(key.clone(), Arc::clone(&projection));

    let mut tasks = Vec::new();
    for _ in 0..100 {
        let projection = Arc::clone(&projection);
        let cache = Arc::clone(&cache);
        let key = key.clone();
        tasks.push(tokio::spawn(async move {
            cached_projection_mount(projection, cache, &key)
                .await
                .expect("cached projection mount")
        }));
    }
    let mut mounts = Vec::new();
    for task in tasks {
        mounts.push(task.await.expect("projection task"));
    }
    assert_eq!(projection.refs.load(Ordering::Acquire), 100);
    assert!(
        mounts
            .iter()
            .all(|mount| mount.workspace_root.as_path() == Path::new("/private/workspace"))
    );
    assert!(
        mounts
            .iter()
            .all(|mount| mount.home_root.as_path() == Path::new("/private/home"))
    );

    let closes = mounts
        .into_iter()
        .map(|mount| tokio::spawn(mount.close_async()))
        .collect::<Vec<_>>();
    for close in closes {
        close.await.expect("projection close task");
    }
    assert_eq!(cleanup_count.load(Ordering::Acquire), 1);
    assert!(cache.lock().await.is_empty());
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn last_close_refuses_remount_while_projection_is_closing() {
    let release = Arc::new(tokio::sync::Notify::new());
    let entered = Arc::new(tokio::sync::Notify::new());
    let (binding, key) = test_projection_key([0xA3; 32], [0xB4; 16]);
    let projection = Arc::new(CachedProcessProjection {
        binding,
        workspace_mountpoint: PathBuf::from("/private/workspace-close"),
        home_mountpoint: PathBuf::from("/private/home-close"),
        fleet_shared_mountpoint: None,
        refs: AtomicU64::new(0),
        closing: AtomicBool::new(false),
        cleanup_failed: AtomicBool::new(false),
        cleanup: {
            let release = Arc::clone(&release);
            let entered = Arc::clone(&entered);
            Arc::new(move || {
                let release = Arc::clone(&release);
                let entered = Arc::clone(&entered);
                Box::pin(async move {
                    entered.notify_one();
                    release.notified().await;
                    true
                })
            })
        },
    });
    let cache = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
    cache
        .lock()
        .await
        .insert(key.clone(), Arc::clone(&projection));

    let mount = cached_projection_mount(Arc::clone(&projection), Arc::clone(&cache), &key)
        .await
        .expect("initial mount");
    let close = tokio::spawn(mount.close_async());
    entered.notified().await;
    assert!(projection.closing.load(Ordering::Acquire));
    let Err(error) =
        cached_projection_mount(Arc::clone(&projection), Arc::clone(&cache), &key).await
    else {
        panic!("remount during last-close must fail closed");
    };
    assert!(error.contains("closing"));
    release.notify_one();
    close.await.expect("projection close task");
    assert!(cache.lock().await.is_empty());
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn failed_projection_cleanup_retries_before_new_mount() {
    let attempts = Arc::new(AtomicU64::new(0));
    let attempts_for_projection = Arc::clone(&attempts);
    let (binding, key) = test_projection_key([0xA2; 32], [0xB3; 16]);
    let projection = Arc::new(CachedProcessProjection {
        binding,
        workspace_mountpoint: PathBuf::from("/private/workspace-retry"),
        home_mountpoint: PathBuf::from("/private/home-retry"),
        fleet_shared_mountpoint: None,
        refs: AtomicU64::new(0),
        closing: AtomicBool::new(false),
        cleanup_failed: AtomicBool::new(false),
        cleanup: Arc::new(move || {
            let attempts = Arc::clone(&attempts_for_projection);
            Box::pin(async move { attempts.fetch_add(1, Ordering::AcqRel) >= 1 })
        }),
    });
    let cache = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
    cache
        .lock()
        .await
        .insert(key.clone(), Arc::clone(&projection));

    let mount = cached_projection_mount(Arc::clone(&projection), Arc::clone(&cache), &key)
        .await
        .expect("cached projection mount");
    mount.close_async().await;
    assert!(projection.cleanup_failed.load(Ordering::Acquire));
    assert!(cache.lock().await.contains_key(&key));

    let mut projections = cache.lock().await;
    assert!(retry_failed_projection(&projection, &mut projections, &key).await);
    assert_eq!(attempts.load(Ordering::Acquire), 2);
    assert!(projections.is_empty());
}
