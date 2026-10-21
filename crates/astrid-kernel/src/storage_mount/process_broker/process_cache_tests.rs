use super::*;

fn test_key(marker: u8) -> ProcessProjectionKey {
    ProcessProjectionKey {
        principal_uid: astrid_core::PrincipalUid::from_bytes([marker; 32]),
        owner: StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([marker; 32])),
        branch: astrid_core::WorkspaceUid::from_bytes([marker.wrapping_add(1); 16]),
        read_write: true,
    }
}

fn projection_with_cleanup(
    cleanup: ProjectionCleanup,
    cleanup_failed: bool,
) -> Arc<CachedProcessProjection> {
    Arc::new(CachedProcessProjection {
        workspace_mountpoint: PathBuf::from("/private/workspace-admit"),
        home_mountpoint: PathBuf::from("/private/home-admit"),
        fleet_shared_mountpoint: None,
        refs: AtomicU64::new(0),
        closing: AtomicBool::new(false),
        cleanup_failed: AtomicBool::new(cleanup_failed),
        cleanup,
    })
}

#[tokio::test]
async fn admit_releases_cache_lock_before_failed_cleanup_retry() {
    let projection = projection_with_cleanup(Arc::new(|| Box::pin(async { true })), true);
    let cache = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
    let key = test_key(0xC1);
    cache.lock().await.insert(key, Arc::clone(&projection));
    let guard = cache.lock().await;

    let admitted = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        admit_cached_process_projection(&cache, guard, key),
    )
    .await
    .expect("retry must not deadlock on the projection cache lock")
    .expect("successful cleanup retry");
    let (cached, guard) = admitted;
    assert!(
        cached.is_none(),
        "successful retry must clear the cached pair before a new mount"
    );
    assert!(guard.is_empty());
    drop(guard);
    assert!(
        !projection.cleanup_failed.load(Ordering::Acquire),
        "cleanup_failed must clear only after the pair is removed under the cache lock"
    );
}

#[tokio::test]
async fn concurrent_admit_after_failed_cleanup_does_not_hold_lock_across_join() {
    let projection = projection_with_cleanup(Arc::new(|| Box::pin(async { true })), true);
    let cache = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
    let key = test_key(0xC2);
    cache.lock().await.insert(key, Arc::clone(&projection));

    let left = {
        let cache = Arc::clone(&cache);
        tokio::spawn(async move {
            let guard = cache.lock().await;
            let (cached, guard) = admit_cached_process_projection(&cache, guard, key)
                .await
                .expect("left admit");
            drop(guard);
            cached.is_some()
        })
    };
    let right = {
        let cache = Arc::clone(&cache);
        tokio::spawn(async move {
            let guard = cache.lock().await;
            let (cached, guard) = admit_cached_process_projection(&cache, guard, key)
                .await
                .expect("right admit");
            drop(guard);
            cached.is_some()
        })
    };

    let left_cached = left.await.expect("left join");
    let right_cached = right.await.expect("right join");
    assert!(
        !left_cached && !right_cached,
        "neither admit should retain a pair after both retries clear the cache"
    );
    assert!(cache.lock().await.is_empty());
}
