//! Last-reference teardown retains custody even when its caller is cancelled.

use super::{CachedProcessProjection, ProcessProjectionKey};
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::Ordering},
};

type ProjectionCache =
    Arc<tokio::sync::Mutex<BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>>>;

pub(super) async fn release_owned_projection(
    projection: Arc<CachedProcessProjection>,
    cache: ProjectionCache,
    key: ProcessProjectionKey,
) {
    // Spawn on first poll inside the caller's runtime, before any await. The
    // owned task retains the reference and exact cache identity if close_async
    // is cancelled while waiting for the initial cache lock or native teardown.
    let teardown = tokio::spawn(release_projection(projection, cache, key));
    if let Err(error) = teardown.await {
        tracing::error!(%error, "owned process projection teardown failed");
    }
}

async fn release_projection(
    projection: Arc<CachedProcessProjection>,
    cache: ProjectionCache,
    key: ProcessProjectionKey,
) {
    {
        let projections = cache.lock().await;
        if projection.refs.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        if !projections
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &projection))
        {
            return;
        }
        projection.closing.store(true, Ordering::Release);
        // Pending is a retry blocker, including after cancellation or panic.
        // The production cleanup callback serializes exact teardown state.
        projection.cleanup_failed.store(true, Ordering::Release);
    }
    if !(projection.cleanup)().await {
        return;
    }
    let mut projections = cache.lock().await;
    if projections
        .get(&key)
        .is_some_and(|current| Arc::ptr_eq(current, &projection))
    {
        projections.remove(&key);
    }
}
