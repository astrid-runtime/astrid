use std::sync::Arc;

use super::{
    CachedProcessProjection, Kernel, ParentTokenSlot, ProcessProjectionBinding,
    ProcessProjectionKey, ProjectionLeaseTarget,
};
pub(crate) use crate::storage_mount::process_broker::process_stop::retain_gates::*;

pub(crate) async fn fence_projection_leases_for_test(
    kernel: &Kernel,
    binding: &ProcessProjectionBinding,
    branch: &ProjectionLeaseTarget,
    owner: &ProjectionLeaseTarget,
    shared: Option<&ProjectionLeaseTarget>,
) -> bool {
    super::fence_projection_leases(kernel, binding, branch, owner, shared).await
}

pub(crate) async fn cached_projection_mount(
    projection: Arc<CachedProcessProjection>,
    projections: Arc<
        tokio::sync::Mutex<
            std::collections::BTreeMap<ProcessProjectionKey, Arc<CachedProcessProjection>>,
        >,
    >,
    key: &ProcessProjectionKey,
) -> Result<astrid_capsule::context::ProcessStorageMount, String> {
    {
        let _guard = projections.lock().await;
        super::retain_cached_projection(&projection)?;
    }
    Ok(super::projection_mount(
        projection,
        projections,
        key.clone(),
    ))
}

static PARENT_TOKEN_FAILURE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

static PARENT_TOKEN_FAILURE_TEST_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(crate) fn inject_parent_token_failure(slot: ParentTokenSlot, current_test_id: u64) -> bool {
    current_test_id == PARENT_TOKEN_FAILURE_TEST_ID.load(std::sync::atomic::Ordering::Acquire)
        && PARENT_TOKEN_FAILURE
            .compare_exchange(
                slot as u8,
                0,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
        && {
            PARENT_TOKEN_FAILURE_TEST_ID.store(0, std::sync::atomic::Ordering::Release);
            true
        }
}

pub(crate) fn arm_parent_token_failure(slot: ParentTokenSlot, test_id: u64) {
    PARENT_TOKEN_FAILURE.store(slot as u8, std::sync::atomic::Ordering::Release);
    PARENT_TOKEN_FAILURE_TEST_ID.store(test_id, std::sync::atomic::Ordering::Release);
}
