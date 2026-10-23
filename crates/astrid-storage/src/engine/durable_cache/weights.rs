//! Charged weights for immutable records, principal associations, and projections.

use std::sync::Arc;

use super::{CachedProjection, PrincipalEntry};
use crate::engine::ProjectionCacheKey;
use crate::storage_model::{ObjectId, ObjectRecord};

pub(super) fn cache_weight(record: &ObjectRecord) -> u64 {
    let resident_metadata = std::mem::size_of::<ObjectRecord>()
        .saturating_add(std::mem::size_of::<Arc<ObjectRecord>>())
        .saturating_add(std::mem::size_of::<ObjectId>())
        .saturating_add(std::mem::size_of::<u64>());
    record
        .retained_bytes()
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(resident_metadata).unwrap_or(u64::MAX))
}

pub(super) fn association_weight<P>() -> u64 {
    u64::try_from(
        std::mem::size_of::<P>()
            .saturating_add(std::mem::size_of::<ObjectId>())
            .saturating_add(std::mem::size_of::<u64>())
            .saturating_add(std::mem::size_of::<ObjectId>())
            .saturating_add(std::mem::size_of::<u64>()),
    )
    .unwrap_or(u64::MAX)
}

pub(super) fn projection_weight(entry: &PrincipalEntry) -> u64 {
    entry.projections.values().fold(0_u64, |total, projection| {
        total.saturating_add(projection.weight)
    })
}

pub(super) fn projection_cache_weight(payload: u64) -> u64 {
    let metadata = std::mem::size_of::<ProjectionCacheKey>()
        .saturating_add(std::mem::size_of::<CachedProjection>())
        .saturating_add(std::mem::size_of::<usize>().saturating_mul(3));
    payload.saturating_add(u64::try_from(metadata).unwrap_or(u64::MAX))
}
