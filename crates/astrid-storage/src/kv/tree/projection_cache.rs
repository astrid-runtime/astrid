//! Optional decoded KV state shares the engine's existing memory authority.
use super::delta::Projection;
use crate::engine::{
    KvProjectionEngine, ProjectionCacheEntry, ProjectionCacheKey, ProjectionCachePayload,
};
use crate::storage_model::ObjectId;

// Separate from the content projection keys 1 through 3.
const DECODED_KV_CACHE_KEY: ProjectionCacheKey = ProjectionCacheKey::new(4);

impl ProjectionCachePayload for Projection {
    fn retained_bytes(&self) -> u64 {
        u64::try_from(std::mem::size_of::<Self>().saturating_add(self.overlay.retained_bytes()))
            .unwrap_or(u64::MAX)
    }
}

pub(super) fn load<P, E: KvProjectionEngine<P>>(
    engine: &E,
    owner: &P,
    head: ObjectId,
) -> Option<Projection> {
    engine
        .load_kv_projection_cache(owner, head, DECODED_KV_CACHE_KEY)
        .and_then(|entry| entry.downcast::<Projection>())
        .filter(|projection| projection.head == Some(head))
        .map(|projection| (*projection).clone())
}

pub(super) fn retain<P, E: KvProjectionEngine<P>>(engine: &E, owner: &P, projection: &Projection) {
    let Some(head) = projection.head else {
        return;
    };
    // Newly committed heads may not be associated with the governed cache yet.
    // Failure of this optional prefetch cannot turn a committed write into an error.
    if matches!(engine.load_kv_object_for(owner, head), Ok(Some(_))) {
        engine.retain_kv_projection_cache(
            owner,
            head,
            DECODED_KV_CACHE_KEY,
            ProjectionCacheEntry::new(projection.clone()),
        );
    }
}

pub(super) fn replace<P, E: KvProjectionEngine<P>>(
    engine: &E,
    owner: &P,
    previous: Option<ObjectId>,
    projection: &Projection,
) {
    if let Some(previous) = previous.filter(|previous| Some(*previous) != projection.head) {
        engine.discard_kv_projection_cache(owner, previous, DECODED_KV_CACHE_KEY);
    }
    retain(engine, owner, projection);
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests;
