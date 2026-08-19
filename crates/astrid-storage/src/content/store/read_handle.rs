//! Immutable principal-content read handles and their compaction leases.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::content::PrincipalContentError;
use crate::content_dag::{
    ContentDescriptor, ContentVerificationState, OpenedContent, VerifiedContent,
    read_opened_content_and_verify, read_opened_content_range_with_verification,
    read_verified_content, read_verified_content_range,
};
use crate::engine::{PrincipalProjectionEngine, ProjectionCacheEntry};
use crate::storage_model::{ObjectId, RootState};

use super::projection::{
    CachedPartialVerification, CachedVerifiedContent, EngineSource, map_read_error,
};
use super::{PARTIAL_VERIFICATION_CACHE_KEY, VERIFIED_CONTENT_CACHE_KEY};

/// Principal-scoped immutable content handle for repeated verified reads.
///
/// The handle captures the root generation and decoded file descriptor that
/// authorized the open. Later catalog changes do not retarget an existing
/// handle. A compaction caller must retain the descriptor's closure as a
/// `ReadHandle` root while it promises continued readability. Without that
/// lease, collecting the closure makes later reads fail with
/// [`crate::content_dag::ContentError::MissingObject`]; a handle never
/// retargets to newer bytes.
pub struct PrincipalContentReadHandle<P: Ord, E> {
    pub(super) engine: Arc<E>,
    pub(super) opened: OpenedContent,
    pub(super) principal: P,
    pub(super) principal_root: RootState,
    // Keeping the lease in the handle's ownership graph makes the catalog
    // generation a live compaction root until the caller drops this handle.
    // The field is intentionally not read after construction.
    pub(super) _lease: ContentReadLease<P>,
}

/// Live immutable content closures retained while read handles remain open.
#[derive(Debug)]
pub(super) struct ContentReadLeaseRegistry<P> {
    next: AtomicU64,
    roots: parking_lot::Mutex<std::collections::BTreeMap<u64, (P, ObjectId)>>,
}

impl<P> Default for ContentReadLeaseRegistry<P> {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(1),
            roots: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
        }
    }
}

impl<P: Clone> ContentReadLeaseRegistry<P> {
    pub(super) fn register(
        self: &Arc<Self>,
        principal: P,
        object: ObjectId,
    ) -> ContentReadLease<P> {
        let token = self.next.fetch_add(1, Ordering::Relaxed);
        self.roots.lock().insert(token, (principal, object));
        ContentReadLease {
            registry: Arc::clone(self),
            token,
        }
    }

    pub(super) fn roots(&self) -> Vec<(P, ObjectId)> {
        self.roots.lock().values().cloned().collect()
    }
}

#[derive(Debug)]
pub(super) struct ContentReadLease<P> {
    registry: Arc<ContentReadLeaseRegistry<P>>,
    token: u64,
}

impl<P> Drop for ContentReadLease<P> {
    fn drop(&mut self) {
        self.registry.roots.lock().remove(&self.token);
    }
}

impl<P: Ord, E> fmt::Debug for PrincipalContentReadHandle<P, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrincipalContentReadHandle")
            .field("descriptor", &self.opened.descriptor())
            .field("principal_root", &self.principal_root)
            .finish_non_exhaustive()
    }
}

impl<P, E> PrincipalContentReadHandle<P, E>
where
    P: Clone + Ord,
    E: PrincipalProjectionEngine<P>,
{
    /// Return the immutable descriptor validated when the handle was opened.
    #[must_use]
    pub const fn descriptor(&self) -> ContentDescriptor {
        self.opened.descriptor()
    }

    /// Return the principal root generation that authorized this handle.
    #[must_use]
    pub const fn principal_root(&self) -> RootState {
        self.principal_root
    }

    /// Reconstruct the complete opened value.
    ///
    /// # Errors
    ///
    /// Returns a content or projection error when verification or allocation
    /// fails. This includes [`crate::content_dag::ContentError::MissingObject`]
    /// if a compaction caller allowed the opened closure to be collected.
    pub fn read(&self) -> Result<Vec<u8>, PrincipalContentError> {
        let source = EngineSource::<P, E>::new(self.engine.as_ref(), &self.principal);
        if let Some(verified) = self.verified() {
            return read_verified_content(&source, verified).map_err(map_read_error);
        }
        let (bytes, verified) =
            read_opened_content_and_verify(&source, self.opened).map_err(map_read_error)?;
        self.mark_verified(verified);
        Ok(bytes)
    }

    /// Reconstruct an exact range of the opened value.
    ///
    /// # Errors
    ///
    /// Returns a content, projection, range, or allocation error when the
    /// requested bytes cannot be reconstructed exactly. This includes
    /// [`crate::content_dag::ContentError::MissingObject`] if a compaction
    /// caller allowed the opened closure to be collected.
    pub fn read_range(&self, offset: u64, length: u64) -> Result<Vec<u8>, PrincipalContentError> {
        let source = EngineSource::<P, E>::new(self.engine.as_ref(), &self.principal);
        if let Some(verified) = self.verified() {
            return read_verified_content_range(&source, verified, offset, length)
                .map_err(map_read_error);
        }
        let file = self.opened.descriptor().file();
        let known = self
            .engine
            .load_projection_cache(&self.principal, file, PARTIAL_VERIFICATION_CACHE_KEY)
            .and_then(|entry| entry.downcast::<CachedPartialVerification>());
        let empty = ContentVerificationState::default();
        let (bytes, delta) = read_opened_content_range_with_verification(
            &source,
            self.opened,
            known.as_deref().map_or(&empty, |known| &known.0),
            offset,
            length,
        )
        .map_err(map_read_error)?;
        if !delta.is_empty() {
            let mut next = known
                .as_deref()
                .map_or_else(ContentVerificationState::default, |known| known.0.clone());
            next.merge(delta);
            let _ = self.engine.retain_projection_cache(
                &self.principal,
                file,
                PARTIAL_VERIFICATION_CACHE_KEY,
                ProjectionCacheEntry::new(CachedPartialVerification(next)),
            );
        }
        Ok(bytes)
    }

    fn verified(&self) -> Option<VerifiedContent> {
        self.engine
            .load_projection_cache(
                &self.principal,
                self.opened.descriptor().file(),
                VERIFIED_CONTENT_CACHE_KEY,
            )
            .and_then(|entry| entry.downcast::<CachedVerifiedContent>())
            .map(|verified| verified.0)
    }

    fn mark_verified(&self, verified: VerifiedContent) {
        let file = verified.descriptor().file();
        let _ = self.engine.discard_projection_cache(
            &self.principal,
            file,
            PARTIAL_VERIFICATION_CACHE_KEY,
        );
        let _ = self.engine.retain_projection_cache(
            &self.principal,
            file,
            VERIFIED_CONTENT_CACHE_KEY,
            ProjectionCacheEntry::new(CachedVerifiedContent(verified)),
        );
    }
}
