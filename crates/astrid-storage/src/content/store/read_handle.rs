//! Immutable principal-content read handles and their compaction leases.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::{Condvar, Mutex};

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
///
/// `in_flight` is announced before any engine-backed open resolution and held
/// until the lease is registered or the open fails. Compaction observes this
/// counter only while it already owns the engine mutation fence, so an opener
/// cannot register a handle to bytes collected in that window. The registry
/// mutex is never held across engine calls.
struct RegistryState<P> {
    compacting: bool,
    in_flight: u64,
    roots: BTreeMap<u64, (P, ObjectId)>,
}

pub(super) struct ContentReadLeaseRegistry<P> {
    next: AtomicU64,
    state: Mutex<RegistryState<P>>,
    not_compacting: Condvar,
    #[cfg(test)]
    open_read_gate: Mutex<Option<Arc<OpenReadTestGate>>>,
}

impl<P> Default for ContentReadLeaseRegistry<P> {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(1),
            state: Mutex::new(RegistryState {
                compacting: false,
                in_flight: 0,
                roots: BTreeMap::new(),
            }),
            not_compacting: Condvar::new(),
            #[cfg(test)]
            open_read_gate: Mutex::new(None),
        }
    }
}

impl<P> ContentReadLeaseRegistry<P> {
    /// Announce an in-flight open, then wait if compaction already owns the fence.
    pub(super) fn begin_open(self: &Arc<Self>) -> InFlightOpenGuard<P> {
        let mut state = self.state.lock();
        state.in_flight = state
            .in_flight
            .checked_add(1)
            .expect("in-flight content open counter overflow");
        while state.compacting {
            self.not_compacting.wait(&mut state);
        }
        InFlightOpenGuard {
            registry: Arc::clone(self),
        }
    }

    /// Snapshot registered handle roots after the engine fence is held.
    ///
    /// Fails closed when an opener already announced. `compacting` stays true
    /// until the returned guard drops so later openers wait, then resolve
    /// post-compaction state.
    pub(crate) fn begin_compaction_observation(
        self: &Arc<Self>,
    ) -> Result<CompactionObservationGuard<P>, CompactionObservationError> {
        let mut state = self.state.lock();
        if state.in_flight > 0 {
            return Err(CompactionObservationError);
        }
        state.compacting = true;
        Ok(CompactionObservationGuard {
            live_roots: state.roots.values().map(|(_, object)| *object).collect(),
            registry: Arc::clone(self),
        })
    }

    #[cfg(test)]
    pub(super) fn install_open_read_test_gate(&self, gate: Arc<OpenReadTestGate>) {
        *self.open_read_gate.lock() = Some(gate);
    }

    #[cfg(test)]
    pub(super) fn pause_after_resolve_for_test(&self) {
        let gate = self.open_read_gate.lock().clone();
        if let Some(gate) = gate {
            gate.pause();
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
        self.state.lock().roots.insert(token, (principal, object));
        ContentReadLease {
            registry: Arc::clone(self),
            token,
        }
    }

    pub(super) fn roots(&self) -> Vec<(P, ObjectId)> {
        self.state.lock().roots.values().cloned().collect()
    }
}

/// Guard that keeps `in_flight` raised until open registers a lease or fails.
pub(crate) struct InFlightOpenGuard<P> {
    registry: Arc<ContentReadLeaseRegistry<P>>,
}

impl<P> Drop for InFlightOpenGuard<P> {
    fn drop(&mut self) {
        let mut state = self.registry.state.lock();
        state.in_flight = state.in_flight.saturating_sub(1);
    }
}

/// Compaction-owned observation; Drop clears `compacting` and wakes openers.
pub(crate) struct CompactionObservationGuard<P> {
    registry: Arc<ContentReadLeaseRegistry<P>>,
    live_roots: Vec<ObjectId>,
}

impl<P> CompactionObservationGuard<P> {
    pub(crate) fn live_object_ids(&self) -> Vec<ObjectId> {
        self.live_roots.clone()
    }
}

impl<P> Drop for CompactionObservationGuard<P> {
    fn drop(&mut self) {
        self.registry.state.lock().compacting = false;
        self.registry.not_compacting.notify_all();
    }
}

/// An opener was already announced when compaction tried to snapshot handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompactionObservationError;

pub(super) struct ContentReadLease<P> {
    registry: Arc<ContentReadLeaseRegistry<P>>,
    token: u64,
}

impl<P> Drop for ContentReadLease<P> {
    fn drop(&mut self) {
        self.registry.state.lock().roots.remove(&self.token);
    }
}

/// Deterministic pause after engine resolve and before lease registration.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct OpenReadTestGate {
    entered: Mutex<bool>,
    entered_cv: Condvar,
    released: Mutex<bool>,
    released_cv: Condvar,
}

#[cfg(test)]
impl OpenReadTestGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Mutex::new(false),
            entered_cv: Condvar::new(),
            released: Mutex::new(false),
            released_cv: Condvar::new(),
        })
    }

    pub(crate) fn wait_until_entered(&self) {
        let mut entered = self.entered.lock();
        while !*entered {
            self.entered_cv.wait(&mut entered);
        }
    }

    pub(crate) fn release(&self) {
        *self.released.lock() = true;
        self.released_cv.notify_all();
    }

    fn pause(&self) {
        {
            let mut entered = self.entered.lock();
            *entered = true;
            self.entered_cv.notify_all();
        }
        let mut released = self.released.lock();
        while !*released {
            self.released_cv.wait(&mut released);
        }
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
