//! Disposable, explicitly trusted source-change acceleration.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::Arc;

use astrid_storage_content::VerifiedContent;
use parking_lot::Mutex;

/// Identity of a source namespace whose change tokens share one trust policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceScopeId([u8; 32]);

impl SourceScopeId {
    /// Construct an opaque source-scope identity.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Platform-stable identity of one source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableSourceId([u8; 16]);

impl StableSourceId {
    /// Construct a platform adapter's stable file identity.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Epoch of the source's trusted monotonic change journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceEpoch([u8; 32]);

impl SourceEpoch {
    /// Construct an opaque source epoch.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Complete source version observed by a filesystem adapter.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceFingerprint {
    scope: SourceScopeId,
    path: PathBuf,
    logical_bytes: u64,
    modified_nanoseconds: i128,
    stable_id: StableSourceId,
    epoch: SourceEpoch,
}

impl SourceFingerprint {
    /// Construct the complete key used for source-change detection.
    #[must_use]
    pub fn new(
        scope: SourceScopeId,
        path: PathBuf,
        logical_bytes: u64,
        modified_nanoseconds: i128,
        stable_id: StableSourceId,
        epoch: SourceEpoch,
    ) -> Self {
        Self {
            scope,
            path,
            logical_bytes,
            modified_nanoseconds,
            stable_id,
            epoch,
        }
    }

    fn locator(&self) -> SourceLocator {
        SourceLocator {
            scope: self.scope,
            path: self.path.clone(),
        }
    }

    fn retained_bytes(&self) -> u64 {
        u64::try_from(std::mem::size_of::<Self>().saturating_add(self.path.as_os_str().len()))
            .unwrap_or(u64::MAX)
    }
}

/// Trust assigned to one source observation by the platform adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceTrust {
    /// Astrid owns the immutable source or trusts its monotonic change journal.
    TrustedChangeToken,
    /// Metadata may schedule work but cannot establish byte identity.
    UntrustedMetadata,
}

/// Source fingerprint plus the authority granted to its change token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceObservation {
    fingerprint: SourceFingerprint,
    trust: SourceTrust,
}

impl SourceObservation {
    /// Record a trusted source-change observation.
    #[must_use]
    pub const fn trusted(fingerprint: SourceFingerprint) -> Self {
        Self {
            fingerprint,
            trust: SourceTrust::TrustedChangeToken,
        }
    }

    /// Record untrusted metadata that may schedule but never skip byte reads.
    #[must_use]
    pub const fn untrusted(fingerprint: SourceFingerprint) -> Self {
        Self {
            fingerprint,
            trust: SourceTrust::UntrustedMetadata,
        }
    }

    /// Return the adapter-assigned trust class.
    #[must_use]
    pub const fn trust(&self) -> SourceTrust {
        self.trust
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SourceLocator {
    scope: SourceScopeId,
    path: PathBuf,
}

#[derive(Clone)]
struct CachedSource {
    fingerprint: SourceFingerprint,
    verified: VerifiedContent,
    retained_bytes: u64,
    tick: u64,
}

#[derive(Default)]
struct ChangeCacheState {
    entries: BTreeMap<SourceLocator, CachedSource>,
    eviction: BTreeSet<(u64, SourceLocator)>,
    retained_bytes: u64,
    next_tick: u64,
}

/// Memory-bounded process-local source-change accelerator.
///
/// The cache is never authoritative or exported. Only trusted change tokens
/// can produce a hit; untrusted metadata always falls through to byte reads.
/// Capacity is operator supplied rather than embedded as a deployment limit.
#[derive(Clone)]
pub struct ContentChangeCache {
    capacity_bytes: NonZeroU64,
    state: Arc<Mutex<ChangeCacheState>>,
}

impl ContentChangeCache {
    /// Construct an empty cache with an explicit resident-memory budget.
    #[must_use]
    pub fn new(capacity_bytes: NonZeroU64) -> Self {
        Self {
            capacity_bytes,
            state: Arc::new(Mutex::new(ChangeCacheState::default())),
        }
    }

    /// Return the current disposable entry count for operator diagnostics.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.state.lock().entries.len()
    }

    /// Return the cache's approximate resident byte charge.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.state.lock().retained_bytes
    }

    pub(super) fn lookup(&self, observation: &SourceObservation) -> Option<VerifiedContent> {
        if observation.trust != SourceTrust::TrustedChangeToken {
            return None;
        }
        let locator = observation.fingerprint.locator();
        let mut state = self.state.lock();
        let cached = state.entries.get(&locator)?.clone();
        if cached.fingerprint != observation.fingerprint {
            return None;
        }
        state.eviction.remove(&(cached.tick, locator.clone()));
        let tick = next_tick(&mut state);
        if let Some(entry) = state.entries.get_mut(&locator) {
            entry.tick = tick;
        }
        state.eviction.insert((tick, locator));
        Some(cached.verified)
    }

    pub(super) fn record(&self, observation: &SourceObservation, verified: VerifiedContent) {
        if observation.trust != SourceTrust::TrustedChangeToken {
            return;
        }
        let locator = observation.fingerprint.locator();
        let retained_bytes = observation
            .fingerprint
            .retained_bytes()
            .saturating_add(u64::try_from(std::mem::size_of::<CachedSource>()).unwrap_or(u64::MAX));
        if retained_bytes > self.capacity_bytes.get() {
            return;
        }
        let mut state = self.state.lock();
        if let Some(previous) = state.entries.remove(&locator) {
            state.eviction.remove(&(previous.tick, locator.clone()));
            state.retained_bytes = state.retained_bytes.saturating_sub(previous.retained_bytes);
        }
        let tick = next_tick(&mut state);
        state.entries.insert(
            locator.clone(),
            CachedSource {
                fingerprint: observation.fingerprint.clone(),
                verified,
                retained_bytes,
                tick,
            },
        );
        state.eviction.insert((tick, locator));
        state.retained_bytes = state.retained_bytes.saturating_add(retained_bytes);
        while state.retained_bytes > self.capacity_bytes.get() {
            let Some((tick, victim)) = state.eviction.pop_first() else {
                break;
            };
            if let Some(entry) = state.entries.get(&victim)
                && entry.tick == tick
            {
                let removed = state.entries.remove(&victim);
                if let Some(removed) = removed {
                    state.retained_bytes =
                        state.retained_bytes.saturating_sub(removed.retained_bytes);
                }
            }
        }
    }
}

impl std::fmt::Debug for ContentChangeCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock();
        formatter
            .debug_struct("ContentChangeCache")
            .field("capacity_bytes", &self.capacity_bytes)
            .field("entries", &state.entries.len())
            .field("retained_bytes", &state.retained_bytes)
            .finish()
    }
}

fn next_tick(state: &mut ChangeCacheState) -> u64 {
    if state.next_tick == u64::MAX {
        let ordered = state.eviction.iter().cloned().collect::<Vec<_>>();
        state.eviction.clear();
        for (next, (_, locator)) in ordered.into_iter().enumerate() {
            let tick = u64::try_from(next).unwrap_or(u64::MAX - 1);
            if let Some(entry) = state.entries.get_mut(&locator) {
                entry.tick = tick;
            }
            state.eviction.insert((tick, locator));
        }
        state.next_tick = u64::try_from(state.entries.len()).unwrap_or(u64::MAX - 1);
    }
    let tick = state.next_tick;
    state.next_tick = state.next_tick.saturating_add(1);
    tick
}
