//! Append-only durable realization of the principal-store model.
//!
//! Object frames and principal-root transitions live in separate files. New
//! immutable objects are flushed before a root-journal frame can make them
//! authoritative. A disposable persistent index accelerates clean reopen but
//! never participates in root authority or archival export.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(test)]
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Seek, SeekFrom};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::time::Duration;

use crate::volume::{AstridVolume, VolumeRegion};

use crate::content_dag::ContentError;
use crate::storage_model::{
    InsertOutcome, ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity,
    ObjectKind, ObjectRecord, ObjectReference, PhysicalModelError, PrincipalUsage, ReferenceKind,
    ReferenceLabel, RootGeneration, RootState,
};
use arc_swap::ArcSwap;
use fs2::FileExt;
use parking_lot::{Mutex, MutexGuard, RwLock};

use crate::engine::{CommitOutcome, RootSnapshot, RootTransaction};
use group::CommitGroup;
pub use group::GroupCommitPolicy;

const ARENA_FILE: &str = "objects.arena";
const ROOT_FILE: &str = "roots.journal";
const INDEX_FILE: &str = "objects.index";
const LOCK_FILE: &str = "store.lock";
const WAL_FILE: &str = "transactions.wal";
const WAL_WRITE_BUFFER_BYTES: usize = 64 * 1024;
const ARENA_MAGIC: [u8; 8] = *b"ASTOBJ1\0";
const ROOT_MAGIC: [u8; 8] = *b"ASTROOT\0";
const INDEX_MAGIC: [u8; 8] = *b"ASTIDX1\0";
const FRAME_VERSION: u16 = 1;
const FRAME_HEADER_LEN: u64 = 52;
const FRAME_HEADER_LEN_USIZE: usize = 52;
const CHECKSUM_START: usize = 20;
const LIFECYCLE_USABLE: u8 = 0;
const LIFECYCLE_REQUIRES_RECOVERY: u8 = 1;
const LIFECYCLE_CLOSED: u8 = 2;

/// Explicit durable-frame parser allocation boundary.
///
/// This is a parser/resource guard, not a principal quota or a file-size cap.
/// Embeddings that do not need a stricter parser guard can use
/// [`Self::process_addressable`] without creating a hidden deployment quota.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryLimits {
    max_frame_bytes: u64,
}

impl RecoveryLimits {
    /// Use the largest frame representable by this process.
    ///
    /// Allocation remains fallible. This is a parser representation boundary,
    /// not a policy quota or hidden deployment capacity.
    #[must_use]
    pub fn process_addressable() -> Self {
        Self {
            max_frame_bytes: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        }
    }

    /// Construct an explicit frame-allocation ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::InvalidLimits`] when `max_frame_bytes` is zero
    /// or cannot be represented by this process.
    pub fn new(max_frame_bytes: u64) -> Result<Self, DurableError> {
        if max_frame_bytes == 0 || usize::try_from(max_frame_bytes).is_err() {
            return Err(DurableError::InvalidLimits);
        }
        Ok(Self { max_frame_bytes })
    }

    /// Return the configured maximum decoded frame payload.
    #[must_use]
    pub const fn max_frame_bytes(self) -> u64 {
        self.max_frame_bytes
    }
}

const DEFAULT_RECOVERY_ATTEMPTS: NonZeroU32 = match NonZeroU32::new(3) {
    Some(attempts) => attempts,
    None => panic!("the default recovery attempt count is non-zero"),
};
const DEFAULT_RECOVERY_BACKOFF: Duration = Duration::from_millis(10);

/// Bounded policy for reopening a poisoned durable engine in process.
///
/// One foreground operation performs at most `attempts` recovery scans. Only
/// filesystem I/O failures are retried; structural corruption fails
/// immediately. A later operation may make a fresh bounded attempt, so a
/// prolonged disk-full incident does not permanently disable the store after
/// space is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryRetryPolicy {
    attempts: NonZeroU32,
    backoff: Duration,
}

impl RecoveryRetryPolicy {
    /// Construct a bounded fixed-backoff recovery policy.
    #[must_use]
    pub const fn new(attempts: NonZeroU32, backoff: Duration) -> Self {
        Self { attempts, backoff }
    }

    /// Perform exactly one recovery attempt without intentional delay.
    #[must_use]
    pub const fn immediate() -> Self {
        Self::new(NonZeroU32::MIN, Duration::ZERO)
    }

    /// Return the maximum attempts made by one foreground operation.
    #[must_use]
    pub const fn attempts(self) -> NonZeroU32 {
        self.attempts
    }

    /// Return the fixed delay between retryable recovery failures.
    #[must_use]
    pub const fn backoff(self) -> Duration {
        self.backoff
    }
}

impl Default for RecoveryRetryPolicy {
    fn default() -> Self {
        Self::new(DEFAULT_RECOVERY_ATTEMPTS, DEFAULT_RECOVERY_BACKOFF)
    }
}

/// Complete non-persistent operating policy for one durable engine instance.
///
/// These values govern latency, recovery work, and disposable resident memory.
/// They never participate in object identity, durable framing, or principal
/// storage quota.
pub struct DurableEnginePolicy<P> {
    group_commit: GroupCommitPolicy,
    recovery: RecoveryRetryPolicy,
    object_cache: ObjectCacheConfig<P>,
    transaction_wal: TransactionWalPolicy,
}

impl<P> DurableEnginePolicy<P> {
    /// Combine explicit group-commit, recovery, and decoded-cache policies.
    #[must_use]
    pub const fn new(
        group_commit: GroupCommitPolicy,
        recovery: RecoveryRetryPolicy,
        object_cache: ObjectCacheConfig<P>,
    ) -> Self {
        Self {
            group_commit,
            recovery,
            object_cache,
            transaction_wal: TransactionWalPolicy::disabled(),
        }
    }

    /// Select whether new root transactions publish through the single-sync
    /// transaction WAL. Recovery always replays an existing WAL regardless of
    /// this setting so disabling new WAL writes cannot hide durable state.
    #[must_use]
    pub const fn with_transaction_wal(mut self, policy: TransactionWalPolicy) -> Self {
        self.transaction_wal = policy;
        self
    }
}

/// Publication policy for new durable root transactions.
///
/// This is an operating policy only. It does not change object identity,
/// principal authority, quota accounting, or the canonical object/root
/// formats produced after checkpointing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransactionWalPolicy {
    checkpoint_bytes: Option<NonZeroU64>,
}

impl TransactionWalPolicy {
    /// Preserve the legacy ordered arena-sync then root-sync publication path.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            checkpoint_bytes: None,
        }
    }

    /// Publish complete root transactions with one transaction-WAL sync,
    /// then checkpoint prior committed contents once their physical length
    /// reaches `checkpoint_bytes`.
    #[must_use]
    pub const fn enabled(checkpoint_bytes: NonZeroU64) -> Self {
        Self {
            checkpoint_bytes: Some(checkpoint_bytes),
        }
    }

    pub(in crate::engine::durable) const fn is_enabled(self) -> bool {
        self.checkpoint_bytes.is_some()
    }

    const fn checkpoint_bytes(self) -> Option<NonZeroU64> {
        self.checkpoint_bytes
    }
}

impl<P> Default for DurableEnginePolicy<P> {
    fn default() -> Self {
        Self::new(
            GroupCommitPolicy::default(),
            RecoveryRetryPolicy::default(),
            ObjectCacheConfig::bounded(default_decoded_object_cache_bytes()),
        )
    }
}

/// Working-set for decoded volume objects after layout-2.
///
/// One gibibyte. Large enough that a moved audit tree's hot nodes stay
/// decoded. A smaller default keeps every host-call audit on the volume
/// checksum path.
fn default_decoded_object_cache_bytes() -> NonZeroU64 {
    // One gibibyte: large enough that a moved audit tree's hot nodes stay
    // decoded after layout-2. Smaller defaults keep every host-call audit
    // on the volume checksum path.
    NonZeroU64::new(1024 * 1024 * 1024).expect("one gibibyte is non-zero")
}

/// Canonical persistent representation of a domain-bearing principal value.
///
/// Decoding must reject invalid bytes. For every accepted byte string `b`,
/// `encode(decode(b))` must equal `b`; recovery enforces that round trip so two
/// byte representations cannot silently name one principal.
pub trait PrincipalCodec<P>: Send + Sync {
    /// Encode one validated principal identifier.
    fn encode(&self, principal: &P) -> Vec<u8>;

    /// Decode and validate one principal identifier.
    fn decode(&self, bytes: &[u8]) -> Option<P>;

    /// Check whether this durable wire grammar admits the principal.
    ///
    /// The default accepts every in-memory principal. Integration codecs use
    /// this hook to reserve wire capacity without activating it as durable
    /// runtime state.
    ///
    /// # Errors
    ///
    /// Returns an admission error when the principal is reserved by this
    /// active grammar.
    fn admit_principal(&self, _principal: &P) -> Result<(), DurableError> {
        Ok(())
    }
}

/// Algorithm and construction version carried beside every durable identity.
///
/// Digest length is encoded independently at each wire occurrence. The
/// current in-memory [`ObjectId`] remains 32 bytes, while the durable grammar
/// can carry successor digests of different lengths without changing its
/// framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityScheme {
    algorithm: u16,
    construction: u16,
}

impl IdentityScheme {
    /// Construct a non-zero algorithm and identity-construction pair.
    #[must_use]
    pub const fn new(algorithm: u16, construction: u16) -> Option<Self> {
        if algorithm == 0 || construction == 0 {
            return None;
        }
        Some(Self {
            algorithm,
            construction,
        })
    }

    /// Return the registered digest-algorithm code.
    #[must_use]
    pub const fn algorithm(self) -> u16 {
        self.algorithm
    }

    /// Return the algorithm-scoped identity-construction version.
    #[must_use]
    pub const fn construction(self) -> u16 {
        self.construction
    }
}

/// Logical identity implementation with an explicit durable wire scheme.
///
/// A future engine may support several implementations simultaneously. The
/// first durable engine accepts one scheme per open store but writes the tag
/// at every identity-bearing location so the format does not impose that
/// limitation.
pub trait PersistentObjectIdentity: ObjectIdentity {
    /// Return the durable algorithm and construction-version tag.
    fn scheme(&self) -> IdentityScheme;
}

struct SharedPrincipalCodec<C>(Arc<C>);

impl<C> Clone for SharedPrincipalCodec<C> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<C> SharedPrincipalCodec<C> {
    fn new(codec: C) -> Self {
        Self(Arc::new(codec))
    }
}

impl<P, C> PrincipalCodec<P> for SharedPrincipalCodec<C>
where
    C: PrincipalCodec<P>,
{
    fn encode(&self, principal: &P) -> Vec<u8> {
        self.0.encode(principal)
    }

    fn decode(&self, bytes: &[u8]) -> Option<P> {
        self.0.decode(bytes)
    }

    fn admit_principal(&self, principal: &P) -> Result<(), DurableError> {
        self.0.admit_principal(principal)
    }
}

struct SharedIdentity<I>(Arc<I>);

impl<I> Clone for SharedIdentity<I> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<I> SharedIdentity<I> {
    fn new(identity: I) -> Self {
        Self(Arc::new(identity))
    }
}

impl<I> ObjectIdentity for SharedIdentity<I>
where
    I: ObjectIdentity,
{
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.0.identify(record)
    }
}

impl<I> PersistentObjectIdentity for SharedIdentity<I>
where
    I: PersistentObjectIdentity,
{
    fn scheme(&self) -> IdentityScheme {
        self.0.scheme()
    }
}

/// Failure to open, recover, or update a durable principal store.
#[derive(Debug)]
#[non_exhaustive]
pub enum DurableError {
    /// The portable state model rejected an operation.
    Model(ModelError),
    /// The canonical physical-representation model rejected an operation.
    PhysicalModel(PhysicalModelError),
    /// Canonical content construction rejected a staged byte stream.
    Content(ContentError),
    /// A filesystem operation failed.
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Underlying platform error.
        source: io::Error,
    },
    /// Another process or engine instance holds the store lock.
    LockHeld(PathBuf),
    /// Recovery limits were zero or not representable by this process.
    InvalidLimits,
    /// A complete stored frame failed structural or checksum validation.
    Corrupt {
        /// Store file containing the bad frame.
        file: &'static str,
        /// Byte offset of the frame.
        offset: u64,
        /// Stable diagnostic category.
        detail: &'static str,
    },
    /// A declared frame exceeds the operator-supplied recovery allocation
    /// boundary.
    FrameTooLarge {
        /// Store file containing the declaration.
        file: &'static str,
        /// Byte offset of the frame.
        offset: u64,
        /// Declared payload bytes.
        declared: u64,
        /// Configured maximum payload bytes.
        limit: u64,
    },
    /// Principal bytes were invalid or non-canonical.
    InvalidPrincipal {
        /// Root-journal frame containing the bytes.
        offset: u64,
    },
    /// The in-memory principal is not admitted by the active wire grammar.
    UnsupportedPrincipal,
    /// A structurally valid frame violates the portable state model during
    /// recovery.
    RecoveryModel {
        /// Store file containing the frame.
        file: &'static str,
        /// Byte offset of the frame.
        offset: u64,
        /// Model invariant that failed.
        source: ModelError,
    },
    /// A length could not be represented by the persistent frame grammar.
    EncodingOverflow,
    /// A `store.meta` bootstrap object attempted to own principal state.
    BootstrapObjectOwnsState,
    /// A destination-only snapshot restore violated its empty-store or
    /// canonical-closure contract.
    InvalidRestore(&'static str),
    /// Physical representation metadata or its authority journal was invalid.
    InvalidRepresentationState(&'static str),
    /// Compaction evidence, retention, or its native fact snapshot was invalid.
    InvalidCompactionEvidence(&'static str),
    /// The native liveness snapshot changed between proof and physical rewrite.
    CompactionSnapshotChanged,
    /// No unreachable object exists for a garbage-collecting compaction plan.
    NoCompactionWork,
    /// The injected Tensor Logic proof verifier rejected the deletion plan.
    CompactionProofRejected,
    /// A named crash boundary interrupted the transaction.
    FaultInjected(FaultPoint),
    /// A prior write or injected crash may have diverged memory from disk.
    RequiresRecovery,
    /// The engine was explicitly closed and no longer owns store files.
    Closed,
}

impl fmt::Display for DurableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "{error}"),
            Self::PhysicalModel(error) => write!(formatter, "{error}"),
            Self::Content(error) => write!(formatter, "{error}"),
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::LockHeld(path) => {
                write!(formatter, "principal store is locked: {}", path.display())
            },
            Self::InvalidLimits => {
                formatter.write_str("recovery frame limit must be non-zero and process-addressable")
            },
            Self::Corrupt {
                file,
                offset,
                detail,
            } => write!(formatter, "corrupt {file} frame at byte {offset}: {detail}"),
            Self::FrameTooLarge {
                file,
                offset,
                declared,
                limit,
            } => write!(
                formatter,
                "{file} frame at byte {offset} declares {declared} bytes, exceeding limit {limit}"
            ),
            Self::InvalidPrincipal { offset } => {
                write!(
                    formatter,
                    "invalid principal bytes at root-journal byte {offset}"
                )
            },
            Self::UnsupportedPrincipal => {
                formatter.write_str("principal is not admitted by the durable owner codec")
            },
            Self::RecoveryModel {
                file,
                offset,
                source,
            } => write!(
                formatter,
                "{file} frame at byte {offset} violates the state model: {source}"
            ),
            Self::EncodingOverflow => formatter.write_str("durable frame length overflow"),
            Self::BootstrapObjectOwnsState => {
                formatter.write_str("standalone bootstrap object must not own other objects")
            },
            Self::InvalidRestore(detail) => write!(formatter, "invalid snapshot restore: {detail}"),
            Self::InvalidRepresentationState(detail) => {
                write!(formatter, "invalid representation state: {detail}")
            },
            Self::InvalidCompactionEvidence(detail) => {
                write!(formatter, "invalid compaction evidence: {detail}")
            },
            Self::CompactionSnapshotChanged => {
                formatter.write_str("compaction liveness snapshot changed after planning")
            },
            Self::NoCompactionWork => {
                formatter.write_str("compaction plan contains no unreachable objects")
            },
            Self::CompactionProofRejected => {
                formatter.write_str("compaction proof verifier rejected the deletion plan")
            },
            Self::FaultInjected(point) => write!(formatter, "fault injected at {point:?}"),
            Self::RequiresRecovery => {
                formatter.write_str("durable engine requires authoritative recovery")
            },
            Self::Closed => formatter.write_str("durable engine is closed"),
        }
    }
}

impl std::error::Error for DurableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Model(error) | Self::RecoveryModel { source: error, .. } => Some(error),
            Self::PhysicalModel(error) => Some(error),
            Self::Content(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<ModelError> for DurableError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<PhysicalModelError> for DurableError {
    fn from(error: PhysicalModelError) -> Self {
        Self::PhysicalModel(error)
    }
}

impl From<ContentError> for DurableError {
    fn from(error: ContentError) -> Self {
        Self::Content(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ArenaLocation {
    offset: u64,
    payload_len: u64,
    checksum: [u8; 32],
}

#[derive(Debug)]
struct DurableInner<P: Ord> {
    roots_by_principal: BTreeMap<P, RootState>,
    index: BTreeMap<ObjectId, ArenaLocation>,
    pending_wal: wal::PendingWalOverlay<P>,
    pending_index_locations: Vec<(ObjectId, ArenaLocation)>,
    pending_direct_objects: BTreeMap<ObjectId, representations::DirectArenaObject>,
    validated: BTreeSet<ObjectId>,
    files: Option<DurableFiles>,
    representations: Option<representations::RepresentationStore>,
    lock: Option<StoreLock>,
    poisoned: bool,
    arena_generation: u64,
}

#[derive(Debug)]
struct DurableFiles {
    arena: File,
    roots: File,
    index_cache: Option<File>,
    arena_len: u64,
    arena_tail: Option<ArenaLocation>,
}

#[derive(Debug)]
struct ArenaReader {
    file: File,
    generation: u64,
}

struct PublishedRoot {
    value: ArcSwap<RootState>,
}

impl PublishedRoot {
    fn new(value: RootState) -> Self {
        Self {
            value: ArcSwap::from_pointee(value),
        }
    }
}

struct PublishedRoots<P: Ord> {
    entries: ArcSwap<BTreeMap<P, Arc<PublishedRoot>>>,
}

impl<P> PublishedRoots<P>
where
    P: Clone + Ord,
{
    fn new(roots: &BTreeMap<P, RootState>) -> Self {
        Self {
            entries: ArcSwap::from_pointee(Self::entries(roots)),
        }
    }

    fn entries(roots: &BTreeMap<P, RootState>) -> BTreeMap<P, Arc<PublishedRoot>> {
        roots
            .iter()
            .map(|(principal, root)| (principal.clone(), Arc::new(PublishedRoot::new(*root))))
            .collect()
    }

    fn get(&self, principal: &P) -> Option<RootState> {
        self.entries
            .load()
            .get(principal)
            .map(|root| **root.value.load())
    }

    fn publish(&self, principal: &P, root: RootState) {
        let current = self.entries.load();
        if let Some(published) = current.get(principal) {
            published.value.store(Arc::new(root));
            return;
        }
        let mut next = (**current).clone();
        next.insert(principal.clone(), Arc::new(PublishedRoot::new(root)));
        self.entries.store(Arc::new(next));
    }

    fn replace(&self, roots: &BTreeMap<P, RootState>) {
        self.entries.store(Arc::new(Self::entries(roots)));
    }
}

#[derive(Debug)]
struct RecoveredStore<P: Ord> {
    roots_by_principal: BTreeMap<P, RootState>,
    index: BTreeMap<ObjectId, ArenaLocation>,
    validated: BTreeSet<ObjectId>,
    files: DurableFiles,
    representations: Option<representations::RepresentationStore>,
    arena_reader: File,
}

struct EngineOpenOptions<P> {
    policy: DurableEnginePolicy<P>,
    faults: Arc<dyn FaultInjector>,
}

type DurableWal<P, I, C> =
    wal::WalWriter<BufWriter<File>, SharedIdentity<I>, SharedPrincipalCodec<C>, P>;

/// Durable principal-store engine over host files or an Astrid volume.
///
/// `P` remains a domain-bearing integration type. `I` computes logical object
/// identity, while `C` owns the canonical persistent representation of `P`.
/// Neither principal authority nor quota policy is inferred by this engine.
pub struct DurableEngine<P: Ord, I, C> {
    directory: Option<PathBuf>,
    directory_capability: Option<Arc<cap_std::fs::Dir>>,
    volume: RwLock<Option<Arc<dyn AstridVolume>>>,
    identity: SharedIdentity<I>,
    principal_codec: SharedPrincipalCodec<C>,
    limits: RecoveryLimits,
    faults: Arc<dyn FaultInjector>,
    group_policy: GroupCommitPolicy,
    commit_group: Mutex<CommitGroup<P>>,
    transaction_wal: TransactionWalPolicy,
    wal: Mutex<Option<DurableWal<P, I, C>>>,
    lifecycle: AtomicU8,
    arena_reader: RwLock<Option<ArenaReader>>,
    object_cache: ObjectCache<P>,
    recovery_policy: RecoveryRetryPolicy,
    preparation_authority: Arc<()>,
    inner: Mutex<DurableInner<P>>,
    published_roots: PublishedRoots<P>,
}

impl<P: Ord, I, C> fmt::Debug for DurableEngine<P, I, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableEngine")
            .field("limits", &self.limits)
            .field("recovery_policy", &self.recovery_policy)
            .field("group_policy", &self.group_policy)
            .finish_non_exhaustive()
    }
}

mod engine;
mod object_access;
mod opening;

impl<P: Ord, I, C> Drop for DurableEngine<P, I, C> {
    fn drop(&mut self) {
        let inner = self.inner.get_mut();
        if let Some(mut files) = inner.files.take()
            && let Some(cache) = &mut files.index_cache
        {
            let _ = cache.sync_data();
        }
        if let Some(lock) = inner.lock.take()
            && let StoreLock::Native(lock) = lock
        {
            let _ = fs2::FileExt::unlock(&lock);
        }
    }
}

mod media;
pub(in crate::engine::durable) use media::{DurableIo, File, StoreLock};

#[derive(Debug)]
struct Persisted {
    locations: Vec<(ObjectId, ArenaLocation)>,
    arena_len: u64,
}

#[derive(Debug)]
struct Prepared<P: Ord> {
    principal: P,
    expected: Option<RootState>,
    root: RootState,
    objects_inserted: u64,
    objects: Vec<(ObjectId, Arc<[u8]>)>,
    commit: Option<(ObjectId, Arc<[u8]>)>,
    journal: Vec<u8>,
    validated: BTreeSet<ObjectId>,
}

fn ensure_usable<P: Ord>(inner: &DurableInner<P>) -> Result<(), DurableError> {
    if inner.poisoned {
        return Err(DurableError::RequiresRecovery);
    }
    if inner.files.is_none() {
        return Err(DurableError::Closed);
    }
    Ok(())
}

fn live_files_mut(files: &mut Option<DurableFiles>) -> Result<&mut DurableFiles, DurableError> {
    files.as_mut().ok_or(DurableError::Closed)
}

impl<P: Ord, I, C> DurableEngine<P, I, C> {
    /// Return backend-reported free capacity and the active arena length.
    ///
    /// The result is media-native: volume-backed engines ask the
    /// [`AstridVolume`] implementation, while legacy hosted-directory engines
    /// inspect their private arena directory. A `None` result means the media
    /// provider cannot report capacity and destructive compaction must fail
    /// closed rather than infer it from an unrelated host path.
    ///
    /// # Errors
    ///
    /// Returns a durable I/O or invalid-media error when capacity cannot be
    /// read from the selected backend.
    pub fn compaction_capacity(&self) -> Result<Option<(u64, u64)>, DurableError> {
        if let Some(volume) = self.volume.read().as_ref().cloned() {
            let region = VolumeRegion::new(ARENA_FILE)
                .map_err(|source| io_error("validate compaction arena region", source))?;
            let arena_bytes = volume
                .region_len(&region)
                .map_err(|source| io_error("read compaction arena length", source))?;
            return volume
                .available_space()
                .map(|available| available.map(|available| (available, arena_bytes)))
                .map_err(|source| io_error("read volume compaction capacity", source));
        }
        let directory = self.hosted_path()?;
        let arena = directory.join(ARENA_FILE);
        let arena_bytes = std::fs::metadata(&arena)
            .map_err(|source| io_error("read hosted compaction arena length", source))?
            .len();
        fs2::available_space(directory)
            .map(|available| Some((available, arena_bytes)))
            .map_err(|source| io_error("read hosted compaction capacity", source))
    }

    fn hosted_directory(&self) -> Result<&cap_std::fs::Dir, DurableError> {
        self.directory_capability
            .as_deref()
            .ok_or(DurableError::InvalidRepresentationState(
                "operation requires a hosted directory media provider",
            ))
    }

    fn hosted_path(&self) -> Result<&Path, DurableError> {
        self.directory
            .as_deref()
            .ok_or(DurableError::InvalidRepresentationState(
                "operation requires a hosted directory media provider",
            ))
    }
}

mod staging;

use crate::engine::durable_cache as cache;
mod compaction;
mod faults;
mod format;
mod group;
mod index;
mod lifecycle;
mod native_io;
mod recovery;
mod representation_engine;
mod representations;
mod restore;
mod roots;
mod validation;
mod wal;

use crate::engine::{ProjectionCacheEntry, ProjectionCacheKey};
use cache::ObjectCache;
pub use cache::{
    ObjectCacheCapacity, ObjectCacheConfig, ObjectCacheController, ObjectCacheMemoryBudget,
    ObjectCacheStats, PrincipalObjectCacheBudget,
};
use compaction::recover_interrupted_compaction;
pub use compaction::{
    CompactionEvidenceBundle, CompactionFacts, CompactionProofVerifier, CompactionReport,
    CompactionRetainedRoot, CompactionRetention, CompactionRootKind,
    DeterministicCompactionProofVerifier, VerifiedCompactionPlan, deterministic_compaction_proof,
};
pub use faults::{FaultInjector, FaultPoint, NoFaults};
use format::{
    PreparedFrame, append_frame, append_frames, append_prepared_frames, canonical_record_bytes,
    corrupt, decode_object_frame, encode_object_frame, ensure_payload_limit, io_error,
    read_indexed_object, read_indexed_object_with_payload, read_indexed_objects, recover_arena,
    scan_frames, scan_frames_observing, verify_indexed_location, verify_indexed_tail,
    visit_indexed_objects,
};
#[cfg(test)]
use format::{frame_checksum, last_batch_spans, open_rw};
use index::{IndexState, recover_index, replace_index, replace_volume_index};
use native_io::{
    create_private as create_private_file_capability, open_directory as open_directory_capability,
    open_rw as open_rw_capability, sync_directory as sync_store_directory_capability,
};
pub(crate) use recovery::OwnerObservations;
pub(crate) use recovery::inspect_native_root_history_without_repair;
#[cfg(test)]
pub(crate) use recovery::inspect_native_wal_owners_without_repair;
pub(crate) use recovery::inspect_volume_root_history_without_repair;
pub(crate) fn inspect_volume_wal_owners_without_repair<P, I, C>(
    volume: &Arc<dyn AstridVolume>,
    identity: &I,
    codec: &C,
    limits: RecoveryLimits,
) -> Result<OwnerObservations<P>, DurableError>
where
    P: Ord,
    I: PersistentObjectIdentity + Clone,
    C: PrincipalCodec<P> + Clone,
{
    let region =
        VolumeRegion::new(WAL_FILE).map_err(|source| io_error("validate WAL region", source))?;
    if !volume
        .region_exists(&region)
        .map_err(|source| io_error("probe WAL region", source))?
    {
        return Ok(OwnerObservations {
            owners: BTreeSet::new(),
            scan_error: None,
        });
    }
    let mut wal = File::volume(Arc::clone(volume), WAL_FILE, false)?;
    wal::wal_root_owners_without_repair(
        &mut wal,
        identity.scheme(),
        &SharedPrincipalCodec::new(codec.clone()),
        limits,
    )
}
use recovery::{RecoveryScope, recover_store, recover_volume};
use roots::{
    encode_root_record, encode_root_snapshot, probe_root_history_without_repair,
    recover_root_history, recover_roots,
};
use validation::{
    ClosureObjects, materialize_closure, preload_indexed_closures, recovery_closure_error,
    usage_from_closure, validate_commit_closure, validate_incremental_closure,
};

#[cfg(test)]
mod compaction_tests;
#[cfg(test)]
mod crash_replay_tests;
#[cfg(test)]
mod group_tests;
#[cfg(test)]
mod index_tests;
#[cfg(test)]
mod tests;
