//! Append-only durable realization of the principal-store model.
//!
//! Object frames and principal-root transitions live in separate files. New
//! immutable objects are flushed before a root-journal frame can make them
//! authoritative. A disposable persistent index accelerates clean reopen but
//! never participates in root authority or archival export.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_storage_model::{
    InsertOutcome, ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity,
    ObjectKind, ObjectRecord, ObjectReference, PrincipalUsage, ReferenceKind, ReferenceLabel,
    RootGeneration, RootState,
};
use fs2::FileExt;
use parking_lot::{Mutex, RwLock};

use crate::{CommitOutcome, RootSnapshot, RootTransaction};

const ARENA_FILE: &str = "objects.arena";
const ROOT_FILE: &str = "roots.journal";
const INDEX_FILE: &str = "objects.index";
const LOCK_FILE: &str = "store.lock";
const ARENA_MAGIC: [u8; 8] = *b"ASTOBJ1\0";
const ROOT_MAGIC: [u8; 8] = *b"ASTROOT\0";
const INDEX_MAGIC: [u8; 8] = *b"ASTIDX1\0";
const FRAME_VERSION: u16 = 1;
const FRAME_HEADER_LEN: u64 = 52;
const FRAME_HEADER_LEN_USIZE: usize = 52;
const CHECKSUM_START: usize = 20;

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

/// Failure to open, recover, or update a durable principal store.
#[derive(Debug)]
#[non_exhaustive]
pub enum DurableError {
    /// The portable state model rejected an operation.
    Model(ModelError),
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
                formatter.write_str("durable engine must be dropped and reopened")
            },
            Self::Closed => formatter.write_str("durable engine is closed"),
        }
    }
}

impl std::error::Error for DurableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Model(error) | Self::RecoveryModel { source: error, .. } => Some(error),
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
    pending_index_locations: Vec<(ObjectId, ArenaLocation)>,
    validated: BTreeSet<ObjectId>,
    files: Option<DurableFiles>,
    lock: Option<File>,
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

/// Host-file durable principal-store engine.
///
/// `P` remains a domain-bearing integration type. `I` computes logical object
/// identity, while `C` owns the canonical persistent representation of `P`.
/// Neither principal authority nor quota policy is inferred by this engine.
pub struct DurableEngine<P: Ord, I, C> {
    directory: PathBuf,
    identity: I,
    principal_codec: C,
    limits: RecoveryLimits,
    faults: Arc<dyn FaultInjector>,
    arena_reader: RwLock<ArenaReader>,
    object_cache: ObjectCache<P>,
    inner: Mutex<DurableInner<P>>,
}

impl<P: Ord, I, C> fmt::Debug for DurableEngine<P, I, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableEngine")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Open or create a durable store with no injected faults.
    ///
    /// # Errors
    ///
    /// Returns an I/O, lock, frame, identity, principal-codec, or model
    /// recovery error. An incomplete or physically invalid final frame is
    /// treated as an uncommitted tail only when no valid frame follows it;
    /// semantic invalidity and interior corruption remain fatal.
    pub fn open(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            Arc::new(NoFaults),
            ObjectCacheConfig::disabled(),
        )
    }

    /// Open or create a durable store with an explicitly governed decoded
    /// object cache.
    ///
    /// The engine never selects a hidden default cache ceiling. The embedding
    /// runtime owns both the live total controller and per-principal budget.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_object_cache(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        object_cache: ObjectCacheConfig<P>,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            Arc::new(NoFaults),
            object_cache,
        )
    }

    /// Open or create a durable store with an explicit fault injector.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_faults(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        faults: Arc<dyn FaultInjector>,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            faults,
            ObjectCacheConfig::disabled(),
        )
    }

    fn open_with_options(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        faults: Arc<dyn FaultInjector>,
        object_cache: ObjectCacheConfig<P>,
    ) -> Result<Self, DurableError> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)
            .map_err(|source| io_error("create principal-store directory", source))?;
        let lock_path = path.join(LOCK_FILE);
        let lock = open_rw(&lock_path)?;
        if let Err(source) = lock.try_lock_exclusive() {
            if source.kind() == io::ErrorKind::WouldBlock {
                return Err(DurableError::LockHeld(lock_path));
            }
            return Err(io_error("lock principal store", source));
        }

        recover_interrupted_compaction(&path, &principal_codec, &identity, limits)?;
        let mut arena = open_rw(&path.join(ARENA_FILE))?;
        let mut roots = open_rw(&path.join(ROOT_FILE))?;
        let mut index_cache = open_rw(&path.join(INDEX_FILE)).ok();
        sync_store_directory(&path)?;
        let scheme = identity.scheme();
        let arena_len = arena
            .metadata()
            .map_err(|source| io_error("read object-arena metadata", source))?
            .len();
        let cached = index_cache
            .as_mut()
            .and_then(|file| recover_index(file, &mut arena, scheme, limits, arena_len));
        let (index, arena_tail) = if let Some(state) = cached {
            (state.objects, state.arena_tail)
        } else {
            let (index, arena_tail) = recover_arena(&mut arena, &identity, limits)?;
            let state = IndexState {
                arena_len: arena
                    .metadata()
                    .map_err(|source| io_error("read recovered arena metadata", source))?
                    .len(),
                arena_tail,
                objects: index,
            };
            drop(index_cache.take());
            index_cache = replace_index(&path, &state, scheme);
            (state.objects, state.arena_tail)
        };
        let (roots_by_principal, validated) = recover_roots(
            &mut roots,
            &mut arena,
            &index,
            &principal_codec,
            &identity,
            limits,
        )?;
        let arena_len = arena
            .metadata()
            .map_err(|source| io_error("read recovered arena metadata", source))?
            .len();
        arena
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek object arena", source))?;
        roots
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek root journal", source))?;
        let arena_reader = arena
            .try_clone()
            .map_err(|source| io_error("clone object arena for positional reads", source))?;

        Ok(Self {
            directory: path,
            identity,
            principal_codec,
            limits,
            faults,
            arena_reader: RwLock::new(ArenaReader {
                file: arena_reader,
                generation: 0,
            }),
            object_cache: ObjectCache::new(object_cache),
            inner: Mutex::new(DurableInner {
                roots_by_principal,
                index,
                pending_index_locations: Vec::new(),
                validated,
                files: Some(DurableFiles {
                    arena,
                    roots,
                    index_cache,
                    arena_len,
                    arena_tail,
                }),
                lock: Some(lock),
                poisoned: false,
                arena_generation: 0,
            }),
        })
    }

    /// Compute the logical identity of a canonical object.
    #[must_use]
    pub fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.identity.identify(record)
    }

    /// Return the number of recovered immutable objects.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write.
    pub fn object_count(&self) -> Result<usize, DurableError> {
        let inner = self.inner.lock();
        ensure_usable(&inner)?;
        Ok(inner.index.len())
    }

    /// Return one recovered immutable object.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write.
    pub fn object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, DurableError> {
        loop {
            let (location, generation) = {
                let inner = self.inner.lock();
                ensure_usable(&inner)?;
                let Some(location) = inner.index.get(&id).copied() else {
                    return Ok(None);
                };
                (location, inner.arena_generation)
            };
            let reader = self.arena_reader.read();
            if reader.generation != generation {
                continue;
            }
            return read_indexed_object(&reader.file, id, location, &self.identity, self.limits)
                .map(Some);
        }
    }

    /// Return one immutable object through the principal-accounted decoded
    /// cache.
    ///
    /// Cache policy never changes read correctness. A bypass or miss performs
    /// the ordinary positional frame read and full validation before the
    /// resulting record can be retained.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write, or a
    /// frame/identity error when the arena cannot supply the requested object.
    pub fn object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<ObjectRecord>, DurableError> {
        self.shared_object_for(principal, id)
            .map(|record| record.map(|record| record.as_ref().clone()))
    }

    /// Return one immutable object through the principal-accounted decoded
    /// cache without cloning its allocation.
    ///
    /// Cache policy never changes read correctness. A bypass or miss performs
    /// the ordinary positional frame read and full validation before the
    /// resulting record can be retained.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write, or a
    /// frame/identity error when the arena cannot supply the requested object.
    pub fn shared_object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<Arc<ObjectRecord>>, DurableError> {
        if let Some(record) = self.object_cache.get(principal, id) {
            return Ok(Some(record));
        }
        let Some(record) = self.object(id)? else {
            return Ok(None);
        };
        let record = self.object_cache.insert(principal, id, record);
        Ok(Some(record))
    }

    /// Return immutable objects in request order through the
    /// principal-accounted decoded cache.
    ///
    /// Cache misses are resolved from one index snapshot. Physically adjacent
    /// arena frames are read as one span and each frame retains its complete
    /// checksum, identity, and canonical decode validation.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write, or a
    /// frame/identity error when the arena cannot supply a requested object.
    pub fn objects_for(
        &self,
        principal: &P,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<ObjectRecord>>, DurableError> {
        self.shared_objects_for(principal, ids).map(|records| {
            records
                .into_iter()
                .map(|record| record.map(|record| record.as_ref().clone()))
                .collect()
        })
    }

    /// Return immutable objects in request order through shared cache
    /// allocations.
    ///
    /// Cache misses are resolved from one index snapshot. Physically adjacent
    /// arena frames are read as one span and each frame retains its complete
    /// checksum, identity, and canonical decode validation.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write, or a
    /// frame/identity error when the arena cannot supply a requested object.
    pub fn shared_objects_for(
        &self,
        principal: &P,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<Arc<ObjectRecord>>>, DurableError> {
        let mut results = vec![None; ids.len()];
        let mut missing = BTreeMap::<ObjectId, Vec<usize>>::new();
        for (index, id) in ids.iter().copied().enumerate() {
            if let Some(record) = self.object_cache.get(principal, id) {
                results[index] = Some(record);
            } else {
                missing.entry(id).or_default().push(index);
            }
        }
        if missing.is_empty() {
            return Ok(results);
        }

        let loaded = loop {
            let (locations, generation) = {
                let inner = self.inner.lock();
                ensure_usable(&inner)?;
                let locations = missing
                    .keys()
                    .filter_map(|id| inner.index.get(id).copied().map(|location| (*id, location)))
                    .collect::<Vec<_>>();
                (locations, inner.arena_generation)
            };
            let reader = self.arena_reader.read();
            if reader.generation != generation {
                continue;
            }
            break read_indexed_objects(&reader.file, &locations, &self.identity, self.limits)?;
        };
        for (id, record) in loaded {
            let cached = self.object_cache.insert(principal, id, record);
            if let Some(indices) = missing.get(&id) {
                for index in indices {
                    results[*index] = Some(Arc::clone(&cached));
                }
            }
        }
        Ok(results)
    }

    /// Return privileged cache diagnostics.
    #[must_use]
    pub fn object_cache_stats(&self) -> ObjectCacheStats {
        self.object_cache.stats()
    }

    /// Return the bytes currently charged to one principal.
    ///
    /// This is kernel/operator accounting and must not be exposed to guests,
    /// because cache residency is a performance detail.
    #[must_use]
    pub fn object_cache_principal_charge(&self, principal: &P) -> u64 {
        self.object_cache.principal_charge(principal)
    }

    /// Load one projection-owned process-local accelerator from governed
    /// cache memory.
    ///
    /// A disabled budget, eviction, missing object association, or type
    /// mismatch returns `None`. The authoritative object path is unaffected.
    #[must_use]
    pub fn projection_cache(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> Option<ProjectionCacheEntry> {
        self.object_cache.projection(principal, object, key)
    }

    /// Retain one projection-owned process-local accelerator under the same
    /// total and per-principal budgets as decoded immutable objects.
    ///
    /// Returns `false` when policy declines retention. Projection correctness
    /// must not depend on this value remaining resident.
    pub fn retain_projection_cache(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
        value: ProjectionCacheEntry,
    ) -> bool {
        self.object_cache
            .retain_projection(principal, object, key, value)
    }

    /// Discard one projection-owned accelerator and release its cache charge.
    pub fn discard_projection_cache(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> bool {
        self.object_cache.discard_projection(principal, object, key)
    }

    /// Persist one standalone immutable object outside a principal root.
    ///
    /// This narrow path exists for store-level bootstrap evidence referenced
    /// by `store.meta`, such as the in-band format specification. The object
    /// must not own another object; graph publication remains a root
    /// transaction. Successful insertion flushes the arena before returning.
    ///
    /// # Errors
    ///
    /// Returns a model, encoding, I/O, recovery-required, or bootstrap-shape
    /// error. An I/O failure poisons this engine instance.
    pub fn persist_standalone_object(
        &self,
        record: &ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), DurableError> {
        if record.owning_references().next().is_some() {
            return Err(DurableError::BootstrapObjectOwnsState);
        }
        let id = self.identify(record);
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        if let Some(location) = inner.index.get(&id).copied() {
            let (existing, needs_flush) = {
                let files = live_files_mut(&mut inner.files)?;
                let existing =
                    read_indexed_object(&files.arena, id, location, &self.identity, self.limits)?;
                (existing, location.offset >= files.arena_len)
            };
            if &existing != record {
                return Err(ModelError::ObjectCollision(id).into());
            }
            if needs_flush {
                let persisted = {
                    let files = live_files_mut(&mut inner.files)?;
                    (|| {
                        files
                            .arena
                            .sync_data()
                            .map_err(|source| io_error("flush standalone object frame", source))?;
                        files
                            .arena
                            .metadata()
                            .map_err(|source| io_error("read standalone arena metadata", source))
                            .map(|metadata| metadata.len())
                    })()
                };
                match persisted {
                    Ok(arena_len) => {
                        if let Err(error) = self.advance_index_frontier(&mut inner, arena_len) {
                            inner.poisoned = true;
                            return Err(error);
                        }
                    },
                    Err(error) => {
                        inner.poisoned = true;
                        return Err(error);
                    },
                }
            }
            return Ok((id, InsertOutcome::AlreadyPresent));
        }
        let payload = encode_object_frame(self.identity.scheme(), id, record)?;
        ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
        let (previous_arena_len, persisted) = {
            let files = live_files_mut(&mut inner.files)?;
            let previous_arena_len = files.arena_len;
            let persisted = (|| {
                let location = append_frame(&mut files.arena, ARENA_MAGIC, &payload)?;
                files
                    .arena
                    .sync_data()
                    .map_err(|source| io_error("flush standalone object frame", source))?;
                let arena_len = files
                    .arena
                    .metadata()
                    .map_err(|source| io_error("read standalone arena metadata", source))?
                    .len();
                Ok((location, arena_len))
            })();
            (previous_arena_len, persisted)
        };
        match persisted {
            Ok((location, arena_len)) => {
                inner.index.insert(id, location);
                inner.pending_index_locations.push((id, location));
                inner.validated.insert(id);
                debug_assert_eq!(
                    previous_arena_len,
                    live_files_mut(&mut inner.files)?.arena_len
                );
                if let Err(error) = self.advance_index_frontier(&mut inner, arena_len) {
                    inner.poisoned = true;
                    return Err(error);
                }
                Ok((id, InsertOutcome::Inserted))
            },
            Err(error) => {
                inner.poisoned = true;
                Err(error)
            },
        }
    }

    /// Return the current durable root for one principal.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write.
    pub fn root(&self, principal: &P) -> Result<Option<RootState>, DurableError> {
        let inner = self.inner.lock();
        ensure_usable(&inner)?;
        Ok(inner.roots_by_principal.get(principal).copied())
    }

    /// Return a consistent copy of every current principal root.
    ///
    /// This is a privileged maintenance surface for ordered store migrations,
    /// compaction, and operator diagnostics. Projection APIs must continue to
    /// address one authorized principal at a time.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write.
    pub fn roots(&self) -> Result<Vec<(P, RootState)>, DurableError> {
        let inner = self.inner.lock();
        ensure_usable(&inner)?;
        Ok(inner
            .roots_by_principal
            .iter()
            .map(|(principal, root)| (principal.clone(), *root))
            .collect())
    }

    /// Capture one current root and its complete owning closure.
    ///
    /// # Errors
    ///
    /// Returns a recovery-required or graph-validation error.
    pub fn snapshot(&self, principal: &P) -> Result<Option<RootSnapshot>, DurableError> {
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        let Some(root) = inner.roots_by_principal.get(principal).copied() else {
            return Ok(None);
        };
        let DurableInner { files, index, .. } = &mut *inner;
        let files = live_files_mut(files)?;
        let records = materialize_closure(
            &mut files.arena,
            index,
            &BTreeMap::new(),
            root.commit,
            &self.identity,
            self.limits,
        )?;
        Ok(Some(RootSnapshot { root, records }))
    }

    /// Calculate stable logical usage for one principal.
    ///
    /// # Errors
    ///
    /// Returns a recovery-required, missing-principal, graph, or arithmetic
    /// error.
    pub fn principal_usage(&self, principal: &P) -> Result<PrincipalUsage, DurableError> {
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        let root = inner
            .roots_by_principal
            .get(principal)
            .copied()
            .ok_or(ModelError::PrincipalMissing)?;
        let DurableInner { files, index, .. } = &mut *inner;
        let files = live_files_mut(files)?;
        let records = materialize_closure(
            &mut files.arena,
            index,
            &BTreeMap::new(),
            root.commit,
            &self.identity,
            self.limits,
        )?;
        usage_from_closure(&records, root.commit).map_err(Into::into)
    }

    /// Persist a complete immutable transaction and publish its root.
    ///
    /// Known-stale transactions and all model/encoding errors are rejected
    /// before any bytes are appended. Once I/O starts, any error poisons this
    /// instance; drop and reopen it so recovery can reconcile disk state.
    ///
    /// # Errors
    ///
    /// Returns an identity, collision, graph, root-conflict, encoding, I/O, or
    /// injected-fault error. A returned I/O/fault error requires reopen.
    pub fn commit(&self, transaction: RootTransaction<P>) -> Result<CommitOutcome, DurableError> {
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        let prepared = self.prepare(&mut inner, transaction)?;
        let previous_arena_len = live_files_mut(&mut inner.files)?.arena_len;
        match self.persist(&mut inner, &prepared) {
            Ok(persisted) => {
                for location in persisted.locations {
                    inner.index.insert(location.0, location.1);
                    inner.pending_index_locations.push(location);
                }
                inner.validated.extend(prepared.validated.iter().copied());
                inner
                    .roots_by_principal
                    .insert(prepared.principal.clone(), prepared.root);
                debug_assert_eq!(
                    previous_arena_len,
                    live_files_mut(&mut inner.files)?.arena_len
                );
                if let Err(error) = self.advance_index_frontier(&mut inner, persisted.arena_len) {
                    inner.poisoned = true;
                    return Err(error);
                }
                Ok(CommitOutcome {
                    root: prepared.root,
                    objects_inserted: prepared.objects_inserted,
                })
            },
            Err(error) => {
                inner.poisoned = true;
                Err(error)
            },
        }
    }

    fn prepare(
        &self,
        inner: &mut DurableInner<P>,
        transaction: RootTransaction<P>,
    ) -> Result<Prepared<P>, DurableError> {
        let RootTransaction {
            principal,
            expected,
            commit: commit_id,
            records,
        } = transaction;
        for (declared, record) in &records {
            let computed = self.identify(record);
            if computed != *declared {
                return Err(ModelError::ObjectIdentityMismatch {
                    declared: *declared,
                    computed,
                }
                .into());
            }
        }
        let actual = inner.roots_by_principal.get(&principal).copied();
        if actual != expected {
            return Err(ModelError::RootConflict { expected, actual }.into());
        }
        let generation = match actual {
            Some(root) => root
                .generation
                .checked_next()
                .ok_or(ModelError::ArithmeticOverflow)?,
            None => RootGeneration::INITIAL,
        };
        let root = RootState {
            generation,
            commit: commit_id,
        };

        let mut unique = BTreeMap::new();
        for (id, record) in records {
            match unique.get(&id) {
                Some(existing) if existing == &record => {},
                Some(_) => return Err(ModelError::ObjectCollision(id).into()),
                None => {
                    unique.insert(id, record);
                },
            }
        }
        let reachable = self.validate_pending_closure(inner, &unique, commit_id)?;

        let mut objects = Vec::new();
        let mut commit_frame = None;
        for (id, record) in unique {
            if !reachable.contains(&id) {
                continue;
            }
            if let Some(location) = inner.index.get(&id).copied() {
                let files = live_files_mut(&mut inner.files)?;
                let existing =
                    read_indexed_object(&files.arena, id, location, &self.identity, self.limits)?;
                if existing != record {
                    return Err(ModelError::ObjectCollision(id).into());
                }
                continue;
            }
            let payload = encode_object_frame(self.identity.scheme(), id, &record)?;
            ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
            if id == commit_id {
                commit_frame = Some((id, payload));
            } else {
                objects.push((id, payload));
            }
        }
        let principal_bytes = self.principal_codec.encode(&principal);
        let journal = encode_root_record(self.identity.scheme(), &principal_bytes, expected, root)?;
        ensure_payload_limit(ROOT_FILE, 0, journal.len(), self.limits)?;

        Ok(Prepared {
            principal,
            root,
            objects_inserted: u64::try_from(objects.len())
                .map_err(|_| ModelError::ArithmeticOverflow)?
                .checked_add(u64::from(commit_frame.is_some()))
                .ok_or(ModelError::ArithmeticOverflow)?,
            objects,
            commit: commit_frame,
            journal,
            validated: reachable,
        })
    }

    fn validate_pending_closure(
        &self,
        inner: &mut DurableInner<P>,
        incoming: &BTreeMap<ObjectId, ObjectRecord>,
        commit: ObjectId,
    ) -> Result<BTreeSet<ObjectId>, DurableError> {
        let DurableInner {
            files,
            index,
            validated,
            ..
        } = inner;
        let files = live_files_mut(files)?;
        validate_incremental_closure(
            &mut files.arena,
            index,
            incoming,
            validated,
            commit,
            &self.identity,
            self.limits,
        )
    }

    fn persist(
        &self,
        inner: &mut DurableInner<P>,
        prepared: &Prepared<P>,
    ) -> Result<Persisted, DurableError> {
        let files = live_files_mut(&mut inner.files)?;
        let mut locations = Vec::new();
        for (id, payload) in &prepared.objects {
            let location = append_frame(&mut files.arena, ARENA_MAGIC, payload)?;
            locations.push((*id, location));
        }
        self.fail_if(FaultPoint::AfterObjectAppend)?;
        if let Some((id, payload)) = &prepared.commit {
            let location = append_frame(&mut files.arena, ARENA_MAGIC, payload)?;
            locations.push((*id, location));
        }
        self.fail_if(FaultPoint::AfterCommitAppend)?;
        files
            .arena
            .sync_data()
            .map_err(|source| io_error("flush transaction object frames", source))?;
        self.fail_if(FaultPoint::AfterObjectFlush)?;
        self.fail_if(FaultPoint::AfterCommitFlush)?;
        self.fail_if(FaultPoint::BeforeRootCas)?;

        append_frame(&mut files.roots, ROOT_MAGIC, &prepared.journal)?;
        files
            .roots
            .sync_data()
            .map_err(|source| io_error("flush root-journal frame", source))?;
        self.fail_if(FaultPoint::AfterRootCas)?;
        let arena_len = files
            .arena
            .metadata()
            .map_err(|source| io_error("read committed arena metadata", source))?
            .len();
        Ok(Persisted {
            locations,
            arena_len,
        })
    }

    fn fail_if(&self, point: FaultPoint) -> Result<(), DurableError> {
        if self.faults.should_fail(point) {
            return Err(DurableError::FaultInjected(point));
        }
        Ok(())
    }
}

impl<P: Ord, I, C> Drop for DurableEngine<P, I, C> {
    fn drop(&mut self) {
        let inner = self.inner.get_mut();
        if let Some(mut files) = inner.files.take()
            && let Some(cache) = &mut files.index_cache
        {
            let _ = cache.sync_data();
        }
        if let Some(lock) = inner.lock.take() {
            let _ = fs2::FileExt::unlock(&lock);
        }
    }
}

#[derive(Debug)]
struct Persisted {
    locations: Vec<(ObjectId, ArenaLocation)>,
    arena_len: u64,
}

#[derive(Debug)]
struct Prepared<P: Ord> {
    principal: P,
    root: RootState,
    objects_inserted: u64,
    objects: Vec<(ObjectId, Vec<u8>)>,
    commit: Option<(ObjectId, Vec<u8>)>,
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

mod staging;

#[path = "../durable_cache.rs"]
mod cache;
mod compaction;
mod faults;
mod format;
mod index;
mod lifecycle;
mod restore;
mod roots;
mod validation;

use crate::{ProjectionCacheEntry, ProjectionCacheKey};
use cache::ObjectCache;
pub use cache::{
    ObjectCacheCapacity, ObjectCacheConfig, ObjectCacheController, ObjectCacheStats,
    PrincipalObjectCacheBudget,
};
use compaction::recover_interrupted_compaction;
pub use compaction::{
    CompactionEvidenceBundle, CompactionFacts, CompactionProofVerifier, CompactionReport,
    CompactionRetainedRoot, CompactionRetention, CompactionRootKind, VerifiedCompactionPlan,
};
pub use faults::{FaultInjector, FaultPoint, NoFaults};
use format::{
    append_frame, append_frames, corrupt, decode_object_frame, encode_object_frame,
    ensure_payload_limit, io_error, open_rw, read_indexed_object, read_indexed_objects,
    recover_arena, scan_frames, sync_store_directory, verify_indexed_location, verify_indexed_tail,
};
#[cfg(test)]
use format::{frame_checksum, last_batch_spans};
use index::{IndexState, recover_index, replace_index};
use roots::{encode_root_record, encode_root_snapshot, recover_roots};
use validation::{
    materialize_closure, recovery_closure_error, usage_from_closure, validate_commit_closure,
    validate_incremental_closure,
};

#[cfg(test)]
mod compaction_tests;
#[cfg(test)]
mod index_tests;
#[cfg(test)]
mod tests;
