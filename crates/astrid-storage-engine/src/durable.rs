//! Append-only durable realization of the principal-store model.
//!
//! Object frames and principal-root transitions live in separate files. New
//! immutable objects are flushed before a root-journal frame can make them
//! authoritative. The in-memory object index is rebuilt from the arena on
//! every open; it is deliberately disposable performance state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_storage_model::{
    InsertOutcome, ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity,
    ObjectKind, ObjectRecord, ObjectReference, PrincipalUsage, ReferenceKind, ReferenceLabel,
    RootGeneration, RootState, World,
};
use fs2::FileExt;
use parking_lot::Mutex;

use crate::{CommitOutcome, RootSnapshot, RootTransaction};

const ARENA_FILE: &str = "objects.arena";
const ROOT_FILE: &str = "roots.journal";
const LOCK_FILE: &str = "store.lock";
const ARENA_MAGIC: [u8; 8] = *b"ASTOBJ1\0";
const ROOT_MAGIC: [u8; 8] = *b"ASTROOT\0";
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

/// Crash boundary exposed by the first durable engine slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FaultPoint {
    /// Non-commit object frames have been appended but not flushed.
    AfterObjectAppend,
    /// The transaction's complete object batch has been flushed.
    AfterObjectFlush,
    /// The transaction's immutable commit frame has been appended.
    AfterCommitAppend,
    /// Compatibility checkpoint after the shared object-batch flush.
    AfterCommitFlush,
    /// All objects are durable but no root-journal frame was appended.
    BeforeRootCas,
    /// The root-journal frame is durable.
    AfterRootCas,
}

/// Injectable crash decision used by recovery tests and harnesses.
pub trait FaultInjector: Send + Sync {
    /// Return `true` to stop at `point` and require the engine to be reopened.
    fn should_fail(&self, point: FaultPoint) -> bool;
}

/// Fault injector that never interrupts a transaction.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFaults;

impl FaultInjector for NoFaults {
    fn should_fail(&self, _point: FaultPoint) -> bool {
        false
    }
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

#[derive(Clone, Copy, Debug)]
struct ArenaLocation {
    offset: u64,
    payload_len: u64,
    checksum: [u8; 32],
}

#[derive(Debug)]
struct DurableInner<P: Ord> {
    roots_by_principal: BTreeMap<P, RootState>,
    index: BTreeMap<ObjectId, ArenaLocation>,
    validated: BTreeSet<ObjectId>,
    files: Option<DurableFiles>,
    poisoned: bool,
}

#[derive(Debug)]
struct DurableFiles {
    arena: File,
    roots: File,
    lock: File,
}

/// Host-file durable principal-store engine.
///
/// `P` remains a domain-bearing integration type. `I` computes logical object
/// identity, while `C` owns the canonical persistent representation of `P`.
/// Neither principal authority nor quota policy is inferred by this engine.
pub struct DurableEngine<P: Ord, I, C> {
    identity: I,
    principal_codec: C,
    limits: RecoveryLimits,
    faults: Arc<dyn FaultInjector>,
    arena_reader: File,
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
    /// recovery error. A truncated final frame is treated as an uncommitted
    /// tail and removed; a complete invalid frame is never silently repaired.
    pub fn open(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
    ) -> Result<Self, DurableError> {
        Self::open_with_faults(path, identity, principal_codec, limits, Arc::new(NoFaults))
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
        let path = path.as_ref();
        std::fs::create_dir_all(path)
            .map_err(|source| io_error("create principal-store directory", source))?;
        let lock_path = path.join(LOCK_FILE);
        let lock = open_rw(&lock_path)?;
        if let Err(source) = lock.try_lock_exclusive() {
            if source.kind() == io::ErrorKind::WouldBlock {
                return Err(DurableError::LockHeld(lock_path));
            }
            return Err(io_error("lock principal store", source));
        }

        let mut arena = open_rw(&path.join(ARENA_FILE))?;
        let mut roots = open_rw(&path.join(ROOT_FILE))?;
        sync_store_directory(path)?;
        let scheme = identity.scheme();
        let index = recover_arena(&mut arena, &identity, limits)?;
        let (roots_by_principal, validated) = recover_roots(
            &mut roots,
            &mut arena,
            &index,
            &principal_codec,
            scheme,
            limits,
        )?;
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
            identity,
            principal_codec,
            limits,
            faults,
            arena_reader,
            inner: Mutex::new(DurableInner {
                roots_by_principal,
                index,
                validated,
                files: Some(DurableFiles { arena, roots, lock }),
                poisoned: false,
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
        let location = {
            let inner = self.inner.lock();
            ensure_usable(&inner)?;
            let Some(location) = inner.index.get(&id).copied() else {
                return Ok(None);
            };
            location
        };
        read_indexed_object(
            &self.arena_reader,
            id,
            location,
            self.identity.scheme(),
            self.limits,
        )
        .map(Some)
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
            let files = live_files_mut(&mut inner.files)?;
            let existing = read_indexed_object(
                &mut files.arena,
                id,
                location,
                self.identity.scheme(),
                self.limits,
            )?;
            if &existing != record {
                return Err(ModelError::ObjectCollision(id).into());
            }
            return Ok((id, InsertOutcome::AlreadyPresent));
        }
        let payload = encode_object_frame(self.identity.scheme(), id, record)?;
        ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
        let persisted = {
            let files = live_files_mut(&mut inner.files)?;
            (|| {
                let location = append_frame(&mut files.arena, ARENA_MAGIC, &payload)?;
                files
                    .arena
                    .sync_data()
                    .map_err(|source| io_error("flush standalone object frame", source))?;
                Ok(location)
            })()
        };
        match persisted {
            Ok(location) => {
                inner.index.insert(id, location);
                inner.validated.insert(id);
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
            self.identity.scheme(),
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
            self.identity.scheme(),
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
        match self.persist(&mut inner, &prepared) {
            Ok(locations) => {
                inner.index.extend(locations);
                inner.validated.extend(prepared.validated.iter().copied());
                inner
                    .roots_by_principal
                    .insert(prepared.principal.clone(), prepared.root);
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
                let existing = read_indexed_object(
                    &mut files.arena,
                    id,
                    location,
                    self.identity.scheme(),
                    self.limits,
                )?;
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
            self.identity.scheme(),
            self.limits,
        )
    }

    fn persist(
        &self,
        inner: &mut DurableInner<P>,
        prepared: &Prepared<P>,
    ) -> Result<Vec<(ObjectId, ArenaLocation)>, DurableError> {
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
        Ok(locations)
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
        if let Some(files) = inner.files.take() {
            let _ = fs2::FileExt::unlock(&files.lock);
        }
    }
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
    if inner.files.is_none() {
        return Err(DurableError::Closed);
    }
    if inner.poisoned {
        return Err(DurableError::RequiresRecovery);
    }
    Ok(())
}

fn live_files_mut(files: &mut Option<DurableFiles>) -> Result<&mut DurableFiles, DurableError> {
    files.as_mut().ok_or(DurableError::Closed)
}

fn materialize_closure(
    arena: &mut File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    incoming: &BTreeMap<ObjectId, ObjectRecord>,
    root: ObjectId,
    scheme: IdentityScheme,
    limits: RecoveryLimits,
) -> Result<Vec<(ObjectId, ObjectRecord)>, DurableError> {
    let mut records = BTreeMap::new();
    let mut marks = BTreeMap::<ObjectId, u8>::new();
    let mut stack = vec![(root, false)];

    while let Some((id, expanded)) = stack.pop() {
        if expanded {
            marks.insert(id, 2);
            continue;
        }
        match marks.get(&id).copied() {
            Some(2) => continue,
            Some(1) => return Err(ModelError::ObjectCycle(id).into()),
            Some(_) | None => {},
        }
        let record = if let Some(record) = incoming.get(&id) {
            record.clone()
        } else {
            let location = index
                .get(&id)
                .copied()
                .ok_or(ModelError::MissingObject(id))?;
            read_indexed_object(arena, id, location, scheme, limits)?
        };
        marks.insert(id, 1);
        stack.push((id, true));
        for child in record.owning_references().rev() {
            stack.push((child, false));
        }
        records.insert(id, record);
    }
    Ok(records.into_iter().collect())
}

fn validate_commit_closure(
    records: &[(ObjectId, ObjectRecord)],
    commit: ObjectId,
) -> Result<(), ModelError> {
    let mut world = World::<()>::new();
    world.import_closure(records, commit)?;
    world.compare_and_swap_root((), None, commit)?;
    Ok(())
}

fn validate_incremental_closure(
    arena: &mut File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    incoming: &BTreeMap<ObjectId, ObjectRecord>,
    validated: &BTreeSet<ObjectId>,
    root: ObjectId,
    scheme: IdentityScheme,
    limits: RecoveryLimits,
) -> Result<BTreeSet<ObjectId>, DurableError> {
    let root_record = if let Some(record) = incoming.get(&root) {
        record.clone()
    } else {
        let location = index
            .get(&root)
            .copied()
            .ok_or(ModelError::MissingObject(root))?;
        read_indexed_object(arena, root, location, scheme, limits)?
    };
    if root_record.kind() != ObjectKind::Commit {
        return Err(ModelError::RootNotCommit {
            object: root,
            actual: root_record.kind(),
        }
        .into());
    }
    let mut reachable = BTreeSet::new();
    let mut marks = BTreeMap::<ObjectId, u8>::new();
    let mut stack = vec![(root, false)];

    while let Some((id, expanded)) = stack.pop() {
        if validated.contains(&id) {
            reachable.insert(id);
            continue;
        }
        if expanded {
            marks.insert(id, 2);
            continue;
        }
        match marks.get(&id).copied() {
            Some(2) => continue,
            Some(1) => return Err(ModelError::ObjectCycle(id).into()),
            Some(_) | None => {},
        }
        let record = if let Some(record) = incoming.get(&id) {
            record.clone()
        } else {
            let location = index
                .get(&id)
                .copied()
                .ok_or(ModelError::MissingObject(id))?;
            read_indexed_object(arena, id, location, scheme, limits)?
        };
        reachable.insert(id);
        marks.insert(id, 1);
        stack.push((id, true));
        for child in record.owning_references().rev() {
            stack.push((child, false));
        }
    }
    Ok(reachable)
}

fn usage_from_closure(
    records: &[(ObjectId, ObjectRecord)],
    commit: ObjectId,
) -> Result<PrincipalUsage, ModelError> {
    let mut world = World::<()>::new();
    world.import_closure(records, commit)?;
    world.compare_and_swap_root((), None, commit)?;
    world.principal_usage(&())
}

fn recovery_closure_error(error: DurableError, root_offset: u64) -> DurableError {
    match error {
        DurableError::Model(source) => DurableError::RecoveryModel {
            file: ROOT_FILE,
            offset: root_offset,
            source,
        },
        other => other,
    }
}

#[path = "durable_staging.rs"]
mod staging;

#[path = "durable_format.rs"]
mod format;
#[path = "durable_lifecycle.rs"]
mod lifecycle;

use format::{
    append_frame, append_frames, encode_object_frame, encode_root_record, ensure_payload_limit,
    io_error, open_rw, read_indexed_object, recover_arena, recover_roots, sync_store_directory,
};
#[cfg(test)]
use format::{decode_object_frame, frame_checksum};

#[cfg(test)]
#[path = "durable_tests.rs"]
mod tests;
