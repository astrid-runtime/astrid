//! Append-only durable realization of the principal-store model.
//!
//! Object frames and principal-root transitions live in separate files. New
//! immutable objects are flushed before a root-journal frame can make them
//! authoritative. The in-memory object index is rebuilt from the arena on
//! every open; it is deliberately disposable performance state.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_storage_model::{
    InsertOutcome, ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity,
    ObjectKind, ObjectRecord, ObjectReference, PrincipalUsage, ReferenceKind, RootState, World,
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

/// Operator-supplied recovery allocation boundary.
///
/// This is a parser/resource guard, not a principal quota or a file-size cap.
/// The durable engine intentionally has no hidden default: its embedding
/// runtime must derive the value from the principal or system resource policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryLimits {
    max_frame_bytes: u64,
}

impl RecoveryLimits {
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

/// Crash boundary exposed by the first durable engine slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    /// Non-commit object frames have been appended but not flushed.
    AfterObjectAppend,
    /// Non-commit object frames have been flushed.
    AfterObjectFlush,
    /// The transaction's immutable commit frame has been appended.
    AfterCommitAppend,
    /// The transaction's immutable commit frame has been flushed.
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
    /// A named crash boundary interrupted the transaction.
    FaultInjected(FaultPoint),
    /// A prior write or injected crash may have diverged memory from disk.
    RequiresRecovery,
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
            Self::FaultInjected(point) => write!(formatter, "fault injected at {point:?}"),
            Self::RequiresRecovery => {
                formatter.write_str("durable engine must be dropped and reopened")
            },
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
    _offset: u64,
    _payload_len: u64,
}

#[derive(Debug)]
struct DurableInner<P: Ord> {
    world: World<P>,
    index: BTreeMap<ObjectId, ArenaLocation>,
    arena: File,
    roots: File,
    lock: File,
    poisoned: bool,
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
    I: ObjectIdentity,
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
        let (mut world, index) = recover_arena(&mut arena, &identity, limits)?;
        recover_roots(&mut roots, &principal_codec, limits, &mut world)?;
        arena
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek object arena", source))?;
        roots
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek root journal", source))?;

        Ok(Self {
            identity,
            principal_codec,
            limits,
            faults,
            inner: Mutex::new(DurableInner {
                world,
                index,
                arena,
                roots,
                lock,
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
        Ok(inner.world.object_count())
    }

    /// Return one recovered immutable object.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write.
    pub fn object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, DurableError> {
        let inner = self.inner.lock();
        ensure_usable(&inner)?;
        Ok(inner.world.object(id).cloned())
    }

    /// Return the current durable root for one principal.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write.
    pub fn root(&self, principal: &P) -> Result<Option<RootState>, DurableError> {
        let inner = self.inner.lock();
        ensure_usable(&inner)?;
        Ok(inner.world.root(principal))
    }

    /// Capture one current root and its complete owning closure.
    ///
    /// # Errors
    ///
    /// Returns a recovery-required or graph-validation error.
    pub fn snapshot(&self, principal: &P) -> Result<Option<RootSnapshot>, DurableError> {
        let inner = self.inner.lock();
        ensure_usable(&inner)?;
        let Some(root) = inner.world.root(principal) else {
            return Ok(None);
        };
        let records = inner.world.export_closure(root.commit)?;
        Ok(Some(RootSnapshot { root, records }))
    }

    /// Calculate stable logical usage for one principal.
    ///
    /// # Errors
    ///
    /// Returns a recovery-required, missing-principal, graph, or arithmetic
    /// error.
    pub fn principal_usage(&self, principal: &P) -> Result<PrincipalUsage, DurableError> {
        let inner = self.inner.lock();
        ensure_usable(&inner)?;
        inner.world.principal_usage(principal).map_err(Into::into)
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
        let prepared = self.prepare(&inner, transaction)?;
        match self.persist(&mut inner, &prepared) {
            Ok(locations) => {
                inner.world = prepared.world;
                inner.index.extend(locations);
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

    /// Flush both authoritative files.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write or the
    /// underlying filesystem error.
    pub fn flush(&self) -> Result<(), DurableError> {
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        if let Err(source) = inner.arena.sync_data() {
            inner.poisoned = true;
            return Err(io_error("flush object arena", source));
        }
        if let Err(source) = inner.roots.sync_data() {
            inner.poisoned = true;
            return Err(io_error("flush root journal", source));
        }
        Ok(())
    }

    fn prepare(
        &self,
        inner: &DurableInner<P>,
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
                return Err(ModelError::ProofIdentityMismatch {
                    declared: *declared,
                    computed,
                }
                .into());
            }
        }
        let actual = inner.world.root(&principal);
        if actual != expected {
            return Err(ModelError::RootConflict { expected, actual }.into());
        }

        let mut world = inner.world.clone();
        let objects_inserted = world.import_closure(&records, commit_id)?;
        let root = world.compare_and_swap_root(principal.clone(), expected, commit_id)?;

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

        let mut objects = Vec::new();
        let mut commit_frame = None;
        for (id, record) in unique {
            if inner.index.contains_key(&id) {
                continue;
            }
            let payload = encode_object_frame(id, &record)?;
            ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
            if id == commit_id {
                commit_frame = Some((id, payload));
            } else {
                objects.push((id, payload));
            }
        }
        let principal = self.principal_codec.encode(&principal);
        let journal = encode_root_record(&principal, expected, root)?;
        ensure_payload_limit(ROOT_FILE, 0, journal.len(), self.limits)?;

        Ok(Prepared {
            world,
            root,
            objects_inserted,
            objects,
            commit: commit_frame,
            journal,
        })
    }

    fn persist(
        &self,
        inner: &mut DurableInner<P>,
        prepared: &Prepared<P>,
    ) -> Result<Vec<(ObjectId, ArenaLocation)>, DurableError> {
        let mut locations = Vec::new();
        for (id, payload) in &prepared.objects {
            let location = append_frame(&mut inner.arena, ARENA_MAGIC, payload)?;
            locations.push((*id, location));
        }
        self.fail_if(FaultPoint::AfterObjectAppend)?;
        inner
            .arena
            .sync_data()
            .map_err(|source| io_error("flush non-commit object frames", source))?;
        self.fail_if(FaultPoint::AfterObjectFlush)?;

        if let Some((id, payload)) = &prepared.commit {
            let location = append_frame(&mut inner.arena, ARENA_MAGIC, payload)?;
            locations.push((*id, location));
        }
        self.fail_if(FaultPoint::AfterCommitAppend)?;
        inner
            .arena
            .sync_data()
            .map_err(|source| io_error("flush commit object frame", source))?;
        self.fail_if(FaultPoint::AfterCommitFlush)?;
        self.fail_if(FaultPoint::BeforeRootCas)?;

        append_frame(&mut inner.roots, ROOT_MAGIC, &prepared.journal)?;
        inner
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
        let _ = fs2::FileExt::unlock(&inner.lock);
    }
}

#[derive(Debug)]
struct Prepared<P: Ord> {
    world: World<P>,
    root: RootState,
    objects_inserted: u64,
    objects: Vec<(ObjectId, Vec<u8>)>,
    commit: Option<(ObjectId, Vec<u8>)>,
    journal: Vec<u8>,
}

fn ensure_usable<P: Ord>(inner: &DurableInner<P>) -> Result<(), DurableError> {
    if inner.poisoned {
        return Err(DurableError::RequiresRecovery);
    }
    Ok(())
}

fn open_rw(path: &Path) -> Result<File, DurableError> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|source| io_error("open principal-store file", source))
}

#[cfg(unix)]
fn sync_store_directory(path: &Path) -> Result<(), DurableError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("flush principal-store directory", source))
}

#[cfg(not(unix))]
fn sync_store_directory(_path: &Path) -> Result<(), DurableError> {
    Ok(())
}

fn io_error(operation: &'static str, source: io::Error) -> DurableError {
    DurableError::Io { operation, source }
}

fn recover_arena<P: Ord, I: ObjectIdentity>(
    arena: &mut File,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(World<P>, BTreeMap<ObjectId, ArenaLocation>), DurableError> {
    let mut world = World::<P>::new();
    let mut index = BTreeMap::new();
    scan_frames(arena, ARENA_FILE, ARENA_MAGIC, limits, |offset, payload| {
        let (id, record) =
            decode_object_frame(payload).map_err(|detail| corrupt(ARENA_FILE, offset, detail))?;
        let computed = identity.identify(&record);
        if computed != id {
            return Err(corrupt(ARENA_FILE, offset, "object identity mismatch"));
        }
        if encode_object_frame(id, &record)? != payload {
            return Err(corrupt(ARENA_FILE, offset, "object frame is not canonical"));
        }
        match world
            .insert_object(id, record)
            .map_err(|source| DurableError::RecoveryModel {
                file: ARENA_FILE,
                offset,
                source,
            })? {
            InsertOutcome::Inserted => {
                index.insert(
                    id,
                    ArenaLocation {
                        _offset: offset,
                        _payload_len: u64::try_from(payload.len())
                            .map_err(|_| DurableError::EncodingOverflow)?,
                    },
                );
            },
            InsertOutcome::AlreadyPresent => {},
        }
        Ok(())
    })?;
    Ok((world, index))
}

fn recover_roots<P, C>(
    roots: &mut File,
    codec: &C,
    limits: RecoveryLimits,
    world: &mut World<P>,
) -> Result<(), DurableError>
where
    P: Clone + Ord,
    C: PrincipalCodec<P>,
{
    scan_frames(roots, ROOT_FILE, ROOT_MAGIC, limits, |offset, payload| {
        let record =
            decode_root_record(payload).map_err(|detail| corrupt(ROOT_FILE, offset, detail))?;
        let principal = codec
            .decode(record.principal)
            .ok_or(DurableError::InvalidPrincipal { offset })?;
        if codec.encode(&principal) != record.principal {
            return Err(DurableError::InvalidPrincipal { offset });
        }
        if encode_root_record(record.principal, record.expected, record.replacement)? != payload {
            return Err(corrupt(
                ROOT_FILE,
                offset,
                "root-journal frame is not canonical",
            ));
        }
        let actual = world
            .compare_and_swap_root(principal, record.expected, record.replacement.commit)
            .map_err(|source| DurableError::RecoveryModel {
                file: ROOT_FILE,
                offset,
                source,
            })?;
        if actual != record.replacement {
            return Err(corrupt(
                ROOT_FILE,
                offset,
                "replacement generation does not match journal history",
            ));
        }
        Ok(())
    })
}

fn scan_frames(
    file: &mut File,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    mut accept: impl FnMut(u64, &[u8]) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    let file_len = file
        .metadata()
        .map_err(|source| io_error("read principal-store metadata", source))?
        .len();
    let mut offset = 0_u64;
    while offset < file_len {
        let remaining = file_len
            .checked_sub(offset)
            .ok_or(DurableError::EncodingOverflow)?;
        if remaining < FRAME_HEADER_LEN {
            truncate_tail(file, offset)?;
            break;
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|source| io_error("seek durable frame", source))?;
        let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
        file.read_exact(&mut header)
            .map_err(|source| io_error("read durable frame header", source))?;
        if header[..8] != magic {
            return Err(corrupt(file_name, offset, "frame magic mismatch"));
        }
        let version = u16::from_le_bytes([header[8], header[9]]);
        if version != FRAME_VERSION {
            return Err(corrupt(file_name, offset, "unsupported frame version"));
        }
        if header[10..12] != [0, 0] {
            return Err(corrupt(
                file_name,
                offset,
                "reserved header bytes are non-zero",
            ));
        }
        let payload_len = u64::from_le_bytes(
            header[12..20]
                .try_into()
                .map_err(|_| DurableError::EncodingOverflow)?,
        );
        if payload_len > limits.max_frame_bytes {
            return Err(DurableError::FrameTooLarge {
                file: file_name,
                offset,
                declared: payload_len,
                limit: limits.max_frame_bytes,
            });
        }
        let frame_len = FRAME_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(DurableError::EncodingOverflow)?;
        let frame_end = offset
            .checked_add(frame_len)
            .ok_or(DurableError::EncodingOverflow)?;
        if frame_end > file_len {
            truncate_tail(file, offset)?;
            break;
        }
        let payload_usize =
            usize::try_from(payload_len).map_err(|_| DurableError::EncodingOverflow)?;
        let mut payload = vec![0_u8; payload_usize];
        file.read_exact(&mut payload)
            .map_err(|source| io_error("read durable frame payload", source))?;
        let checksum: [u8; 32] = header[CHECKSUM_START..]
            .try_into()
            .map_err(|_| DurableError::EncodingOverflow)?;
        if frame_checksum(magic, payload_len, &payload) != checksum {
            return Err(corrupt(file_name, offset, "frame checksum mismatch"));
        }
        accept(offset, &payload)?;
        offset = frame_end;
    }
    file.seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek durable file tail", source))?;
    Ok(())
}

fn truncate_tail(file: &mut File, valid_len: u64) -> Result<(), DurableError> {
    file.set_len(valid_len)
        .map_err(|source| io_error("truncate incomplete durable tail", source))?;
    file.sync_data()
        .map_err(|source| io_error("flush durable tail truncation", source))
}

fn append_frame(
    file: &mut File,
    magic: [u8; 8],
    payload: &[u8],
) -> Result<ArenaLocation, DurableError> {
    let payload_len = u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
    let offset = file
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek durable append", source))?;
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    header[..8].copy_from_slice(&magic);
    header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&payload_len.to_le_bytes());
    header[CHECKSUM_START..].copy_from_slice(&frame_checksum(magic, payload_len, payload));
    file.write_all(&header)
        .map_err(|source| io_error("append durable frame header", source))?;
    file.write_all(payload)
        .map_err(|source| io_error("append durable frame payload", source))?;
    Ok(ArenaLocation {
        _offset: offset,
        _payload_len: payload_len,
    })
}

fn frame_checksum(magic: [u8; 8], payload_len: u64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("astrid durable physical frame checksum v1");
    hasher.update(&magic);
    hasher.update(&FRAME_VERSION.to_le_bytes());
    hasher.update(&payload_len.to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn corrupt(file: &'static str, offset: u64, detail: &'static str) -> DurableError {
    DurableError::Corrupt {
        file,
        offset,
        detail,
    }
}

fn ensure_payload_limit(
    file: &'static str,
    offset: u64,
    payload_len: usize,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let declared = u64::try_from(payload_len).map_err(|_| DurableError::EncodingOverflow)?;
    if declared > limits.max_frame_bytes {
        return Err(DurableError::FrameTooLarge {
            file,
            offset,
            declared,
            limit: limits.max_frame_bytes,
        });
    }
    Ok(())
}

fn encode_object_frame(id: ObjectId, record: &ObjectRecord) -> Result<Vec<u8>, DurableError> {
    let canonical_len = u64::try_from(record.canonical_bytes().len())
        .map_err(|_| DurableError::EncodingOverflow)?;
    let reference_count =
        u64::try_from(record.references().len()).map_err(|_| DurableError::EncodingOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(id.as_bytes());
    bytes.extend_from_slice(&record.kind().code().to_le_bytes());
    bytes.extend_from_slice(&record.format_version().get().to_le_bytes());
    bytes.push(record.class().code());
    bytes.extend_from_slice(&record.logical_bytes().to_le_bytes());
    bytes.extend_from_slice(&canonical_len.to_le_bytes());
    bytes.extend_from_slice(&reference_count.to_le_bytes());
    bytes.extend_from_slice(record.canonical_bytes());
    for reference in record.references() {
        let label_len =
            u64::try_from(reference.label().len()).map_err(|_| DurableError::EncodingOverflow)?;
        bytes.extend_from_slice(&label_len.to_le_bytes());
        bytes.extend_from_slice(reference.label());
        bytes.extend_from_slice(reference.target().as_bytes());
        bytes.push(reference.kind().code());
    }
    Ok(bytes)
}

fn decode_object_frame(bytes: &[u8]) -> Result<(ObjectId, ObjectRecord), &'static str> {
    let mut reader = SliceReader::new(bytes);
    let id = ObjectId::new(reader.array_32()?);
    let kind = ObjectKind::from_code(reader.u16()?).ok_or("unknown object-kind code")?;
    let version = ObjectFormatVersion::new(reader.u16()?);
    let class = ObjectClass::from_code(reader.u8()?).ok_or("unknown object-class code")?;
    let logical_bytes = reader.u64()?;
    let canonical_len = reader.usize_len()?;
    let reference_count = reader.usize_len()?;
    let canonical_bytes = reader.take(canonical_len)?.to_vec();
    if reference_count > reader.remaining() / 41 {
        return Err("reference count exceeds frame capacity");
    }
    let mut references = Vec::new();
    references
        .try_reserve(reference_count)
        .map_err(|_| "reference allocation failed")?;
    for _ in 0..reference_count {
        let label_len = reader.usize_len()?;
        let label = reader.take(label_len)?.to_vec();
        let target = ObjectId::new(reader.array_32()?);
        let reference_kind =
            ReferenceKind::from_code(reader.u8()?).ok_or("unknown reference-kind code")?;
        references.push(ObjectReference::new(label, target, reference_kind));
    }
    if reader.remaining() != 0 {
        return Err("trailing object-frame bytes");
    }
    let record = ObjectRecord::new(
        kind,
        version,
        canonical_bytes,
        references,
        logical_bytes,
        class,
    )
    .map_err(|_| "non-canonical object references")?;
    Ok((id, record))
}

fn encode_root_record(
    principal: &[u8],
    expected: Option<RootState>,
    replacement: RootState,
) -> Result<Vec<u8>, DurableError> {
    let principal_len =
        u64::try_from(principal.len()).map_err(|_| DurableError::EncodingOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&principal_len.to_le_bytes());
    bytes.extend_from_slice(principal);
    match expected {
        None => bytes.push(0),
        Some(root) => {
            bytes.push(1);
            encode_root_state(&mut bytes, root);
        },
    }
    encode_root_state(&mut bytes, replacement);
    Ok(bytes)
}

fn encode_root_state(bytes: &mut Vec<u8>, root: RootState) {
    bytes.extend_from_slice(&root.generation.to_le_bytes());
    bytes.extend_from_slice(root.commit.as_bytes());
}

struct DecodedRootRecord<'a> {
    principal: &'a [u8],
    expected: Option<RootState>,
    replacement: RootState,
}

fn decode_root_record(bytes: &[u8]) -> Result<DecodedRootRecord<'_>, &'static str> {
    let mut reader = SliceReader::new(bytes);
    let principal_len = reader.usize_len()?;
    let principal = reader.take(principal_len)?;
    let expected = match reader.u8()? {
        0 => None,
        1 => Some(reader.root_state()?),
        _ => return Err("invalid expected-root tag"),
    };
    let replacement = reader.root_state()?;
    if reader.remaining() != 0 {
        return Err("trailing root-journal bytes");
    }
    Ok(DecodedRootRecord {
        principal,
        expected,
        replacement,
    })
}

struct SliceReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or("frame length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated frame payload")?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        self.take(1)?.first().copied().ok_or("truncated u8 field")
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| "truncated u16 field")?,
        ))
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| "truncated u64 field")?,
        ))
    }

    fn usize_len(&mut self) -> Result<usize, &'static str> {
        usize::try_from(self.u64()?).map_err(|_| "length is not process-addressable")
    }

    fn array_32(&mut self) -> Result<[u8; 32], &'static str> {
        self.take(32)?
            .try_into()
            .map_err(|_| "truncated 32-byte field")
    }

    fn root_state(&mut self) -> Result<RootState, &'static str> {
        Ok(RootState {
            generation: self.u64()?,
            commit: ObjectId::new(self.array_32()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    #[derive(Clone, Copy, Debug)]
    struct TestIdentity;

    impl ObjectIdentity for TestIdentity {
        fn identify(&self, record: &ObjectRecord) -> ObjectId {
            let mut hasher =
                blake3::Hasher::new_derive_key("astrid durable engine test identity v1");
            hasher.update(&record.kind().code().to_le_bytes());
            hasher.update(&record.format_version().get().to_le_bytes());
            hasher.update(&(record.canonical_bytes().len() as u128).to_le_bytes());
            hasher.update(record.canonical_bytes());
            hasher.update(&record.logical_bytes().to_le_bytes());
            hasher.update(&[record.class().code()]);
            hasher.update(&(record.references().len() as u128).to_le_bytes());
            for reference in record.references() {
                hasher.update(&(reference.label().len() as u128).to_le_bytes());
                hasher.update(reference.label());
                hasher.update(reference.target().as_bytes());
                hasher.update(&[reference.kind().code()]);
            }
            ObjectId::new(*hasher.finalize().as_bytes())
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct ConstantIdentity;

    impl ObjectIdentity for ConstantIdentity {
        fn identify(&self, _record: &ObjectRecord) -> ObjectId {
            ObjectId::new([42; 32])
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct Utf8Codec;

    impl PrincipalCodec<String> for Utf8Codec {
        fn encode(&self, principal: &String) -> Vec<u8> {
            principal.as_bytes().to_vec()
        }

        fn decode(&self, bytes: &[u8]) -> Option<String> {
            std::str::from_utf8(bytes).ok().map(str::to_owned)
        }
    }

    #[derive(Debug)]
    struct FailAt(FaultPoint);

    impl FaultInjector for FailAt {
        fn should_fail(&self, point: FaultPoint) -> bool {
            point == self.0
        }
    }

    type TestEngine = DurableEngine<String, TestIdentity, Utf8Codec>;

    fn limits() -> RecoveryLimits {
        RecoveryLimits::new(1024 * 1024).unwrap()
    }

    fn open(path: &Path) -> TestEngine {
        DurableEngine::open(path, TestIdentity, Utf8Codec, limits()).unwrap()
    }

    fn open_with_fault(path: &Path, point: FaultPoint) -> TestEngine {
        DurableEngine::open_with_faults(
            path,
            TestIdentity,
            Utf8Codec,
            limits(),
            Arc::new(FailAt(point)),
        )
        .unwrap()
    }

    fn transaction(
        principal: &str,
        expected: Option<RootState>,
        payload: &[u8],
    ) -> (ObjectId, RootTransaction<String>) {
        let identity = TestIdentity;
        let leaf = ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::new(1),
            payload.to_vec(),
            Vec::new(),
            u64::try_from(payload.len()).unwrap(),
            ObjectClass::Data,
        )
        .unwrap();
        let leaf_id = identity.identify(&leaf);
        let commit = ObjectRecord::new(
            ObjectKind::Commit,
            ObjectFormatVersion::new(1),
            payload.to_vec(),
            vec![ObjectReference::owns(b"state".to_vec(), leaf_id)],
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let commit_id = identity.identify(&commit);
        (
            commit_id,
            RootTransaction::new(
                principal.to_owned(),
                expected,
                commit_id,
                vec![(leaf_id, leaf), (commit_id, commit)],
            ),
        )
    }

    fn append_partial_header(path: &Path, magic: [u8; 8]) {
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(&magic[..5]).unwrap();
        file.sync_data().unwrap();
    }

    fn append_torn_payload(path: &Path, magic: [u8; 8]) {
        let payload = b"incomplete";
        let payload_len = u64::try_from(payload.len()).unwrap();
        let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
        header[..8].copy_from_slice(&magic);
        header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
        header[12..20].copy_from_slice(&payload_len.to_le_bytes());
        header[CHECKSUM_START..].copy_from_slice(&frame_checksum(magic, payload_len, payload));
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(&header).unwrap();
        file.write_all(&payload[..3]).unwrap();
        file.sync_data().unwrap();
    }

    #[test]
    fn object_frame_round_trips_binary_typed_records() {
        let target = ObjectId::new([9; 32]);
        let record = ObjectRecord::new(
            ObjectKind::PrincipalState,
            ObjectFormatVersion::new(7),
            vec![0, 255, 19],
            vec![
                ObjectReference::new(vec![0, 1], target, ReferenceKind::Evidence),
                ObjectReference::new(vec![255], ObjectId::new([10; 32]), ReferenceKind::Lineage),
            ],
            83,
            ObjectClass::Metadata,
        )
        .unwrap();
        let id = TestIdentity.identify(&record);

        let encoded = encode_object_frame(id, &record).unwrap();
        let decoded = decode_object_frame(&encoded).unwrap();

        assert_eq!(decoded, (id, record));
    }

    #[test]
    fn commit_flush_reopen_rebuilds_index_and_root() {
        let directory = tempfile::tempdir().unwrap();
        let engine = open(directory.path());
        let (commit, transaction) = transaction("alice", None, b"durable");

        let outcome = engine.commit(transaction).unwrap();
        assert_eq!(outcome.objects_inserted(), 2);
        assert_eq!(outcome.root().commit, commit);
        engine.flush().unwrap();
        drop(engine);

        let reopened = open(directory.path());
        assert_eq!(
            reopened.root(&"alice".to_owned()).unwrap(),
            Some(outcome.root())
        );
        assert_eq!(reopened.object_count().unwrap(), 2);
        assert_eq!(
            reopened
                .snapshot(&"alice".to_owned())
                .unwrap()
                .unwrap()
                .records()
                .len(),
            2
        );
    }

    #[test]
    fn every_exposed_fault_recovers_old_or_new_complete_root() {
        for point in [
            FaultPoint::AfterObjectAppend,
            FaultPoint::AfterObjectFlush,
            FaultPoint::AfterCommitAppend,
            FaultPoint::AfterCommitFlush,
            FaultPoint::BeforeRootCas,
            FaultPoint::AfterRootCas,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let initial = open(directory.path());
            let (_, first) = transaction("alice", None, b"before");
            let old = initial.commit(first).unwrap().root();
            drop(initial);

            let interrupted = open_with_fault(directory.path(), point);
            let (new_commit, update) = transaction("alice", Some(old), b"after");
            assert!(matches!(
                interrupted.commit(update),
                Err(DurableError::FaultInjected(actual)) if actual == point
            ));
            assert!(matches!(
                interrupted.snapshot(&"alice".to_owned()),
                Err(DurableError::RequiresRecovery)
            ));
            assert!(matches!(
                interrupted.root(&"alice".to_owned()),
                Err(DurableError::RequiresRecovery)
            ));
            assert!(matches!(
                interrupted.object_count(),
                Err(DurableError::RequiresRecovery)
            ));
            drop(interrupted);

            let recovered = open(directory.path());
            let visible = recovered.root(&"alice".to_owned()).unwrap().unwrap();
            if point == FaultPoint::AfterRootCas {
                assert_eq!(
                    visible,
                    RootState {
                        generation: 1,
                        commit: new_commit,
                    },
                    "point {point:?}"
                );
            } else {
                assert_eq!(visible, old, "point {point:?}");
            }
            assert!(recovered.snapshot(&"alice".to_owned()).unwrap().is_some());
        }
    }

    #[test]
    fn truncated_arena_tail_is_removed_without_changing_root() {
        let directory = tempfile::tempdir().unwrap();
        let engine = open(directory.path());
        let (_, transaction) = transaction("alice", None, b"state");
        let root = engine.commit(transaction).unwrap().root();
        drop(engine);
        let arena = directory.path().join(ARENA_FILE);
        let valid_len = std::fs::metadata(&arena).unwrap().len();
        append_partial_header(&arena, ARENA_MAGIC);

        let recovered = open(directory.path());

        assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
        assert_eq!(std::fs::metadata(arena).unwrap().len(), valid_len);
    }

    #[test]
    fn truncated_root_payload_is_removed_without_changing_root() {
        let directory = tempfile::tempdir().unwrap();
        let engine = open(directory.path());
        let (_, transaction) = transaction("alice", None, b"state");
        let root = engine.commit(transaction).unwrap().root();
        drop(engine);
        let journal = directory.path().join(ROOT_FILE);
        let valid_len = std::fs::metadata(&journal).unwrap().len();
        append_torn_payload(&journal, ROOT_MAGIC);

        let recovered = open(directory.path());

        assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
        assert_eq!(std::fs::metadata(journal).unwrap().len(), valid_len);
    }

    #[test]
    fn checksum_corruption_is_fatal_not_silently_truncated() {
        let directory = tempfile::tempdir().unwrap();
        let engine = open(directory.path());
        let (_, transaction) = transaction("alice", None, b"state");
        engine.commit(transaction).unwrap();
        drop(engine);
        let arena = directory.path().join(ARENA_FILE);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(arena)
            .unwrap();
        file.seek(SeekFrom::Start(FRAME_HEADER_LEN + 33)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Start(FRAME_HEADER_LEN + 33)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_data().unwrap();
        drop(file);

        assert!(matches!(
            DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
            Err(DurableError::Corrupt {
                file: ARENA_FILE,
                detail: "frame checksum mismatch",
                ..
            })
        ));
    }

    #[test]
    fn recovery_reports_root_journal_model_failure_with_offset() {
        let directory = tempfile::tempdir().unwrap();
        drop(open(directory.path()));
        let journal = directory.path().join(ROOT_FILE);
        let payload = encode_root_record(
            b"alice",
            None,
            RootState {
                generation: 0,
                commit: ObjectId::new([99; 32]),
            },
        )
        .unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal)
            .unwrap();
        append_frame(&mut file, ROOT_MAGIC, &payload).unwrap();
        file.sync_data().unwrap();
        drop(file);

        assert!(matches!(
            DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
            Err(DurableError::RecoveryModel {
                file: ROOT_FILE,
                offset: 0,
                source: ModelError::MissingObject(_),
            })
        ));
    }

    #[test]
    fn recovery_never_accepts_an_identity_collision() {
        let directory = tempfile::tempdir().unwrap();
        drop(open(directory.path()));
        let first = ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::new(1),
            b"first".to_vec(),
            Vec::new(),
            5,
            ObjectClass::Data,
        )
        .unwrap();
        let second = ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::new(1),
            b"second".to_vec(),
            Vec::new(),
            6,
            ObjectClass::Data,
        )
        .unwrap();
        let id = ObjectId::new([42; 32]);
        let arena = directory.path().join(ARENA_FILE);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(arena)
            .unwrap();
        append_frame(
            &mut file,
            ARENA_MAGIC,
            &encode_object_frame(id, &first).unwrap(),
        )
        .unwrap();
        append_frame(
            &mut file,
            ARENA_MAGIC,
            &encode_object_frame(id, &second).unwrap(),
        )
        .unwrap();
        file.sync_data().unwrap();
        drop(file);

        assert!(matches!(
            DurableEngine::open(
                directory.path(),
                ConstantIdentity,
                Utf8Codec,
                limits()
            ),
            Err(DurableError::RecoveryModel {
                file: ARENA_FILE,
                source: ModelError::ObjectCollision(object),
                ..
            }) if object == id
        ));
    }

    #[test]
    fn recovery_rejects_oversized_declaration_before_allocating_payload() {
        let directory = tempfile::tempdir().unwrap();
        drop(open(directory.path()));
        let arena = directory.path().join(ARENA_FILE);
        let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
        header[..8].copy_from_slice(&ARENA_MAGIC);
        header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
        header[12..20].copy_from_slice(&1024_u64.to_le_bytes());
        let mut file = OpenOptions::new().append(true).open(arena).unwrap();
        file.write_all(&header).unwrap();
        file.sync_data().unwrap();
        drop(file);
        let tiny = RecoveryLimits::new(64).unwrap();

        assert!(matches!(
            DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, tiny),
            Err(DurableError::FrameTooLarge {
                file: ARENA_FILE,
                offset: 0,
                declared: 1024,
                limit: 64,
            })
        ));
    }

    #[test]
    fn stale_root_conflict_appends_no_bytes_and_does_not_poison() {
        let directory = tempfile::tempdir().unwrap();
        let engine = open(directory.path());
        let (_, first) = transaction("alice", None, b"first");
        let installed = engine.commit(first).unwrap().root();
        let arena = directory.path().join(ARENA_FILE);
        let journal = directory.path().join(ROOT_FILE);
        let before = (
            std::fs::metadata(&arena).unwrap().len(),
            std::fs::metadata(&journal).unwrap().len(),
        );
        let (_, stale) = transaction("alice", None, b"stale");

        assert!(matches!(
            engine.commit(stale),
            Err(DurableError::Model(ModelError::RootConflict { .. }))
        ));
        assert_eq!(
            before,
            (
                std::fs::metadata(arena).unwrap().len(),
                std::fs::metadata(journal).unwrap().len(),
            )
        );
        assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(installed));
        assert!(engine.snapshot(&"alice".to_owned()).unwrap().is_some());
    }

    #[test]
    fn concurrent_genesis_has_one_durable_winner() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(open(directory.path()));
        let barrier = Arc::new(Barrier::new(9));
        let mut handles = Vec::new();
        for value in 0_u8..8 {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let (_, transaction) = transaction("alice", None, &[value]);
                barrier.wait();
                engine.commit(transaction)
            }));
        }
        barrier.wait();

        let mut successes = 0;
        for handle in handles {
            match handle.join().unwrap() {
                Ok(_) => successes += 1,
                Err(DurableError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => panic!("unexpected commit error: {error}"),
            }
        }
        assert_eq!(successes, 1);
        let root = engine.root(&"alice".to_owned()).unwrap().unwrap();
        drop(engine);

        let recovered = open(directory.path());
        assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    }

    #[test]
    fn second_writer_cannot_open_the_same_store() {
        let directory = tempfile::tempdir().unwrap();
        let first = open(directory.path());

        assert!(matches!(
            DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
            Err(DurableError::LockHeld(_))
        ));

        drop(first);
        assert!(DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()).is_ok());
    }

    #[test]
    fn configured_frame_boundary_rejects_before_writing() {
        let directory = tempfile::tempdir().unwrap();
        let tiny = RecoveryLimits::new(64).unwrap();
        let engine = DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, tiny).unwrap();
        let (_, transaction) = transaction("alice", None, b"too large");

        assert!(matches!(
            engine.commit(transaction),
            Err(DurableError::FrameTooLarge {
                file: ARENA_FILE,
                limit: 64,
                ..
            })
        ));
        assert_eq!(engine.object_count().unwrap(), 0);
        assert!(engine.snapshot(&"alice".to_owned()).unwrap().is_none());
        assert_eq!(
            std::fs::metadata(directory.path().join(ARENA_FILE))
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            std::fs::metadata(directory.path().join(ROOT_FILE))
                .unwrap()
                .len(),
            0
        );
    }
}
