//! Recovery and canonical-file replay for the transaction WAL.
//!
//! The scanner deliberately keeps the physical stream bounded one record at a
//! time.  Replay retains only the descriptors and decoded objects of one
//! committed transaction, validates that transaction against the current
//! owner roots, and publishes the canonical arena/root files before the WAL is
//! truncated.

use super::super::File;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufWriter, Read, Seek, SeekFrom};

use crate::storage_model::{ModelError, ObjectId, ObjectRecord, RootState};

use super::codec::{
    PHYSICAL_HEADER_LEN, checksum_valid, decode_object_body, decode_object_storage_body,
    decode_physical_header, decode_record, validate_logical_body, validate_record_version,
    wal_physical_limit,
};
use super::root_history::{self, Decision};
use super::scan::WalScanner;
use super::transaction::{self, Batch, Event, Origin, Step};
use super::types::{WalEvent, WalObjectDescriptor, WalRootDescriptor};
use super::{WalLimits, durable_error};
use crate::engine::durable::format::{append_frames, canonical_record_bytes, encode_object_frame};
use crate::engine::durable::representations::RepresentationStore;
use crate::engine::durable::root_transition::{self, Replay};
use crate::engine::durable::validation::{ClosureObjects, validate_incremental_closure};
use crate::engine::durable::{
    ARENA_MAGIC, ArenaLocation, DurableError, PersistentObjectIdentity, PrincipalCodec, ROOT_MAGIC,
    RecoveryLimits, SharedIdentity, SharedPrincipalCodec,
};

type PendingTransaction = Batch<WalObjectDescriptor, WalRootDescriptor>;

/// Both canonical replay and the protected-arena repair probe consume only
/// complete transactions. Uncommitted descriptors stay private to this call.
pub(super) fn next_transaction<P, I, C, R: Read + Seek>(
    scanner: &mut WalScanner<R, I, C, P>,
) -> Result<Option<PendingTransaction>, DurableError>
where
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut pending = None;
    loop {
        let event = match scanner.next_event().map_err(durable_error)? {
            Some(WalEvent::Begin(begin)) => Event::Begin(Origin {
                sequence: begin.sequence.get(),
                offset: begin.offset.get(),
            }),
            Some(WalEvent::Object(object)) => Event::Object(object),
            Some(WalEvent::Root(root)) => Event::Root(root),
            Some(WalEvent::Commit(tx)) => Event::Commit {
                offset: tx.begin_offset.get(),
                marker: tx.marker,
            },
            Some(WalEvent::Tail(_)) => Event::Tail,
            None => Event::Eof,
        };
        match transaction::advance(pending, event).map_err(|error| {
            corrupt_wal(match error {
                transaction::Error::Nested => "nested WAL transaction",
                transaction::Error::ObjectBeforeBegin => "WAL object appeared before Begin",
                transaction::Error::RootBeforeBegin => "WAL root appeared before Begin",
                transaction::Error::CommitBeforeBegin => "WAL Commit appeared before Begin",
                transaction::Error::Mismatch => "WAL commit does not match pending transaction",
                transaction::Error::Unfinished => "WAL scanner ended with an active transaction",
            })
        })? {
            Step::Pending(batch) => pending = Some(batch),
            Step::Committed(batch) => return Ok(Some(batch)),
            Step::End => return Ok(None),
        }
    }
}

/// Return object identities from complete WAL transactions whose object
/// payloads are canonical. Root-CAS conflicts do not invalidate this
/// content-addressed repair evidence: replay appends the objects before it
/// reports the stale root transition, and the WAL remains available.
///
/// Object descriptors are accumulated only when their enclosing Commit event
/// is observed. A torn or uncommitted WAL tail therefore contributes no repair
/// evidence to the caller's protected-arena decision.
#[allow(clippy::needless_pass_by_value)]
#[allow(dead_code)]
pub(crate) fn wal_repair_object_ids<P, I, C>(
    wal: &File,
    identity: SharedIdentity<I>,
    codec: SharedPrincipalCodec<C>,
    root_history: &BTreeMap<P, (RootState, u64)>,
    limits: RecoveryLimits,
) -> Result<BTreeSet<ObjectId>, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let reader = wal
        .try_clone()
        .map_err(|source| io_error("clone ASTWAL2 probe reader", source))?;
    let mut scanner =
        WalScanner::new(reader, identity.clone(), codec.clone(), limits).map_err(durable_error)?;
    let mut payload_reader = scanner
        .reader()
        .try_clone()
        .map_err(|source| io_error("clone ASTWAL2 probe payload reader", source))?;
    let mut committed = BTreeSet::new();
    let mut roots = root_history.clone();
    while let Some(transaction) = next_transaction(&mut scanner)? {
        let mut object_ids = BTreeSet::new();
        for descriptor in transaction.objects() {
            let (id, _record, _payload) =
                read_object_record(&mut payload_reader, *descriptor, &identity, limits)?;
            if id != descriptor.id() {
                return Err(corrupt_wal("WAL object descriptor identity mismatch"));
            }
            object_ids.insert(id);
        }
        scanner.restore_cursor().map_err(durable_error)?;
        let mut next_roots = roots.clone();
        let mut root_conflict = false;
        for descriptor in transaction.roots() {
            let transition = descriptor.transition();
            let principal = codec
                .decode(transition.principal())
                .ok_or(DurableError::InvalidPrincipal { offset: 0 })?;
            if codec.encode(&principal) != transition.principal() {
                return Err(DurableError::InvalidPrincipal { offset: 0 });
            }
            let actual = root_history::lookup(&roots, &principal);
            if actual != transition.expected() && actual != Some(transition.replacement()) {
                // Object bytes remain safe repair evidence even when
                // this transaction's root CAS is stale. Replay folds
                // them before reporting the conflict, while the WAL
                // stays available because checkpointing is deferred.
                root_conflict = true;
                break;
            }
            if actual != Some(transition.replacement()) {
                next_roots.insert(principal, (transition.replacement(), 0));
            }
        }
        committed.extend(object_ids);
        if !root_conflict {
            roots = next_roots;
        }
    }
    Ok(committed)
}

/// Replay an existing ASTWAL2 stream and return a writer resumed at its clean
/// append boundary.
///
/// The WAL file is consumed by the scanner and then reused by the returned
/// writer.  `identity` and `codec` are cloned only for scanner validation;
/// production callers pass the engine's `Arc`-owned implementations.
#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_wal<P, I, C>(
    wal: File,
    arena: &mut File,
    roots: &mut File,
    index: &mut BTreeMap<ObjectId, ArenaLocation>,
    validated: &mut BTreeSet<ObjectId>,
    mut root_history: BTreeMap<P, (RootState, u64)>,
    representations: Option<&mut RepresentationStore>,
    identity: SharedIdentity<I>,
    codec: SharedPrincipalCodec<C>,
    limits: RecoveryLimits,
) -> Result<super::super::DurableWal<P, I, C>, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let replay_identity = identity.clone();
    let replay_codec = codec.clone();
    let mut scanner = WalScanner::new(wal, identity, codec, limits).map_err(durable_error)?;
    let mut payload_reader = scanner
        .reader()
        .try_clone()
        .map_err(|source| io_error("clone ASTWAL2 replay reader", source))?;
    let mut representations = representations;
    while let Some(transaction) = next_transaction(&mut scanner)? {
        replay_transaction(
            transaction,
            &mut payload_reader,
            arena,
            roots,
            index,
            validated,
            &mut root_history,
            representations.as_deref_mut(),
            &replay_identity,
            &replay_codec,
            limits,
        )?;
        scanner.restore_cursor().map_err(durable_error)?;
    }

    // Resume at the committed boundary after the canonical file flushes below.
    // The writer discards any uncommitted tail and retains the committed prefix.
    let resume = scanner
        .into_scanned()
        .map_err(durable_error)?
        .map_reader(|file| BufWriter::with_capacity(super::super::WAL_WRITE_BUFFER_BYTES, file));

    // Preserve the committed WAL prefix while the canonical files are flushed.
    // A buffered volume WAL syncs the container before it trims an incomplete tail.
    let prepared = super::super::recovery::prepare_recovered_files(
        arena,
        roots,
        representations,
        None,
        resume,
    )?;

    // The caller still has to validate the repaired representation and root
    // closures. It checkpoints this resumed writer only after every such
    // authority check succeeds, so a failed recovery keeps the WAL evidence
    // available for the next attempt.
    prepared.finish(|resume| resume.into_writer(limits).map_err(durable_error))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn replay_transaction<P, I, C>(
    transaction: PendingTransaction,
    wal: &mut File,
    arena: &mut File,
    roots_file: &mut File,
    index: &mut BTreeMap<ObjectId, ArenaLocation>,
    validated: &mut BTreeSet<ObjectId>,
    root_history: &mut BTreeMap<P, (RootState, u64)>,
    mut representations: Option<&mut RepresentationStore>,
    identity: &I,
    codec: &C,
    limits: RecoveryLimits,
) -> Result<(), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut incoming = BTreeMap::<ObjectId, ObjectRecord>::new();
    let mut payloads = BTreeMap::<ObjectId, Vec<u8>>::new();
    for descriptor in transaction.objects {
        let (id, record, payload) = read_object_record(wal, descriptor, identity, limits)?;
        if id != descriptor.id() {
            return Err(corrupt_wal("WAL object descriptor identity mismatch"));
        }
        if incoming.insert(id, record.clone()).is_some() {
            return Err(ModelError::ObjectCollision(id).into());
        }
        payloads.insert(id, payload);
    }

    // Existing objects are immutable.  A replayed descriptor is accepted
    // only when its canonical bytes exactly match the arena copy already
    // indexed under that identity.
    for (id, record) in &incoming {
        if let Some(location) = index.get(id).copied() {
            let existing = crate::engine::durable::format::read_indexed_object(
                arena, *id, location, identity, limits,
            )?;
            if existing != *record {
                return Err(ModelError::ObjectCollision(*id).into());
            }
        }
    }

    // Fold every missing immutable object before validating root CAS/closure.
    // The WAL is the recovery authority: if a later root check fails, these
    // bytes must still be present so a protected arena suffix cannot be lost
    // while the WAL remains available for a subsequent retry.
    let mut new_objects = Vec::new();
    for (id, payload) in payloads {
        if index.contains_key(&id) {
            continue;
        }
        new_objects.push((id, payload));
    }
    let object_payloads = new_objects
        .iter()
        .map(|(_, payload)| payload.as_slice())
        .collect::<Vec<_>>();
    let locations = append_frames(arena, ARENA_MAGIC, &object_payloads)?;
    // Even an idempotent object fold may publish a missing direct
    // representation for an already-indexed frame. Make the entire arena
    // source durable before any representation StateCas/flush is published.
    arena
        .sync_data()
        .map_err(|source| io_error("flush WAL-replayed object arena", source))?;
    for ((id, _payload), location) in new_objects.into_iter().zip(locations) {
        index.insert(id, location);
    }

    let mut roots_to_publish = Vec::new();
    let mut known = validated.clone();
    for descriptor in &transaction.roots {
        let transition = descriptor.transition();
        let bound = root_history::BoundJournal::bind(
            transition.principal(),
            transition.expected(),
            transition.replacement(),
            descriptor.offset().get(),
            |bytes| codec.decode(bytes),
            |principal| codec.encode(principal),
        )
        .ok_or(DurableError::InvalidPrincipal {
            offset: descriptor.offset().get(),
        })?;
        let actual = root_history::lookup(root_history, bound.owner());
        let replacement = transition.replacement();
        if matches!(
            root_transition::replay(
                actual.map(Into::into),
                transition.expected().map(Into::into),
                replacement.into()
            ),
            Replay::Conflict
        ) {
            return Err(ModelError::RootConflict {
                expected: transition.expected(),
                actual,
            }
            .into());
        }

        // Validate the complete owning closure before any canonical root
        // frame is appended.  WAL objects are supplied as an incoming map, so
        // a transaction can reference objects that are not in the arena yet.
        let reachable = validate_incremental_closure(
            &mut ClosureObjects::<I, P> {
                arena,
                index,
                incoming: &incoming,
                pending: None,
                identity,
                limits,
            },
            &known,
            replacement.commit,
        )?;
        known.extend(reachable);
        roots_to_publish.push(bound);
    }

    let mut direct = Vec::new();
    if let Some(representations) = representations.as_deref_mut() {
        for (id, record) in &incoming {
            if representations.contains_direct(*id) {
                continue;
            }
            let Some(location) = index.get(id).copied() else {
                return Err(ModelError::MissingObject(*id).into());
            };
            let payload = encode_object_frame(identity.scheme(), *id, record)?;
            direct.push(representations.describe_direct(
                *id,
                canonical_record_bytes(&payload, identity.scheme())?,
                location,
            )?);
        }
    }

    if let Some(representations) = representations.as_mut()
        && let Some(update) = representations.append_direct_update(&direct)?
    {
        // The WAL publication is already stable at this point.  This update
        // may issue its own metadata/journal sync; canonical arena/root files
        // are still flushed by the caller before WAL truncation.
        representations.publish_direct_update(update)?;
    }

    let mut journals = Vec::new();
    for bound in roots_to_publish {
        let expected = bound.expected();
        match bound
            .fold(root_history, identity.scheme().into())
            .ok_or(DurableError::EncodingOverflow)?
        {
            Decision::AlreadyPublished => {},
            Decision::Conflict(actual) => {
                return Err(ModelError::RootConflict { expected, actual }.into());
            },
            Decision::Applied(journal) => journals.push(journal),
        }
    }
    if !journals.is_empty() {
        append_frames(roots_file, ROOT_MAGIC, &journals)?;
    }
    validated.extend(known);
    Ok(())
}

fn read_object_record<I: PersistentObjectIdentity>(
    wal: &mut File,
    descriptor: WalObjectDescriptor,
    identity: &I,
    limits: WalLimits,
) -> Result<(ObjectId, ObjectRecord, Vec<u8>), DurableError> {
    wal.seek(SeekFrom::Start(descriptor.offset().get()))
        .map_err(|source| io_error("seek ASTWAL2 object replay", source))?;
    let mut header = [0_u8; PHYSICAL_HEADER_LEN];
    wal.read_exact(&mut header)
        .map_err(|source| io_error("read ASTWAL2 object replay header", source))?;
    let physical = decode_physical_header(&header, descriptor.offset()).map_err(durable_error)?;
    let expected_length = u64::try_from(PHYSICAL_HEADER_LEN)
        .ok()
        .and_then(|header| header.checked_add(physical.payload_len().get()))
        .ok_or(DurableError::EncodingOverflow)?;
    if expected_length != descriptor.length().get()
        || physical.payload_len() > wal_physical_limit(limits).length()
    {
        return Err(corrupt_wal("WAL object descriptor length mismatch"));
    }
    let payload_len = physical.payload_len().as_usize().map_err(durable_error)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_len)
        .map_err(|_| DurableError::EncodingOverflow)?;
    payload.resize(payload_len, 0);
    wal.read_exact(&mut payload)
        .map_err(|source| io_error("read ASTWAL2 object replay payload", source))?;
    if !checksum_valid(physical, &payload) {
        return Err(corrupt_wal("WAL object replay checksum mismatch"));
    }
    let (record, body) = decode_record(&payload, descriptor.offset()).map_err(durable_error)?;
    validate_record_version(physical, record, descriptor.offset()).map_err(durable_error)?;
    if record.kind != super::types::WalRecordKind::Object {
        return Err(corrupt_wal(
            "WAL object descriptor points to another record",
        ));
    }
    validate_logical_body(body, limits, descriptor.offset()).map_err(durable_error)?;
    let (_, decoded) = decode_object_storage_body(body, record.flags, limits, descriptor.offset())
        .map_err(durable_error)?;
    let (id, _length) =
        decode_object_body(&decoded, identity.scheme(), identity, descriptor.offset())
            .map_err(durable_error)?;
    let (_, object) =
        crate::engine::durable::format::decode_object_frame(&decoded, identity.scheme()).map_err(
            |detail| DurableError::Corrupt {
                file: super::super::WAL_FILE,
                offset: descriptor.offset().get(),
                detail,
            },
        )?;
    let canonical = encode_object_frame(identity.scheme(), id, &object)?;
    if canonical.as_slice() != decoded.as_ref() {
        return Err(corrupt_wal("WAL object replay is not canonical"));
    }
    Ok((id, object, canonical))
}

fn corrupt_wal(detail: &'static str) -> DurableError {
    DurableError::Corrupt {
        file: super::super::WAL_FILE,
        offset: 0,
        detail,
    }
}

fn io_error(operation: &'static str, source: std::io::Error) -> DurableError {
    DurableError::Io { operation, source }
}
