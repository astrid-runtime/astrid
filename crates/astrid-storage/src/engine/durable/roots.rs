//! Canonical root-journal transitions, compaction snapshots, and recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::storage_model::{ModelError, ObjectId, ObjectRecord, RootState};

use super::closure_load::CommitError;
use super::journal_history::{self, Rejection};
use super::journal_snapshot::{self, SnapshotError};
use super::journal_transition::{self, Record as DecodedRootRecord};
use super::root_wire::{self, TailError};
use super::{
    ArenaLocation, DurableError, DurableIo, File, IdentityScheme, PersistentObjectIdentity,
    PrincipalCodec, ROOT_FILE, ROOT_MAGIC, RecoveryLimits, corrupt, preload_indexed_closures,
    recovery_closure_error, scan_frames,
};

use journal_snapshot::{HeaderError, JournalHeader};
impl From<IdentityScheme> for super::root_wire::Scheme {
    fn from(scheme: IdentityScheme) -> Self {
        Self {
            algorithm: scheme.algorithm().to_le_bytes(),
            construction: scheme.construction().to_le_bytes(),
        }
    }
}

impl From<RootState> for super::root_wire::Root {
    fn from(root: RootState) -> Self {
        journal_history::to_wire(root)
    }
}

impl From<super::root_wire::Root> for RootState {
    fn from(root: super::root_wire::Root) -> Self {
        journal_history::from_wire(root)
    }
}

pub(super) fn recover_root_history<P, C, R>(
    roots: &mut R,
    codec: &C,
    scheme: IdentityScheme,
    limits: RecoveryLimits,
) -> Result<BTreeMap<P, (RootState, u64)>, DurableError>
where
    P: Ord,
    C: PrincipalCodec<P>,
    R: DurableIo,
{
    let mut recovered = BTreeMap::<P, (RootState, u64)>::new();
    scan_frames(roots, ROOT_FILE, ROOT_MAGIC, limits, |offset, payload| {
        let record = decode_root_journal_record(payload, scheme)
            .map_err(|detail| corrupt(ROOT_FILE, offset, detail))?;
        apply_root_journal_record(&mut recovered, codec, scheme, offset, payload, record)
    })?;
    Ok(recovered)
}

pub(super) fn recover_roots<P, I, C, R>(
    roots: &mut R,
    arena: &mut File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    codec: &C,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(BTreeMap<P, RootState>, BTreeSet<ObjectId>), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
    R: DurableIo,
{
    let recovered = recover_root_history(roots, codec, identity.scheme(), limits)?;
    validate_recovered_roots(recovered, arena, index, identity, limits)
}

fn validate_recovered_roots<P, I>(
    recovered: BTreeMap<P, (RootState, u64)>,
    arena: &mut File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(BTreeMap<P, RootState>, BTreeSet<ObjectId>), DurableError>
where
    P: Ord,
    I: PersistentObjectIdentity,
{
    let preload = preload_indexed_closures(
        arena,
        index,
        super::journal_closure::commits(&recovered),
        identity,
        limits,
    )
    .map_err(|error| {
        let root_offset = recovered.values().next().map_or(0, |(_, offset)| *offset);
        recovery_closure_error(error, root_offset)
    })?;
    let validated = validate_preloaded(&recovered, &preload)?;
    Ok((
        recovered
            .into_iter()
            .map(|(principal, (root, _))| (principal, root))
            .collect(),
        validated,
    ))
}

pub(super) fn validate_preloaded<P: Ord>(
    recovered: &BTreeMap<P, (RootState, u64)>,
    preload: &BTreeMap<ObjectId, ObjectRecord>,
) -> Result<BTreeSet<ObjectId>, DurableError> {
    use super::closure_walk::Failure;
    use super::journal_closure;
    journal_closure::validate(recovered, preload).map_err(|failure| match failure {
        journal_closure::Failure::Walk(at, failure) => {
            let source = match failure {
                Failure::Cycle(id) => ModelError::ObjectCycle(id),
                Failure::Root(id) | Failure::Source(_, id) => ModelError::MissingObject(id),
            };
            recovery_closure_error(source.into(), at)
        },
        journal_closure::Failure::Commit(offset, commit, kind) => DurableError::RecoveryModel {
            file: ROOT_FILE,
            offset,
            source: match kind {
                CommitError::WrongKind(actual) => ModelError::RootNotCommit {
                    object: commit,
                    actual,
                },
                CommitError::Missing => ModelError::MissingObject(commit),
            },
        },
    })
}

fn apply_root_journal_record<P, C>(
    recovered: &mut BTreeMap<P, (RootState, u64)>,
    codec: &C,
    scheme: IdentityScheme,
    offset: u64,
    payload: &[u8],
    record: DecodedRootJournalRecord,
) -> Result<(), DurableError>
where
    P: Ord,
    C: PrincipalCodec<P>,
{
    match record {
        DecodedRootJournalRecord::Transition(record) => {
            apply_transition(recovered, codec, scheme, offset, payload, &record)
        },
        DecodedRootJournalRecord::Snapshot(entries) => journal_snapshot::restore(
            recovered,
            offset,
            payload,
            entries,
            |rows| encode_root_snapshot(scheme, rows),
            |bytes| decode_principal(codec, bytes, offset),
        )
        .map_err(|error| match error {
            SnapshotError::Position => corrupt(
                ROOT_FILE,
                offset,
                "root snapshot must be the first journal frame",
            ),
            SnapshotError::Noncanonical => {
                corrupt(ROOT_FILE, offset, "root snapshot frame is not canonical")
            },
            SnapshotError::Duplicate => corrupt(
                ROOT_FILE,
                offset,
                "root snapshot decodes duplicate principals",
            ),
            SnapshotError::Codec(error) => error,
        }),
    }
}

fn apply_transition<P, C>(
    recovered: &mut BTreeMap<P, (RootState, u64)>,
    codec: &C,
    scheme: IdentityScheme,
    offset: u64,
    payload: &[u8],
    record: &DecodedRootRecord,
) -> Result<(), DurableError>
where
    P: Ord,
    C: PrincipalCodec<P>,
{
    use journal_transition::Error;
    record
        .replay(
            recovered,
            scheme.into(),
            offset,
            payload,
            |key| codec.decode(key),
            |owner| codec.encode(owner),
        )
        .map_err(|error| match error {
            Error::Length => DurableError::EncodingOverflow,
            Error::Noncanonical => {
                corrupt(ROOT_FILE, offset, "root-journal frame is not canonical")
            },
            Error::Principal => DurableError::InvalidPrincipal { offset },
            Error::History(Rejection::Conflict(actual)) => DurableError::RecoveryModel {
                file: ROOT_FILE,
                offset,
                source: ModelError::RootConflict {
                    expected: record.expected,
                    actual,
                },
            },
            Error::History(Rejection::Overflow) => DurableError::RecoveryModel {
                file: ROOT_FILE,
                offset,
                source: ModelError::ArithmeticOverflow,
            },
            Error::History(Rejection::Generation) => corrupt(
                ROOT_FILE,
                offset,
                "replacement generation does not match journal history",
            ),
        })
}

fn decode_principal<P, C>(codec: &C, bytes: &[u8], offset: u64) -> Result<P, DurableError>
where
    C: PrincipalCodec<P>,
{
    journal_history::principal(bytes, |key| codec.decode(key), |owner| codec.encode(owner))
        .ok_or(DurableError::InvalidPrincipal { offset })
}

pub(super) fn encode_root_record(
    scheme: IdentityScheme,
    principal: &[u8],
    expected: Option<RootState>,
    replacement: RootState,
) -> Result<Vec<u8>, DurableError> {
    journal_transition::encode(principal, scheme.into(), expected, replacement)
        .ok_or(DurableError::EncodingOverflow)
}

pub(super) fn encode_root_snapshot(
    scheme: IdentityScheme,
    roots: &[(Vec<u8>, RootState)],
) -> Result<Vec<u8>, DurableError> {
    if !journal_snapshot::strictly_ordered(roots) {
        return Err(corrupt(
            ROOT_FILE,
            0,
            "root snapshot principals are not strictly ordered",
        ));
    }
    Ok(journal_snapshot::serialize(roots, scheme.into()))
}

enum DecodedRootJournalRecord {
    Transition(DecodedRootRecord),
    Snapshot(Vec<(Vec<u8>, RootState)>),
}

fn decode_root_journal_record(
    bytes: &[u8],
    scheme: IdentityScheme,
) -> Result<DecodedRootJournalRecord, &'static str> {
    let mut reader = RootReader::new(bytes);
    let header =
        journal_snapshot::read_header(bytes, &mut reader.offset).map_err(|error| match error {
            HeaderError::Read(e) => read_error(e),
            HeaderError::UnknownRecord => "unknown root-journal extension record",
            HeaderError::Length => "length is not process-addressable",
        })?;
    let prefix = match header {
        JournalHeader::Transition(length) => length,
        JournalHeader::Snapshot(count) => {
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(count)
                .map_err(|_| "root snapshot allocation failed")?;
            let entries = journal_snapshot::read_rows(
                bytes,
                &mut reader.offset,
                count,
                scheme.into(),
                entries,
            )
            .map_err(|error| match error {
                journal_snapshot::RowError::Read(e) => read_error(e),
                journal_snapshot::RowError::Length => "length is not process-addressable",
                journal_snapshot::RowError::Root(e) => reader.root_error(e, scheme),
            })?;
            journal_snapshot::finish(&entries, reader.offset, bytes.len()).map_err(|error| {
                match error {
                    journal_snapshot::EndError::Order => {
                        "root snapshot principals are not strictly ordered"
                    },
                    journal_snapshot::EndError::Trailing => "trailing root snapshot bytes",
                }
            })?;
            return Ok(DecodedRootJournalRecord::Snapshot(entries));
        },
    };

    let principal_len =
        usize::try_from(prefix).map_err(|_| "principal length is not process-addressable")?;
    let principal = reader.take(principal_len)?.to_vec();
    let (expected, replacement) = root_wire::read_tail(bytes, &mut reader.offset, scheme.into())
        .map_err(|error| match error {
            TailError::Read(e) => read_error(e),
            TailError::Root(e) => reader.root_error(e, scheme),
            TailError::ExpectedTag => "invalid expected-root tag",
            TailError::Trailing => "trailing root-journal bytes",
        })?;
    Ok(DecodedRootJournalRecord::Transition(DecodedRootRecord {
        principal,
        expected: expected.map(Into::into),
        replacement: replacement.into(),
    }))
}

fn read_error(error: super::root_wire::ReadError) -> &'static str {
    match error {
        super::root_wire::ReadError::Overflow(_) => "frame length overflow",
        super::root_wire::ReadError::Truncated => "truncated frame payload",
    }
}

struct RootReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RootReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        super::root_wire::take(self.bytes, &mut self.offset, len).map_err(read_error)
    }

    fn root_error(
        &mut self,
        error: super::root_wire::RootError,
        scheme: IdentityScheme,
    ) -> &'static str {
        let (algorithm, construction, size) = match error {
            super::root_wire::RootError::Read(e) => return read_error(e),
            super::root_wire::RootError::Scheme {
                algorithm,
                construction,
                size,
            } => (
                u16::from_le_bytes(algorithm),
                u16::from_le_bytes(construction),
                u32::from_le_bytes(size),
            ),
        };
        let Ok(len) = usize::try_from(size) else {
            return "identity digest length overflow";
        };
        if algorithm == 0 || construction == 0 || len == 0 {
            return "identity tag fields must be non-zero";
        }
        // Journal diagnostics distinguish an incomplete digest from an
        // unsupported identity. Preserve the existing error precedence.
        if let Err(error) = self.take(len) {
            return error;
        }
        if algorithm != scheme.algorithm() || construction != scheme.construction() {
            return "unsupported identity algorithm or construction version";
        }
        "identity digest length does not match the supported scheme"
    }
}

#[cfg(test)]
#[path = "root_journal_decode_tests.rs"]
mod decode_tests;
