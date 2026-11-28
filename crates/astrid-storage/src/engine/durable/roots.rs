//! Canonical root-journal transitions, compaction snapshots, and recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::storage_model::{ModelError, ObjectId, ObjectRecord, RootState};

use super::closure_load::CommitError;
use super::journal_history::{self, Rejection};
use super::journal_snapshot::{self, SnapshotError};
use super::journal_transition::{self, DecodeError};
use super::root_wire::TailError;
use super::{
    ArenaLocation, DurableError, DurableIo, File, IdentityScheme, PersistentObjectIdentity,
    PrincipalCodec, ROOT_FILE, RecoveryLimits, corrupt, preload_indexed_closures,
    recovery_closure_error,
};

use super::{journal_apply, journal_payload};
use journal_snapshot::{CompleteError, EndError, HeaderError, RowError};
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
    let mut recovered = super::journal_visitor::RootHistory::new(
        scheme.into(),
        |key: &[u8]| codec.decode(key),
        |p: &P| codec.encode(p),
    );
    super::format::scan_root_file(roots, limits, &mut recovered, |offset, payload, error| {
        match error {
            journal_apply::VisitError::Decode(cursor, error) => corrupt(
                ROOT_FILE,
                offset,
                decode_error(payload, cursor, scheme, error),
            ),
            journal_apply::VisitError::Apply(error) => apply_error(offset, error),
        }
    })?;
    Ok(recovered.finish())
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
    validate_recovered_roots(&recovered, arena, index, identity, limits)
}

fn validate_recovered_roots<P, I>(
    recovered: &BTreeMap<P, (RootState, u64)>,
    arena: &mut File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(BTreeMap<P, RootState>, BTreeSet<ObjectId>), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
{
    let preload = preload_indexed_closures(
        arena,
        index,
        super::journal_closure::commits(recovered),
        identity,
        limits,
    )
    .map_err(|error| {
        let root_offset = recovered.values().next().map_or(0, |(_, offset)| *offset);
        recovery_closure_error(error, root_offset)
    })?;
    let validated = validate_preloaded(recovered, &preload)?;
    let candidate = recovered
        .iter()
        .map(|(owner, (root, _))| (owner.clone(), *root))
        .collect();
    let roots = super::journal_closure::project(recovered, candidate)
        .ok_or(DurableError::InvalidRootProjection)?;
    Ok((roots, validated))
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

fn apply_error(offset: u64, error: journal_apply::Error) -> DurableError {
    use journal_transition::Error;
    match error {
        journal_apply::Error::Transition(expected, error) => match error {
            Error::Length => DurableError::EncodingOverflow,
            Error::Noncanonical => {
                corrupt(ROOT_FILE, offset, "root-journal frame is not canonical")
            },
            Error::Principal => DurableError::InvalidPrincipal { offset },
            Error::History(Rejection::Conflict(actual)) => DurableError::RecoveryModel {
                file: ROOT_FILE,
                offset,
                source: ModelError::RootConflict { expected, actual },
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
        },
        journal_apply::Error::Snapshot(error) => match error {
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
            SnapshotError::Codec(journal_apply::CodecError::Order) => corrupt(
                ROOT_FILE,
                0,
                "root snapshot principals are not strictly ordered",
            ),
            SnapshotError::Codec(journal_apply::CodecError::Principal) => {
                DurableError::InvalidPrincipal { offset }
            },
        },
    }
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
    journal_snapshot::encode_ordered(roots, scheme.into()).ok_or_else(|| {
        corrupt(
            ROOT_FILE,
            0,
            "root snapshot principals are not strictly ordered",
        )
    })
}

#[cfg(test)]
fn decode_root_journal_record(
    bytes: &[u8],
    scheme: IdentityScheme,
) -> Result<journal_payload::Record, &'static str> {
    let mut cursor = 0;
    journal_payload::decode(bytes, &mut cursor, scheme.into())
        .map_err(|error| decode_error(bytes, cursor, scheme, error))
}

fn decode_error(
    bytes: &[u8],
    cursor: usize,
    scheme: IdentityScheme,
    error: journal_payload::Error,
) -> &'static str {
    let mut reader = RootReader {
        bytes,
        offset: cursor,
    };
    match error {
        journal_payload::Error::Header(error) => match error {
            HeaderError::Read(e) => read_error(e),
            HeaderError::UnknownRecord => "unknown root-journal extension record",
            HeaderError::Length => "length is not process-addressable",
        },
        journal_payload::Error::Snapshot(error) => match error {
            CompleteError::Capacity => "root snapshot allocation failed",
            CompleteError::Row(RowError::Read(e)) => read_error(e),
            CompleteError::Row(RowError::Length) => "length is not process-addressable",
            CompleteError::Row(RowError::Root(e)) => reader.root_error(e, scheme),
            CompleteError::End(EndError::Order) => {
                "root snapshot principals are not strictly ordered"
            },
            CompleteError::End(EndError::Trailing) => "trailing root snapshot bytes",
        },
        journal_payload::Error::Transition(error) => match error {
            DecodeError::Length => "principal length is not process-addressable",
            DecodeError::Principal(e) | DecodeError::Tail(TailError::Read(e)) => read_error(e),
            DecodeError::Tail(TailError::Root(e)) => reader.root_error(e, scheme),
            DecodeError::Tail(TailError::ExpectedTag) => "invalid expected-root tag",
            DecodeError::Tail(TailError::Trailing) => "trailing root-journal bytes",
        },
    }
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
