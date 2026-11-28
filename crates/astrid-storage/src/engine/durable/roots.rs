//! Canonical root-journal transitions, compaction snapshots, and recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::storage_model::{ModelError, ObjectId, RootState};

use super::journal_history::{self, Rejection};
use super::journal_snapshot::{self, SnapshotError};
use super::root_wire::{self, TailError};
use super::{
    ArenaLocation, DurableError, DurableIo, File, IdentityScheme, PersistentObjectIdentity,
    PrincipalCodec, ROOT_FILE, ROOT_MAGIC, RecoveryLimits, corrupt, materialize_closure,
    preload_indexed_closures, recovery_closure_error, scan_frames, validate_commit_closure,
};

const SNAPSHOT_SENTINEL: u64 = u64::MAX;
const SNAPSHOT_RECORD: u8 = 1;
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
    let mut validated = BTreeSet::new();
    let preload = preload_indexed_closures(
        arena,
        index,
        recovered.values().map(|(root, _)| root.commit),
        identity,
        limits,
    )
    .map_err(|error| {
        let root_offset = recovered.values().next().map_or(0, |(_, offset)| *offset);
        recovery_closure_error(error, root_offset)
    })?;
    let empty_index = BTreeMap::new();
    for (root, offset) in recovered.values().copied() {
        let records = materialize_closure(
            &mut super::ClosureObjects::<_, P> {
                arena,
                index: &empty_index,
                incoming: &preload,
                pending: None,
                identity,
                limits,
            },
            root.commit,
        )
        .map_err(|error| recovery_closure_error(error, offset))?;
        validate_commit_closure(&records, root.commit).map_err(|source| {
            DurableError::RecoveryModel {
                file: ROOT_FILE,
                offset,
                source,
            }
        })?;
        validated.extend(records.into_iter().map(|(id, _)| id));
    }
    Ok((
        recovered
            .into_iter()
            .map(|(principal, (root, _))| (principal, root))
            .collect(),
        validated,
    ))
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
            let canonical = encode_root_record(
                scheme,
                &record.principal,
                record.expected,
                record.replacement,
            )?;
            if canonical != payload {
                return Err(corrupt(
                    ROOT_FILE,
                    offset,
                    "root-journal frame is not canonical",
                ));
            }
            apply_transition(recovered, codec, offset, &record)
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
    offset: u64,
    record: &DecodedRootRecord,
) -> Result<(), DurableError>
where
    P: Ord,
    C: PrincipalCodec<P>,
{
    let principal = decode_principal(codec, &record.principal, offset)?;
    journal_history::apply(
        recovered,
        principal,
        record.expected,
        record.replacement,
        offset,
    )
    .map_err(|error| match error {
        Rejection::Conflict(actual) => DurableError::RecoveryModel {
            file: ROOT_FILE,
            offset,
            source: ModelError::RootConflict {
                expected: record.expected,
                actual,
            },
        },
        Rejection::Overflow => DurableError::RecoveryModel {
            file: ROOT_FILE,
            offset,
            source: ModelError::ArithmeticOverflow,
        },
        Rejection::Generation => corrupt(
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
    super::root_wire::encode(
        principal,
        scheme.into(),
        expected.map(Into::into),
        replacement.into(),
    )
    .ok_or(DurableError::EncodingOverflow)
}

pub(super) fn encode_root_snapshot(
    scheme: IdentityScheme,
    roots: &[(Vec<u8>, RootState)],
) -> Result<Vec<u8>, DurableError> {
    if roots
        .windows(2)
        .any(|pair| pair[0].0.as_slice() >= pair[1].0.as_slice())
    {
        return Err(corrupt(
            ROOT_FILE,
            0,
            "root snapshot principals are not strictly ordered",
        ));
    }
    let count = u64::try_from(roots.len()).map_err(|_| DurableError::EncodingOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&SNAPSHOT_SENTINEL.to_le_bytes());
    bytes.push(SNAPSHOT_RECORD);
    bytes.extend_from_slice(&count.to_le_bytes());
    for (principal, root) in roots {
        let principal_len =
            u64::try_from(principal.len()).map_err(|_| DurableError::EncodingOverflow)?;
        bytes.extend_from_slice(&principal_len.to_le_bytes());
        bytes.extend_from_slice(principal);
        encode_root_state(&mut bytes, scheme, *root);
    }
    Ok(bytes)
}

fn encode_root_state(bytes: &mut Vec<u8>, scheme: IdentityScheme, root: RootState) {
    super::root_wire::Root::from(root).append(bytes, scheme.into());
}

enum DecodedRootJournalRecord {
    Transition(DecodedRootRecord),
    Snapshot(Vec<(Vec<u8>, RootState)>),
}

struct DecodedRootRecord {
    principal: Vec<u8>,
    expected: Option<RootState>,
    replacement: RootState,
}

fn decode_root_journal_record(
    bytes: &[u8],
    scheme: IdentityScheme,
) -> Result<DecodedRootJournalRecord, &'static str> {
    let mut reader = RootReader::new(bytes);
    let prefix = reader.u64()?;
    if prefix == SNAPSHOT_SENTINEL {
        if reader.u8()? != SNAPSHOT_RECORD {
            return Err("unknown root-journal extension record");
        }
        let count = reader.usize_len()?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| "root snapshot allocation failed")?;
        for _ in 0..count {
            let principal_len = reader.usize_len()?;
            let principal = reader.take(principal_len)?.to_vec();
            let root = reader.root_state(scheme)?;
            entries.push((principal, root));
        }
        if entries
            .windows(2)
            .any(|pair| pair[0].0.as_slice() >= pair[1].0.as_slice())
        {
            return Err("root snapshot principals are not strictly ordered");
        }
        if reader.remaining() != 0 {
            return Err("trailing root snapshot bytes");
        }
        return Ok(DecodedRootJournalRecord::Snapshot(entries));
    }

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

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        super::root_wire::take(self.bytes, &mut self.offset, len).map_err(read_error)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        self.take(1)?.first().copied().ok_or("truncated u8 field")
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

    fn root_state(&mut self, scheme: IdentityScheme) -> Result<RootState, &'static str> {
        super::root_wire::read_root(self.bytes, &mut self.offset, scheme.into())
            .map(Into::into)
            .map_err(|error| self.root_error(error, scheme))
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
