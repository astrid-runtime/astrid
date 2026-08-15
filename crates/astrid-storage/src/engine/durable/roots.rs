//! Canonical root-journal transitions, compaction snapshots, and recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::storage_model::{ModelError, ObjectId, RootGeneration, RootState};

use super::representations::RepresentationStore;
use super::{
    ArenaLocation, DurableError, DurableIo, File, IdentityScheme, PersistentObjectIdentity,
    PrincipalCodec, ROOT_FILE, ROOT_MAGIC, RecoveryLimits, corrupt, materialize_closure,
    recovery_closure_error, scan_frames, validate_commit_closure,
};

const SNAPSHOT_SENTINEL: u64 = u64::MAX;
const SNAPSHOT_RECORD: u8 = 1;
const CURRENT_DIGEST_BYTES: u32 = 32;

pub(super) fn recover_roots<P, I, C, R>(
    roots: &mut R,
    arena: &mut File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    representations: Option<&RepresentationStore>,
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
    let scheme = identity.scheme();
    let mut recovered = BTreeMap::<P, (RootState, u64)>::new();
    scan_frames(roots, ROOT_FILE, ROOT_MAGIC, limits, |offset, payload| {
        let record = decode_root_journal_record(payload, scheme)
            .map_err(|detail| corrupt(ROOT_FILE, offset, detail))?;
        apply_root_journal_record(&mut recovered, codec, scheme, offset, payload, record)
    })?;

    validate_recovered_roots(recovered, arena, index, representations, identity, limits)
}

fn validate_recovered_roots<P, I>(
    recovered: BTreeMap<P, (RootState, u64)>,
    arena: &mut File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    representations: Option<&RepresentationStore>,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(BTreeMap<P, RootState>, BTreeSet<ObjectId>), DurableError>
where
    P: Ord,
    I: PersistentObjectIdentity,
{
    let mut validated = BTreeSet::new();
    for (root, offset) in recovered.values().copied() {
        let records = materialize_closure(
            &mut super::ClosureObjects {
                arena,
                index,
                incoming: &BTreeMap::new(),
                representations,
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
        DecodedRootJournalRecord::Snapshot(entries) => {
            if offset != 0 || !recovered.is_empty() {
                return Err(corrupt(
                    ROOT_FILE,
                    offset,
                    "root snapshot must be the first journal frame",
                ));
            }
            if encode_root_snapshot(scheme, &entries)? != payload {
                return Err(corrupt(
                    ROOT_FILE,
                    offset,
                    "root snapshot frame is not canonical",
                ));
            }
            for (principal_bytes, root) in entries {
                let principal = decode_principal(codec, &principal_bytes, offset)?;
                if recovered.insert(principal, (root, offset)).is_some() {
                    return Err(corrupt(
                        ROOT_FILE,
                        offset,
                        "root snapshot decodes duplicate principals",
                    ));
                }
            }
            Ok(())
        },
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
    let actual = recovered.get(&principal).map(|(root, _)| *root);
    if actual != record.expected {
        return Err(DurableError::RecoveryModel {
            file: ROOT_FILE,
            offset,
            source: ModelError::RootConflict {
                expected: record.expected,
                actual,
            },
        });
    }
    let generation = match actual {
        Some(root) => root.generation.checked_next(),
        None => Some(RootGeneration::INITIAL),
    }
    .ok_or(DurableError::RecoveryModel {
        file: ROOT_FILE,
        offset,
        source: ModelError::ArithmeticOverflow,
    })?;
    if record.replacement.generation != generation {
        return Err(corrupt(
            ROOT_FILE,
            offset,
            "replacement generation does not match journal history",
        ));
    }
    recovered.insert(principal, (record.replacement, offset));
    Ok(())
}

fn decode_principal<P, C>(codec: &C, bytes: &[u8], offset: u64) -> Result<P, DurableError>
where
    C: PrincipalCodec<P>,
{
    let principal = codec
        .decode(bytes)
        .ok_or(DurableError::InvalidPrincipal { offset })?;
    if codec.encode(&principal) != bytes {
        return Err(DurableError::InvalidPrincipal { offset });
    }
    Ok(principal)
}

pub(super) fn encode_root_record(
    scheme: IdentityScheme,
    principal: &[u8],
    expected: Option<RootState>,
    replacement: RootState,
) -> Result<Vec<u8>, DurableError> {
    let principal_len =
        u64::try_from(principal.len()).map_err(|_| DurableError::EncodingOverflow)?;
    if principal_len == SNAPSHOT_SENTINEL {
        return Err(DurableError::EncodingOverflow);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&principal_len.to_le_bytes());
    bytes.extend_from_slice(principal);
    match expected {
        None => bytes.push(0),
        Some(root) => {
            bytes.push(1);
            encode_root_state(&mut bytes, scheme, root);
        },
    }
    encode_root_state(&mut bytes, scheme, replacement);
    Ok(bytes)
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
    bytes.extend_from_slice(&root.generation.get().to_le_bytes());
    encode_identity(bytes, scheme, root.commit);
}

fn encode_identity(bytes: &mut Vec<u8>, scheme: IdentityScheme, id: ObjectId) {
    bytes.extend_from_slice(&scheme.algorithm().to_le_bytes());
    bytes.extend_from_slice(&scheme.construction().to_le_bytes());
    bytes.extend_from_slice(&CURRENT_DIGEST_BYTES.to_le_bytes());
    bytes.extend_from_slice(id.as_bytes());
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
    let expected = match reader.u8()? {
        0 => None,
        1 => Some(reader.root_state(scheme)?),
        _ => return Err("invalid expected-root tag"),
    };
    let replacement = reader.root_state(scheme)?;
    if reader.remaining() != 0 {
        return Err("trailing root-journal bytes");
    }
    Ok(DecodedRootJournalRecord::Transition(DecodedRootRecord {
        principal,
        expected,
        replacement,
    }))
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

    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| "truncated u32 field")?,
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

    fn identity(&mut self, scheme: IdentityScheme) -> Result<ObjectId, &'static str> {
        let algorithm = self.u16()?;
        let construction = self.u16()?;
        let digest_len =
            usize::try_from(self.u32()?).map_err(|_| "identity digest length overflow")?;
        if algorithm == 0 || construction == 0 || digest_len == 0 {
            return Err("identity tag fields must be non-zero");
        }
        let digest = self.take(digest_len)?;
        if algorithm != scheme.algorithm() || construction != scheme.construction() {
            return Err("unsupported identity algorithm or construction version");
        }
        digest
            .try_into()
            .map(ObjectId::new)
            .map_err(|_| "identity digest length does not match the supported scheme")
    }

    fn root_state(&mut self, scheme: IdentityScheme) -> Result<RootState, &'static str> {
        Ok(RootState {
            generation: RootGeneration::new(self.u64()?),
            commit: self.identity(scheme)?,
        })
    }
}
