//! Checksummed append-only lifecycle journal for staged generations.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use uuid::Uuid;

use super::format::{StagingIntent, decode_intent, encode_intent};
use super::{StagedContentId, connection};
use crate::error::StorageResult;
use crate::principal_state::native_io::PrivateDirectory;

const JOURNAL_MAGIC: [u8; 8] = *b"ASTRSTG1";
const JOURNAL_VERSION: u16 = 1;
const JOURNAL_HEADER_BYTES: usize = 52;
const CHECKSUM_OFFSET: usize = 20;
const SEALED_RECORD: u8 = 1;
const PUBLISHED_RECORD: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct StageKey {
    pub(super) sequence: u64,
    pub(super) id: StagedContentId,
}

impl StageKey {
    pub(super) const fn from_intent(intent: &StagingIntent) -> Self {
        Self {
            sequence: intent.sequence,
            id: intent.id,
        }
    }
}

#[derive(Debug)]
pub(super) enum JournalRecord {
    Sealed(StagingIntent),
    Published(StageKey),
}

#[derive(Debug)]
pub(super) struct JournalRecovery {
    pub(super) pending: BTreeMap<StageKey, StagingIntent>,
    pub(super) completed: BTreeSet<StageKey>,
}

pub(super) fn open_journal(
    root: &PrivateDirectory,
    path: &Path,
) -> StorageResult<(File, JournalRecovery)> {
    let name = path
        .file_name()
        .map(Path::new)
        .ok_or_else(|| connection(format!("staging journal {} has no name", path.display())))?;
    let mut file = if root.contains(name)? {
        root.open_file_rw(name)?
    } else {
        root.create_file(name)?
    };
    let recovery = recover(&mut file, path)?;
    Ok((file, recovery))
}

pub(super) fn append_records(file: &mut File, records: &[JournalRecord]) -> StorageResult<()> {
    file.seek(SeekFrom::End(0))
        .map_err(|error| connection(format!("seek staging journal tail: {error}")))?;
    for record in records {
        let payload = encode_record(record)?;
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| connection("staging journal record length overflow".to_owned()))?;
        let mut header = [0_u8; JOURNAL_HEADER_BYTES];
        header[..8].copy_from_slice(&JOURNAL_MAGIC);
        header[8..10].copy_from_slice(&JOURNAL_VERSION.to_le_bytes());
        header[12..20].copy_from_slice(&payload_len.to_le_bytes());
        let checksum = frame_checksum(&header, &payload);
        header[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        file.write_all(&header)
            .and_then(|()| file.write_all(&payload))
            .map_err(|error| connection(format!("append staging journal record: {error}")))?;
    }
    Ok(())
}

pub(super) fn flush_journal(file: &File) -> StorageResult<()> {
    file.sync_all()
        .map_err(|error| connection(format!("flush staging intent journal: {error}")))
}

pub(super) fn truncate_empty(file: &mut File) -> StorageResult<()> {
    file.set_len(0)
        .and_then(|()| file.sync_all())
        .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(|error| connection(format!("truncate empty staging journal: {error}")))
}

fn recover(file: &mut File, path: &Path) -> StorageResult<JournalRecovery> {
    let file_len = file
        .metadata()
        .map_err(|error| {
            connection(format!(
                "inspect staging journal {}: {error}",
                path.display()
            ))
        })?
        .len();
    let mut offset = 0_u64;
    let mut pending = BTreeMap::new();
    let mut completed = BTreeSet::new();
    let mut sequences = BTreeMap::new();
    let mut identifiers = BTreeMap::new();
    while offset < file_len {
        let Some((record, frame_end)) = recover_frame(file, offset, file_len)? else {
            break;
        };
        apply_record(
            record,
            &mut pending,
            &mut completed,
            &mut sequences,
            &mut identifiers,
        )?;
        offset = frame_end;
    }
    file.seek(SeekFrom::End(0))
        .map_err(|error| connection(format!("seek recovered staging journal tail: {error}")))?;
    Ok(JournalRecovery { pending, completed })
}

fn recover_frame(
    file: &mut File,
    offset: u64,
    file_len: u64,
) -> StorageResult<Option<(JournalRecord, u64)>> {
    let remaining = file_len
        .checked_sub(offset)
        .ok_or_else(|| connection("staging journal length underflow".to_owned()))?;
    let header_bytes = u64::try_from(JOURNAL_HEADER_BYTES)
        .map_err(|_| connection("staging journal header overflow".to_owned()))?;
    if remaining < header_bytes {
        truncate_tail(file, offset)?;
        return Ok(None);
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| connection(format!("seek staging journal frame: {error}")))?;
    let mut header = [0_u8; JOURNAL_HEADER_BYTES];
    file.read_exact(&mut header)
        .map_err(|error| connection(format!("read staging journal header: {error}")))?;
    let payload_len = u64::from_le_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| connection("invalid staging journal payload length".to_owned()))?,
    );
    let Some(frame_end) = offset
        .checked_add(header_bytes)
        .and_then(|end| end.checked_add(payload_len))
    else {
        return recover_invalid_tail(file, offset, file_len, "length overflows file");
    };
    if frame_end > file_len {
        return recover_invalid_tail(file, offset, file_len, "length exceeds file");
    }
    let payload_bytes = usize::try_from(payload_len)
        .map_err(|_| connection("staging journal payload is not addressable".to_owned()))?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_bytes)
        .map_err(|_| connection("staging journal payload allocation failed".to_owned()))?;
    payload.resize(payload_bytes, 0);
    file.read_exact(&mut payload)
        .map_err(|error| connection(format!("read staging journal payload: {error}")))?;
    let expected: [u8; 32] = header[CHECKSUM_OFFSET..]
        .try_into()
        .map_err(|_| connection("staging journal checksum width mismatch".to_owned()))?;
    if frame_checksum(&header, &payload) != expected {
        return recover_invalid_tail(file, offset, file_len, "checksum mismatch");
    }
    // The checksum binds the physical header. A self-consistent unknown
    // header is a newer or otherwise unsupported format, not a torn tail;
    // fail without modifying it so an older binary cannot destroy it.
    if header[..8] != JOURNAL_MAGIC {
        return Err(connection(format!(
            "unsupported staging journal magic at {offset}"
        )));
    }
    if u16::from_le_bytes([header[8], header[9]]) != JOURNAL_VERSION {
        return Err(connection(format!(
            "unsupported staging journal version at {offset}"
        )));
    }
    if header[10..12] != [0, 0] {
        return Err(connection(format!(
            "staging journal reserved bytes are non-zero at {offset}"
        )));
    }
    let record = decode_record(&payload)
        .map_err(|detail| connection(format!("decode staging journal at {offset}: {detail}")))?;
    Ok(Some((record, frame_end)))
}

fn recover_invalid_tail(
    file: &mut File,
    offset: u64,
    file_len: u64,
    detail: &str,
) -> StorageResult<Option<(JournalRecord, u64)>> {
    if valid_frame_follows(file, offset, file_len)? {
        return Err(connection(format!(
            "corrupt interior staging journal frame at {offset}: {detail}"
        )));
    }
    truncate_tail(file, offset)?;
    Ok(None)
}

fn apply_record(
    record: JournalRecord,
    pending: &mut BTreeMap<StageKey, StagingIntent>,
    completed: &mut BTreeSet<StageKey>,
    sequences: &mut BTreeMap<u64, StagedContentId>,
    identifiers: &mut BTreeMap<StagedContentId, u64>,
) -> StorageResult<()> {
    match record {
        JournalRecord::Sealed(intent) => {
            let key = StageKey::from_intent(&intent);
            if pending.contains_key(&key) || completed.contains(&key) {
                return Err(connection(format!(
                    "duplicate sealed staging journal record for {}-{}",
                    key.sequence, key.id
                )));
            }
            if let Some(existing) = sequences.get(&key.sequence) {
                return Err(connection(format!(
                    "staging journal sequence {} names both {} and {}",
                    key.sequence, existing, key.id
                )));
            }
            if let Some(existing) = identifiers.get(&key.id) {
                return Err(connection(format!(
                    "staging journal identifier {} names both sequence {} and {}",
                    key.id, existing, key.sequence
                )));
            }
            sequences.insert(key.sequence, key.id);
            identifiers.insert(key.id, key.sequence);
            pending.insert(key, intent);
        },
        JournalRecord::Published(key) => {
            if pending.remove(&key).is_none() {
                return Err(connection(format!(
                    "publication record has no sealed predecessor for {}-{}",
                    key.sequence, key.id
                )));
            }
            completed.insert(key);
        },
    }
    Ok(())
}

fn encode_record(record: &JournalRecord) -> StorageResult<Vec<u8>> {
    match record {
        JournalRecord::Sealed(intent) => {
            let intent = encode_intent(intent)?;
            let mut bytes = Vec::with_capacity(intent.len().saturating_add(1));
            bytes.push(SEALED_RECORD);
            bytes.extend_from_slice(&intent);
            Ok(bytes)
        },
        JournalRecord::Published(key) => {
            let mut bytes = Vec::with_capacity(25);
            bytes.push(PUBLISHED_RECORD);
            bytes.extend_from_slice(&key.sequence.to_le_bytes());
            bytes.extend_from_slice(key.id.0.as_bytes());
            Ok(bytes)
        },
    }
}

fn decode_record(bytes: &[u8]) -> Result<JournalRecord, &'static str> {
    let Some((&tag, payload)) = bytes.split_first() else {
        return Err("empty staging journal record");
    };
    match tag {
        SEALED_RECORD => decode_intent(payload).map(JournalRecord::Sealed),
        PUBLISHED_RECORD => {
            let sequence = payload
                .get(..8)
                .ok_or("truncated staging publication record")?
                .try_into()
                .map(u64::from_le_bytes)
                .map_err(|_| "invalid staging publication sequence")?;
            let id: [u8; 16] = payload
                .get(8..24)
                .ok_or("truncated staging publication identifier")?
                .try_into()
                .map_err(|_| "invalid staging publication identifier")?;
            if payload.len() != 24 {
                return Err("staging publication record has trailing bytes");
            }
            Ok(JournalRecord::Published(StageKey {
                sequence,
                id: StagedContentId(Uuid::from_bytes(id)),
            }))
        },
        _ => Err("unknown staging journal record kind"),
    }
}

fn valid_frame_follows(file: &mut File, invalid_offset: u64, file_len: u64) -> StorageResult<bool> {
    let Some(mut candidate) = invalid_offset.checked_add(1) else {
        return Ok(false);
    };
    let header_len = u64::try_from(JOURNAL_HEADER_BYTES)
        .map_err(|_| connection("staging journal header overflow".to_owned()))?;
    while candidate
        .checked_add(header_len)
        .is_some_and(|end| end <= file_len)
    {
        file.seek(SeekFrom::Start(candidate))
            .map_err(|error| connection(format!("seek staging recovery candidate: {error}")))?;
        let mut header = [0_u8; JOURNAL_HEADER_BYTES];
        file.read_exact(&mut header)
            .map_err(|error| connection(format!("read staging recovery candidate: {error}")))?;
        let payload_len = u64::from_le_bytes(
            header[12..20]
                .try_into()
                .map_err(|_| connection("invalid staging recovery payload length".to_owned()))?,
        );
        let frame_end = candidate
            .checked_add(header_len)
            .and_then(|value| value.checked_add(payload_len));
        if frame_end.is_some_and(|end| end <= file_len) {
            let payload_bytes = usize::try_from(payload_len)
                .map_err(|_| connection("staging journal payload is not addressable".to_owned()))?;
            let mut payload = Vec::new();
            payload
                .try_reserve_exact(payload_bytes)
                .map_err(|_| connection("staging journal payload allocation failed".to_owned()))?;
            payload.resize(payload_bytes, 0);
            file.read_exact(&mut payload)
                .map_err(|error| connection(format!("read staging recovery payload: {error}")))?;
            let expected: [u8; 32] = header[CHECKSUM_OFFSET..]
                .try_into()
                .map_err(|_| connection("staging journal checksum width mismatch".to_owned()))?;
            // This scan is a truncation barrier, not an acceptance path. A
            // checksum-valid envelope proves that durable bytes follow the
            // damaged frame even when this binary does not understand the
            // envelope's header or record version.
            if frame_checksum(&header, &payload) == expected {
                return Ok(true);
            }
        }
        candidate = candidate
            .checked_add(1)
            .ok_or_else(|| connection("staging journal scan offset overflow".to_owned()))?;
    }
    Ok(false)
}

fn truncate_tail(file: &mut File, valid_len: u64) -> StorageResult<()> {
    file.set_len(valid_len)
        .and_then(|()| file.sync_all())
        .map_err(|error| connection(format!("truncate torn staging journal tail: {error}")))
}

fn frame_checksum(header: &[u8; JOURNAL_HEADER_BYTES], payload: &[u8]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("astrid native content staging journal frame v1");
    // This physical-prefix construction is stable across journal record
    // versions. Binding magic, version, reserved space, and length lets
    // recovery distinguish an unfsynced/torn tail from a self-consistent
    // future frame that an older binary must preserve.
    hasher.update(&header[..CHECKSUM_OFFSET]);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
pub(super) fn encoded_frame(record: &JournalRecord) -> StorageResult<Vec<u8>> {
    let payload = encode_record(record)?;
    let payload_len = u64::try_from(payload.len())
        .map_err(|_| connection("staging journal record length overflow".to_owned()))?;
    let mut frame = vec![0_u8; JOURNAL_HEADER_BYTES];
    frame[..8].copy_from_slice(&JOURNAL_MAGIC);
    frame[8..10].copy_from_slice(&JOURNAL_VERSION.to_le_bytes());
    frame[12..20].copy_from_slice(&payload_len.to_le_bytes());
    let header: &[u8; JOURNAL_HEADER_BYTES] = frame[..JOURNAL_HEADER_BYTES]
        .try_into()
        .map_err(|_| connection("staging journal test header width mismatch".to_owned()))?;
    let checksum = frame_checksum(header, &payload);
    frame[CHECKSUM_OFFSET..JOURNAL_HEADER_BYTES].copy_from_slice(&checksum);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

#[cfg(test)]
pub(super) fn refresh_frame_checksum(frame: &mut [u8]) -> StorageResult<()> {
    let (header, payload) = frame.split_at_mut(JOURNAL_HEADER_BYTES);
    let header: &mut [u8; JOURNAL_HEADER_BYTES] = header
        .try_into()
        .map_err(|_| connection("staging journal test header width mismatch".to_owned()))?;
    let checksum = frame_checksum(header, payload);
    header[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    Ok(())
}
