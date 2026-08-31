use std::io::{Read, Seek, SeekFrom};
use std::marker::PhantomData;

use super::super::{PersistentObjectIdentity, PrincipalCodec};

use super::codec::{
    PHYSICAL_HEADER_LEN, RecordHeader, WAL_MAGIC, checksum_valid, decode_begin_body,
    decode_commit_body, decode_object_body, decode_object_storage_body, decode_physical_header,
    decode_record_header, decode_root_body, digest_record, digest_record_with_flags,
    logical_record_length, new_digest, record_body, validate_logical_body, validate_record_version,
    wal_physical_limit,
};
use super::types::{
    WalBeginDescriptor, WalCommitDescriptor, WalCount, WalError, WalEvent, WalLength, WalLimits,
    WalObjectDescriptor, WalOffset, WalOrdinal, WalRecordKind, WalResumeState, WalRootDescriptor,
    WalScanTail, WalSequence, WalTailKind, WalTransactionDescriptor,
};

/// A scanner-finished stream paired with the exact validated append state.
/// The reader is consumed by `into_writer`, so a resume token cannot be paired
/// with a different sink.
pub(crate) struct ScannedWal<R, I, C, P> {
    reader: R,
    identity: I,
    codec: C,
    state: WalResumeState,
    _principal: PhantomData<P>,
}

impl<R, I, C, P> ScannedWal<R, I, C, P> {
    #[cfg(test)]
    pub(super) fn reader(&self) -> &R {
        &self.reader
    }

    pub(super) fn into_parts(self) -> (R, I, C, WalResumeState) {
        (self.reader, self.identity, self.codec, self.state)
    }

    pub(super) fn map_reader<S>(self, map: impl FnOnce(R) -> S) -> ScannedWal<S, I, C, P> {
        ScannedWal {
            reader: map(self.reader),
            identity: self.identity,
            codec: self.codec,
            state: self.state,
            _principal: PhantomData,
        }
    }
}

/// A streaming ASTWAL2 scanner. It reads one physical record at a time and
/// emits descriptors without retaining object/root payloads or all frames.
pub(crate) struct WalScanner<R, I, C, P> {
    reader: R,
    identity: I,
    codec: C,
    limits: WalLimits,
    offset: u64,
    next_search_offset: u64,
    last_sequence: Option<WalSequence>,
    active: Option<ActiveScan>,
    finished: bool,
    resume_offset: Option<WalOffset>,
    _principal: PhantomData<P>,
}

struct ActiveScan {
    begin_offset: WalOffset,
    sequence: WalSequence,
    scheme: super::super::IdentityScheme,
    next_ordinal: WalOrdinal,
    object_count: WalCount,
    root_count: WalCount,
    logical_count: WalCount,
    logical_bytes: WalLength,
    digest: blake3::Hasher,
    previous_object: Option<crate::storage_model::ObjectId>,
    previous_principal: Option<Vec<u8>>,
    saw_root: bool,
}

impl<R, I, C, P> WalScanner<R, I, C, P>
where
    R: Read + Seek,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Borrow the scanner's source stream before converting it into a resume
    /// token. Replay clones this stream to reread object bodies by descriptor
    /// while retaining the scanner-owned sink for writer resumption.
    pub(super) fn reader(&self) -> &R {
        &self.reader
    }

    /// Restore the source cursor after a replay reader that shares the same
    /// underlying file descriptor has sought to an object descriptor.
    pub(super) fn restore_cursor(&mut self) -> Result<(), WalError> {
        self.reader
            .seek(SeekFrom::Start(self.offset))
            .map(|_| ())
            .map_err(|source| WalError::Io {
                operation: "restore ASTWAL2 scanner cursor",
                source,
            })
    }

    /// Construct a scanner positioned at the beginning of a WAL stream.
    pub(super) fn new(
        mut reader: R,
        identity: I,
        codec: C,
        limits: WalLimits,
    ) -> Result<Self, WalError> {
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|source| WalError::Io {
                operation: "seek ASTWAL2 scan",
                source,
            })?;
        Ok(Self {
            reader,
            identity,
            codec,
            limits,
            offset: 0,
            next_search_offset: 1,
            last_sequence: None,
            active: None,
            finished: false,
            resume_offset: None,
            _principal: PhantomData,
        })
    }

    /// Emit the next validated descriptor event, or `None` at clean EOF.
    pub(super) fn next_event(&mut self) -> Result<Option<WalEvent>, WalError> {
        if self.finished {
            return Ok(None);
        }
        let record_offset = WalOffset::new(self.offset);
        self.next_search_offset = self.offset.saturating_add(1);
        let mut header = [0_u8; PHYSICAL_HEADER_LEN];
        let header_bytes = read_prefix(&mut self.reader, &mut header)?;
        if header_bytes == 0 {
            return Ok(self.tail_or_end(record_offset, WalTailKind::Incomplete, false));
        }
        if header_bytes < PHYSICAL_HEADER_LEN {
            return Ok(self.tail_or_end(record_offset, WalTailKind::Incomplete, true));
        }
        let Ok(physical) = decode_physical_header(&header, record_offset) else {
            return self.bad_physical(record_offset);
        };
        let payload_len = physical.payload_len;
        let limit = wal_physical_limit(self.limits).length();
        let payload_start = self
            .offset
            .checked_add(
                u64::try_from(PHYSICAL_HEADER_LEN)
                    .map_err(|_| WalError::Encoding("WAL physical header length overflow"))?,
            )
            .ok_or(WalError::LengthOverflow { value: payload_len })?;
        let file_len = stream_len_at(&mut self.reader, payload_start)?;
        let payload_end = payload_start
            .checked_add(payload_len.get())
            .ok_or(WalError::LengthOverflow { value: payload_len })?;
        if payload_end > file_len {
            if has_valid_physical_after(
                &mut self.reader,
                record_offset.get().saturating_add(1),
                self.limits,
            )? {
                return Err(WalError::InteriorCorruption {
                    offset: record_offset,
                    detail: "incomplete WAL record before a later record",
                });
            }
            return Ok(self.tail_or_end(record_offset, WalTailKind::Incomplete, true));
        }
        if payload_len > limit {
            if has_valid_physical_after(
                &mut self.reader,
                record_offset.get().saturating_add(1),
                self.limits,
            )? {
                return Err(WalError::InteriorCorruption {
                    offset: record_offset,
                    detail: "oversized WAL record before a later record",
                });
            }
            return Err(WalError::FrameTooLarge {
                offset: record_offset,
                declared: payload_len,
                limit,
            });
        }
        self.next_search_offset = payload_end;
        let payload_size = payload_len.as_usize()?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_size)
            .map_err(|_| WalError::Encoding("WAL record allocation failed"))?;
        payload.resize(payload_size, 0);
        read_exact_payload(&mut self.reader, &mut payload, record_offset)?;
        self.offset = payload_end;
        if !checksum_valid(physical, &payload) {
            return self.bad_physical(record_offset);
        }
        let record = decode_record_header(&payload, record_offset)?;
        validate_record_version(physical, record, record_offset)?;
        let body = record_body(&payload, record_offset)?;
        validate_logical_body(body, self.limits, record_offset)?;
        self.consume_record(record_offset, payload_end, record, body)
    }

    /// Consume a scanner that reached clean EOF or a truncatable tail.
    pub(super) fn into_scanned(self) -> Result<ScannedWal<R, I, C, P>, WalError> {
        if !self.finished {
            return Err(WalError::InvalidTransaction(
                "WAL scanner has not reached a resume boundary",
            ));
        }
        let append_offset = self.resume_offset.ok_or(WalError::InvalidTransaction(
            "WAL scanner has no resume offset",
        ))?;
        Ok(ScannedWal {
            reader: self.reader,
            identity: self.identity,
            codec: self.codec,
            state: WalResumeState::new(append_offset, self.last_sequence),
            _principal: PhantomData,
        })
    }

    fn consume_record(
        &mut self,
        offset: WalOffset,
        end: u64,
        record: RecordHeader,
        body: &[u8],
    ) -> Result<Option<WalEvent>, WalError> {
        let physical_length = WalLength::new(end.checked_sub(offset.get()).ok_or(
            WalError::LengthOverflow {
                value: WalLength::new(end),
            },
        )?);
        if self.active.is_none() {
            return self.consume_begin(offset, physical_length, record, body);
        }
        let active = self.active.as_ref().ok_or(WalError::InvalidTransaction(
            "WAL active transaction disappeared",
        ))?;
        if record.sequence != active.sequence {
            return Err(WalError::SequenceMismatch {
                expected: active.sequence,
                found: record.sequence,
            });
        }
        if record.ordinal != active.next_ordinal {
            return Err(WalError::OrdinalMismatch {
                expected: active.next_ordinal,
                found: record.ordinal,
            });
        }
        match record.kind {
            WalRecordKind::Begin => Err(WalError::Corrupt {
                offset,
                detail: "WAL Begin appeared inside a transaction",
            }),
            WalRecordKind::Object => {
                self.consume_object(offset, physical_length, record.flags, body)
            },
            WalRecordKind::Root => self.consume_root(offset, physical_length, body),
            WalRecordKind::Commit => self.consume_commit(offset, physical_length, body),
        }
    }

    fn consume_begin(
        &mut self,
        offset: WalOffset,
        _physical_length: WalLength,
        record: RecordHeader,
        body: &[u8],
    ) -> Result<Option<WalEvent>, WalError> {
        if record.kind != WalRecordKind::Begin || record.ordinal != WalOrdinal::new(0) {
            return Err(WalError::Corrupt {
                offset,
                detail: "WAL stream must begin each transaction with ordinal-zero Begin",
            });
        }
        if self
            .last_sequence
            .is_some_and(|last| record.sequence <= last)
        {
            let previous = match self.last_sequence {
                Some(previous) => previous,
                None => record.sequence,
            };
            return Err(WalError::SequenceRegression {
                previous,
                current: record.sequence,
            });
        }
        let (scheme, hints) = decode_begin_body(body, offset)?;
        if self.identity.scheme() != scheme {
            return Err(WalError::IdentitySchemeMismatch);
        }
        let logical_bytes = logical_record_length(body)?;
        let mut digest = new_digest();
        digest_record(
            &mut digest,
            WalRecordKind::Begin,
            record.sequence,
            record.ordinal,
            body,
        )?;
        self.active = Some(ActiveScan {
            begin_offset: offset,
            sequence: record.sequence,
            scheme,
            next_ordinal: WalOrdinal::new(1),
            object_count: WalCount::new(0),
            root_count: WalCount::new(0),
            logical_count: WalCount::new(1),
            logical_bytes,
            digest,
            previous_object: None,
            previous_principal: None,
            saw_root: false,
        });
        Ok(Some(WalEvent::Begin(WalBeginDescriptor {
            offset,
            sequence: record.sequence,
            scheme,
            hints,
        })))
    }

    fn consume_object(
        &mut self,
        offset: WalOffset,
        physical_length: WalLength,
        flags: u8,
        body: &[u8],
    ) -> Result<Option<WalEvent>, WalError> {
        let (scheme, previous, count, logical, saw_root) = {
            let active = self.active.as_ref().ok_or(WalError::InvalidTransaction(
                "WAL object has no active transaction",
            ))?;
            (
                active.scheme,
                active.previous_object,
                active.object_count,
                active.logical_bytes,
                active.saw_root,
            )
        };
        if saw_root {
            return Err(WalError::OrderingViolation);
        }
        let canonical = decode_object_storage_body(body, flags, self.limits, offset)?;
        let (id, body_length) = decode_object_body(&canonical, scheme, &self.identity, offset)?;
        if previous.is_some_and(|previous| previous >= id) {
            return Err(WalError::OrderingViolation);
        }
        let next_count = count
            .checked_inc()
            .ok_or(WalError::CountOverflow { field: "objects" })?;
        let logical_record = logical_record_length(body)?;
        let next_logical = logical
            .checked_add(logical_record)
            .ok_or(WalError::CountOverflow {
                field: "logical bytes",
            })?;
        let active = self.active.as_mut().ok_or(WalError::InvalidTransaction(
            "WAL object transaction disappeared",
        ))?;
        let ordinal = active.next_ordinal;
        let next_ordinal = ordinal
            .checked_next()
            .ok_or(WalError::CountOverflow { field: "ordinals" })?;
        active.object_count = next_count;
        active.logical_bytes = next_logical;
        active.next_ordinal = next_ordinal;
        active.previous_object = Some(id);
        digest_record_with_flags(
            &mut active.digest,
            WalRecordKind::Object,
            flags,
            active.sequence,
            ordinal,
            body,
        )?;
        active.logical_count =
            active
                .logical_count
                .checked_inc()
                .ok_or(WalError::CountOverflow {
                    field: "logical records",
                })?;
        Ok(Some(WalEvent::Object(WalObjectDescriptor {
            offset,
            length: physical_length,
            id,
            logical_bytes: body_length,
        })))
    }

    fn consume_root(
        &mut self,
        offset: WalOffset,
        physical_length: WalLength,
        body: &[u8],
    ) -> Result<Option<WalEvent>, WalError> {
        let (scheme, previous, count, logical) = {
            let active = self.active.as_ref().ok_or(WalError::InvalidTransaction(
                "WAL root has no active transaction",
            ))?;
            (
                active.scheme,
                active.previous_principal.clone(),
                active.root_count,
                active.logical_bytes,
            )
        };
        let (transition, _body_length) = decode_root_body(body, scheme, &self.codec, offset)?;
        if previous
            .as_deref()
            .is_some_and(|previous| previous >= transition.principal())
        {
            return Err(WalError::OrderingViolation);
        }
        let next_count = count
            .checked_inc()
            .ok_or(WalError::CountOverflow { field: "roots" })?;
        let logical_record = logical_record_length(body)?;
        let next_logical = logical
            .checked_add(logical_record)
            .ok_or(WalError::CountOverflow {
                field: "logical bytes",
            })?;
        let active = self.active.as_mut().ok_or(WalError::InvalidTransaction(
            "WAL root transaction disappeared",
        ))?;
        let ordinal = active.next_ordinal;
        let next_ordinal = ordinal
            .checked_next()
            .ok_or(WalError::CountOverflow { field: "ordinals" })?;
        active.root_count = next_count;
        active.logical_bytes = next_logical;
        active.next_ordinal = next_ordinal;
        active.previous_principal = Some(transition.principal().to_vec());
        active.saw_root = true;
        digest_record(
            &mut active.digest,
            WalRecordKind::Root,
            active.sequence,
            ordinal,
            body,
        )?;
        active.logical_count =
            active
                .logical_count
                .checked_inc()
                .ok_or(WalError::CountOverflow {
                    field: "logical records",
                })?;
        Ok(Some(WalEvent::Root(WalRootDescriptor {
            offset,
            length: physical_length,
            transition,
        })))
    }

    fn consume_commit(
        &mut self,
        offset: WalOffset,
        physical_length: WalLength,
        body: &[u8],
    ) -> Result<Option<WalEvent>, WalError> {
        let active = self.active.as_ref().ok_or(WalError::InvalidTransaction(
            "WAL Commit has no active transaction",
        ))?;
        if !active.saw_root {
            return Err(WalError::ZeroRoots);
        }
        let (sequence, logical_count, object_count, root_count, logical_bytes, digest) =
            decode_commit_body(body, offset)?;
        if sequence != active.sequence {
            return Err(WalError::CommitSequenceMismatch {
                expected: active.sequence,
                found: sequence,
            });
        }
        if logical_count != active.logical_count {
            return Err(WalError::CommitCountMismatch {
                field: "logical records",
            });
        }
        if object_count != active.object_count {
            return Err(WalError::CommitCountMismatch { field: "objects" });
        }
        if root_count != active.root_count {
            return Err(WalError::CommitCountMismatch { field: "roots" });
        }
        if logical_bytes != active.logical_bytes {
            return Err(WalError::CommitCountMismatch {
                field: "logical bytes",
            });
        }
        let expected_digest = super::codec::finish_digest(&active.digest);
        if digest != expected_digest {
            return Err(WalError::DigestMismatch);
        }
        let descriptor = WalCommitDescriptor {
            offset,
            length: physical_length,
            sequence,
            logical_count,
            object_count,
            root_count,
            logical_bytes,
            digest,
        };
        let transaction = WalTransactionDescriptor {
            begin_offset: active.begin_offset,
            commit: descriptor,
        };
        self.last_sequence = Some(sequence);
        self.active = None;
        Ok(Some(WalEvent::Commit(transaction)))
    }

    fn bad_physical(&mut self, offset: WalOffset) -> Result<Option<WalEvent>, WalError> {
        if has_valid_physical_after(
            &mut self.reader,
            offset.get().saturating_add(1),
            self.limits,
        )? {
            return Err(WalError::InteriorCorruption {
                offset,
                detail: "invalid WAL physical record before a later record",
            });
        }
        Ok(self.tail_or_end(offset, WalTailKind::InvalidChecksum, true))
    }

    fn tail_or_end(
        &mut self,
        offset: WalOffset,
        kind: WalTailKind,
        force_tail: bool,
    ) -> Option<WalEvent> {
        if self.active.is_some() || force_tail {
            let tail_offset = self
                .active
                .as_ref()
                .map_or(offset, |active| active.begin_offset);
            self.resume_offset = Some(tail_offset);
            self.active = None;
            self.finished = true;
            return Some(WalEvent::Tail(WalScanTail {
                offset: tail_offset,
                kind,
            }));
        }
        self.resume_offset = Some(offset);
        self.finished = true;
        None
    }

    /// Restart owner observation at a physical frame candidate after malformed
    /// evidence. Normal replay never uses this lossy mode.
    pub(super) fn reset_after_malformed_evidence(
        &mut self,
        candidate: u64,
    ) -> Result<(), WalError> {
        self.reader
            .seek(SeekFrom::Start(candidate))
            .map_err(|source| WalError::Io {
                operation: "seek ASTWAL2 owner resynchronization",
                source,
            })?;
        self.offset = candidate;
        self.next_search_offset = candidate.saturating_add(1);
        self.last_sequence = None;
        self.active = None;
        self.finished = false;
        self.resume_offset = None;
        Ok(())
    }

    /// Find the next physical candidate after the current attempted frame.
    pub(super) fn next_physical_candidate(&mut self) -> Result<Option<u64>, WalError> {
        next_valid_physical_after(&mut self.reader, self.next_search_offset, self.limits)
    }
}

fn read_prefix<R: Read>(reader: &mut R, destination: &mut [u8]) -> Result<usize, WalError> {
    let mut read = 0_usize;
    while read < destination.len() {
        let amount = reader
            .read(&mut destination[read..])
            .map_err(|source| WalError::Io {
                operation: "read ASTWAL2 header",
                source,
            })?;
        if amount == 0 {
            break;
        }
        read = read.checked_add(amount).ok_or(WalError::CountOverflow {
            field: "header bytes",
        })?;
    }
    Ok(read)
}

fn read_exact_payload<R: Read>(
    reader: &mut R,
    payload: &mut [u8],
    offset: WalOffset,
) -> Result<(), WalError> {
    let mut read = 0_usize;
    while read < payload.len() {
        let amount = reader
            .read(&mut payload[read..])
            .map_err(|source| WalError::Io {
                operation: "read ASTWAL2 payload",
                source,
            })?;
        if amount == 0 {
            return Err(WalError::Corrupt {
                offset,
                detail: "WAL payload ended unexpectedly",
            });
        }
        read = read.checked_add(amount).ok_or(WalError::CountOverflow {
            field: "payload bytes",
        })?;
    }
    Ok(())
}

fn stream_len_at<R: Seek>(reader: &mut R, restore: u64) -> Result<u64, WalError> {
    let length = reader
        .seek(SeekFrom::End(0))
        .map_err(|source| WalError::Io {
            operation: "read ASTWAL2 length",
            source,
        })?;
    reader
        .seek(SeekFrom::Start(restore))
        .map_err(|source| WalError::Io {
            operation: "restore ASTWAL2 cursor",
            source,
        })?;
    Ok(length)
}

#[allow(
    clippy::too_many_lines,
    reason = "interior physical recovery must keep its bounded byte-stream state together"
)]
fn has_valid_physical_after<R: Read + Seek>(
    reader: &mut R,
    start: u64,
    limits: WalLimits,
) -> Result<bool, WalError> {
    Ok(next_valid_physical_after(reader, start, limits)?.is_some())
}

#[allow(
    clippy::too_many_lines,
    reason = "physical recovery keeps candidate seek, decode, and checksum state together"
)]
fn next_valid_physical_after<R: Read + Seek>(
    mut reader: &mut R,
    start: u64,
    limits: WalLimits,
) -> Result<Option<u64>, WalError> {
    let saved = reader.stream_position().map_err(|source| WalError::Io {
        operation: "save ASTWAL2 cursor",
        source,
    })?;
    let file_len = reader
        .seek(SeekFrom::End(0))
        .map_err(|source| WalError::Io {
            operation: "read ASTWAL2 length",
            source,
        })?;
    let mut candidate = start;
    while candidate < file_len {
        reader
            .seek(SeekFrom::Start(candidate))
            .map_err(|source| WalError::Io {
                operation: "seek ASTWAL2 interior candidate",
                source,
            })?;
        let mut first = [0_u8; 1];
        if !read_probe(&mut reader, &mut first, "read ASTWAL2 interior candidate")? {
            break;
        }
        if first[0] != WAL_MAGIC[0] {
            candidate = candidate.checked_add(1).ok_or(WalError::CountOverflow {
                field: "candidate offsets",
            })?;
            continue;
        }
        let mut header = [0_u8; PHYSICAL_HEADER_LEN];
        header[0] = first[0];
        if !read_probe(
            &mut reader,
            &mut header[1..],
            "read ASTWAL2 interior header",
        )? {
            candidate = candidate.checked_add(1).ok_or(WalError::CountOverflow {
                field: "candidate offsets",
            })?;
            continue;
        }
        let offset = WalOffset::new(candidate);
        let Ok(physical) = super::codec::decode_physical_header(&header, offset) else {
            candidate = candidate.checked_add(1).ok_or(WalError::CountOverflow {
                field: "candidate offsets",
            })?;
            continue;
        };
        let end = candidate
            .checked_add(
                u64::try_from(PHYSICAL_HEADER_LEN)
                    .map_err(|_| WalError::Encoding("WAL physical header length overflow"))?,
            )
            .and_then(|value| value.checked_add(physical.payload_len.get()));
        let Some(end) = end else {
            candidate = candidate.checked_add(1).ok_or(WalError::CountOverflow {
                field: "candidate offsets",
            })?;
            continue;
        };
        if end <= file_len && physical.payload_len > wal_physical_limit(limits).length() {
            reader
                .seek(SeekFrom::Start(saved))
                .map_err(|source| WalError::Io {
                    operation: "restore ASTWAL2 cursor",
                    source,
                })?;
            return Ok(Some(candidate));
        }
        if end > file_len {
            candidate = candidate.checked_add(1).ok_or(WalError::CountOverflow {
                field: "candidate offsets",
            })?;
            continue;
        }
        let Ok(payload_len) = physical.payload_len.as_usize() else {
            candidate = candidate.checked_add(1).ok_or(WalError::CountOverflow {
                field: "candidate offsets",
            })?;
            continue;
        };
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_len)
            .map_err(|_| WalError::Encoding("WAL interior allocation failed"))?;
        payload.resize(payload_len, 0);
        if read_probe(&mut reader, &mut payload, "read ASTWAL2 interior payload")?
            && checksum_valid(physical, &payload)
        {
            reader
                .seek(SeekFrom::Start(saved))
                .map_err(|source| WalError::Io {
                    operation: "restore ASTWAL2 cursor",
                    source,
                })?;
            return Ok(Some(candidate));
        }
        candidate = candidate.checked_add(1).ok_or(WalError::CountOverflow {
            field: "candidate offsets",
        })?;
    }
    reader
        .seek(SeekFrom::Start(saved))
        .map_err(|source| WalError::Io {
            operation: "restore ASTWAL2 cursor",
            source,
        })?;
    Ok(None)
}

fn read_probe<R: Read>(
    reader: &mut R,
    destination: &mut [u8],
    operation: &'static str,
) -> Result<bool, WalError> {
    let mut read = 0_usize;
    while read < destination.len() {
        match reader.read(&mut destination[read..]) {
            Ok(0) => return Ok(false),
            Ok(amount) => {
                read = read.checked_add(amount).ok_or(WalError::CountOverflow {
                    field: "interior probe bytes",
                })?;
            },
            Err(source) if source.kind() == std::io::ErrorKind::Interrupted => {},
            Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(source) => return Err(WalError::Io { operation, source }),
        }
    }
    Ok(true)
}
