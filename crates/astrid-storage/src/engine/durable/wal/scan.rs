use std::io::{Read, Seek, SeekFrom};
use std::marker::PhantomData;

use super::super::{PersistentObjectIdentity, PrincipalCodec};

use super::codec::{
    PHYSICAL_HEADER_LEN, RecordHeader, WAL_MAGIC, checksum_valid, decode_begin_body,
    decode_object_body, decode_object_storage_body, decode_physical_header, decode_record,
    decode_root_body, new_digest, update_digest, validate_logical_body, validate_record_version,
    wal_physical_limit,
};
use super::measured_record::{DataKind, Measured};
use super::physical_wire::{Extent, extent};
use super::types::{
    WalBeginDescriptor, WalError, WalEvent, WalLength, WalLimits, WalObjectDescriptor, WalOffset,
    WalOrdinal, WalRecordKind, WalResumeState, WalRootDescriptor, WalScanTail, WalSequence,
    WalTailKind, WalTransactionDescriptor,
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
    counts: super::commit_wire::Counts,
    digest: blake3::Hasher,
    previous_object: Option<crate::storage_model::ObjectId>,
    previous_principal: Option<Vec<u8>>,
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
        let mut header = [0_u8; PHYSICAL_HEADER_LEN];
        let mut input = FrameInput {
            reader: &mut self.reader,
            purpose: ReadPurpose::Header,
        };
        let header_bytes = super::read_buffer::fill(&mut input, &mut header)?;
        if header_bytes == 0 {
            return Ok(self.tail_or_end(record_offset, WalTailKind::Incomplete, false));
        }
        if header_bytes < PHYSICAL_HEADER_LEN {
            return Ok(self.tail_or_end(record_offset, WalTailKind::Incomplete, true));
        }
        let Ok(physical) = decode_physical_header(&header, record_offset) else {
            return self.bad_physical(record_offset);
        };
        let payload_len = physical.payload_len();
        let limit = wal_physical_limit(self.limits).length();
        let payload_start = super::physical_wire::payload_start(record_offset.get())
            .ok_or(WalError::LengthOverflow { value: payload_len })?;
        let file_len = stream_len_at(&mut input, payload_start)?;
        let payload_end = match extent(
            payload_start,
            physical.payload_len().get(),
            file_len,
            limit.get(),
        ) {
            Extent::Complete(end) => end,
            Extent::Overflow => return Err(WalError::LengthOverflow { value: payload_len }),
            Extent::Incomplete => {
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
            },
            Extent::Oversized => {
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
            },
        };
        let payload_size = payload_len.as_usize()?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_size)
            .map_err(|_| WalError::Encoding("WAL record allocation failed"))?;
        payload.resize(payload_size, 0);
        input.purpose = ReadPurpose::Payload;
        let integrity = super::read_buffer::read_payload(
            &mut input,
            &mut payload,
            physical,
            super::super::format::frame_checksum,
        )?;
        if matches!(integrity, super::read_buffer::Payload::Short) {
            return Err(WalError::Corrupt {
                offset: record_offset,
                detail: "WAL payload ended unexpectedly",
            });
        }
        self.offset = payload_end;
        if matches!(integrity, super::read_buffer::Payload::BadChecksum) {
            return self.bad_physical(record_offset);
        }
        let (record, body) = decode_record(&payload, record_offset)?;
        validate_record_version(physical, record, record_offset)?;
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
        let body = super::record_wire::body_at_position(
            body,
            record.sequence.get(),
            record.ordinal.get(),
            active.sequence.get(),
            active.counts.logical,
        )
        .map_err(|error| match error {
            super::record_wire::PositionError::Sequence => WalError::SequenceMismatch {
                expected: active.sequence,
                found: record.sequence,
            },
            super::record_wire::PositionError::Ordinal => WalError::OrdinalMismatch {
                expected: WalOrdinal::new(active.counts.logical),
                found: record.ordinal,
            },
        })?;
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
        let measured =
            Measured::begin(record.sequence.get(), body).map_err(|_| WalError::CountOverflow {
                field: "logical bytes",
            })?;
        let mut digest = new_digest();
        let (counts, ()) = measured.observe(update_digest(&mut digest));
        self.active = Some(ActiveScan {
            begin_offset: offset,
            sequence: record.sequence,
            scheme,
            counts,
            digest,
            previous_object: None,
            previous_principal: None,
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
        let active = self.active.as_mut().ok_or(WalError::InvalidTransaction(
            "WAL object has no active transaction",
        ))?;
        let scheme = active.scheme;
        let previous = active.previous_object;
        if active.counts.roots != 0 {
            return Err(WalError::OrderingViolation);
        }
        let (encoding, canonical) = decode_object_storage_body(body, flags, self.limits, offset)?;
        let (id, body_length) = decode_object_body(&canonical, scheme, &self.identity, offset)?;
        if previous.is_some_and(|previous| previous >= id) {
            return Err(WalError::OrderingViolation);
        }
        let measured =
            Measured::append(active.counts, DataKind::Object(encoding), body).map_err(|error| {
                WalError::CountOverflow {
                    field: error.field("ordinals"),
                }
            })?;
        let (counts, ()) = measured.observe(update_digest(&mut active.digest));
        active.counts = counts;
        active.previous_object = Some(id);
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
        let active = self.active.as_mut().ok_or(WalError::InvalidTransaction(
            "WAL root has no active transaction",
        ))?;
        let scheme = active.scheme;
        let previous = active.previous_principal.as_deref();
        let (transition, _body_length) = decode_root_body(body, scheme, &self.codec, offset)?;
        if !super::root_history::follows(previous, transition.principal()) {
            return Err(WalError::OrderingViolation);
        }
        let measured = Measured::append(active.counts, DataKind::Root, body).map_err(|error| {
            WalError::CountOverflow {
                field: error.field("ordinals"),
            }
        })?;
        let (counts, ()) = measured.observe(update_digest(&mut active.digest));
        active.counts = counts;
        active.previous_principal = Some(transition.principal().to_vec());
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
        if active.counts.roots == 0 {
            return Err(WalError::ZeroRoots);
        }
        let marker = super::commit_wire::decode(body).ok_or(WalError::Corrupt {
            offset,
            detail: "WAL Commit body length is invalid",
        })?;
        let sequence = WalSequence::new(marker.counts.sequence).ok_or(WalError::Corrupt {
            offset,
            detail: "WAL Commit sequence is zero",
        })?;
        let checked = marker
            .confirm(&active.counts, || {
                *super::codec::finish_digest(&active.digest).as_bytes()
            })
            .map_err(|mismatch| match mismatch {
                super::commit_wire::Mismatch::Digest => WalError::DigestMismatch,
                super::commit_wire::Mismatch::Sequence => WalError::CommitSequenceMismatch {
                    expected: active.sequence,
                    found: sequence,
                },
                super::commit_wire::Mismatch::Logical => WalError::CommitCountMismatch {
                    field: "logical records",
                },
                super::commit_wire::Mismatch::Objects => {
                    WalError::CommitCountMismatch { field: "objects" }
                },
                super::commit_wire::Mismatch::Roots => {
                    WalError::CommitCountMismatch { field: "roots" }
                },
                super::commit_wire::Mismatch::Bytes => WalError::CommitCountMismatch {
                    field: "logical bytes",
                },
            })?;
        let transaction = WalTransactionDescriptor {
            begin_offset: active.begin_offset,
            offset,
            length: physical_length,
            marker: checked,
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
        use super::interior::{Boundary, boundary};
        let active_begin = self.active.as_ref().map(|active| active.begin_offset.get());
        self.finished = true;
        match boundary(active_begin, offset.get(), force_tail) {
            Boundary::Tail(begin) => {
                let offset = WalOffset::new(begin);
                self.resume_offset = Some(offset);
                self.active = None;
                Some(WalEvent::Tail(WalScanTail { offset, kind }))
            },
            Boundary::End(end) => {
                self.resume_offset = Some(WalOffset::new(end));
                None
            },
        }
    }
}

#[derive(Clone, Copy)]
enum ReadPurpose {
    Header,
    Payload,
    Interior(&'static str),
}

struct FrameInput<'a, R> {
    reader: &'a mut R,
    purpose: ReadPurpose,
}

impl<R: Read> super::read_buffer::Source for FrameInput<'_, R> {
    type Error = WalError;

    fn read_part(&mut self, destination: &mut [u8]) -> Result<usize, WalError> {
        let (operation, field) = match self.purpose {
            ReadPurpose::Header => ("read ASTWAL2 header", "header bytes"),
            ReadPurpose::Payload => ("read ASTWAL2 payload", "payload bytes"),
            ReadPurpose::Interior(operation) => (operation, "interior probe bytes"),
        };
        loop {
            match self.reader.read(destination) {
                Ok(n) if n <= destination.len() => return Ok(n),
                Ok(_) => return Err(WalError::CountOverflow { field }),
                Err(source)
                    if matches!(self.purpose, ReadPurpose::Interior(_))
                        && source.kind() == std::io::ErrorKind::Interrupted => {},
                Err(source) => return Err(WalError::Io { operation, source }),
            }
        }
    }
}

impl<R: Read + Seek> super::read_buffer::Positioned for FrameInput<'_, R> {
    type SeekError = std::io::Error;

    fn seek_end(&mut self) -> Result<u64, Self::SeekError> {
        self.reader.seek(SeekFrom::End(0))
    }

    fn seek_start(&mut self, offset: u64) -> Result<(), Self::SeekError> {
        self.reader.seek(SeekFrom::Start(offset)).map(|_| ())
    }
}

fn stream_len_at<R: Read + Seek>(
    input: &mut FrameInput<'_, R>,
    restore: u64,
) -> Result<u64, WalError> {
    use super::read_buffer::LengthError;
    super::read_buffer::length_at(input, restore).map_err(|error| match error {
        LengthError::End(source) => WalError::Io {
            operation: "read ASTWAL2 length",
            source,
        },
        LengthError::Restore(source) => WalError::Io {
            operation: "restore ASTWAL2 cursor",
            source,
        },
    })
}

fn has_valid_physical_after<R: Read + Seek>(
    reader: &mut R,
    start: u64,
    limits: WalLimits,
) -> Result<bool, WalError> {
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
    let (reader, result) = super::interior::search(reader, start, file_len, |reader, offset| {
        let probe = probe_candidate(reader, offset, file_len, limits);
        (reader, probe)
    });
    let found = result.map_err(|(_, error)| error)?;
    reader
        .seek(SeekFrom::Start(saved))
        .map_err(|source| WalError::Io {
            operation: "restore ASTWAL2 cursor",
            source,
        })?;
    Ok(found.is_some())
}

fn probe_candidate<R: Read + Seek>(
    reader: &mut R,
    candidate: u64,
    file_len: u64,
    limits: WalLimits,
) -> Result<super::interior::Probe, WalError> {
    use super::interior::Probe;
    reader
        .seek(SeekFrom::Start(candidate))
        .map_err(|source| WalError::Io {
            operation: "seek ASTWAL2 interior candidate",
            source,
        })?;
    let mut header = [0u8; PHYSICAL_HEADER_LEN];
    if !read_probe(reader, &mut header[..1], "read ASTWAL2 interior candidate")? {
        return Ok(Probe::End);
    }
    if header[0] != WAL_MAGIC[0]
        || !read_probe(reader, &mut header[1..], "read ASTWAL2 interior header")?
    {
        return Ok(Probe::Miss);
    }
    let Ok(physical) = decode_physical_header(&header, WalOffset::new(candidate)) else {
        return Ok(Probe::Miss);
    };
    let Some(start) = super::physical_wire::payload_start(candidate) else {
        return Ok(Probe::Miss);
    };
    match extent(
        start,
        physical.payload_len().get(),
        file_len,
        wal_physical_limit(limits).length().get(),
    ) {
        Extent::Oversized => return Ok(Probe::Found),
        Extent::Overflow | Extent::Incomplete => return Ok(Probe::Miss),
        Extent::Complete(_) => {},
    }
    let Ok(size) = physical.payload_len().as_usize() else {
        return Ok(Probe::Miss);
    };
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(size)
        .map_err(|_| WalError::Encoding("WAL interior allocation failed"))?;
    payload.resize(size, 0);
    if read_probe(reader, &mut payload, "read ASTWAL2 interior payload")?
        && checksum_valid(physical, &payload)
    {
        Ok(Probe::Found)
    } else {
        Ok(Probe::Miss)
    }
}

fn read_probe<R: Read>(
    reader: &mut R,
    destination: &mut [u8],
    operation: &'static str,
) -> Result<bool, WalError> {
    let mut input = FrameInput {
        reader,
        purpose: ReadPurpose::Interior(operation),
    };
    match super::read_buffer::fill(&mut input, destination) {
        Ok(filled) => Ok(filled == destination.len()),
        Err(WalError::Io { source, .. }) if source.kind() == std::io::ErrorKind::UnexpectedEof => {
            Ok(false)
        },
        Err(error) => Err(error),
    }
}
