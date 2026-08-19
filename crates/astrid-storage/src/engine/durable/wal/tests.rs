#![allow(
    clippy::arithmetic_side_effects,
    reason = "tests construct fixed wire images and bounded fault-injection offsets"
)]
#![allow(
    clippy::too_many_lines,
    reason = "raw test transaction builders keep deterministic wire fixtures together"
)]

use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use super::codec::RECORD_HEADER_LEN;
use super::*;
use crate::engine::durable::format::{encode_object_frame, frame_checksum};
use crate::engine::durable::roots::encode_root_record;
use crate::engine::durable::{
    IdentityScheme, PersistentObjectIdentity, PrincipalCodec, RecoveryLimits,
};
use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity, ObjectKind,
};
use crate::storage_model::{ObjectRecord, RootGeneration, RootState};

#[derive(Clone, Copy)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut bytes = [0_u8; 32];
        if record.canonical_bytes().len() >= 8 {
            bytes[..8].copy_from_slice(&record.canonical_bytes()[..8]);
        }
        ObjectId::new(bytes)
    }
}

impl PersistentObjectIdentity for TestIdentity {
    fn scheme(&self) -> IdentityScheme {
        scheme()
    }
}

#[derive(Clone, Copy)]
struct AlternateIdentity;

impl ObjectIdentity for AlternateIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        TestIdentity.identify(record)
    }
}

impl PersistentObjectIdentity for AlternateIdentity {
    fn scheme(&self) -> IdentityScheme {
        IdentityScheme::new(2, 1).unwrap()
    }
}

#[derive(Clone, Copy)]
struct TestCodec;

impl PrincipalCodec<String> for TestCodec {
    fn encode(&self, principal: &String) -> Vec<u8> {
        principal.as_bytes().to_vec()
    }

    fn decode(&self, bytes: &[u8]) -> Option<String> {
        String::from_utf8(bytes.to_vec()).ok()
    }
}

#[derive(Default)]
struct CountingSink {
    bytes: Vec<u8>,
    position: usize,
    seeks: usize,
    syncs: usize,
    fail_sync: bool,
    fail_after: Option<usize>,
}

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(limit) = self.fail_after {
            if self.bytes.len() >= limit {
                return Err(io::Error::other("injected write failure"));
            }
            let allowed = limit.saturating_sub(self.bytes.len()).min(bytes.len());
            self.bytes.extend_from_slice(&bytes[..allowed]);
            self.position = self.position.saturating_add(allowed);
            if allowed < bytes.len() {
                return Err(io::Error::other("injected partial write"));
            }
            return Ok(allowed);
        }
        self.bytes.extend_from_slice(bytes);
        self.position = self.position.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for CountingSink {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.seeks = self.seeks.saturating_add(1);
        let next = match position {
            SeekFrom::Start(value) => value,
            SeekFrom::Current(value) => {
                let current = i128::try_from(self.position).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "position overflow")
                })?;
                let next = current.checked_add(i128::from(value)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "position overflow")
                })?;
                u64::try_from(next)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "position overflow"))?
            },
            SeekFrom::End(value) => {
                let current = i128::try_from(self.bytes.len())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length overflow"))?;
                let next = current.checked_add(i128::from(value)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "position overflow")
                })?;
                u64::try_from(next)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "position overflow"))?
            },
        };
        self.position = usize::try_from(next)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "position overflow"))?;
        Ok(next)
    }
}

impl WalSink for CountingSink {
    fn sync_data(&mut self) -> io::Result<()> {
        self.syncs = self.syncs.saturating_add(1);
        if self.fail_sync {
            Err(io::Error::other("injected sync failure"))
        } else {
            Ok(())
        }
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        let length = usize::try_from(len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length overflow"))?;
        self.bytes.resize(length, 0);
        self.position = self.position.min(length);
        Ok(())
    }
}

impl WalSink for Cursor<Vec<u8>> {
    fn sync_data(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        let length = usize::try_from(len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length overflow"))?;
        self.get_mut().resize(length, 0);
        self.set_position(self.position().min(len));
        Ok(())
    }
}

#[derive(Default)]
struct DiscardSink {
    position: u64,
    written: u64,
}

impl Write for DiscardSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length overflow"))?;
        self.position = self
            .position
            .checked_add(length)
            .ok_or_else(|| io::Error::other("position overflow"))?;
        self.written = self
            .written
            .checked_add(length)
            .ok_or_else(|| io::Error::other("written overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for DiscardSink {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => value,
            SeekFrom::Current(value) => {
                let current = i128::from(self.position);
                let next = current.checked_add(i128::from(value)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "position overflow")
                })?;
                u64::try_from(next)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "position overflow"))?
            },
            SeekFrom::End(value) => {
                let current = i128::from(self.position);
                let next = current.checked_add(i128::from(value)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "position overflow")
                })?;
                u64::try_from(next)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "position overflow"))?
            },
        };
        self.position = next;
        Ok(next)
    }
}

impl WalSink for DiscardSink {
    fn sync_data(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.position = len;
        Ok(())
    }
}

struct FailingProbeReader {
    inner: Cursor<Vec<u8>>,
    fail_from: u64,
}

impl Read for FailingProbeReader {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }
        let position = self.inner.position();
        if position >= self.fail_from {
            return Err(io::Error::other("injected interior probe read failure"));
        }
        let available = usize::try_from(self.fail_from - position)
            .unwrap_or(destination.len())
            .min(destination.len());
        self.inner.read(&mut destination[..available])
    }
}

impl Seek for FailingProbeReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

fn scheme() -> IdentityScheme {
    IdentityScheme::new(1, 1).unwrap()
}

fn new_writer<S: WalSink>(
    sink: S,
    limits: RecoveryLimits,
) -> WalWriter<S, TestIdentity, TestCodec, String> {
    WalWriter::new(sink, TestIdentity, TestCodec, limits).unwrap()
}

fn sequence(value: u64) -> WalSequence {
    WalSequence::new(value).unwrap()
}

fn record(value: u64, payload_len: usize) -> ObjectRecord {
    let mut payload = value.to_be_bytes().to_vec();
    payload.resize(payload_len.max(8), 0);
    ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        payload,
        Vec::new(),
        u64::try_from(payload_len.max(8)).unwrap(),
        ObjectClass::Data,
    )
    .unwrap()
}

fn object_id(value: u64) -> ObjectId {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    ObjectId::new(bytes)
}

fn root(value: u64) -> RootState {
    RootState {
        generation: RootGeneration::INITIAL,
        commit: object_id(value),
    }
}

fn writer_with_transaction(
    sequence_value: u64,
    hints: Option<WalBeginHints>,
) -> (Vec<u8>, CountingSink) {
    let mut writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(sequence_value), hints).unwrap();
    writer.append_object(object_id(1), &record(1, 8)).unwrap();
    writer
        .append_root(&"alice".to_owned(), None, root(100))
        .unwrap();
    writer.finish_commit().unwrap();
    let sink = writer.into_inner();
    (sink.bytes.clone(), sink)
}

fn raw_transaction(
    sequence_value: u64,
    object_id_value: Option<ObjectId>,
    principal: &[u8],
    include_root: bool,
) -> Vec<u8> {
    let sequence = sequence(sequence_value);
    let begin_body = super::codec::encode_begin_body(scheme(), None).unwrap();
    let object_body = encode_object_frame(
        scheme(),
        object_id_value.unwrap_or_else(|| object_id(1)),
        &record(1, 8),
    )
    .unwrap();
    let root_body = encode_root_record(scheme(), principal, None, root(100)).unwrap();
    let mut digest = super::codec::new_digest();
    let mut logical_count = WalCount::new(1);
    let mut logical_bytes = super::codec::logical_record_length(&begin_body).unwrap();
    super::codec::digest_record(
        &mut digest,
        WalRecordKind::Begin,
        sequence,
        WalOrdinal::new(0),
        &begin_body,
    )
    .unwrap();
    let mut bytes = super::codec::encode_physical_record(
        WalRecordKind::Begin,
        sequence,
        WalOrdinal::new(0),
        &begin_body,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let mut ordinal = WalOrdinal::new(1);
    let mut object_count = WalCount::new(0);
    if object_id_value.is_some() {
        super::codec::digest_record(
            &mut digest,
            WalRecordKind::Object,
            sequence,
            ordinal,
            &object_body,
        )
        .unwrap();
        logical_count = logical_count.checked_inc().unwrap();
        logical_bytes = logical_bytes
            .checked_add(super::codec::logical_record_length(&object_body).unwrap())
            .unwrap();
        object_count = object_count.checked_inc().unwrap();
        bytes.extend(
            super::codec::encode_physical_record(
                WalRecordKind::Object,
                sequence,
                ordinal,
                &object_body,
                RecoveryLimits::process_addressable(),
            )
            .unwrap(),
        );
        ordinal = ordinal.checked_next().unwrap();
    }
    let root_count = if include_root {
        super::codec::digest_record(
            &mut digest,
            WalRecordKind::Root,
            sequence,
            ordinal,
            &root_body,
        )
        .unwrap();
        logical_count = logical_count.checked_inc().unwrap();
        logical_bytes = logical_bytes
            .checked_add(super::codec::logical_record_length(&root_body).unwrap())
            .unwrap();
        bytes.extend(
            super::codec::encode_physical_record(
                WalRecordKind::Root,
                sequence,
                ordinal,
                &root_body,
                RecoveryLimits::process_addressable(),
            )
            .unwrap(),
        );
        WalCount::new(1)
    } else {
        WalCount::new(0)
    };
    if include_root {
        ordinal = ordinal.checked_next().unwrap();
    }
    let commit_body = super::codec::encode_commit_body(
        sequence,
        logical_count,
        object_count,
        root_count,
        logical_bytes,
        super::codec::finish_digest(&digest),
    );
    bytes.extend(
        super::codec::encode_physical_record(
            WalRecordKind::Commit,
            sequence,
            ordinal,
            &commit_body,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    bytes
}

fn mutate_record(bytes: &mut [u8], index: usize, mutate: impl FnOnce(&mut [u8])) {
    let offset = physical_record_offset(bytes, index);
    let payload_len = usize::try_from(u64::from_le_bytes(
        bytes[offset + 12..offset + 20].try_into().unwrap(),
    ))
    .unwrap();
    let payload_start = offset + 52;
    let payload_end = payload_start + payload_len;
    mutate(&mut bytes[payload_start..payload_end]);
    let checksum = frame_checksum(
        super::codec::WAL_MAGIC,
        u64::try_from(payload_len).unwrap(),
        &bytes[payload_start..payload_end],
    );
    bytes[offset + 20..offset + 52].copy_from_slice(&checksum);
}

fn physical_record_offset(bytes: &[u8], index: usize) -> usize {
    let mut offset = 0_usize;
    for current in 0..=index {
        let payload_len = usize::try_from(u64::from_le_bytes(
            bytes[offset + 12..offset + 20].try_into().unwrap(),
        ))
        .unwrap();
        if current == index {
            return offset;
        }
        offset = offset + 52 + payload_len;
    }
    unreachable!("requested WAL record exists")
}

fn corrupt_record_checksum(bytes: &mut [u8], index: usize) {
    let mut offset = 0_usize;
    for current in 0..=index {
        let payload_len = usize::try_from(u64::from_le_bytes(
            bytes[offset + 12..offset + 20].try_into().unwrap(),
        ))
        .unwrap();
        let payload_start = offset + 52;
        let payload_end = payload_start + payload_len;
        if current == index {
            bytes[payload_start] ^= 1;
            return;
        }
        offset = payload_end;
    }
}

fn scan_events(bytes: Vec<u8>) -> Result<Vec<WalEvent>, WalError> {
    let mut scanner = WalScanner::new(
        Cursor::new(bytes),
        TestIdentity,
        TestCodec,
        RecoveryLimits::process_addressable(),
    )?;
    let mut events = Vec::new();
    while let Some(event) = scanner.next_event()? {
        events.push(event);
    }
    Ok(events)
}

fn scan_events_with_limits(
    bytes: Vec<u8>,
    limits: RecoveryLimits,
) -> Result<Vec<WalEvent>, WalError> {
    let mut scanner = WalScanner::new(Cursor::new(bytes), TestIdentity, TestCodec, limits)?;
    let mut events = Vec::new();
    while let Some(event) = scanner.next_event()? {
        events.push(event);
    }
    Ok(events)
}

fn scan_events_with_identity<I: PersistentObjectIdentity>(
    bytes: Vec<u8>,
    identity: I,
) -> Result<Vec<WalEvent>, WalError> {
    let mut scanner = WalScanner::new(
        Cursor::new(bytes),
        identity,
        TestCodec,
        RecoveryLimits::process_addressable(),
    )?;
    let mut events = Vec::new();
    while let Some(event) = scanner.next_event()? {
        events.push(event);
    }
    Ok(events)
}

type TestScannedWal = ScannedWal<Cursor<Vec<u8>>, TestIdentity, TestCodec, String>;

fn scan_events_and_state(bytes: Vec<u8>) -> Result<(Vec<WalEvent>, TestScannedWal), WalError> {
    let mut scanner = WalScanner::new(
        Cursor::new(bytes),
        TestIdentity,
        TestCodec,
        RecoveryLimits::process_addressable(),
    )?;
    let mut events = Vec::new();
    while let Some(event) = scanner.next_event()? {
        events.push(event);
    }
    let finished = scanner.into_scanned()?;
    Ok((events, finished))
}

#[test]
fn round_trip_streams_descriptors_and_ignores_hints() {
    let hints = Some(WalBeginHints::new(
        WalCount::new(999),
        WalCount::new(999),
        WalLength::new(u64::MAX),
    ));
    let (bytes, sink) = writer_with_transaction(1, hints);
    assert_eq!(sink.syncs, 0);
    let events = scan_events(bytes).unwrap();
    assert!(matches!(events.first(), Some(WalEvent::Begin(_))));
    assert!(matches!(events.get(1), Some(WalEvent::Object(_))));
    assert!(matches!(events.get(2), Some(WalEvent::Root(_))));
    assert!(matches!(events.get(3), Some(WalEvent::Commit(_))));
}

#[test]
fn compressed_object_round_trip_preserves_canonical_length_and_legacy_records() {
    let record = record(1, 4096);
    let canonical = encode_object_frame(scheme(), object_id(1), &record).unwrap();
    let mut writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(1), None).unwrap();
    let descriptor = writer.append_object(object_id(1), &record).unwrap();
    assert_eq!(descriptor.logical_bytes.get(), canonical.len() as u64);
    writer
        .append_root(&"alice".to_owned(), None, root(100))
        .unwrap();
    writer.finish_commit().unwrap();
    let mut compressed = writer.into_inner().bytes;
    let object_offset = physical_record_offset(&compressed, 1);
    assert_eq!(
        u16::from_le_bytes(
            compressed[object_offset + 8..object_offset + 10]
                .try_into()
                .unwrap()
        ),
        2,
        "compressed Object records must advertise their forward-only physical version"
    );
    mutate_record(&mut compressed, 1, |payload| {
        assert_eq!(payload[1], super::codec::OBJECT_FLAG_LZ4);
        assert!(payload.len() < canonical.len() + RECORD_HEADER_LEN);
    });
    assert!(scan_events(compressed).unwrap().iter().any(|event| {
        matches!(event, WalEvent::Object(object) if object.logical_bytes == descriptor.logical_bytes)
    }));

    // The original flags-zero grammar remains accepted byte-for-byte.
    assert!(scan_events(raw_transaction(2, Some(object_id(1)), b"alice", true)).is_ok());
}

#[test]
fn compressed_object_flag_changes_transaction_digest() {
    let body = b"same stored bytes";
    let mut legacy = super::codec::new_digest();
    super::codec::digest_record(
        &mut legacy,
        WalRecordKind::Object,
        sequence(1),
        WalOrdinal::new(1),
        body,
    )
    .unwrap();
    let mut compressed = super::codec::new_digest();
    super::codec::digest_record_with_flags(
        &mut compressed,
        WalRecordKind::Object,
        super::codec::OBJECT_FLAG_LZ4,
        sequence(1),
        WalOrdinal::new(1),
        body,
    )
    .unwrap();
    assert_ne!(
        super::codec::finish_digest(&legacy),
        super::codec::finish_digest(&compressed),
        "Commit.digest must bind the Object decoding mode"
    );
}

#[test]
fn incompressible_object_falls_back_to_flags_zero() {
    let canonical = *blake3::hash(b"bounded incompressible WAL body").as_bytes();
    let (flags, stored) = super::codec::encode_object_storage_body(&canonical).unwrap();
    assert_eq!(flags, 0);
    assert_eq!(stored.as_ref(), canonical);
}

#[test]
fn compressed_object_rejects_corruption_and_oversized_declaration() {
    let canonical = encode_object_frame(scheme(), object_id(1), &record(1, 4096)).unwrap();
    let (flags, stored) = super::codec::encode_object_storage_body(&canonical).unwrap();
    assert_eq!(flags, super::codec::OBJECT_FLAG_LZ4);

    let mut corrupt = stored.into_owned();
    corrupt[..8].copy_from_slice(&(u64::try_from(canonical.len()).unwrap() - 1).to_le_bytes());
    assert!(matches!(
        super::codec::decode_object_storage_body(
            &corrupt,
            flags,
            RecoveryLimits::process_addressable(),
            WalOffset::new(0),
        ),
        Err(WalError::Corrupt { .. })
    ));

    let limits = RecoveryLimits::new(128).unwrap();
    let mut oversized = vec![0_u8; 9];
    oversized[..8].copy_from_slice(&129_u64.to_le_bytes());
    assert!(matches!(
        super::codec::decode_object_storage_body(&oversized, flags, limits, WalOffset::new(0),),
        Err(WalError::FrameTooLarge { .. })
    ));
}

#[test]
fn finish_does_not_sync_and_publish_syncs_once_for_two_transactions() {
    let mut writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(1), None).unwrap();
    writer
        .append_root(&"alice".to_owned(), None, root(100))
        .unwrap();
    writer.finish_commit().unwrap();
    writer.begin(sequence(2), None).unwrap();
    writer
        .append_root(&"bob".to_owned(), None, root(101))
        .unwrap();
    writer.finish_commit().unwrap();
    assert_eq!(writer.pending_publications(), 2);
    assert_eq!(writer.publish().unwrap(), 2);
    let sink = writer.into_inner();
    assert_eq!(
        sink.seeks, 1,
        "record appends must not seek or flush buffers"
    );
    assert_eq!(sink.syncs, 1);
}

#[test]
fn prepared_object_fast_path_checks_declared_identity() {
    let mut writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(1), None).unwrap();
    let id = object_id(1);
    let frame = encode_object_frame(scheme(), id, &record(1, 8)).unwrap();
    assert!(matches!(
        writer.append_prepared_object(object_id(2), &frame),
        Err(WalError::ObjectIdentityMismatch { .. })
    ));
    writer.append_prepared_object(id, &frame).unwrap();
    writer
        .append_root(&"alice".to_owned(), None, root(100))
        .unwrap();
    writer.finish_commit().unwrap();
    assert_eq!(writer.publish().unwrap(), 1);
}

#[test]
fn new_writer_rejects_nonempty_sink() {
    assert!(matches!(
        WalWriter::new(
            Cursor::new(b"existing WAL bytes".to_vec()),
            TestIdentity,
            TestCodec,
            RecoveryLimits::process_addressable(),
        ),
        Err(WalError::InvalidTransaction(_))
    ));
}

#[test]
fn resume_seeds_sequence_and_rejects_regression() {
    let (bytes, _) = writer_with_transaction(5, None);
    let (_, scanned) = scan_events_and_state(bytes).unwrap();
    let mut writer = scanned
        .into_writer(RecoveryLimits::process_addressable())
        .unwrap();
    assert!(matches!(
        writer.begin(sequence(5), None),
        Err(WalError::SequenceRegression { .. })
    ));
    writer.begin(sequence(6), None).unwrap();
    writer
        .append_root(&"alice".to_owned(), None, root(106))
        .unwrap();
    writer.finish_commit().unwrap();
}

#[test]
fn scanner_rejects_mixed_identity_scheme_and_resume_owns_identity() {
    let (bytes, _) = writer_with_transaction(5, None);
    assert!(matches!(
        scan_events_with_identity(bytes.clone(), AlternateIdentity),
        Err(WalError::IdentitySchemeMismatch)
    ));

    let (_, finished) = scan_events_and_state(bytes).unwrap();
    let mut writer = finished
        .into_writer(RecoveryLimits::process_addressable())
        .unwrap();
    writer.begin(sequence(6), None).unwrap();
    writer
        .append_root(&"alice".to_owned(), None, root(106))
        .unwrap();
    writer.finish_commit().unwrap();
}

#[test]
fn resume_tail_truncates_at_begin_before_new_transaction() {
    let (first, _) = writer_with_transaction(1, None);
    let mut tail_writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    tail_writer.begin(sequence(2), None).unwrap();
    tail_writer
        .append_root(&"alice".to_owned(), None, root(102))
        .unwrap();
    let tail = tail_writer.into_inner().bytes;
    let mut image = first.clone();
    image.extend_from_slice(&tail[..tail.len() / 2]);
    let begin_offset = u64::try_from(first.len()).unwrap();

    let mut scanner = WalScanner::new(
        Cursor::new(image.clone()),
        TestIdentity,
        TestCodec,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    while let Some(event) = scanner.next_event().unwrap() {
        if matches!(event, WalEvent::Tail(_)) {
            break;
        }
    }
    let finished = scanner.into_scanned().unwrap();
    assert_eq!(
        finished.reader().get_ref().len(),
        usize::try_from(begin_offset + u64::try_from(tail.len() / 2).unwrap()).unwrap()
    );
    let mut writer = finished
        .into_writer(RecoveryLimits::process_addressable())
        .unwrap();
    writer.begin(sequence(3), None).unwrap();
    writer
        .append_root(&"alice".to_owned(), None, root(103))
        .unwrap();
    writer.finish_commit().unwrap();
    let final_bytes = writer.into_inner().into_inner();
    let (events, _) = scan_events_and_state(final_bytes).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, WalEvent::Commit(_)))
            .count(),
        2
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, WalEvent::Tail(_)))
    );
}

#[test]
fn writer_rejects_zero_root_and_impossible_generation() {
    let mut writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(1), None).unwrap();
    assert!(matches!(writer.finish_commit(), Err(WalError::ZeroRoots)));
    assert!(matches!(
        writer.append_root(
            &"alice".to_owned(),
            None,
            RootState {
                generation: RootGeneration::new(1),
                commit: object_id(1),
            },
        ),
        Err(WalError::InvalidTransaction(_))
    ));
}

#[test]
fn checksum_bad_final_tail_is_truncatable_but_interior_bad_is_fatal() {
    let (first, _) = writer_with_transaction(1, None);
    let (mut second, _) = writer_with_transaction(2, None);
    corrupt_record_checksum(&mut second, 3);
    let mut final_image = first.clone();
    final_image.extend_from_slice(&second);
    let events = scan_events(final_image).unwrap();
    assert!(matches!(events.last(), Some(WalEvent::Tail(_))));

    let (third, _) = writer_with_transaction(3, None);
    let mut interior = first;
    interior.extend_from_slice(&second);
    interior.extend_from_slice(&third);
    assert!(matches!(
        scan_events(interior),
        Err(WalError::InteriorCorruption { .. })
    ));
}

#[test]
fn torn_active_transaction_reports_begin_offset() {
    let (first, _) = writer_with_transaction(1, None);
    let mut writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(2), None).unwrap();
    writer
        .append_object(object_id(2), &record(2, 4096))
        .unwrap();
    writer
        .append_root(&"alice".to_owned(), None, root(102))
        .unwrap();
    let second = writer.into_inner().bytes;
    let begin_offset = u64::try_from(first.len()).unwrap();
    let mut image = first;
    image.extend_from_slice(&second[..second.len() - 7]);
    let events = scan_events(image).unwrap();
    assert!(matches!(
        events.last(),
        Some(WalEvent::Tail(WalScanTail { offset, .. })) if offset.get() == begin_offset
    ));
}

#[test]
fn tx1_complete_tx2_torn_preserves_tx1_commit_descriptor() {
    let (first, _) = writer_with_transaction(1, None);
    let mut writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(2), None).unwrap();
    writer
        .append_root(&"alice".to_owned(), None, root(102))
        .unwrap();
    let second = writer.into_inner().bytes;
    let mut image = first.clone();
    image.extend_from_slice(&second[..second.len() / 2]);
    let events = scan_events(image).unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, WalEvent::Commit(_)))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, WalEvent::Tail(_)))
    );
}

#[test]
fn semantic_commit_count_and_digest_mismatch_is_fatal() {
    let mut bytes = raw_transaction(1, Some(object_id(1)), b"alice", true);
    mutate_record(&mut bytes, 3, |payload| payload[RECORD_HEADER_LEN + 8] ^= 1);
    assert!(matches!(
        scan_events(bytes),
        Err(WalError::CommitCountMismatch { .. })
    ));

    let mut bytes = raw_transaction(1, Some(object_id(1)), b"alice", true);
    mutate_record(&mut bytes, 3, |payload| {
        payload[RECORD_HEADER_LEN + 40] ^= 1;
    });
    assert!(matches!(scan_events(bytes), Err(WalError::DigestMismatch)));
}

#[test]
fn identity_and_principal_codec_mismatches_are_fatal() {
    let bytes = raw_transaction(1, Some(object_id(2)), b"alice", true);
    assert!(matches!(
        scan_events(bytes),
        Err(WalError::ObjectIdentityMismatch { .. })
    ));

    let bytes = raw_transaction(1, Some(object_id(1)), b"\xff", true);
    assert!(matches!(
        scan_events(bytes),
        Err(WalError::PrincipalMismatch)
    ));
}

#[test]
fn ordering_duplicate_tag_sequence_and_ordinal_errors_are_fatal() {
    let mut writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(1), None).unwrap();
    writer
        .append_root(&"alice".to_owned(), None, root(100))
        .unwrap();
    assert!(matches!(
        writer.append_object(object_id(1), &record(1, 8)),
        Err(WalError::OrderingViolation)
    ));

    let mut bytes = raw_transaction(1, Some(object_id(1)), b"alice", true);
    mutate_record(&mut bytes, 1, |payload| {
        payload[12..20].copy_from_slice(&2_u64.to_le_bytes());
    });
    assert!(matches!(
        scan_events(bytes),
        Err(WalError::OrdinalMismatch { .. })
    ));

    let mut bytes = raw_transaction(1, Some(object_id(1)), b"alice", true);
    mutate_record(&mut bytes, 1, |payload| {
        payload[4..12].copy_from_slice(&2_u64.to_le_bytes());
    });
    assert!(matches!(
        scan_events(bytes),
        Err(WalError::SequenceMismatch { .. })
    ));
}

#[test]
fn sequence_regression_and_zero_root_are_fatal() {
    let mut bytes = raw_transaction(2, Some(object_id(1)), b"alice", true);
    bytes.extend_from_slice(&raw_transaction(1, Some(object_id(1)), b"alice", true));
    assert!(matches!(
        scan_events(bytes),
        Err(WalError::SequenceRegression { .. })
    ));

    let bytes = raw_transaction(1, None, b"alice", false);
    assert!(matches!(scan_events(bytes), Err(WalError::ZeroRoots)));
}

#[test]
fn per_record_bounds_apply_before_allocation_and_oversized_interior_is_fatal() {
    let limits = RecoveryLimits::new(128).unwrap();
    let oversized_payload_len =
        usize::try_from(super::codec::wal_physical_limit(limits).length().get())
            .unwrap()
            .checked_add(1)
            .unwrap();
    let mut bytes = vec![0_u8; 52 + oversized_payload_len];
    bytes[..8].copy_from_slice(&super::codec::WAL_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
    bytes[12..20].copy_from_slice(&u64::try_from(oversized_payload_len).unwrap().to_le_bytes());
    let checksum = frame_checksum(
        super::codec::WAL_MAGIC,
        u64::try_from(oversized_payload_len).unwrap(),
        &bytes[52..],
    );
    bytes[20..52].copy_from_slice(&checksum);
    let mut scanner = WalScanner::new(Cursor::new(bytes), TestIdentity, TestCodec, limits).unwrap();
    assert!(matches!(
        scanner.next_event(),
        Err(WalError::FrameTooLarge { .. })
    ));

    let (first, _) = writer_with_transaction(1, None);
    let (later, _) = writer_with_transaction(2, None);
    let mut interior = first;
    let mut oversized = vec![0_u8; 52 + oversized_payload_len];
    oversized[..8].copy_from_slice(&super::codec::WAL_MAGIC);
    oversized[8..10].copy_from_slice(&1_u16.to_le_bytes());
    oversized[12..20].copy_from_slice(&u64::try_from(oversized_payload_len).unwrap().to_le_bytes());
    let checksum = frame_checksum(
        super::codec::WAL_MAGIC,
        u64::try_from(oversized_payload_len).unwrap(),
        &oversized[52..],
    );
    oversized[20..52].copy_from_slice(&checksum);
    interior.extend_from_slice(&oversized);
    interior.extend_from_slice(&later);
    let mut scanner =
        WalScanner::new(Cursor::new(interior), TestIdentity, TestCodec, limits).unwrap();
    let mut saw_interior = false;
    loop {
        match scanner.next_event() {
            Ok(Some(_)) => {},
            Ok(None) => break,
            Err(error) => {
                assert!(matches!(error, WalError::InteriorCorruption { .. }));
                saw_interior = true;
                break;
            },
        }
    }
    assert!(saw_interior);
}

#[test]
fn wal_limit_includes_record_header_but_rejects_logical_limit_plus_one() {
    let exact_body = encode_object_frame(scheme(), object_id(1), &record(1, 8)).unwrap();
    let canonical_limit = u64::try_from(exact_body.len()).unwrap();
    let limits = RecoveryLimits::new(canonical_limit).unwrap();
    let exact_principal = "abcdefghijklmnopqrst".to_owned();
    let exact_root =
        encode_root_record(scheme(), exact_principal.as_bytes(), None, root(100)).unwrap();
    assert_eq!(u64::try_from(exact_root.len()).unwrap(), canonical_limit);

    let mut writer = new_writer(CountingSink::default(), limits);
    writer.begin(sequence(1), None).unwrap();
    writer.append_object(object_id(1), &record(1, 8)).unwrap();
    writer
        .append_root(&exact_principal, None, root(100))
        .unwrap();
    writer.finish_commit().unwrap();
    let bytes = writer.into_inner().bytes;
    let events = scan_events_with_limits(bytes, limits).unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, WalEvent::Commit(_)))
    );

    let oversized_record = record(1, 9);
    let oversized_body = encode_object_frame(scheme(), object_id(1), &oversized_record).unwrap();
    assert_eq!(
        u64::try_from(oversized_body.len()).unwrap(),
        canonical_limit.checked_add(1).unwrap()
    );
    let mut oversized_writer = new_writer(
        CountingSink::default(),
        RecoveryLimits::process_addressable(),
    );
    oversized_writer.begin(sequence(1), None).unwrap();
    oversized_writer
        .append_object(object_id(1), &oversized_record)
        .unwrap();
    oversized_writer
        .append_root(&exact_principal, None, root(100))
        .unwrap();
    oversized_writer.finish_commit().unwrap();
    let oversized_bytes = oversized_writer.into_inner().bytes;
    assert!(matches!(
        scan_events_with_limits(oversized_bytes, limits),
        Err(WalError::FrameTooLarge { .. } | WalError::InteriorCorruption { .. })
    ));

    let mut writer = new_writer(CountingSink::default(), limits);
    writer.begin(sequence(1), None).unwrap();
    assert!(matches!(
        writer.append_object(object_id(1), &oversized_record),
        Err(WalError::FrameTooLarge { .. })
    ));

    let oversized_principal = "abcdefghijklmnopqrstu".to_owned();
    let mut writer = new_writer(CountingSink::default(), limits);
    writer.begin(sequence(1), None).unwrap();
    writer.append_object(object_id(1), &record(1, 8)).unwrap();
    assert!(matches!(
        writer.append_root(&oversized_principal, None, root(100)),
        Err(WalError::FrameTooLarge { .. })
    ));
}

#[test]
fn incomplete_claimed_payload_before_later_record_is_interior_corruption() {
    let (first, _) = writer_with_transaction(1, None);
    let (later, _) = writer_with_transaction(2, None);
    let mut image = first;
    let mut incomplete = vec![0_u8; super::codec::PHYSICAL_HEADER_LEN];
    incomplete[..super::codec::WAL_MAGIC.len()].copy_from_slice(&super::codec::WAL_MAGIC);
    incomplete[8..10].copy_from_slice(&1_u16.to_le_bytes());
    incomplete[12..20].copy_from_slice(&1_000_000_u64.to_le_bytes());
    image.extend_from_slice(&incomplete);
    image.extend_from_slice(&later);

    assert!(matches!(
        scan_events(image),
        Err(WalError::InteriorCorruption { .. })
    ));
}

#[test]
fn interior_probe_propagates_non_eof_read_error() {
    let (first, _) = writer_with_transaction(1, None);
    let (later, _) = writer_with_transaction(2, None);
    let mut image = first;
    let mut incomplete = vec![0_u8; super::codec::PHYSICAL_HEADER_LEN];
    incomplete[..super::codec::WAL_MAGIC.len()].copy_from_slice(&super::codec::WAL_MAGIC);
    incomplete[8..10].copy_from_slice(&1_u16.to_le_bytes());
    incomplete[12..20].copy_from_slice(&1_000_000_u64.to_le_bytes());
    let malformed_offset = image.len();
    image.extend_from_slice(&incomplete);
    image.extend_from_slice(&later);
    let fail_from = u64::try_from(
        malformed_offset
            .checked_add(super::codec::PHYSICAL_HEADER_LEN)
            .unwrap(),
    )
    .unwrap();
    let reader = FailingProbeReader {
        inner: Cursor::new(image),
        fail_from,
    };
    let mut scanner = WalScanner::new(
        reader,
        TestIdentity,
        TestCodec,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    loop {
        match scanner.next_event() {
            Ok(Some(_)) => {},
            Ok(None) => panic!("faulted interior probe unexpectedly reached EOF"),
            Err(WalError::Io { operation, .. }) => {
                assert!(operation.contains("interior"));
                break;
            },
            Err(error) => panic!("unexpected scanner error: {error}"),
        }
    }
}

#[test]
fn writer_is_poisoned_after_partial_write_or_sync_failure() {
    let mut sink = CountingSink {
        fail_after: Some(0),
        ..CountingSink::default()
    };
    let mut writer = new_writer(sink, RecoveryLimits::process_addressable());
    assert!(matches!(
        writer.begin(sequence(1), None),
        Err(WalError::Io { .. })
    ));
    assert!(matches!(
        writer.begin(sequence(2), None),
        Err(WalError::InvalidTransaction(_))
    ));

    sink = CountingSink {
        fail_sync: true,
        ..CountingSink::default()
    };
    let mut writer = new_writer(sink, RecoveryLimits::process_addressable());
    writer.begin(sequence(1), None).unwrap();
    writer
        .append_root(&"alice".to_owned(), None, root(100))
        .unwrap();
    writer.finish_commit().unwrap();
    assert!(matches!(writer.publish(), Err(WalError::Io { .. })));
    assert!(matches!(
        writer.publish(),
        Err(WalError::InvalidTransaction(_))
    ));
}

#[test]
fn no_total_record_or_logical_byte_cap_is_imposed() {
    let mut writer = new_writer(
        DiscardSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(1), None).unwrap();
    for value in 1..=4097_u64 {
        writer
            .append_object(object_id(value), &record(value, 8))
            .unwrap();
    }
    writer
        .append_root(&"alice".to_owned(), None, root(100))
        .unwrap();
    writer.finish_commit().unwrap();
    let sink = writer.into_inner();
    assert!(sink.written > 64 * 1024);

    let mut writer = new_writer(
        DiscardSink::default(),
        RecoveryLimits::process_addressable(),
    );
    writer.begin(sequence(2), None).unwrap();
    for value in 1..=65_u64 {
        writer
            .append_object(object_id(value), &record(value, 1_048_576))
            .unwrap();
    }
    writer
        .append_root(&"alice".to_owned(), None, root(100))
        .unwrap();
    writer.finish_commit().unwrap();
    assert!(writer.pending_publications() == 1);
}

#[test]
fn checked_newtypes_reject_zero_and_overflow() {
    assert!(WalSequence::new(0).is_none());
    assert!(WalOrdinal::new(u64::MAX).checked_next().is_none());
    assert!(
        WalLength::new(u64::MAX)
            .checked_add(WalLength::new(1))
            .is_none()
    );
    assert!(WalCount::new(u64::MAX).checked_inc().is_none());
    assert_eq!(
        super::codec::wal_physical_limit(RecoveryLimits::process_addressable())
            .length()
            .get(),
        u64::try_from(usize::MAX).unwrap()
    );
}
