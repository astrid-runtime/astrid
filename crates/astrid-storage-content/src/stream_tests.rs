use std::collections::BTreeMap;
use std::io::{self, Read};

use astrid_storage_model::{ObjectId, ObjectIdentity, ObjectKind, ObjectRecord};

use super::tests::{TestIdentity, deterministic_bytes};
use crate::build::{Child, tree_record};
use crate::stream::TreeAccumulator;
use crate::{
    CHUNK_TREE_FANOUT, ChunkingProfile, ContentError, ContentObjectSink, ContentStreamError,
    build_content, build_content_streaming, insert_record,
};

struct CollectingSink {
    records: BTreeMap<ObjectId, ObjectRecord>,
}

impl CollectingSink {
    fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }
}

impl ContentObjectSink for CollectingSink {
    type Error = ContentError;

    fn stage_content_object(&mut self, record: ObjectRecord) -> Result<ObjectId, Self::Error> {
        insert_record(&TestIdentity, &mut self.records, record)
    }
}

struct FragmentedReader {
    bytes: Vec<u8>,
    offset: usize,
    fragment: usize,
    maximum_request: usize,
    fail_at: Option<usize>,
}

impl FragmentedReader {
    fn new(bytes: Vec<u8>, fragment: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            fragment,
            maximum_request: 0,
            fail_at: None,
        }
    }

    fn failing(bytes: Vec<u8>, fragment: usize, fail_at: usize) -> Self {
        Self {
            fail_at: Some(fail_at),
            ..Self::new(bytes, fragment)
        }
    }
}

impl Read for FragmentedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.maximum_request = self.maximum_request.max(output.len());
        if self.fail_at.is_some_and(|limit| self.offset >= limit) {
            return Err(io::Error::other("injected source failure"));
        }
        let remaining = self.bytes.len().saturating_sub(self.offset);
        let before_failure = self
            .fail_at
            .map_or(remaining, |limit| limit.saturating_sub(self.offset));
        let length = remaining
            .min(before_failure)
            .min(self.fragment)
            .min(output.len());
        if length == 0 {
            return Ok(0);
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(io::Error::other("fragmented-reader position overflow"))?;
        output[..length].copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(length)
    }
}

fn assert_stream_matches_slice(profile: ChunkingProfile, bytes: &[u8], fragment: usize) {
    let expected = build_content(&TestIdentity, profile, bytes).unwrap();
    let mut source = FragmentedReader::new(bytes.to_vec(), fragment);
    let mut sink = CollectingSink::new();

    let streamed = build_content_streaming(profile, &mut source, &mut sink).unwrap();

    assert_eq!(streamed.descriptor(), expected.descriptor());
    assert_eq!(
        sink.records.into_iter().collect::<Vec<_>>(),
        expected.records()
    );
    assert!(
        source.maximum_request
            <= usize::try_from(profile.maximum_bytes())
                .unwrap()
                .saturating_add(1)
    );
}

#[test]
fn streaming_matches_slice_for_boundary_and_multilevel_inputs() {
    let profile = ChunkingProfile::fastcdc_v2020(64, 256, 1024, 17).unwrap();
    for length in [0, 1, 63, 64, 1023, 1024, 1025, 16_384, 262_144] {
        let bytes = deterministic_bytes(length);
        for fragment in [1, 7, 257, 4096] {
            assert_stream_matches_slice(profile, &bytes, fragment);
        }
    }
}

#[test]
fn streaming_preserves_the_whole_small_file_rule() {
    let profile = ChunkingProfile::ASTRID_V1;
    let bytes = deterministic_bytes(usize::try_from(profile.maximum_bytes()).unwrap());
    let mut sink = CollectingSink::new();

    let streamed = build_content_streaming(profile, bytes.as_slice(), &mut sink).unwrap();

    assert_eq!(streamed.descriptor().chunk_count(), 1);
    assert_eq!(streamed.peak_pending_tree_children(), 1);
}

fn synthetic_child(index: usize) -> Child {
    let mut identity = [0x5a_u8; 32];
    identity[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
    Child {
        id: ObjectId::new(identity),
        logical_bytes: u64::try_from(index % 17).unwrap().checked_add(1).unwrap(),
        chunk_count: 1,
    }
}

fn reference_tree(
    sink: &mut CollectingSink,
    mut level: Vec<Child>,
) -> Result<Option<Child>, ContentError> {
    if level.is_empty() {
        return Ok(None);
    }
    if level.len() == 1 {
        return Ok(level.pop());
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(CHUNK_TREE_FANOUT));
        for children in level.chunks(CHUNK_TREE_FANOUT) {
            let (record, logical_bytes, chunk_count) = tree_record(children)?;
            let id = sink.stage_content_object(record)?;
            next.push(Child {
                id,
                logical_bytes,
                chunk_count,
            });
        }
        level = next;
    }
    Ok(level.pop())
}

#[test]
fn eager_tree_emission_matches_canonical_fanout_boundaries() {
    for count in [
        0,
        1,
        CHUNK_TREE_FANOUT - 1,
        CHUNK_TREE_FANOUT,
        CHUNK_TREE_FANOUT + 1,
        CHUNK_TREE_FANOUT + 2,
        CHUNK_TREE_FANOUT * CHUNK_TREE_FANOUT - 1,
        CHUNK_TREE_FANOUT * CHUNK_TREE_FANOUT,
        CHUNK_TREE_FANOUT * CHUNK_TREE_FANOUT + 1,
    ] {
        let children: Vec<_> = (0..count).map(synthetic_child).collect();
        let mut expected_sink = CollectingSink::new();
        let expected = reference_tree(&mut expected_sink, children.clone()).unwrap();
        let mut actual_sink = CollectingSink::new();
        let mut accumulator = TreeAccumulator::new();
        for child in children {
            accumulator.push(&mut actual_sink, child).unwrap();
        }
        let (actual, peak) = accumulator.finish(&mut actual_sink).unwrap();

        assert_eq!(actual, expected, "root differs at {count} children");
        assert_eq!(
            actual_sink.records, expected_sink.records,
            "records differ at {count} children"
        );
        assert!(
            peak <= CHUNK_TREE_FANOUT.saturating_mul(4),
            "retained {peak} children at {count} inputs"
        );
    }
}

struct DiscardingSink {
    staged: usize,
}

impl ContentObjectSink for DiscardingSink {
    type Error = ContentError;

    fn stage_content_object(&mut self, record: ObjectRecord) -> Result<ObjectId, Self::Error> {
        self.staged = self
            .staged
            .checked_add(1)
            .ok_or(ContentError::LengthOverflow)?;
        Ok(TestIdentity.identify(&record))
    }
}

#[test]
fn tree_metadata_stays_bounded_for_a_virtual_64_gib_stream() {
    const VIRTUAL_CHUNKS: usize = 1024 * 1024;
    let mut sink = DiscardingSink { staged: 0 };
    let mut accumulator = TreeAccumulator::new();
    for index in 0..VIRTUAL_CHUNKS {
        accumulator.push(&mut sink, synthetic_child(index)).unwrap();
    }
    let (root, peak) = accumulator.finish(&mut sink).unwrap();

    assert!(root.is_some());
    assert!(sink.staged > VIRTUAL_CHUNKS / CHUNK_TREE_FANOUT);
    assert!(
        peak <= CHUNK_TREE_FANOUT.saturating_mul(4),
        "one million chunks retained {peak} live child records"
    );
}

#[test]
fn source_failure_returns_no_descriptor_after_bounded_staging() {
    let profile = ChunkingProfile::fastcdc_v2020(64, 256, 1024, 0).unwrap();
    let bytes = deterministic_bytes(8192);
    let mut source = FragmentedReader::failing(bytes, 211, 4096);
    let mut sink = CollectingSink::new();

    let result = build_content_streaming(profile, &mut source, &mut sink);

    assert!(matches!(result, Err(ContentStreamError::Source(_))));
    assert!(!sink.records.is_empty());
    assert!(
        sink.records
            .values()
            .all(|record| { !matches!(record.kind(), astrid_storage_model::ObjectKind::File) })
    );
}

#[derive(Debug, PartialEq, Eq)]
struct SinkFailure;

impl std::fmt::Display for SinkFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("injected sink failure")
    }
}

impl std::error::Error for SinkFailure {}

struct FailingSink {
    remaining: usize,
}

impl ContentObjectSink for FailingSink {
    type Error = SinkFailure;

    fn stage_content_object(&mut self, _record: ObjectRecord) -> Result<ObjectId, Self::Error> {
        if self.remaining == 0 {
            return Err(SinkFailure);
        }
        self.remaining = self.remaining.saturating_sub(1);
        Ok(ObjectId::new(
            [u8::try_from(self.remaining).unwrap_or(0); 32],
        ))
    }
}

#[test]
fn sink_failure_is_preserved_without_a_descriptor() {
    let profile = ChunkingProfile::fastcdc_v2020(64, 256, 1024, 0).unwrap();
    let bytes = deterministic_bytes(4096);
    let mut sink = FailingSink { remaining: 1 };

    let result = build_content_streaming(profile, bytes.as_slice(), &mut sink);

    assert!(matches!(result, Err(ContentStreamError::Sink(SinkFailure))));
}

struct TreeFailingSink {
    file_seen: bool,
}

impl ContentObjectSink for TreeFailingSink {
    type Error = SinkFailure;

    fn stage_content_object(&mut self, record: ObjectRecord) -> Result<ObjectId, Self::Error> {
        match record.kind() {
            ObjectKind::ChunkTree => Err(SinkFailure),
            ObjectKind::File => {
                self.file_seen = true;
                Ok(TestIdentity.identify(&record))
            },
            _ => Ok(TestIdentity.identify(&record)),
        }
    }
}

#[test]
fn eager_tree_sink_failure_never_emits_a_file_descriptor() {
    let profile = ChunkingProfile::fastcdc_v2020(64, 256, 1024, 0).unwrap();
    let bytes = deterministic_bytes(256 * 1024);
    let mut sink = TreeFailingSink { file_seen: false };

    let result = build_content_streaming(profile, bytes.as_slice(), &mut sink);

    assert!(matches!(result, Err(ContentStreamError::Sink(SinkFailure))));
    assert!(!sink.file_seen);
}
