use std::collections::BTreeMap;
use std::io::{self, Read};

use astrid_storage_model::{ObjectId, ObjectRecord};

use super::tests::{TestIdentity, deterministic_bytes};
use crate::{
    ChunkingProfile, ContentError, ContentObjectSink, ContentStreamError, build_content,
    build_content_streaming, insert_record,
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
    assert_eq!(streamed.unique_chunks(), expected.unique_chunks());
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
    assert_eq!(streamed.unique_chunks(), 1);
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
