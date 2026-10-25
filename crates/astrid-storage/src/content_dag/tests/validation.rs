use super::*;
use crate::content_dag::{output_measurement::measure, validate_opened_content};

#[test]
fn count_validation_reads_the_same_objects_without_a_whole_value_buffer() {
    let bytes = deterministic_bytes(1024 * 1024);
    let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    let source = MapSource::new(built.records());
    let opened = open_content(&source, built.descriptor().file()).unwrap();
    let (result, output) = measure(|| validate_opened_content(&source, opened));
    result.unwrap();
    assert_eq!(output.reserved, 0);
    assert_eq!(output.written, bytes.len());
    let validating_loads = source.loads.get();
    let source = MapSource::new(built.records());
    let (read, output) = measure(|| read_content(&source, built.descriptor().file()));
    assert_eq!(read.unwrap(), bytes);
    assert_eq!(output.reserved, bytes.len());
    assert_eq!(output.written, bytes.len());
    assert_eq!(
        source.loads.get(),
        validating_loads,
        "counting must not bypass object visits"
    );
    // Only the concatenated output is eliminated. The same bounded full-chunk
    // FastCDC window remains necessary for canonical boundary verification.
    let opened = open_content(&source, built.descriptor().file()).unwrap();
    let (range, output) = measure(|| read_opened_content_range(&source, opened, 17, 100));
    assert_eq!(range.unwrap(), bytes[17..117]);
    assert_eq!(output.reserved, 100);
    assert_eq!(output.written, 100);
}

fn assert_validation_error_matches_read(file: ObjectId, source: &MapSource) {
    let opened = open_content(source, file).unwrap();
    let read_error = read_opened_content(source, opened).unwrap_err().to_string();
    let (result, output) = measure(|| validate_opened_content(source, opened));
    assert_eq!(result.unwrap_err().to_string(), read_error);
    assert_eq!(output.reserved, 0);
}

#[test]
fn counting_preserves_missing_chunk_and_shape_failures() {
    let bytes = deterministic_bytes(1024 * 1024);
    let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    let mut source = MapSource::new(built.records());
    let missing = *source
        .records
        .iter()
        .find(|(_, record)| record.kind() == ObjectKind::Chunk)
        .unwrap()
        .0;
    source.records.remove(&missing);
    assert_validation_error_matches_read(built.descriptor().file(), &source);
    let profile = ChunkingProfile::fastcdc_v2020(64, 256, 1024, 0).unwrap();
    for chunks in [
        vec![vec![1; 63], vec![2; 962]],
        vec![vec![1; 64], vec![2; 1025]],
    ] {
        let (file, source) = manual_content(profile, &chunks);
        let opened = open_content(&source, file).unwrap();
        let result = validate_opened_content(&source, opened);
        assert!(matches!(
            result,
            Err(ContentReadError::Content(ContentError::InvalidObject {
                detail: "content shape violates the declared chunking profile",
                ..
            }))
        ));
        assert_eq!(source.loads.get(), 2, "shape errors precede chunk reads");
        assert_validation_error_matches_read(file, &source);
    }
}

#[test]
fn counting_preserves_cross_child_and_final_fastcdc_checks() {
    let profile = ChunkingProfile::ASTRID_V1;
    let bytes = deterministic_bytes(512 * 1024);
    let (file, source) = manual_content(
        profile,
        &[bytes[..256 * 1024].to_vec(), bytes[256 * 1024..].to_vec()],
    );
    assert_validation_error_matches_read(file, &source);
    let profile = ChunkingProfile::fastcdc_v2020(64, 256, 1024, 0).unwrap();
    let bytes = deterministic_bytes(1025);
    let cut = fastcdc::v2020::FastCDC::with_level_and_seed(
        &bytes,
        64,
        256,
        1024,
        fastcdc::v2020::Normalization::Level1,
        0,
    )
    .next()
    .unwrap()
    .length;
    let alternate = if cut == 512 { 513 } else { 512 };
    let (file, source) = manual_content(
        profile,
        &[bytes[..alternate].to_vec(), bytes[alternate..].to_vec()],
    );
    assert_validation_error_matches_read(file, &source);

    let profile = ChunkingProfile::ASTRID_V1;
    let bytes = deterministic_bytes(1024 * 1024);
    let mut chunks: Vec<Vec<u8>> = fastcdc::v2020::FastCDC::with_level_and_seed(
        &bytes,
        profile.minimum_bytes() as usize,
        profile.average_bytes() as usize,
        profile.maximum_bytes() as usize,
        fastcdc::v2020::Normalization::Level1,
        profile.gear_seed(),
    )
    .map(|chunk| bytes[chunk.offset..chunk.offset + chunk.length].to_vec())
    .collect();
    let last = chunks.pop().unwrap();
    chunks.last_mut().unwrap().extend(last);
    assert!(chunks.last().unwrap().len() <= profile.maximum_bytes() as usize);
    let (file, source) = manual_content(profile, &chunks);
    assert_validation_error_matches_read(file, &source);
}

#[test]
fn empty_count_validation_does_not_reserve_or_write() {
    let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &[]).unwrap();
    let source = MapSource::new(built.records());
    let opened = open_content(&source, built.descriptor().file()).unwrap();
    let (result, output) = measure(|| validate_opened_content(&source, opened));
    result.unwrap();
    assert_eq!(output.reserved, 0);
    assert_eq!(output.written, 0);
}

#[test]
fn count_validation_does_not_grant_later_reads_a_boundary_skip() {
    let bytes = deterministic_bytes(1024 * 1024);
    let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    let mut source = MapSource::new(built.records());
    let opened = open_content(&source, built.descriptor().file()).unwrap();
    validate_opened_content(&source, opened).unwrap();
    // This grammar-test source deliberately preserves identities and metadata
    // while replacing chunk payloads. It isolates fresh FastCDC validation
    // from the object-identity checks performed by real durable sources.
    for record in source.records.values_mut() {
        if record.kind() == ObjectKind::Chunk {
            *record = ObjectRecord::new(
                record.kind(),
                record.format_version(),
                vec![0x55; record.canonical_bytes().len()],
                vec![],
                record.logical_bytes(),
                record.class(),
            )
            .unwrap();
        }
    }
    assert!(matches!(
        read_opened_content(&source, opened),
        Err(ContentReadError::Content(ContentError::InvalidObject {
            detail: "chunk boundary violates the declared FastCDC profile",
            ..
        }))
    ));
}
