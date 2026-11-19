//! Manual matched content-path profiles; no allocation capture is enabled.

use super::*;
use crate::content_dag::{OpenedContent, validate_opened_content};
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
enum Operation {
    Validate,
    Read,
    Partial,
}

fn exercise(operation: Operation, source: &MapSource, opened: OpenedContent, length: usize) {
    match operation {
        Operation::Validate => validate_opened_content(source, opened).unwrap(),
        Operation::Read => {
            let bytes = read_opened_content(source, opened).unwrap();
            assert_eq!(bytes.len(), length);
            drop(std::hint::black_box(bytes));
        },
        Operation::Partial => {
            let offset = length / 3;
            let amount = length.strict_sub(offset).min(8192);
            let bytes =
                read_opened_content_range(source, opened, offset as u64, amount as u64).unwrap();
            assert_eq!(bytes.len(), amount);
            drop(std::hint::black_box(bytes));
        },
    }
}

fn profile(operation: Operation) {
    for (length, iterations) in [
        (0, 4096),
        (8192, 2048),
        (512 * 1024, 128),
        (8 * 1024 * 1024, 8),
    ] {
        let bytes = deterministic_bytes(length);
        let built = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
        let source = MapSource::new(built.records());
        let opened = open_content(&source, built.descriptor().file()).unwrap();
        drop(built);
        drop(bytes);
        let first = Instant::now();
        exercise(operation, &source, opened, length);
        let first_us = first.elapsed().as_micros();
        let iterations = if matches!(operation, Operation::Partial) && length >= 512 * 1024 {
            128
        } else {
            iterations
        };
        source.loads.set(0);
        let start = Instant::now();
        for _ in 0..iterations {
            exercise(operation, &source, opened, length);
        }
        println!(
            "content_profile operation={operation:?} bytes={length} first_us={first_us} loop_us={} iterations={iterations} object_loads={}",
            start.elapsed().as_micros(),
            source.loads.get()
        );
    }
}

#[test]
#[ignore = "manual native in-memory validation profile, not a CI gate"]
fn validation_profile() {
    profile(Operation::Validate);
}

#[test]
#[ignore = "manual buffered-read control for the same shared traversal"]
fn full_read_profile() {
    profile(Operation::Read);
}

#[test]
#[ignore = "manual partial-read control for the same shared traversal"]
fn partial_read_profile() {
    profile(Operation::Partial);
}
