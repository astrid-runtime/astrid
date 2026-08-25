//! Startup-only fallback when a newer committed root loses an owning object.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};

use super::tests::{
    TEST_IDENTITY_SCHEME, TestEngine, TestIdentity, Utf8Codec, flip_byte, limits, open, transaction,
};
use super::*;

fn frame_end(path: &std::path::Path, offset: u64) -> u64 {
    let mut file = File::open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    file.read_exact(&mut header).unwrap();
    let payload_len = u64::from_le_bytes(header[12..20].try_into().unwrap());
    offset
        .checked_add(FRAME_HEADER_LEN)
        .and_then(|value| value.checked_add(payload_len))
        .unwrap()
}

fn append_root_frame(path: &std::path::Path, expected: Option<RootState>, replacement: RootState) {
    let payload =
        encode_root_record(TEST_IDENTITY_SCHEME, b"alice", expected, replacement).unwrap();
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    append_frame(&mut journal, ROOT_MAGIC, &payload).unwrap();
    journal.sync_data().unwrap();
}

fn commit_pair(directory: &std::path::Path) -> (TestEngine, RootState, RootState, u64) {
    let engine = open(directory);
    let (_, first_transaction) = transaction("alice", None, b"before");
    let first = engine.commit(first_transaction).unwrap().root();
    let (_, second_transaction) = transaction("alice", Some(first), b"after");
    let second = engine.commit(second_transaction).unwrap().root();
    let newer_offset = frame_end(&directory.join(ROOT_FILE), 0);
    (engine, first, second, newer_offset)
}

#[test]
fn live_reads_fail_closed_without_startup_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let (engine, _first, newest, _newer_offset) = commit_pair(directory.path());
    let arena = directory.path().join(ARENA_FILE);
    let arena_len = std::fs::metadata(&arena).unwrap().len();
    flip_byte(&arena, arena_len.saturating_sub(1));

    assert!(matches!(
        engine.snapshot(&"alice".to_owned()),
        Err(DurableError::Corrupt {
            file: ARENA_FILE,
            detail: "frame checksum mismatch",
            ..
        })
    ));
    assert_eq!(engine.root(&"alice".to_owned()).unwrap(), Some(newest));
    assert!(engine.rejected_recovery_candidates().unwrap().is_empty());
}

#[test]
fn startup_falls_back_to_prior_complete_root_and_retains_journal_frame() {
    let directory = tempfile::tempdir().unwrap();
    let (engine, first, newest, newer_offset) = commit_pair(directory.path());
    let journal = directory.path().join(ROOT_FILE);
    let journal_len = std::fs::metadata(&journal).unwrap().len();
    let arena = directory.path().join(ARENA_FILE);
    let arena_len = std::fs::metadata(&arena).unwrap().len();
    flip_byte(&arena, arena_len.saturating_sub(1));
    drop(engine);

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(first));
    assert_ne!(first, newest);
    assert_eq!(
        std::fs::metadata(&journal).unwrap().len(),
        journal_len,
        "incomplete closure must not truncate its complete root frame"
    );
    let rejected = recovered.rejected_recovery_candidates().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].principal, "alice");
    assert_eq!(rejected[0].offset, newer_offset);
    assert_eq!(rejected[0].root, newest);
    assert_eq!(rejected[0].missing, newest.commit);
}

#[test]
fn startup_fallback_survives_copy_to_a_fresh_backend() {
    let source = tempfile::tempdir().unwrap();
    let (engine, first, newest, newer_offset) = commit_pair(source.path());
    let arena = source.path().join(ARENA_FILE);
    let arena_len = std::fs::metadata(&arena).unwrap().len();
    flip_byte(&arena, arena_len.saturating_sub(1));
    drop(engine);

    let copy = tempfile::tempdir().unwrap();
    for file_name in [ARENA_FILE, ROOT_FILE, INDEX_FILE] {
        std::fs::copy(source.path().join(file_name), copy.path().join(file_name)).unwrap();
    }

    let recovered = DurableEngine::open(copy.path(), TestIdentity, Utf8Codec, limits()).unwrap();

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(first));
    let rejected = recovered.rejected_recovery_candidates().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].principal, "alice");
    assert_eq!(rejected[0].offset, newer_offset);
    assert_eq!(rejected[0].root, newest);
    assert_eq!(rejected[0].missing, newest.commit);
}

#[test]
fn startup_skips_multiple_newest_incomplete_roots_and_reports_each() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"before");
    let first = engine.commit(transaction).unwrap().root();
    drop(engine);
    let journal = directory.path().join(ROOT_FILE);
    let first_rejected = RootState {
        generation: first.generation.checked_next().unwrap(),
        commit: ObjectId::new([0xA1; 32]),
    };
    let second_rejected = RootState {
        generation: first_rejected.generation.checked_next().unwrap(),
        commit: ObjectId::new([0xA2; 32]),
    };
    let first_rejected_offset = std::fs::metadata(&journal).unwrap().len();
    append_root_frame(&journal, Some(first), first_rejected);
    let second_rejected_offset = std::fs::metadata(&journal).unwrap().len();
    append_root_frame(&journal, Some(first_rejected), second_rejected);
    let journal_len = std::fs::metadata(&journal).unwrap().len();

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(first));
    assert_eq!(std::fs::metadata(&journal).unwrap().len(), journal_len);
    let rejected = recovered.rejected_recovery_candidates().unwrap();
    assert_eq!(rejected.len(), 2);
    assert_eq!(rejected[0].principal, "alice");
    assert_eq!(rejected[0].offset, second_rejected_offset);
    assert_eq!(rejected[0].root, second_rejected);
    assert_eq!(rejected[0].missing, second_rejected.commit);
    assert_eq!(rejected[1].principal, "alice");
    assert_eq!(rejected[1].offset, first_rejected_offset);
    assert_eq!(rejected[1].root, first_rejected);
    assert_eq!(rejected[1].missing, first_rejected.commit);
}

#[test]
fn startup_fallback_then_commit_reopens_without_root_conflict() {
    let source = tempfile::tempdir().unwrap();
    let (engine, first, newest, _newer_offset) = commit_pair(source.path());
    let journal = source.path().join(ROOT_FILE);
    let journal_len_before_fallback = std::fs::metadata(&journal).unwrap().len();
    let arena = source.path().join(ARENA_FILE);
    let arena_len = std::fs::metadata(&arena).unwrap().len();
    flip_byte(&arena, arena_len.saturating_sub(1));
    drop(engine);

    let recovered = open(source.path());
    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(first));
    assert_eq!(recovered.rejected_recovery_candidates().unwrap().len(), 1);

    let (_, transaction) = transaction("alice", Some(first), b"after-recovery");
    let committed = recovered.commit(transaction).unwrap().root();
    assert_eq!(committed.generation.get(), newest.generation.get() + 1);
    assert_eq!(committed.generation.get(), 2);
    recovered.flush().unwrap();

    let copy = tempfile::tempdir().unwrap();
    for file_name in [ARENA_FILE, ROOT_FILE, INDEX_FILE] {
        std::fs::copy(source.path().join(file_name), copy.path().join(file_name)).unwrap();
    }
    drop(recovered);

    let reopened = open(copy.path());
    assert_eq!(reopened.root(&"alice".to_owned()).unwrap(), Some(committed));
    assert!(
        std::fs::metadata(copy.path().join(ROOT_FILE))
            .unwrap()
            .len()
            > journal_len_before_fallback,
        "the post-fallback commit must append a new journal frame"
    );
    let mut journal_bytes = Vec::new();
    File::open(copy.path().join(ROOT_FILE))
        .unwrap()
        .read_to_end(&mut journal_bytes)
        .unwrap();
    assert!(
        journal_bytes
            .windows(newest.commit.as_bytes().len())
            .any(|window| window == &newest.commit.as_bytes()[..]),
        "the rejected candidate frame must remain retained in the journal"
    );
}

#[test]
fn production_recovery_fallback_report_visible() {
    let directory = tempfile::tempdir().unwrap();
    let (engine, first, newest, newer_offset) = commit_pair(directory.path());
    let arena = directory.path().join(ARENA_FILE);
    let arena_len = std::fs::metadata(&arena).unwrap().len();
    flip_byte(&arena, arena_len.saturating_sub(1));
    drop(engine);

    let recovered =
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()).unwrap();
    let report = recovered.rejected_recovery_candidates().unwrap();
    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(first));
    assert_eq!(report.len(), 1);
    assert_eq!(report[0].principal, "alice");
    assert_eq!(report[0].offset, newer_offset);
    assert_eq!(report[0].root, newest);
    assert_eq!(report[0].missing, newest.commit);
}

#[test]
fn startup_fallback_does_not_swallow_unrelated_model_errors() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"before");
    let first = engine.commit(transaction).unwrap().root();
    drop(engine);

    let wrong_expected = RootState {
        generation: first.generation,
        commit: ObjectId::new([0x55; 32]),
    };
    let replacement = RootState {
        generation: first.generation.checked_next().unwrap(),
        commit: ObjectId::new([0x56; 32]),
    };
    append_root_frame(
        &directory.path().join(ROOT_FILE),
        Some(wrong_expected),
        replacement,
    );

    assert!(matches!(
        DurableEngine::open(directory.path(), TestIdentity, Utf8Codec, limits()),
        Err(DurableError::RecoveryModel {
            source: ModelError::RootConflict { .. },
            ..
        })
    ));
}
