//! Recovery-index regressions kept separate from the engine behavior suite.

use std::io::Write;

use super::tests::{TEST_IDENTITY_SCHEME, TestIdentity, flip_byte, open, transaction};
use super::*;

const OBJECT_CANONICAL_BYTES_OFFSET: u64 = 40 + 2 + 2 + 1 + 8 + 8 + 8;

fn first_frame_end(path: &Path) -> u64 {
    let bytes = std::fs::read(path).unwrap();
    let payload_len = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    FRAME_HEADER_LEN.checked_add(payload_len).unwrap()
}

#[test]
fn corrupt_index_falls_back_to_authoritative_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"durable");
    let root = engine.commit(transaction).unwrap().root();
    engine.flush().unwrap();
    drop(engine);

    let index = directory.path().join(INDEX_FILE);
    let index_len = std::fs::metadata(&index).unwrap().len();
    flip_byte(&index, index_len.saturating_sub(1));

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(recovered.object_count().unwrap(), 2);
    assert!(std::fs::metadata(index).unwrap().len() > FRAME_HEADER_LEN);
}

#[test]
fn torn_index_tail_is_truncated_without_touching_authority() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"durable");
    let root = engine.commit(transaction).unwrap().root();
    engine.flush().unwrap();
    drop(engine);
    let index = directory.path().join(INDEX_FILE);
    let valid_len = std::fs::metadata(&index).unwrap().len();
    let mut file = OpenOptions::new().append(true).open(&index).unwrap();
    file.write_all(&INDEX_MAGIC[..5]).unwrap();
    file.sync_data().unwrap();
    drop(file);

    let recovered = open(directory.path());

    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert_eq!(std::fs::metadata(index).unwrap().len(), valid_len);
}

#[test]
fn stale_index_rebuilds_and_includes_authoritative_arena_tail() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"rooted");
    engine.commit(transaction).unwrap();
    engine.flush().unwrap();

    let orphan = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"authoritative orphan".to_vec(),
        Vec::new(),
        20,
        ObjectClass::Data,
    )
    .unwrap();
    let orphan_id = TestIdentity.identify(&orphan);
    let payload = encode_object_frame(TEST_IDENTITY_SCHEME, orphan_id, &orphan).unwrap();
    let arena_path = directory.path().join(ARENA_FILE);
    let mut arena = OpenOptions::new().append(true).open(&arena_path).unwrap();
    append_frame(&mut arena, ARENA_MAGIC, &payload).unwrap();
    arena.sync_data().unwrap();
    drop(arena);
    drop(engine);

    let recovered = open(directory.path());

    assert_eq!(recovered.object(orphan_id).unwrap(), Some(orphan));
    assert_eq!(recovered.object_count().unwrap(), 3);
}

#[test]
fn index_never_selects_principal_roots() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let first = engine.commit(transaction).unwrap().root();
    engine.flush().unwrap();
    drop(engine);

    let replacement = RootState {
        generation: first.generation.checked_next().unwrap(),
        commit: first.commit,
    };
    let payload =
        encode_root_record(TEST_IDENTITY_SCHEME, b"alice", Some(first), replacement).unwrap();
    let journal_path = directory.path().join(ROOT_FILE);
    let mut journal = OpenOptions::new().append(true).open(journal_path).unwrap();
    append_frame(&mut journal, ROOT_MAGIC, &payload).unwrap();
    journal.sync_data().unwrap();
    drop(journal);

    let recovered = open(directory.path());

    assert_eq!(
        recovered.root(&"alice".to_owned()).unwrap(),
        Some(replacement)
    );
}

#[test]
fn flush_checkpoints_and_discards_accumulated_index_deltas() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    engine.commit(transaction).unwrap();
    let index = directory.path().join(INDEX_FILE);
    let with_delta = std::fs::metadata(&index).unwrap().len();

    engine.flush().unwrap();

    let checkpoint = std::fs::metadata(&index).unwrap().len();
    assert_eq!(checkpoint, first_frame_end(&index));
    assert!(checkpoint < with_delta);
}

#[test]
fn root_only_commit_preserves_the_full_arena_frontier() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, transaction) = transaction("alice", None, b"state");
    let first = engine.commit(transaction).unwrap().root();
    let orphan = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"later arena object".to_vec(),
        Vec::new(),
        18,
        ObjectClass::Data,
    )
    .unwrap();
    let (orphan_id, _) = engine.persist_standalone_object(&orphan).unwrap();
    let root_only = RootTransaction::new("alice".to_owned(), Some(first), first.commit, Vec::new());
    let replacement = engine.commit(root_only).unwrap().root();
    engine.flush().unwrap();
    drop(engine);

    let recovered = open(directory.path());

    assert_eq!(
        recovered.root(&"alice".to_owned()).unwrap(),
        Some(replacement)
    );
    assert_eq!(recovered.object(orphan_id).unwrap(), Some(orphan));
    assert_eq!(recovered.object_count().unwrap(), 3);
}

#[test]
fn clean_index_defers_orphan_payload_scrub_but_reads_remain_verified() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let orphan = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"unrooted cache probe".to_vec(),
        Vec::new(),
        20,
        ObjectClass::Data,
    )
    .unwrap();
    let (orphan_id, outcome) = engine.persist_standalone_object(&orphan).unwrap();
    assert_eq!(outcome, InsertOutcome::Inserted);
    let tail = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"valid physical tail".to_vec(),
        Vec::new(),
        19,
        ObjectClass::Data,
    )
    .unwrap();
    engine.persist_standalone_object(&tail).unwrap();
    engine.flush().unwrap();
    drop(engine);

    let arena = directory.path().join(ARENA_FILE);
    let payload_byte = FRAME_HEADER_LEN
        .checked_add(OBJECT_CANONICAL_BYTES_OFFSET)
        .unwrap();
    flip_byte(&arena, payload_byte);

    let recovered = open(directory.path());
    assert!(matches!(
        recovered.object(orphan_id),
        Err(DurableError::Corrupt {
            file: ARENA_FILE,
            detail: "frame checksum mismatch",
            ..
        })
    ));
}

#[test]
fn rooted_staging_advances_the_index_across_earlier_orphans() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let orphan = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"staged orphan before the rooted batch".to_vec(),
        Vec::new(),
        35,
        ObjectClass::Data,
    )
    .unwrap();
    let (orphan_id, outcome) = engine.stage_object(&orphan).unwrap();
    assert_eq!(outcome, InsertOutcome::Inserted);

    let (commit, transaction) = transaction("alice", None, b"rooted staging");
    let staged = transaction
        .records()
        .iter()
        .map(|(_, record)| record.clone())
        .collect();
    engine.stage_objects(staged).unwrap();
    let root = engine
        .commit(RootTransaction::new(
            "alice".to_owned(),
            None,
            commit,
            Vec::new(),
        ))
        .unwrap()
        .root();
    drop(engine);

    let arena = directory.path().join(ARENA_FILE);
    let orphan_payload_byte = FRAME_HEADER_LEN
        .checked_add(OBJECT_CANONICAL_BYTES_OFFSET)
        .unwrap();
    flip_byte(&arena, orphan_payload_byte);

    let recovered = open(directory.path());
    assert_eq!(recovered.root(&"alice".to_owned()).unwrap(), Some(root));
    assert!(matches!(
        recovered.object(orphan_id),
        Err(DurableError::Corrupt {
            file: ARENA_FILE,
            detail: "frame checksum mismatch",
            ..
        })
    ));
}
