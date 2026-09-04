//! Preservation regressions for incomplete staging journals.

use std::io::{Seek as _, Write as _};

use astrid_core::identity::PrincipalUid;
use uuid::Uuid;

use crate::content::{ChunkingProfile, ContentName};

use super::journal::{JournalRecord, encoded_frame};
use super::{
    JOURNAL_FILE, NativeContentStagingArea, StagedContentId, StagedContentWriter, StagingIntent,
};

#[test]
fn torn_journal_tail_is_preserved_without_reopening() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut first_writer = writer(&area, "first");
    first_writer.write_all(b"first").unwrap();
    let first = first_writer.seal().unwrap();
    append_partial(&area, &sealed_frame(&first, "torn", 4), true);
    drop(area);
    assert_blocked(&directory.path().join(JOURNAL_FILE));
}

#[test]
fn torn_physical_header_tail_is_preserved_without_reopening() {
    for field in ["version", "reserved"] {
        let directory = tempfile::tempdir().unwrap();
        let area = open_area(directory.path());
        let mut first_writer = writer(&area, "first");
        first_writer.write_all(b"first").unwrap();
        let first = first_writer.seal().unwrap();
        let mut frame = sealed_frame(&first, "torn-header", 0);
        if field == "version" {
            frame[8..10].copy_from_slice(&0_u16.to_le_bytes());
        } else {
            frame[10] = 1;
        }
        append_partial(&area, &frame, false);
        drop(area);
        assert_blocked(&directory.path().join(JOURNAL_FILE));
    }
}

#[test]
fn overflowing_torn_length_tail_is_preserved_without_reopening() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut first_writer = writer(&area, "first");
    first_writer.write_all(b"first").unwrap();
    let first = first_writer.seal().unwrap();
    let mut frame = sealed_frame(&first, "overflowing-tail", 0);
    frame[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    append_partial(&area, &frame, false);
    drop(area);
    assert_blocked(&directory.path().join(JOURNAL_FILE));
}

fn owner() -> super::StateOwner {
    super::StateOwner::Principal(PrincipalUid::from_bytes([8; 32]))
}

fn open_area(path: &std::path::Path) -> NativeContentStagingArea {
    NativeContentStagingArea::open_with_group_commit_policy(
        path,
        crate::engine::GroupCommitPolicy::immediate(),
    )
    .unwrap()
}

fn writer(area: &NativeContentStagingArea, name: &str) -> StagedContentWriter {
    area.begin(
        owner(),
        ContentName::new(name).unwrap(),
        ChunkingProfile::ASTRID_V1,
    )
    .unwrap()
}

fn sealed_frame(previous: &super::ReadyStagedContent, name: &str, logical_bytes: u64) -> Vec<u8> {
    encoded_frame(&JournalRecord::Sealed(StagingIntent {
        sequence: previous.sequence().checked_add(1).unwrap(),
        id: StagedContentId(Uuid::new_v4()),
        owner: owner(),
        name: ContentName::new(name).unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes,
    }))
    .unwrap()
}

fn append_partial(area: &NativeContentStagingArea, frame: &[u8], partial: bool) {
    let mut journal = area.inner.journal.lock();
    journal.file.seek(std::io::SeekFrom::End(0)).unwrap();
    journal
        .file
        .write_all(if partial {
            &frame[..frame.len() / 2]
        } else {
            frame
        })
        .unwrap();
}

fn assert_blocked(journal_path: &std::path::Path) {
    let bytes_before = std::fs::read(journal_path).unwrap();
    let error = NativeContentStagingArea::open_with_group_commit_policy(
        journal_path.parent().unwrap(),
        crate::engine::GroupCommitPolicy::immediate(),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("could not prove complete coverage"),
        "{error}"
    );
    assert_eq!(std::fs::read(journal_path).unwrap(), bytes_before);
}
