use std::io::{Seek, SeekFrom, Write};

use super::super::codec::IndexedExtent;
use super::super::test_support::container_bytes;
use super::*;
use crate::volume::AstridVolume;

fn fixture() -> (tempfile::TempDir, std::sync::Arc<HostedFileVolume>, Page) {
    let directory = tempfile::tempdir().unwrap();
    let volume = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
    let region = VolumeRegion::new("data/page-test").unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, &[41; 32]).unwrap();
    volume.sync().unwrap();
    let physical = volume.state.lock().regions[&region].extents[&0].physical_offset;
    let page = Page::Leaf(vec![IndexedExtent::new(0, 32, physical).unwrap()]);
    (directory, volume, page)
}

fn read(state: &ContainerState, reference: PageRef) -> io::Result<Page> {
    RecordReader {
        file: &state.file,
        published_before: RecordOffset::new(state.valid_len)?,
        commit_sequence: RecordSequence::new(state.sequence.strict_add(1))?,
    }
    .read_page(reference)
}

#[test]
fn page_append_and_read_use_real_container_identity_and_checksum() {
    let (_directory, volume, page) = fixture();
    let mut state = volume.state.lock();
    let reference = append_page(&mut state, &page).unwrap();
    assert_eq!(read(&state, reference).unwrap(), page);
    assert_eq!(state.sequence, reference.sequence().get());
}

#[test]
fn rejects_tampered_page_bytes_without_mutating_container_length() {
    let (_directory, volume, page) = fixture();
    let mut state = volume.state.lock();
    let reference = append_page(&mut state, &page).unwrap();
    let length = state.file.metadata().unwrap().len();
    let payload = reference.offset().get()
        + super::super::super::RECORD_FIXED_BYTES as u64
        + INDEX_PAGE_REGION.len() as u64;
    state.file.seek(SeekFrom::Start(payload + 16)).unwrap();
    state.file.write_all(&[255]).unwrap();
    assert!(read(&state, reference).is_err());
    assert_eq!(state.file.metadata().unwrap().len(), length);
}

#[test]
fn envelope_and_reference_binding_reject_wrong_record_kind_or_namespace() {
    for (operation, region, offset) in [
        (Operation::Write, INDEX_PAGE_REGION, 0),
        (Operation::IndexPage, "data/incorrect", 0),
        (Operation::IndexPage, INDEX_PAGE_REGION, 1),
    ] {
        let (_directory, volume, page) = fixture();
        let mut state = volume.state.lock();
        let record_offset = RecordOffset::new(state.valid_len).unwrap();
        let sequence = RecordSequence::new(state.sequence.strict_add(1)).unwrap();
        let record = HostedFileVolume::append_record(
            &mut state,
            operation,
            &VolumeRegion::new(region).unwrap(),
            offset,
            &page.encode().unwrap(),
        )
        .unwrap();
        let reference = page
            .reference(record_offset, sequence, record.checksum)
            .unwrap();
        assert!(read(&state, reference).is_err());
    }
}

#[test]
fn page_must_be_completely_before_publication_boundary() {
    let (_directory, volume, page) = fixture();
    let mut state = volume.state.lock();
    let reference = append_page(&mut state, &page).unwrap();
    for limit in [
        reference.offset().get(),
        reference.offset().get() + 1,
        state.valid_len - 1,
    ] {
        let reader = RecordReader {
            file: &state.file,
            published_before: RecordOffset::new(limit).unwrap(),
            commit_sequence: RecordSequence::new(state.sequence.strict_add(1)).unwrap(),
        };
        assert!(reader.read_page(reference).is_err(), "limit={limit}");
    }
    let reader = RecordReader {
        file: &state.file,
        published_before: RecordOffset::new(state.valid_len).unwrap(),
        commit_sequence: reference.sequence(),
    };
    assert!(reader.read_page(reference).is_err());
}

#[test]
fn invalid_page_is_rejected_before_any_file_mutation() {
    let (_directory, volume, _) = fixture();
    let mut state = volume.state.lock();
    let before = (
        state.valid_len,
        state.sequence,
        state.file.metadata().unwrap().len(),
    );
    let invalid = Page::Leaf(vec![IndexedExtent::new(0, 2, state.valid_len).unwrap()]);
    assert!(append_page(&mut state, &invalid).is_err());
    assert_eq!(
        before,
        (
            state.valid_len,
            state.sequence,
            state.file.metadata().unwrap().len()
        )
    );
}

#[test]
fn streamed_conversion_builds_and_verifies_multiple_real_record_levels() {
    use super::super::{
        assembly::build_tree,
        codec::{BRANCH_CAPACITY, LEAF_CAPACITY},
        traversal,
    };

    let (_directory, volume, _) = fixture();
    let mut state = volume.state.lock();
    let region = VolumeRegion::new("data/page-test").unwrap();
    let physical = state.regions[&region].extents[&0].physical_offset;
    // Repeated physical references are legal; this tests only index structure
    // and never changes or duplicates application data.
    let count = LEAF_CAPACITY * (BRANCH_CAPACITY + 1) + 1;
    let extents = (0..count)
        .map(|index| IndexedExtent::new(index as u64 * 2, index as u64 * 2 + 1, physical));
    let root = build_tree(extents, &mut |page| append_page(&mut state, page))
        .unwrap()
        .unwrap();
    assert_eq!(root.level().get(), 2);
    assert_eq!(root.extent_count().get(), count as u64);
    let reader = RecordReader {
        file: &state.file,
        published_before: RecordOffset::new(state.valid_len).unwrap(),
        commit_sequence: RecordSequence::new(state.sequence.strict_add(1)).unwrap(),
    };
    traversal::verify_tree(&reader, root).unwrap();
    let mut visited = 0;
    let start = (LEAF_CAPACITY * BRANCH_CAPACITY - 1) as u64 * 2;
    traversal::visit_range(
        &reader,
        root,
        super::super::reference::ExtentRange::new(start, start + 5).unwrap(),
        &mut |entry| {
            assert_eq!(entry.range().start(), start + visited * 2);
            assert_eq!(entry.physical().get(), physical);
            visited += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(visited, 3);
}

#[test]
fn recovery_discards_complete_and_torn_unpublished_page_records() {
    for torn in [false, true] {
        let (directory, volume, page) = fixture();
        let mut state = volume.state.lock();
        let committed_end = state.durable_len;
        append_page(&mut state, &page).unwrap();
        let copy = directory.path().join(if torn {
            "torn.volume"
        } else {
            "complete.volume"
        });
        std::fs::write(&copy, container_bytes(&state.file)).unwrap();
        if torn {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&copy)
                .unwrap()
                .set_len(state.valid_len - 1)
                .unwrap();
        }
        drop(state);
        let reopened = HostedFileVolume::open(&copy).unwrap();
        let region = VolumeRegion::new("data/page-test").unwrap();
        let mut bytes = [0; 32];
        assert_eq!(reopened.read_region_at(&region, 0, &mut bytes).unwrap(), 32);
        assert_eq!(bytes, [41; 32]);
        assert_eq!(reopened.list_regions("").unwrap(), [region]);
        let state = reopened.state.lock();
        assert_eq!(state.valid_len, committed_end);
        assert_eq!(state.durable_len, committed_end);
    }
}
