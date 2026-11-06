use super::*;
use crate::volume::{
    AstridVolume,
    hosted::{
        HostedFileVolume,
        extent_index::{
            codec::IndexedExtent, publication::prepare_checkpoint, records::append_page,
        },
    },
};

fn shared_checkpoint(path: &std::path::Path, lower_child: bool, shared: bool) {
    let volume = HostedFileVolume::open(path).unwrap();
    let names = [
        VolumeRegion::new("data/a").unwrap(),
        VolumeRegion::new("data/b").unwrap(),
    ];
    for name in &names {
        volume.create_region(name, true).unwrap();
        volume.write_region_at(name, 0, b"a\0z").unwrap();
    }
    let mut state = volume.state.lock();
    let physical = state.regions[&names[0]].extents[&0].physical_offset;
    let first = append_page(
        &mut state,
        &Page::Leaf(vec![
            IndexedExtent::new(0, if lower_child { 1 } else { 3 }, physical).unwrap(),
        ]),
    )
    .unwrap();
    for (index, name) in names.iter().enumerate() {
        let leaf = if index == 0 || shared {
            first
        } else {
            append_page(
                &mut state,
                &Page::Leaf(vec![
                    IndexedExtent::new(0, if lower_child { 1 } else { 3 }, physical).unwrap(),
                ]),
            )
            .unwrap()
        };
        let root = if lower_child {
            let last = append_page(
                &mut state,
                &Page::Leaf(vec![
                    IndexedExtent::new(2, 3, physical.strict_add(2)).unwrap(),
                ]),
            )
            .unwrap();
            append_page(&mut state, &Page::Branch(vec![leaf, last])).unwrap()
        } else {
            leaf
        };
        let region = state.regions.get_mut(name).unwrap();
        region.root = Some(root);
        region.base_limit = region.length;
        region.extents.clear();
    }
    prepare_checkpoint(&mut state).unwrap();
    HostedFileVolume::make_durable(&mut state).unwrap();
}

#[test]
fn checkpoint_rejects_checksum_valid_cross_region_shared_pages() {
    for lower_child in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("astrid.volume");
        shared_checkpoint(&path, lower_child, true);
        let Err(error) = HostedFileVolume::open(&path) else {
            panic!("shared pages accepted");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("shared or overlapping extent-index page")
        );
    }
}

#[test]
fn checkpoint_accepts_distinct_pages_with_identical_region_content() {
    for lower_child in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("astrid.volume");
        shared_checkpoint(&path, lower_child, false);
        let volume = HostedFileVolume::open(&path).unwrap();
        for name in ["data/a", "data/b"] {
            let mut bytes = [0; 3];
            assert_eq!(
                volume
                    .read_region_at(&VolumeRegion::new(name).unwrap(), 0, &mut bytes)
                    .unwrap(),
                3
            );
            assert_eq!(&bytes, b"a\0z");
        }
        // A later ordinary publication may reuse this region's old pages even
        // though another region's pages lie between them physically.
        let name = VolumeRegion::new("data/a").unwrap();
        volume.write_region_at(&name, 1, b"x").unwrap();
        prepare_checkpoint(&mut volume.state.lock()).unwrap();
        volume.sync().unwrap();
        drop(volume);
        let reopened = HostedFileVolume::open(&path).unwrap();
        let mut bytes = [0; 3];
        reopened.read_region_at(&name, 0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"axz");
    }
}

#[test]
fn checkpoint_page_ownership_rejects_overlap_in_both_orders_and_overflow() {
    let file = tempfile::tempfile().unwrap();
    let reader = CheckpointPages {
        reader: RecordReader {
            file: &file,
            published_before: RecordOffset::new(u64::MAX).unwrap(),
            commit_sequence: RecordSequence::new(u64::MAX).unwrap(),
        },
        offsets: RefCell::new(BTreeSet::new()),
    };
    let start = INDEX_PAGE_RECORD_BYTES.strict_add(8);
    reader.claim(RecordOffset::new(start).unwrap()).unwrap();
    for overlapping in [start, start.strict_sub(1), start.strict_add(1)] {
        assert!(
            reader
                .claim(RecordOffset::new(overlapping).unwrap())
                .is_err()
        );
    }
    reader.claim(RecordOffset::new(8).unwrap()).unwrap();
    reader
        .claim(RecordOffset::new(start.strict_add(INDEX_PAGE_RECORD_BYTES)).unwrap())
        .unwrap();
    assert!(reader.claim(RecordOffset::new(u64::MAX).unwrap()).is_err());
    assert_eq!(reader.offsets.borrow().len(), 3);
}
