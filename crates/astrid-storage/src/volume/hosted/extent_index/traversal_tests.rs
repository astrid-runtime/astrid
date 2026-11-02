use std::cell::RefCell;
use std::collections::BTreeMap;

use super::super::reference::{RecordOffset, RecordSequence};
use super::*;

#[derive(Default)]
struct Reader {
    pages: BTreeMap<u64, Page>,
    reads: RefCell<Vec<u64>>,
}

impl PageReader for Reader {
    fn read_page(&self, reference: PageRef) -> io::Result<Page> {
        self.reads.borrow_mut().push(reference.offset().get());
        self.pages
            .get(&reference.offset().get())
            .cloned()
            .ok_or_else(|| invalid("injected missing page"))
    }
}

fn fixture() -> (Reader, PageRef) {
    let mut reader = Reader::default();
    let mut leaves = Vec::new();
    for index in 0..3_u64 {
        let page = Page::Leaf(vec![
            IndexedExtent::new(
                index.strict_mul(10),
                index.strict_mul(10).strict_add(3),
                8_u64.strict_add(index.strict_mul(3)),
            )
            .unwrap(),
        ]);
        let offset = 1024_u64.strict_add(index.strict_mul(4096));
        let reference = page
            .reference(
                RecordOffset::new(offset).unwrap(),
                RecordSequence::new(index.strict_add(1)).unwrap(),
                [0; 32],
            )
            .unwrap();
        reader.pages.insert(offset, page);
        leaves.push(reference);
    }
    let page = Page::Branch(leaves);
    let root = page
        .reference(
            RecordOffset::new(16384).unwrap(),
            RecordSequence::new(4).unwrap(),
            [0; 32],
        )
        .unwrap();
    reader.pages.insert(16384, page);
    (reader, root)
}

#[test]
fn full_validation_reads_every_page_in_logical_order() {
    let (reader, root) = fixture();
    verify_tree(&reader, root).unwrap();
    assert_eq!(*reader.reads.borrow(), [16384, 1024, 5120, 9216]);
}

#[test]
fn range_lookup_skips_unrelated_pages_and_preserves_holes() {
    let (reader, root) = fixture();
    let mut found = Vec::new();
    visit_range(
        &reader,
        root,
        ExtentRange::new(11, 20).unwrap(),
        &mut |entry| {
            found.push(entry);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range(), ExtentRange::new(10, 13).unwrap());
    assert_eq!(*reader.reads.borrow(), [16384, 5120]);
    reader.reads.borrow_mut().clear();
    visit_range(
        &reader,
        root,
        ExtentRange::new(13, 20).unwrap(),
        &mut |_| panic!("hole must have no extents"),
    )
    .unwrap();
    assert_eq!(*reader.reads.borrow(), [16384]);
}

#[test]
fn full_open_validation_catches_corruption_outside_requested_range() {
    let (mut reader, root) = fixture();
    reader.pages.remove(&9216);
    visit_range(&reader, root, ExtentRange::new(0, 1).unwrap(), &mut |_| {
        Ok(())
    })
    .unwrap();
    assert!(verify_tree(&reader, root).is_err());
}

#[test]
fn descriptor_mismatch_and_visitor_errors_are_not_hidden() {
    let (mut reader, root) = fixture();
    let error = visit_range(&reader, root, ExtentRange::new(0, 1).unwrap(), &mut |_| {
        Err(io::Error::other("visitor failed"))
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "visitor failed");
    reader
        .pages
        .insert(1024, Page::Leaf(vec![IndexedExtent::new(0, 2, 8).unwrap()]));
    assert!(verify_tree(&reader, root).is_err());
}
