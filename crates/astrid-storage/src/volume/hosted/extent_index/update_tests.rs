use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use super::super::assembly::build_tree;
use super::super::codec::{LEAF_CAPACITY, Page};
use super::super::reference::{ExtentRange, RecordOffset, RecordSequence};
use super::super::traversal::{verify_tree, visit_range};
use super::*;

#[derive(Clone, Default)]
struct Store {
    pages: Rc<RefCell<BTreeMap<u64, Page>>>,
    reads: Rc<Cell<usize>>,
}

impl Store {
    fn append(&self, page: &Page) -> io::Result<PageRef> {
        let ordinal = (self.pages.borrow().len() as u64).strict_add(1);
        let offset = 1_000_000_u64.strict_add(ordinal.strict_mul(8192));
        let bytes = page.encode()?;
        let reference = page.reference(
            RecordOffset::new(offset)?,
            RecordSequence::new(ordinal)?,
            *blake3::hash(&bytes).as_bytes(),
        )?;
        self.pages.borrow_mut().insert(offset, page.clone());
        Ok(reference)
    }

    fn build(&self, entries: &[IndexedExtent]) -> Option<PageRef> {
        build_tree(entries.iter().copied().map(Ok), &mut |page| {
            self.append(page)
        })
        .unwrap()
    }

    fn projection(&self, root: Option<PageRef>, length: usize) -> Vec<Option<u64>> {
        let mut result = vec![None; length];
        if let Some(root) = root {
            verify_tree(self, root).unwrap();
            visit_range(
                self,
                root,
                ExtentRange::new(0, length as u64).unwrap(),
                &mut |entry| {
                    for position in entry.range().start()..entry.range().end() {
                        let slot = &mut result[usize::try_from(position).unwrap()];
                        assert!(slot.is_none(), "overlap at {position}");
                        *slot = Some(
                            entry
                                .physical()
                                .get()
                                .strict_add(position.strict_sub(entry.range().start())),
                        );
                    }
                    Ok(())
                },
            )
            .unwrap();
        }
        result
    }
}

impl PageReader for Store {
    fn read_page(&self, reference: PageRef) -> io::Result<Page> {
        self.reads.set(self.reads.get().strict_add(1));
        self.pages
            .borrow()
            .get(&reference.offset().get())
            .cloned()
            .ok_or_else(|| invalid("missing test page"))
    }
}

fn extent(start: u64, end: u64, physical: u64) -> IndexedExtent {
    IndexedExtent::new(start, end, physical).unwrap()
}

#[test]
fn unchanged_tree_reuses_root_without_reads_or_writes() {
    let store = Store::default();
    let entries = (0..1000)
        .map(|index| extent(index * 3, index * 3 + 2, 8 + index * 2))
        .collect::<Vec<_>>();
    let root = store.build(&entries);
    let before = store.pages.borrow().len();
    store.reads.set(0);
    let actual = rewrite_tree(&store, root, u64::MAX, std::iter::empty(), &mut |_| {
        panic!("unchanged tree wrote a page")
    })
    .unwrap();
    assert_eq!(actual, root);
    assert_eq!(store.reads.get(), 0);
    assert_eq!(store.pages.borrow().len(), before);
}

#[test]
fn point_overwrite_rewrites_one_leaf_and_its_root() {
    let store = Store::default();
    let count = LEAF_CAPACITY * 8;
    let entries = (0..count)
        .map(|index| extent(index as u64 * 3, index as u64 * 3 + 1, 8 + index as u64))
        .collect::<Vec<_>>();
    let root = store.build(&entries);
    let before = store.pages.borrow().len();
    let position = (LEAF_CAPACITY * 4) as u64 * 3;
    let actual = rewrite_tree(
        &store,
        root,
        u64::MAX,
        [Ok(extent(position, position + 1, 100_000))].into_iter(),
        &mut |page| store.append(page),
    )
    .unwrap();
    assert_eq!(store.pages.borrow().len() - before, 2);
    let projection = store.projection(actual, count * 3);
    assert_eq!(
        projection[usize::try_from(position).unwrap()],
        Some(100_000)
    );
    for (index, entry) in entries.iter().enumerate() {
        if entry.range().start() != position {
            assert_eq!(projection[index * 3], Some(entry.physical().get()));
        }
    }
}

#[test]
fn merge_matches_byte_oracle_across_holes_splits_spanning_writes_and_truncation() {
    let store = Store::default();
    let entries = (0..231)
        .map(|index| extent(index * 4, index * 4 + 2, 8 + index * 2))
        .collect::<Vec<_>>();
    let root = store.build(&entries);
    let base = store.projection(root, 1200);
    let mut seed = 17_u64;
    for iteration in 0..200 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let limit = if iteration % 3 == 0 {
            seed % 925
        } else {
            u64::MAX
        };
        let mut pending = Vec::new();
        let mut start = seed % 20;
        while start < 1150 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let end = (start + 1 + seed % 190).min(1200);
            pending.push(extent(start, end, 100_000 + start));
            start = end + 1 + seed % 70;
        }
        let mut expected = base.clone();
        for (position, slot) in expected.iter_mut().enumerate() {
            if position as u64 >= limit {
                *slot = None;
            }
        }
        for entry in &pending {
            for position in entry.range().start()..entry.range().end() {
                expected[usize::try_from(position).unwrap()] = Some(
                    entry
                        .physical()
                        .get()
                        .strict_add(position.strict_sub(entry.range().start())),
                );
            }
        }
        let actual = rewrite_tree(
            &store,
            root,
            limit,
            pending.into_iter().map(Ok),
            &mut |page| store.append(page),
        )
        .unwrap();
        assert_eq!(
            store.projection(actual, 1200),
            expected,
            "iteration={iteration}, limit={limit}"
        );
    }
}

#[test]
fn append_packs_the_existing_right_edge_instead_of_adding_a_tiny_leaf() {
    let store = Store::default();
    let entries = (0..LEAF_CAPACITY)
        .map(|index| extent(index as u64 * 2, index as u64 * 2 + 1, 8 + index as u64))
        .collect::<Vec<_>>();
    let root = store.build(&entries);
    let last = (LEAF_CAPACITY * 2) as u64;
    let actual = rewrite_tree(
        &store,
        root,
        u64::MAX,
        [Ok(extent(last, last + 1, 100_000))].into_iter(),
        &mut |page| store.append(page),
    )
    .unwrap()
    .unwrap();
    let mut counts = Vec::new();
    visit_leaf_refs(&store, actual, &mut |reference| {
        counts.push(reference.extent_count().get());
        Ok(())
    })
    .unwrap();
    assert_eq!(counts, [85, 86]);
}

#[test]
fn deleting_all_base_extents_leaves_only_new_writes_or_an_empty_tree() {
    let store = Store::default();
    let root = store.build(&[extent(10, 20, 8)]);
    assert!(
        rewrite_tree(&store, root, 0, std::iter::empty(), &mut |page| store
            .append(page))
        .unwrap()
        .is_none()
    );
    let actual = rewrite_tree(
        &store,
        root,
        0,
        [Ok(extent(15, 17, 100))].into_iter(),
        &mut |page| store.append(page),
    )
    .unwrap();
    let projection = store.projection(actual, 30);
    assert_eq!(projection[15..17], [Some(100), Some(101)]);
    assert_eq!(projection.iter().filter(|value| value.is_some()).count(), 2);
}
