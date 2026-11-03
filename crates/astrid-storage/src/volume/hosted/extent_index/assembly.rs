//! Bounded leaf packing shared by conversion and incremental index updates.

use std::io;

use super::builder::BranchBuilder;
use super::codec::{IndexedExtent, LEAF_CAPACITY, Page};
use super::reference::PageRef;

// Occupancy follows the fixed leaf grammar. It is not a workload ceiling.
pub(super) const MIN_LEAF_ENTRIES: usize = LEAF_CAPACITY.div_ceil(2);

#[derive(Default)]
pub(super) struct TreeBuilder {
    branches: BranchBuilder,
    pending: Vec<IndexedExtent>,
}

impl TreeBuilder {
    pub(super) fn pending_entries(&self) -> usize {
        self.pending.len()
    }

    pub(super) fn push(
        &mut self,
        entry: IndexedExtent,
        append: &mut impl FnMut(&Page) -> io::Result<PageRef>,
    ) -> io::Result<()> {
        self.pending.push(entry);
        if self.pending.len() == LEAF_CAPACITY.strict_mul(2) {
            let remainder = self.pending.split_off(LEAF_CAPACITY);
            let entries = std::mem::replace(&mut self.pending, remainder);
            self.emit(entries, append)?;
        }
        Ok(())
    }

    pub(super) fn reuse_leaf(
        &mut self,
        reference: PageRef,
        append: &mut impl FnMut(&Page) -> io::Result<PageRef>,
    ) -> io::Result<()> {
        self.flush(append)?;
        self.branches.push_leaf(reference, &mut |children| {
            append(&Page::Branch(children.to_vec()))
        })
    }

    pub(super) fn finish(
        mut self,
        append: &mut impl FnMut(&Page) -> io::Result<PageRef>,
    ) -> io::Result<Option<PageRef>> {
        self.flush(append)?;
        self.branches
            .finish(&mut |children| append(&Page::Branch(children.to_vec())))
    }

    fn flush(&mut self, append: &mut impl FnMut(&Page) -> io::Result<PageRef>) -> io::Result<()> {
        let entries = std::mem::take(&mut self.pending);
        if entries.len() > LEAF_CAPACITY {
            let middle = entries.len() / 2;
            self.emit(entries[..middle].to_vec(), append)?;
            self.emit(entries[middle..].to_vec(), append)?;
        } else if !entries.is_empty() {
            self.emit(entries, append)?;
        }
        Ok(())
    }

    fn emit(
        &mut self,
        entries: Vec<IndexedExtent>,
        append: &mut impl FnMut(&Page) -> io::Result<PageRef>,
    ) -> io::Result<()> {
        let page = Page::Leaf(entries);
        let reference = append(&page)?;
        page.validate_reference(reference)?;
        self.branches.push_leaf(reference, &mut |children| {
            append(&Page::Branch(children.to_vec()))
        })
    }
}

/// Initial conversion consumes the existing map once. Incremental updates use
/// `TreeBuilder` directly so unaffected leaves retain their physical identities.
pub(in crate::volume::hosted) fn build_tree(
    extents: impl Iterator<Item = io::Result<IndexedExtent>>,
    append: &mut impl FnMut(&Page) -> io::Result<PageRef>,
) -> io::Result<Option<PageRef>> {
    let mut builder = TreeBuilder::default();
    for entry in extents {
        builder.push(entry?, append)?;
    }
    builder.finish(append)
}
