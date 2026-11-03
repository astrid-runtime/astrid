//! Merge pending logical writes with immutable leaves, preserving unchanged
//! leaf and branch records. Application payload offsets never move here.

use std::io;

use super::assembly::{MIN_LEAF_ENTRIES, TreeBuilder, build_tree};
use super::codec::{IndexedExtent, Page};
use super::reference::PageRef;
use super::traversal::{PageReader, visit_leaf_refs};

pub(super) fn rewrite_tree(
    reader: &impl PageReader,
    root: Option<PageRef>,
    base_limit: u64,
    mut pending: impl Iterator<Item = io::Result<IndexedExtent>>,
    append: &mut impl FnMut(&Page) -> io::Result<PageRef>,
) -> io::Result<Option<PageRef>> {
    let next = pending.next().transpose()?;
    if next.is_none() && root.is_none_or(|root| root.range().end() <= base_limit) {
        return Ok(root);
    }
    if root.is_none() {
        return build_tree(next.into_iter().map(Ok).chain(pending), append);
    }
    let mut append_reusing = |page: &Page| {
        if let Some(root) = root
            && matches!(page, Page::Branch(_))
            && let Some(reference) = matching_branch(reader, root, page)?
        {
            return Ok(reference);
        }
        append(page)
    };
    let mut update = Update {
        reader,
        pending,
        next,
        covered_until: 0,
        base_limit,
        root_end: root.map_or(0, |root| root.range().end()),
        output: TreeBuilder::default(),
        append: &mut append_reusing,
    };
    if let Some(root) = root {
        visit_leaf_refs(reader, root, &mut |leaf| update.apply_leaf(leaf))?;
    }
    while update.next.is_some() {
        update.emit_pending()?;
    }
    update.output.finish(update.append)
}

struct Update<'a, R, I, W> {
    reader: &'a R,
    pending: I,
    next: Option<IndexedExtent>,
    covered_until: u64,
    base_limit: u64,
    root_end: u64,
    output: TreeBuilder,
    append: &'a mut W,
}

impl<R, I, W> Update<'_, R, I, W>
where
    R: PageReader,
    I: Iterator<Item = io::Result<IndexedExtent>>,
    W: FnMut(&Page) -> io::Result<PageRef>,
{
    fn apply_leaf(&mut self, reference: PageRef) -> io::Result<()> {
        while self
            .next
            .is_some_and(|entry| entry.range().start() < reference.range().start())
        {
            self.emit_pending()?;
        }
        if self.base_limit <= reference.range().start()
            || self.covered_until >= reference.range().end()
        {
            return Ok(());
        }
        let overlaps = self
            .next
            .is_some_and(|entry| entry.range().start() < reference.range().end());
        let needs_packing = (self.next.is_some() && reference.range().end() == self.root_end)
            || (self.output.pending_entries() > 0
                && self.output.pending_entries() < MIN_LEAF_ENTRIES)
            || reference.extent_count().get() < MIN_LEAF_ENTRIES as u64;
        if !overlaps
            && !needs_packing
            && self.covered_until <= reference.range().start()
            && self.base_limit >= reference.range().end()
        {
            return self.output.reuse_leaf(reference, self.append);
        }
        let page = self.reader.read_page(reference)?;
        page.validate_reference(reference)?;
        let Page::Leaf(entries) = page else {
            return Err(invalid("leaf reference names branch"));
        };
        for entry in entries {
            self.apply_extent(entry)?;
        }
        Ok(())
    }

    fn apply_extent(&mut self, entry: IndexedExtent) -> io::Result<()> {
        let mut start = entry.range().start().max(self.covered_until);
        let end = entry.range().end().min(self.base_limit);
        if start >= end {
            return Ok(());
        }
        while let Some(pending) = self.next
            && pending.range().start() < end
        {
            if start < pending.range().start() {
                self.emit_old(entry, start, pending.range().start().min(end))?;
            }
            self.emit_pending()?;
            start = start.max(self.covered_until);
            if start >= end {
                return Ok(());
            }
        }
        self.emit_old(entry, start, end)
    }

    fn emit_old(&mut self, entry: IndexedExtent, start: u64, end: u64) -> io::Result<()> {
        if start >= end {
            return Ok(());
        }
        let physical = entry
            .physical()
            .get()
            .checked_add(start.strict_sub(entry.range().start()))
            .ok_or_else(|| invalid("extent-index clipped payload offset overflow"))?;
        self.output
            .push(IndexedExtent::new(start, end, physical)?, self.append)
    }

    fn emit_pending(&mut self) -> io::Result<()> {
        let entry = self
            .next
            .take()
            .ok_or_else(|| invalid("missing pending extent"))?;
        if entry.range().start() < self.covered_until {
            return Err(invalid("pending extents overlap or are unordered"));
        }
        self.output.push(entry, self.append)?;
        self.covered_until = entry.range().end();
        self.next = self.pending.next().transpose()?;
        Ok(())
    }
}

fn matching_branch(
    reader: &impl PageReader,
    reference: PageRef,
    expected: &Page,
) -> io::Result<Option<PageRef>> {
    let (level, range, count) = expected.summary()?;
    if reference.level().get() < level.get()
        || reference.range().start() > range.start()
        || reference.range().end() < range.end()
    {
        return Ok(None);
    }
    let page = reader.read_page(reference)?;
    page.validate_reference(reference)?;
    if reference.level() == level {
        return Ok((reference.range() == range
            && reference.extent_count() == count
            && &page == expected)
            .then_some(reference));
    }
    let Page::Branch(children) = page else {
        return Err(invalid("branch reference names leaf"));
    };
    for child in children {
        if child.range().start() <= range.start() && child.range().end() >= range.end() {
            return matching_branch(reader, child, expected);
        }
    }
    Ok(None)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
