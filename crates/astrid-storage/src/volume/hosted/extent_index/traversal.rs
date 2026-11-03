//! Bounded-memory traversal of the authoritative immutable index.

use std::io;

use super::codec::{IndexedExtent, Page};
use super::reference::{ExtentRange, PageRef};

/// Reads the named record and verifies its envelope, sequence and checksum.
/// Traversal separately verifies that the decoded page matches its descriptor.
pub(in crate::volume::hosted) trait PageReader {
    fn read_page(&self, reference: PageRef) -> io::Result<Page>;
}

/// Opening a checkpoint must visit the complete tree before publishing its
/// namespace. A successful range lookup is not a substitute for this check.
pub(in crate::volume::hosted) fn verify_tree(
    reader: &impl PageReader,
    root: PageRef,
) -> io::Result<()> {
    let mut count = 0_u64;
    visit(reader, root, None, &mut |_| {
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid("extent-index traversal count overflow"))?;
        Ok(())
    })?;
    if count != root.extent_count().get() {
        return Err(invalid("extent-index traversal count mismatch"));
    }
    Ok(())
}

pub(in crate::volume::hosted) fn visit_range(
    reader: &impl PageReader,
    root: PageRef,
    range: ExtentRange,
    visitor: &mut impl FnMut(IndexedExtent) -> io::Result<()>,
) -> io::Result<()> {
    visit(reader, root, Some(range), visitor)
}

/// Visits leaf identities without reading their payloads. This is only for
/// updating an index whose complete tree was validated before namespace use.
pub(super) fn visit_leaf_refs(
    reader: &impl PageReader,
    reference: PageRef,
    visitor: &mut impl FnMut(PageRef) -> io::Result<()>,
) -> io::Result<()> {
    if reference.level().get() == 0 {
        return visitor(reference);
    }
    let page = reader.read_page(reference)?;
    page.validate_reference(reference)?;
    let Page::Branch(children) = page else {
        return Err(invalid("extent-index branch reference names a leaf"));
    };
    for child in children {
        visit_leaf_refs(reader, child, visitor)?;
    }
    Ok(())
}

fn visit(
    reader: &impl PageReader,
    reference: PageRef,
    range: Option<ExtentRange>,
    visitor: &mut impl FnMut(IndexedExtent) -> io::Result<()>,
) -> io::Result<()> {
    if range.is_some_and(|range| !overlaps(reference.range(), range)) {
        return Ok(());
    }
    let page = reader.read_page(reference)?;
    page.validate_reference(reference)?;
    match page {
        Page::Leaf(entries) => {
            for entry in entries {
                if range.is_none_or(|range| overlaps(entry.range(), range)) {
                    visitor(entry)?;
                }
            }
        },
        Page::Branch(children) => {
            // require_child enforces a strictly decreasing level and backward
            // physical identity. At most one bounded page is held per level.
            for child in children {
                visit(reader, child, range, visitor)?;
            }
        },
    }
    Ok(())
}

fn overlaps(left: ExtentRange, right: ExtentRange) -> bool {
    left.start() < right.end() && right.start() < left.end()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "traversal_tests.rs"]
mod tests;
