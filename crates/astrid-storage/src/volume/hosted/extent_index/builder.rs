//! Streaming branch construction for initial conversion of a legacy map.
//!
//! Keep two children behind a full branch so finishing never requires a
//! singleton branch or rereading and rewriting a previously emitted branch.

use std::io;

use super::codec::BRANCH_CAPACITY;
use super::reference::PageRef;

#[derive(Default)]
pub(in crate::volume::hosted) struct BranchBuilder {
    levels: Vec<Vec<PageRef>>,
    previous_end: Option<u64>,
}

impl BranchBuilder {
    pub(in crate::volume::hosted) fn push_leaf(
        &mut self,
        leaf: PageRef,
        append: &mut impl FnMut(&[PageRef]) -> io::Result<PageRef>,
    ) -> io::Result<()> {
        if leaf.level().get() != 0
            || self
                .previous_end
                .is_some_and(|end| end > leaf.range().start())
        {
            return Err(invalid("extent-index leaves are not ordered and disjoint"));
        }
        self.push(leaf, append)?;
        self.previous_end = Some(leaf.range().end());
        Ok(())
    }

    fn push(
        &mut self,
        page: PageRef,
        append: &mut impl FnMut(&[PageRef]) -> io::Result<PageRef>,
    ) -> io::Result<()> {
        let level = usize::from(page.level().get());
        if self.levels.len() <= level {
            self.levels.resize_with(level.strict_add(1), Vec::new);
        }
        self.levels[level].push(page);
        if self.levels[level].len() == BRANCH_CAPACITY.strict_add(2) {
            let remainder = self.levels[level].split_off(BRANCH_CAPACITY);
            let children = std::mem::replace(&mut self.levels[level], remainder);
            let parent = Self::append_checked(&children, append)?;
            self.push(parent, append)?;
        }
        Ok(())
    }

    pub(in crate::volume::hosted) fn finish(
        mut self,
        append: &mut impl FnMut(&[PageRef]) -> io::Result<PageRef>,
    ) -> io::Result<Option<PageRef>> {
        loop {
            let Some(level) = self.levels.iter().position(|pages| !pages.is_empty()) else {
                return Ok(None);
            };
            let children = std::mem::take(&mut self.levels[level]);
            if children.len() == 1 && self.levels.iter().all(Vec::is_empty) {
                return Ok(children.first().copied());
            }
            if children.len() > BRANCH_CAPACITY {
                let middle = children.len() / 2;
                for group in [&children[..middle], &children[middle..]] {
                    let parent = Self::append_checked(group, append)?;
                    self.push(parent, append)?;
                }
            } else {
                let parent = Self::append_checked(&children, append)?;
                self.push(parent, append)?;
            }
        }
    }

    fn append_checked(
        children: &[PageRef],
        append: &mut impl FnMut(&[PageRef]) -> io::Result<PageRef>,
    ) -> io::Result<PageRef> {
        if children.len() < 2 || children.len() > BRANCH_CAPACITY {
            return Err(invalid("extent-index branch has invalid child count"));
        }
        let parent = append(children)?;
        let mut previous_end = None;
        let mut count = 0_u64;
        for child in children {
            parent.require_child(*child)?;
            if previous_end.is_some_and(|end| end > child.range().start()) {
                return Err(invalid("extent-index branch children overlap"));
            }
            previous_end = Some(child.range().end());
            count = count
                .checked_add(child.extent_count().get())
                .ok_or_else(|| invalid("extent-index branch count overflow"))?;
        }
        if children.first().map(|child| child.range().start()) != Some(parent.range().start())
            || previous_end != Some(parent.range().end())
            || count != parent.extent_count().get()
        {
            return Err(invalid("extent-index writer returned a mismatched branch"));
        }
        Ok(parent)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "builder_tests.rs"]
mod tests;
