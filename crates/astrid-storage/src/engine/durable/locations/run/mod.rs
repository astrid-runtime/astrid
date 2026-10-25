//! Authenticated immutable process-local location runs.
//!
//! Anonymous files are accelerators only. A trusted root digest in RAM binds
//! every lookup path, including absence, to the entries supplied by recovery
//! or admission. No run survives process exit or enters durable store framing.

use std::fs::File;
use std::io::Write;

use super::super::ArenaLocation;
use super::super::{DurableError, ObjectId};
use super::{ClosureProof, LocatorValue};
use crate::engine::durable::media::DurableIo;

mod builder;
mod reader;

pub(super) use builder::Builder;
pub(super) use reader::Entries;

// Private page layout for anonymous accelerators, not a persistent protocol or
// an admission ceiling. Fixed pages bound each read/build workspace.
const PAGE_BYTES: usize = 4096;
const HEADER_BYTES: usize = 8;
const ENTRY_BYTES: usize = 88;
const CHILD_BYTES: usize = 72;
const LEAF_CAPACITY: usize = (PAGE_BYTES - HEADER_BYTES) / ENTRY_BYTES;
const BRANCH_CAPACITY: usize = (PAGE_BYTES - HEADER_BYTES) / CHILD_BYTES;
const SCRATCH_FILE: &str = "anonymous location accelerator";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Node {
    offset: u64,
    digest: [u8; 32],
    upper: ObjectId,
    level: u8,
}

#[derive(Debug)]
pub(super) struct Run {
    file: File,
    root: Node,
    pub(super) count: usize,
    bytes: u64,
}

#[derive(Debug)]
enum Page {
    Leaf(Vec<(ObjectId, LocatorValue)>),
    Branch(Vec<Node>),
}

/// Operation-scoped authenticated page reuse for one anonymous run.
///
/// At most one decoded page is retained per tree level. Slots are rebound to
/// the exact run incarnation (full root node identity and byte length); a
/// replaced run never reuses a prior page. Cached pages key the complete
/// `Node` (offset, digest, upper, level) so a colliding offset/digest with a
/// different authenticated upper cannot skip decode. Callers create a fresh
/// memo per operation and must not retain it across engines or principals.
#[derive(Debug, Default)]
pub(in crate::engine::durable::locations) struct PageMemo {
    root_offset: u64,
    root_digest: [u8; 32],
    root_upper: [u8; 32],
    bytes: u64,
    levels: Vec<Option<CachedPage>>,
    #[cfg(test)]
    hits: usize,
    #[cfg(test)]
    misses: usize,
}

#[derive(Debug)]
struct CachedPage {
    node: Node,
    page: Page,
}

impl PageMemo {
    pub(in crate::engine::durable::locations) fn bind(&mut self, run: &Run) {
        if self.root_offset == run.root.offset
            && self.root_digest == run.root.digest
            && self.root_upper == *run.root.upper.as_bytes()
            && self.bytes == run.bytes
            && self.levels.len() == usize::from(run.root.level).strict_add(1)
        {
            return;
        }
        self.root_offset = run.root.offset;
        self.root_digest = run.root.digest;
        self.root_upper = *run.root.upper.as_bytes();
        self.bytes = run.bytes;
        self.levels.clear();
        self.levels
            .resize_with(usize::from(run.root.level).strict_add(1), || None);
    }

    #[cfg(test)]
    pub(in crate::engine::durable::locations) fn test_hits(&self) -> usize {
        self.hits
    }

    #[cfg(test)]
    pub(in crate::engine::durable::locations) fn test_misses(&self) -> usize {
        self.misses
    }
}

impl Run {
    #[cfg(test)]
    pub(super) fn lookup(&self, id: ObjectId) -> Result<Option<ArenaLocation>, DurableError> {
        self.lookup_row(id).map(|row| row.map(|row| row.location))
    }

    #[cfg(test)]
    pub(super) fn lookup_row(&self, id: ObjectId) -> Result<Option<LocatorValue>, DurableError> {
        self.lookup_row_memoized(id, &mut PageMemo::default())
    }

    pub(super) fn lookup_row_memoized(
        &self,
        id: ObjectId,
        memo: &mut PageMemo,
    ) -> Result<Option<LocatorValue>, DurableError> {
        let mut node = self.root;
        loop {
            let next = {
                match self.page_memoized(node, memo)? {
                    Page::Leaf(entries) => {
                        return Ok(entries
                            .binary_search_by_key(&id, |entry| entry.0)
                            .ok()
                            .map(|at| entries[at].1));
                    },
                    Page::Branch(children) => {
                        let at = children.partition_point(|child| child.upper < id);
                        let Some(child) = children.get(at) else {
                            return Ok(None);
                        };
                        *child
                    },
                }
            };
            node = next;
        }
    }

    #[cfg(test)]
    pub(super) fn test_file(&self) -> &File {
        &self.file
    }

    #[cfg(test)]
    pub(super) fn entries(
        &self,
    ) -> impl Iterator<Item = Result<(ObjectId, ArenaLocation), DurableError>> + '_ {
        self.rows()
            .map(|entry| entry.map(|(id, row)| (id, row.location)))
    }

    pub(super) fn rows(&self) -> Entries<'_> {
        Entries::new(self)
    }

    fn page_memoized<'a>(
        &'a self,
        node: Node,
        memo: &'a mut PageMemo,
    ) -> Result<&'a Page, DurableError> {
        memo.bind(self);
        let level = usize::from(node.level);
        let hit = memo
            .levels
            .get(level)
            .and_then(|slot| slot.as_ref())
            .is_some_and(|cached| cached.node == node);
        if hit {
            #[cfg(test)]
            {
                memo.hits = memo.hits.strict_add(1);
            }
            return Ok(&memo
                .levels
                .get(level)
                .and_then(|slot| slot.as_ref())
                .expect("hit requires occupied slot")
                .page);
        }
        #[cfg(test)]
        {
            memo.misses = memo.misses.strict_add(1);
        }
        let page = self.page(node)?;
        let slot = memo
            .levels
            .get_mut(level)
            .ok_or(DurableError::InvalidRepresentationState(
                "location page memo missing tree level",
            ))?;
        *slot = Some(CachedPage { node, page });
        Ok(&slot.as_ref().expect("just installed page").page)
    }

    fn page(&self, node: Node) -> Result<Page, DurableError> {
        #[cfg(test)]
        PAGE_AUTH_COUNT.with(|count| count.set(count.get().strict_add(1)));
        if !node
            .offset
            .is_multiple_of(u64::try_from(PAGE_BYTES).map_err(|_| DurableError::EncodingOverflow)?)
            || node
                .offset
                .checked_add(u64::try_from(PAGE_BYTES).map_err(|_| DurableError::EncodingOverflow)?)
                .is_none_or(|end| end > self.bytes)
        {
            return Err(corrupt(node.offset, "location page outside anonymous run"));
        }
        let mut bytes = [0; PAGE_BYTES];
        let mut read = 0;
        while read < bytes.len() {
            let offset = node
                .offset
                .checked_add(u64::try_from(read).map_err(|_| DurableError::EncodingOverflow)?)
                .ok_or(DurableError::EncodingOverflow)?;
            let count = self
                .file
                .durable_read_at(&mut bytes[read..], offset)
                .map_err(|source| super::super::io_error("read anonymous location page", source))?;
            if count == 0 {
                return Err(corrupt(offset, "truncated anonymous location page"));
            }
            read = read.strict_add(count);
        }
        if digest(node.offset, &bytes) != node.digest {
            return Err(corrupt(
                node.offset,
                "anonymous location page authentication failed",
            ));
        }
        reader::decode(node, &bytes)
    }
}

#[cfg(test)]
std::thread_local! {
    static PAGE_AUTH_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(in crate::engine::durable::locations) fn test_take_page_auth_count() -> usize {
    PAGE_AUTH_COUNT.with(|count| count.replace(0))
}

fn digest(offset: u64, bytes: &[u8; PAGE_BYTES]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("astrid process-local location page v1");
    hash.update(&offset.to_le_bytes());
    hash.update(bytes);
    *hash.finalize().as_bytes()
}

fn corrupt(offset: u64, detail: &'static str) -> DurableError {
    DurableError::Corrupt {
        file: SCRATCH_FILE,
        offset,
        detail,
    }
}

#[cfg(test)]
mod tests;
