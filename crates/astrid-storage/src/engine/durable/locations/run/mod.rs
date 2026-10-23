//! Authenticated immutable process-local location runs.
//!
//! Anonymous files are accelerators only. A trusted root digest in RAM binds
//! every lookup path, including absence, to the entries supplied by recovery
//! or admission. No run survives process exit or enters durable store framing.

use std::fs::File;
use std::io::Write;

use super::super::{ArenaLocation, DurableError, ObjectId};
use crate::engine::durable::media::DurableIo;

mod builder;
mod reader;

pub(super) use builder::Builder;
pub(super) use reader::Entries;

// Private page layout for anonymous accelerators, not a persistent protocol or
// an admission ceiling. Fixed pages bound each read/build workspace.
const PAGE_BYTES: usize = 4096;
const HEADER_BYTES: usize = 8;
const ENTRY_BYTES: usize = 80;
const CHILD_BYTES: usize = 72;
const LEAF_CAPACITY: usize = (PAGE_BYTES - HEADER_BYTES) / ENTRY_BYTES;
const BRANCH_CAPACITY: usize = (PAGE_BYTES - HEADER_BYTES) / CHILD_BYTES;
const SCRATCH_FILE: &str = "anonymous location accelerator";

#[derive(Clone, Copy, Debug)]
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

enum Page {
    Leaf(Vec<(ObjectId, ArenaLocation)>),
    Branch(Vec<Node>),
}

impl Run {
    pub(super) fn lookup(&self, id: ObjectId) -> Result<Option<ArenaLocation>, DurableError> {
        let mut node = self.root;
        loop {
            match self.page(node)? {
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
                    node = *child;
                },
            }
        }
    }

    #[cfg(test)]
    pub(super) fn test_file(&self) -> &File {
        &self.file
    }

    pub(super) fn entries(&self) -> Entries<'_> {
        Entries::new(self)
    }

    fn page(&self, node: Node) -> Result<Page, DurableError> {
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
