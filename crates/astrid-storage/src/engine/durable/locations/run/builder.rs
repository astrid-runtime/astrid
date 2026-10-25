//! Bounded bottom-up construction: one unfinished page per tree level.

use super::{
    BRANCH_CAPACITY, CHILD_BYTES, DurableError, ENTRY_BYTES, File, HEADER_BYTES, LEAF_CAPACITY,
    LocatorValue, Node, ObjectId, PAGE_BYTES, Run, Write, corrupt, digest,
};

pub(in crate::engine::durable::locations) struct Builder {
    file: File,
    pub(super) leaf: Vec<(ObjectId, LocatorValue)>,
    pub(super) levels: Vec<Vec<Node>>,
    bytes: u64,
    count: usize,
    previous: Option<ObjectId>,
}

#[cfg(test)]
use super::ArenaLocation;

impl Builder {
    pub(in crate::engine::durable::locations) fn new() -> Result<Self, DurableError> {
        Ok(Self {
            file: tempfile::tempfile().map_err(|source| {
                super::super::super::io_error("create anonymous location accelerator", source)
            })?,
            leaf: Vec::with_capacity(LEAF_CAPACITY),
            levels: Vec::new(),
            bytes: 0,
            count: 0,
            previous: None,
        })
    }

    #[cfg(test)]
    pub(in crate::engine::durable::locations) fn push(
        &mut self,
        id: ObjectId,
        location: ArenaLocation,
    ) -> Result<(), DurableError> {
        self.push_row(id, LocatorValue::unknown(location))
    }

    pub(in crate::engine::durable::locations) fn push_row(
        &mut self,
        id: ObjectId,
        location: LocatorValue,
    ) -> Result<(), DurableError> {
        if self.previous.is_some_and(|previous| previous >= id) {
            return Err(corrupt(
                self.bytes,
                "location input is not unique and ordered",
            ));
        }
        self.leaf.push((id, location));
        self.previous = Some(id);
        self.count = self
            .count
            .checked_add(1)
            .ok_or(DurableError::EncodingOverflow)?;
        if self.leaf.len() == LEAF_CAPACITY {
            self.flush_leaf()?;
        }
        Ok(())
    }

    pub(in crate::engine::durable::locations) fn finish(
        mut self,
    ) -> Result<Option<Run>, DurableError> {
        if self.count == 0 {
            return Ok(None);
        }
        if !self.leaf.is_empty() {
            self.flush_leaf()?;
        }
        loop {
            let mut pending = self.levels.iter().flatten();
            let node = *pending
                .next()
                .ok_or_else(|| corrupt(self.bytes, "location builder lost root"))?;
            if pending.next().is_none() {
                return Ok(Some(Run {
                    file: self.file,
                    root: node,
                    count: self.count,
                    bytes: self.bytes,
                }));
            }
            let level = self
                .levels
                .iter()
                .position(|nodes| !nodes.is_empty())
                .ok_or(DurableError::EncodingOverflow)?;
            let nodes = std::mem::take(&mut self.levels[level]);
            let parent = self.branch(&nodes)?;
            self.push_node(parent)?;
        }
    }

    fn flush_leaf(&mut self) -> Result<(), DurableError> {
        let mut bytes = [0; PAGE_BYTES];
        bytes[1..3].copy_from_slice(
            &u16::try_from(self.leaf.len())
                .map_err(|_| DurableError::EncodingOverflow)?
                .to_le_bytes(),
        );
        for ((id, row), target) in self
            .leaf
            .iter()
            .zip(bytes[HEADER_BYTES..].chunks_exact_mut(ENTRY_BYTES))
        {
            let location = row.location;
            target[80] = u8::from(row.proof == super::ClosureProof::Complete);
            target[..32].copy_from_slice(id.as_bytes());
            target[32..40].copy_from_slice(&location.offset.to_le_bytes());
            target[40..48].copy_from_slice(&location.payload_len.to_le_bytes());
            target[48..80].copy_from_slice(&location.checksum);
        }
        let upper = self.leaf.last().ok_or(DurableError::EncodingOverflow)?.0;
        let node = self.append(&bytes, upper, 0)?;
        self.leaf.clear();
        self.push_node(node)
    }

    fn push_node(&mut self, mut node: Node) -> Result<(), DurableError> {
        loop {
            let level = usize::from(node.level);
            while self.levels.len() <= level {
                self.levels.push(Vec::with_capacity(BRANCH_CAPACITY));
            }
            self.levels[level].push(node);
            if self.levels[level].len() != BRANCH_CAPACITY {
                return Ok(());
            }
            let nodes = std::mem::take(&mut self.levels[level]);
            node = self.branch(&nodes)?;
        }
    }

    fn branch(&mut self, nodes: &[Node]) -> Result<Node, DurableError> {
        let last = nodes.last().ok_or(DurableError::EncodingOverflow)?;
        let level = last
            .level
            .checked_add(1)
            .ok_or(DurableError::EncodingOverflow)?;
        let mut bytes = [0; PAGE_BYTES];
        bytes[0] = level;
        bytes[1..3].copy_from_slice(
            &u16::try_from(nodes.len())
                .map_err(|_| DurableError::EncodingOverflow)?
                .to_le_bytes(),
        );
        for (node, target) in nodes
            .iter()
            .zip(bytes[HEADER_BYTES..].chunks_exact_mut(CHILD_BYTES))
        {
            target[..32].copy_from_slice(node.upper.as_bytes());
            target[32..40].copy_from_slice(&node.offset.to_le_bytes());
            target[40..72].copy_from_slice(&node.digest);
        }
        self.append(&bytes, last.upper, level)
    }

    fn append(
        &mut self,
        bytes: &[u8; PAGE_BYTES],
        upper: ObjectId,
        level: u8,
    ) -> Result<Node, DurableError> {
        let offset = self.bytes;
        self.file.write_all(bytes).map_err(|source| {
            super::super::super::io_error("write anonymous location page", source)
        })?;
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|_| DurableError::EncodingOverflow)?)
            .ok_or(DurableError::EncodingOverflow)?;
        Ok(Node {
            offset,
            digest: digest(offset, bytes),
            upper,
            level,
        })
    }
}
