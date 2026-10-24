//! Authenticated lookups and ordered traversal of anonymous runs.

use super::{
    ArenaLocation, BRANCH_CAPACITY, CHILD_BYTES, ClosureProof, DurableError, ENTRY_BYTES,
    HEADER_BYTES, LEAF_CAPACITY, LocatorValue, Node, ObjectId, PAGE_BYTES, Page, Run, corrupt,
};

pub(in crate::engine::durable::locations) struct Entries<'a> {
    run: &'a Run,
    pending: Vec<Node>,
    leaf: std::vec::IntoIter<(ObjectId, LocatorValue)>,
    failed: bool,
}

impl<'a> Entries<'a> {
    pub(super) fn new(run: &'a Run) -> Self {
        Self {
            run,
            pending: vec![run.root],
            leaf: Vec::new().into_iter(),
            failed: false,
        }
    }
}

impl Iterator for Entries<'_> {
    type Item = Result<(ObjectId, LocatorValue), DurableError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            if let Some(entry) = self.leaf.next() {
                return Some(Ok(entry));
            }
            let node = self.pending.pop()?;
            match self.run.page(node) {
                Ok(Page::Leaf(entries)) => self.leaf = entries.into_iter(),
                Ok(Page::Branch(children)) => self.pending.extend(children.into_iter().rev()),
                Err(error) => {
                    self.failed = true;
                    return Some(Err(error));
                },
            }
        }
    }
}

pub(super) fn decode(node: Node, bytes: &[u8; PAGE_BYTES]) -> Result<Page, DurableError> {
    let count = usize::from(u16::from_le_bytes(
        bytes[1..3]
            .try_into()
            .map_err(|_| corrupt(node.offset, "invalid page count"))?,
    ));
    let capacity = if node.level == 0 {
        LEAF_CAPACITY
    } else {
        BRANCH_CAPACITY
    };
    if count == 0
        || count > capacity
        || bytes[0] != node.level
        || bytes[3..HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(corrupt(node.offset, "invalid anonymous page shape"));
    }
    let width = if node.level == 0 {
        ENTRY_BYTES
    } else {
        CHILD_BYTES
    };
    let end = HEADER_BYTES
        .checked_add(
            count
                .checked_mul(width)
                .ok_or(DurableError::EncodingOverflow)?,
        )
        .ok_or(DurableError::EncodingOverflow)?;
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(corrupt(node.offset, "noncanonical anonymous page padding"));
    }
    let records = bytes[HEADER_BYTES..end].chunks_exact(width);
    let mut previous = None;
    // The authenticated page header already bounds the exact row count. Reserve
    // only its active variant once, avoiding repeated growth on random lookups.
    let mut leaves = Vec::with_capacity(if node.level == 0 { count } else { 0 });
    let mut children = Vec::with_capacity(if node.level == 0 { 0 } else { count });
    for record in records {
        let key = ObjectId::new(
            record[..32]
                .try_into()
                .map_err(|_| corrupt(node.offset, "invalid location key"))?,
        );
        if previous.is_some_and(|previous| previous >= key) {
            return Err(corrupt(node.offset, "unordered anonymous page keys"));
        }
        previous = Some(key);
        let offset = u64::from_le_bytes(
            record[32..40]
                .try_into()
                .map_err(|_| corrupt(node.offset, "invalid location offset"))?,
        );
        if node.level == 0 {
            leaves.push((key, leaf_value(node, offset, record)?));
        } else {
            if offset >= node.offset {
                return Err(corrupt(
                    node.offset,
                    "anonymous page contains a forward edge",
                ));
            }
            children.push(Node {
                offset,
                digest: record[40..72]
                    .try_into()
                    .map_err(|_| corrupt(node.offset, "invalid page digest"))?,
                upper: key,
                level: node.level.strict_sub(1),
            });
        }
    }
    if previous != Some(node.upper) {
        return Err(corrupt(node.offset, "anonymous page range mismatch"));
    }
    if node.level == 0 {
        Ok(Page::Leaf(leaves))
    } else {
        Ok(Page::Branch(children))
    }
}

fn leaf_value(node: Node, offset: u64, record: &[u8]) -> Result<LocatorValue, DurableError> {
    let proof = match record[80] {
        0 => ClosureProof::Unknown,
        1 => ClosureProof::Complete,
        _ => return Err(corrupt(node.offset, "invalid closure proof state")),
    };
    if record[81..].iter().any(|byte| *byte != 0) {
        return Err(corrupt(node.offset, "noncanonical locator proof padding"));
    }
    Ok(LocatorValue {
        proof,
        location: ArenaLocation {
            offset,
            payload_len: u64::from_le_bytes(
                record[40..48]
                    .try_into()
                    .map_err(|_| corrupt(node.offset, "invalid location length"))?,
            ),
            checksum: record[48..80]
                .try_into()
                .map_err(|_| corrupt(node.offset, "invalid location checksum"))?,
        },
    })
}
