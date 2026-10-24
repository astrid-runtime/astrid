//! Share freshly authenticated ancestors within one bounded immutable query.
use super::super::DIGEST_NIBBLES;
use super::{
    BackedPhysicalMap, PhysicalIdentity, PhysicalMapKey, PhysicalMapNode, PhysicalMapNodeId,
    PhysicalMapNodes, PhysicalModelError, SEARCH_KEY_BITS, Vec, legacy, radix, radix_common_prefix,
};
use core::ops::Range;

impl<N: PhysicalMapNodes> BackedPhysicalMap<N> {
    /// Visit each strictly increasing query key exactly once. No node body or
    /// membership evidence survives this call; the next batch rereads media.
    pub(crate) fn try_visit_sorted<I: PhysicalIdentity>(
        &self,
        identity: &I,
        keys: &[PhysicalMapKey],
        mut visit: impl FnMut(PhysicalMapKey, Option<&[u8]>) -> Result<(), N::Error>,
    ) -> Result<(), N::Error> {
        if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(
                PhysicalModelError::InvalidMap("batch keys are not unique and sorted").into(),
            );
        }
        let mut walk = BatchWalk {
            map: self,
            identity,
            keys,
            visit: &mut visit,
            delivered: 0,
        };
        let mut pending = Vec::new();
        if let Some(root) = self.root {
            if !keys.is_empty() {
                pending.push((root, 0, 0..keys.len()));
            }
        } else {
            walk.absent(0..keys.len())?;
        }
        while let Some((id, depth, range)) = pending.pop() {
            walk.step(id, depth, range, &mut pending)?;
        }
        if walk.delivered != keys.len() {
            return Err(walk.invalid_graph("incomplete map batch traversal"));
        }
        Ok(())
    }
}

type Pending = Vec<(PhysicalMapNodeId, u32, Range<usize>)>;

#[derive(Clone, Copy)]
struct RadixChildren<'a> {
    nibbles: u8,
    prefix: &'a [u8],
    bitmap: u16,
    children: &'a [PhysicalMapNodeId],
}

struct BatchWalk<'a, N, I, V> {
    map: &'a BackedPhysicalMap<N>,
    identity: &'a I,
    keys: &'a [PhysicalMapKey],
    visit: &'a mut V,
    delivered: usize,
}

impl<N, I, V> BatchWalk<'_, N, I, V>
where
    N: PhysicalMapNodes,
    I: PhysicalIdentity,
    V: FnMut(PhysicalMapKey, Option<&[u8]>) -> Result<(), N::Error>,
{
    fn invalid_graph(&self, detail: &'static str) -> N::Error {
        self.map.nodes.note_read_failure();
        PhysicalModelError::InvalidMap(detail).into()
    }

    fn deliver(&mut self, key: PhysicalMapKey, value: Option<&[u8]>) -> Result<(), N::Error> {
        (self.visit)(key, value)?;
        self.delivered = self.delivered.strict_add(1);
        Ok(())
    }

    fn absent(&mut self, range: Range<usize>) -> Result<(), N::Error> {
        for at in range {
            self.deliver(self.keys[at], None)?;
        }
        Ok(())
    }

    fn matching(
        &mut self,
        range: Range<usize>,
        predicate: impl Fn(PhysicalMapKey) -> bool,
    ) -> Result<Range<usize>, N::Error> {
        let keys = &self.keys[range.clone()];
        let first = keys
            .iter()
            .position(|key| predicate(*key))
            .unwrap_or(keys.len());
        let last = keys
            .iter()
            .rposition(|key| predicate(*key))
            .map_or(first, |at| at.strict_add(1));
        let matched = range.start.strict_add(first)..range.start.strict_add(last);
        self.absent(range.start..matched.start)?;
        self.absent(matched.end..range.end)?;
        Ok(matched)
    }

    fn step(
        &mut self,
        id: PhysicalMapNodeId,
        minimum: u32,
        range: Range<usize>,
        pending: &mut Pending,
    ) -> Result<(), N::Error> {
        match self.map.node(self.identity, id)? {
            PhysicalMapNode::Leaf { key, value, .. } => {
                for at in range {
                    let requested = self.keys[at];
                    self.deliver(requested, (requested == key).then_some(value.as_slice()))?;
                }
            },
            PhysicalMapNode::Page { entries, .. } => {
                for at in range {
                    let requested = self.keys[at];
                    let value = entries
                        .binary_search_by_key(&requested, |entry| entry.0)
                        .ok()
                        .map(|at| entries[at].1.as_slice());
                    self.deliver(requested, value)?;
                }
            },
            PhysicalMapNode::Branch {
                prefix_bits,
                prefix,
                zero,
                one,
                ..
            } => {
                if prefix_bits < minimum || prefix_bits >= SEARCH_KEY_BITS {
                    return Err(self.invalid_graph("non-increasing map branch depth"));
                }
                let range = self.matching(range, |key| {
                    legacy::matches_prefix(&key.search_key(), prefix_bits, &prefix)
                })?;
                let split = range.start.strict_add(
                    self.keys[range.clone()]
                        .partition_point(|key| !legacy::bit(&key.search_key(), prefix_bits)),
                );
                for (child, part) in [(one, split..range.end), (zero, range.start..split)] {
                    if !part.is_empty() {
                        pending.push((child, prefix_bits.strict_add(1), part));
                    }
                }
            },
            PhysicalMapNode::Radix {
                prefix_nibbles,
                prefix,
                child_bitmap,
                children,
                ..
            } => {
                self.radix(
                    minimum,
                    range,
                    pending,
                    RadixChildren {
                        nibbles: prefix_nibbles,
                        prefix: &prefix,
                        bitmap: child_bitmap,
                        children: &children,
                    },
                )?;
            },
        }
        Ok(())
    }

    fn radix(
        &mut self,
        minimum: u32,
        range: Range<usize>,
        pending: &mut Pending,
        branch: RadixChildren<'_>,
    ) -> Result<(), N::Error> {
        let RadixChildren {
            nibbles,
            prefix,
            bitmap,
            children,
        } = branch;
        let depth = u32::from(nibbles).strict_mul(4);
        if depth < minimum || nibbles >= DIGEST_NIBBLES {
            return Err(self.invalid_graph("non-increasing radix branch depth"));
        }
        let range = self.matching(range, |key| {
            radix_common_prefix(key, nibbles, prefix) == nibbles
        })?;
        let mut start = range.start;
        for nibble in 0..16 {
            let end = start.strict_add(
                self.keys[start..range.end]
                    .partition_point(|key| radix::nibble(*key, nibbles) == nibble),
            );
            if start != end {
                let mask = 1_u16 << nibble;
                if bitmap & mask == 0 {
                    self.absent(start..end)?;
                } else {
                    let at = usize::try_from((bitmap & mask.wrapping_sub(1)).count_ones())
                        .map_err(|_| PhysicalModelError::LengthOverflow)?;
                    let child = children
                        .get(at)
                        .ok_or_else(|| self.invalid_graph("radix child bitmap mismatch"))?;
                    pending.push((*child, depth.strict_add(4), start..end));
                }
            }
            start = end;
        }
        Ok(())
    }
}
