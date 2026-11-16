//! Dense canonical nibble-radix construction.

use super::validation::CanonicalNodeSink;
use alloc::vec::Vec;

use super::{
    DIGEST_NIBBLES, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    PhysicalMapNodeId, PhysicalModelError, RADIX_PAGE_CAPACITY, nibble_prefix_byte_len,
};

mod insert;
pub(super) use insert::{InsertBatch, insert_batch, insert_new};

pub(super) fn build<I: PhysicalIdentity, V: AsRef<[u8]>, N: CanonicalNodeSink>(
    identity: &I,
    domain: PhysicalMapDomain,
    entries: &[(PhysicalMapKey, V)],
    nodes: &mut N,
) -> Result<PhysicalMapNodeId, N::Error> {
    build_range(identity, domain, entries, 0, nodes)
}

fn build_range<I: PhysicalIdentity, V: AsRef<[u8]>, N: CanonicalNodeSink>(
    identity: &I,
    domain: PhysicalMapDomain,
    entries: &[(PhysicalMapKey, V)],
    depth: u8,
    nodes: &mut N,
) -> Result<PhysicalMapNodeId, N::Error> {
    if entries.is_empty() {
        return Err(PhysicalModelError::InvalidMap("empty radix range").into());
    }
    if entries.len() <= RADIX_PAGE_CAPACITY {
        return put_encoded_page(identity, domain, entries, nodes);
    }

    let prefix_nibbles = common_prefix_nibbles(
        entries
            .first()
            .ok_or(PhysicalModelError::InvalidMap("empty radix range"))?
            .0,
        entries
            .last()
            .ok_or(PhysicalModelError::InvalidMap("empty radix range"))?
            .0,
        depth,
    );
    if prefix_nibbles >= DIGEST_NIBBLES {
        return Err(PhysicalModelError::InvalidMap("duplicate radix key").into());
    }

    let mut child_bitmap = 0_u16;
    let mut children = Vec::new();
    let mut start = 0;
    while start < entries.len() {
        let selector = nibble(entries[start].0, prefix_nibbles);
        let mut end = start
            .checked_add(1)
            .ok_or(PhysicalModelError::LengthOverflow)?;
        while end < entries.len() && nibble(entries[end].0, prefix_nibbles) == selector {
            end = end
                .checked_add(1)
                .ok_or(PhysicalModelError::LengthOverflow)?;
        }
        child_bitmap |= 1_u16 << selector;
        children.push(build_range(
            identity,
            domain,
            &entries[start..end],
            prefix_nibbles
                .checked_add(1)
                .ok_or(PhysicalModelError::LengthOverflow)?,
            nodes,
        )?);
        start = end;
    }
    put_encoded_radix(
        identity,
        domain,
        entries,
        prefix_nibbles,
        child_bitmap,
        children,
        nodes,
    )
}

fn put_encoded_page<I, V, N>(
    identity: &I,
    domain: PhysicalMapDomain,
    entries: &[(PhysicalMapKey, V)],
    nodes: &mut N,
) -> Result<PhysicalMapNodeId, N::Error>
where
    I: PhysicalIdentity,
    V: AsRef<[u8]>,
    N: CanonicalNodeSink,
{
    super::validate_page(entries)?;
    let bytes = super::encode_body(|encoder| super::encode::page(domain, entries, encoder))?;
    super::put_identified_bytes(
        identity,
        super::RADIX_MAP_NODE_IDENTITY,
        nodes,
        &bytes,
        || {
            Ok(PhysicalMapNode::Page {
                domain,
                entries: entries
                    .iter()
                    .map(|(key, value)| (*key, value.as_ref().to_vec()))
                    .collect(),
            })
        },
    )
}

fn put_encoded_radix<I, V, N>(
    identity: &I,
    domain: PhysicalMapDomain,
    entries: &[(PhysicalMapKey, V)],
    prefix_nibbles: u8,
    child_bitmap: u16,
    children: Vec<PhysicalMapNodeId>,
    nodes: &mut N,
) -> Result<PhysicalMapNodeId, N::Error>
where
    I: PhysicalIdentity,
    V: AsRef<[u8]>,
    N: CanonicalNodeSink,
{
    let prefix = canonical_nibble_prefix(entries[0].0, prefix_nibbles);
    let subtree_entries =
        u64::try_from(entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?;
    super::validate_radix(
        prefix_nibbles,
        &prefix,
        child_bitmap,
        &children,
        subtree_entries,
    )?;
    let bytes = super::encode_body(|encoder| {
        super::encode::radix(
            domain,
            prefix_nibbles,
            &prefix,
            child_bitmap,
            &children,
            subtree_entries,
            encoder,
        );
        Ok(())
    })?;
    super::put_identified_bytes(
        identity,
        super::RADIX_MAP_NODE_IDENTITY,
        nodes,
        &bytes,
        || {
            Ok(PhysicalMapNode::Radix {
                domain,
                prefix_nibbles,
                prefix,
                child_bitmap,
                children,
                subtree_entries,
            })
        },
    )
}

pub(super) fn nibble(key: PhysicalMapKey, index: u8) -> u8 {
    nibble_from_bytes(key.as_bytes(), index)
}

fn nibble_from_bytes(bytes: &[u8], index: u8) -> u8 {
    let byte = bytes[usize::from(index / 2)];
    if index.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

fn common_prefix_nibbles(left: PhysicalMapKey, right: PhysicalMapKey, mut depth: u8) -> u8 {
    while depth < DIGEST_NIBBLES && nibble(left, depth) == nibble(right, depth) {
        depth = depth.saturating_add(1);
    }
    depth
}

fn common_with_prefix(key: PhysicalMapKey, prefix_nibbles: u8, prefix: &[u8]) -> u8 {
    let mut common = 0;
    while common < prefix_nibbles && nibble(key, common) == nibble_from_bytes(prefix, common) {
        common = common.saturating_add(1);
    }
    common
}

fn canonical_nibble_prefix(key: PhysicalMapKey, nibbles: u8) -> Vec<u8> {
    let mut prefix = key.as_bytes()[..nibble_prefix_byte_len(nibbles)].to_vec();
    if !nibbles.is_multiple_of(2)
        && let Some(last) = prefix.last_mut()
    {
        *last &= 0xf0;
    }
    prefix
}
