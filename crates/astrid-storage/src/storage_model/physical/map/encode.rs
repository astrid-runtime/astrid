//! Shared canonical field encoding for owned nodes and borrowed recovery views.

use super::super::codec::{Encoder, EncodingSink};
use super::super::identity::{encode_map_node_id, encode_physical_digest};
use super::{
    LEGACY_MAP_NODE_VERSION, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNodeId,
    PhysicalModelError, RADIX_MAP_NODE_VERSION,
};

fn header<W: EncodingSink>(
    domain: PhysicalMapDomain,
    version: u16,
    tag: u8,
    encoder: &mut Encoder<W>,
) {
    encoder.u16(version);
    encoder.u8(domain.code());
    encoder.u8(tag);
}

pub(super) fn leaf<W: EncodingSink>(
    domain: PhysicalMapDomain,
    key: &PhysicalMapKey,
    value: &[u8],
    encoder: &mut Encoder<W>,
) -> Result<(), PhysicalModelError> {
    header(domain, LEGACY_MAP_NODE_VERSION, 0, encoder);
    encode_physical_digest(encoder, key.as_bytes());
    encoder.bytes(value)
}

pub(super) fn branch<W: EncodingSink>(
    domain: PhysicalMapDomain,
    prefix_bits: u32,
    prefix: &[u8],
    zero: &PhysicalMapNodeId,
    one: &PhysicalMapNodeId,
    subtree_entries: u64,
    encoder: &mut Encoder<W>,
) {
    header(domain, LEGACY_MAP_NODE_VERSION, 1, encoder);
    encoder.u32(prefix_bits);
    encoder.raw(prefix);
    encode_map_node_id(encoder, *zero);
    encode_map_node_id(encoder, *one);
    encoder.u64(subtree_entries);
}

pub(super) fn page<W: EncodingSink, V: AsRef<[u8]>>(
    domain: PhysicalMapDomain,
    entries: &[(PhysicalMapKey, V)],
    encoder: &mut Encoder<W>,
) -> Result<(), PhysicalModelError> {
    header(domain, RADIX_MAP_NODE_VERSION, 0, encoder);
    encoder.u8(u8::try_from(entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?);
    for (key, value) in entries {
        encode_physical_digest(encoder, key.as_bytes());
        encoder.bytes(value.as_ref())?;
    }
    Ok(())
}

pub(super) fn radix<W: EncodingSink>(
    domain: PhysicalMapDomain,
    prefix_nibbles: u8,
    prefix: &[u8],
    child_bitmap: u16,
    children: &[PhysicalMapNodeId],
    subtree_entries: u64,
    encoder: &mut Encoder<W>,
) {
    header(domain, RADIX_MAP_NODE_VERSION, 1, encoder);
    encoder.u8(prefix_nibbles);
    encoder.raw(prefix);
    encoder.u16(child_bitmap);
    for child in children {
        encode_map_node_id(encoder, *child);
    }
    encoder.u64(subtree_entries);
}
