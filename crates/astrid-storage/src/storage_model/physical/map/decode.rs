//! One canonical grammar, with values borrowed until an owned node is required.

use super::super::codec::Decoder;
use super::super::identity::{
    decode_map_node_id, decode_physical_digest, encode_map_node_id, encode_physical_digest,
};
use super::{
    Encoder, EncodingSink, LEGACY_MAP_NODE_VERSION, PhysicalMapDomain, PhysicalMapKey,
    PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError, RADIX_MAP_NODE_VERSION,
    RADIX_PAGE_CAPACITY, Vec, legacy, nibble_prefix_byte_len, validate_page, validate_radix,
};

#[derive(Clone, Copy)]
pub(super) enum MapNodeView<'a, V: AsRef<[u8]>> {
    Leaf {
        domain: PhysicalMapDomain,
        key: PhysicalMapKey,
        value: &'a [u8],
    },
    Branch {
        domain: PhysicalMapDomain,
        prefix_bits: u32,
        prefix: &'a [u8],
        zero: PhysicalMapNodeId,
        one: PhysicalMapNodeId,
        subtree_entries: u64,
    },
    Page {
        domain: PhysicalMapDomain,
        entries: &'a [(PhysicalMapKey, V)],
    },
    Radix {
        domain: PhysicalMapDomain,
        prefix_nibbles: u8,
        prefix: &'a [u8],
        child_bitmap: u16,
        children: &'a [PhysicalMapNodeId],
        subtree_entries: u64,
    },
}

impl<'a> MapNodeView<'a, Vec<u8>> {
    pub(super) fn from_owned(node: &'a PhysicalMapNode) -> Self {
        match node {
            PhysicalMapNode::Leaf { domain, key, value } => Self::Leaf {
                domain: *domain,
                key: *key,
                value,
            },
            PhysicalMapNode::Branch {
                domain,
                prefix_bits,
                prefix,
                zero,
                one,
                subtree_entries,
            } => Self::Branch {
                domain: *domain,
                prefix_bits: *prefix_bits,
                prefix,
                zero: *zero,
                one: *one,
                subtree_entries: *subtree_entries,
            },
            PhysicalMapNode::Page { domain, entries } => Self::Page {
                domain: *domain,
                entries,
            },
            PhysicalMapNode::Radix {
                domain,
                prefix_nibbles,
                prefix,
                child_bitmap,
                children,
                subtree_entries,
            } => Self::Radix {
                domain: *domain,
                prefix_nibbles: *prefix_nibbles,
                prefix,
                child_bitmap: *child_bitmap,
                children,
                subtree_entries: *subtree_entries,
            },
        }
    }
}

impl<V: AsRef<[u8]>> MapNodeView<'_, V> {
    #[cfg(any(test, not(target_family = "wasm")))]
    pub(super) const fn identity_context(&self) -> &'static str {
        match self {
            Self::Leaf { .. } | Self::Branch { .. } => "astrid-physical-map-node-v1\0",
            Self::Page { .. } | Self::Radix { .. } => "astrid-physical-radix-map-node-v1\0",
        }
    }

    #[cfg(any(test, not(target_family = "wasm")))]
    pub(super) fn with_child_ids<T>(&self, consume: impl FnOnce(&[PhysicalMapNodeId]) -> T) -> T {
        match self {
            Self::Branch { zero, one, .. } => consume(&[*zero, *one]),
            Self::Radix { children, .. } => consume(children),
            Self::Leaf { .. } | Self::Page { .. } => consume(&[]),
        }
    }

    pub(super) fn encode_into<W: EncodingSink>(
        &self,
        encoder: &mut Encoder<W>,
    ) -> Result<(), PhysicalModelError> {
        let (domain, version, tag) = match self {
            Self::Leaf { domain, .. } => (*domain, LEGACY_MAP_NODE_VERSION, 0),
            Self::Branch { domain, .. } => (*domain, LEGACY_MAP_NODE_VERSION, 1),
            Self::Page { domain, .. } => (*domain, RADIX_MAP_NODE_VERSION, 0),
            Self::Radix { domain, .. } => (*domain, RADIX_MAP_NODE_VERSION, 1),
        };
        encoder.u16(version);
        encoder.u8(domain.code());
        encoder.u8(tag);
        match self {
            Self::Leaf { key, value, .. } => {
                encode_physical_digest(encoder, key.as_bytes());
                encoder.bytes(value)?;
            },
            Self::Branch {
                prefix_bits,
                prefix,
                zero,
                one,
                subtree_entries,
                ..
            } => {
                encoder.u32(*prefix_bits);
                encoder.raw(prefix);
                encode_map_node_id(encoder, *zero);
                encode_map_node_id(encoder, *one);
                encoder.u64(*subtree_entries);
            },
            Self::Page { entries, .. } => {
                encoder
                    .u8(u8::try_from(entries.len())
                        .map_err(|_| PhysicalModelError::LengthOverflow)?);
                for (key, value) in *entries {
                    encode_physical_digest(encoder, key.as_bytes());
                    encoder.bytes(value.as_ref())?;
                }
            },
            Self::Radix {
                prefix_nibbles,
                prefix,
                child_bitmap,
                children,
                subtree_entries,
                ..
            } => {
                encoder.u8(*prefix_nibbles);
                encoder.raw(prefix);
                encoder.u16(*child_bitmap);
                for child in *children {
                    encode_map_node_id(encoder, *child);
                }
                encoder.u64(*subtree_entries);
            },
        }
        Ok(())
    }
}

pub(super) fn into_owned(
    node: MapNodeView<'_, &[u8]>,
) -> Result<PhysicalMapNode, PhysicalModelError> {
    Ok(match node {
        MapNodeView::Leaf { domain, key, value } => PhysicalMapNode::Leaf {
            domain,
            key,
            value: value.to_vec(),
        },
        MapNodeView::Branch {
            domain,
            prefix_bits,
            prefix,
            zero,
            one,
            subtree_entries,
        } => PhysicalMapNode::Branch {
            domain,
            prefix_bits,
            prefix: prefix.to_vec(),
            zero,
            one,
            subtree_entries,
        },
        MapNodeView::Page { domain, entries } => {
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(entries.len())
                .map_err(|_| PhysicalModelError::LengthOverflow)?;
            for (key, value) in entries {
                owned.push((*key, value.to_vec()));
            }
            PhysicalMapNode::Page {
                domain,
                entries: owned,
            }
        },
        MapNodeView::Radix {
            domain,
            prefix_nibbles,
            prefix,
            child_bitmap,
            children,
            subtree_entries,
        } => {
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(children.len())
                .map_err(|_| PhysicalModelError::LengthOverflow)?;
            owned.extend_from_slice(children);
            PhysicalMapNode::Radix {
                domain,
                prefix_nibbles,
                prefix: prefix.to_vec(),
                child_bitmap,
                children: owned,
                subtree_entries,
            }
        },
    })
}

pub(super) fn with_decoded<T>(
    bytes: &[u8],
    consume: impl FnOnce(MapNodeView<'_, &[u8]>) -> T,
) -> Result<T, PhysicalModelError> {
    let mut decoder = Decoder::new(bytes);
    let version = decoder.u16()?;
    let domain = PhysicalMapDomain::from_code(decoder.u8()?)?;
    match version {
        LEGACY_MAP_NODE_VERSION => match decoder.u8()? {
            0 => {
                let key = PhysicalMapKey::new(decode_physical_digest(&mut decoder)?);
                let value = decoder.bytes()?;
                finish(
                    decoder,
                    bytes,
                    MapNodeView::Leaf { domain, key, value },
                    consume,
                )
            },
            1 => {
                let prefix_bits = decoder.u32()?;
                let prefix = decoder.take(legacy::prefix_byte_len(prefix_bits)?)?;
                let zero = decode_map_node_id(&mut decoder)?;
                let one = decode_map_node_id(&mut decoder)?;
                let subtree_entries = decoder.u64()?;
                legacy::validate_branch(prefix_bits, prefix, zero, one, subtree_entries)?;
                finish(
                    decoder,
                    bytes,
                    MapNodeView::Branch {
                        domain,
                        prefix_bits,
                        prefix,
                        zero,
                        one,
                        subtree_entries,
                    },
                    consume,
                )
            },
            tag => Err(PhysicalModelError::UnknownTag("physical-map-node", tag)),
        },
        RADIX_MAP_NODE_VERSION => decode_radix(decoder, bytes, domain, consume),
        _ => Err(PhysicalModelError::InvalidMap(
            "unsupported map-node version",
        )),
    }
}

fn decode_radix<T>(
    mut decoder: Decoder<'_>,
    bytes: &[u8],
    domain: PhysicalMapDomain,
    consume: impl FnOnce(MapNodeView<'_, &[u8]>) -> T,
) -> Result<T, PhysicalModelError> {
    match decoder.u8()? {
        0 => {
            let count = usize::from(decoder.u8()?);
            if count == 0 || count > RADIX_PAGE_CAPACITY {
                return Err(PhysicalModelError::InvalidMap(
                    "radix page count is outside its bound",
                ));
            }
            // The existing wire grammar admits exactly one entry per page.
            let key = PhysicalMapKey::new(decode_physical_digest(&mut decoder)?);
            const { assert!(RADIX_PAGE_CAPACITY == 1) };
            let entries = [(key, decoder.bytes()?)];
            validate_page(&entries)?;
            finish(
                decoder,
                bytes,
                MapNodeView::Page {
                    domain,
                    entries: &entries,
                },
                consume,
            )
        },
        1 => {
            let prefix_nibbles = decoder.u8()?;
            let prefix = decoder.take(nibble_prefix_byte_len(prefix_nibbles))?;
            let child_bitmap = decoder.u16()?;
            let count = usize::try_from(child_bitmap.count_ones())
                .map_err(|_| PhysicalModelError::LengthOverflow)?;
            // A u16 selector bitmap has at most sixteen children. This stack
            // buffer is derived from the format, not a new recovery limit.
            let mut children = [PhysicalMapNodeId::new([0; 32]); u16::BITS as usize];
            for child in &mut children[..count] {
                *child = decode_map_node_id(&mut decoder)?;
            }
            let children = &children[..count];
            let subtree_entries = decoder.u64()?;
            validate_radix(
                prefix_nibbles,
                prefix,
                child_bitmap,
                children,
                subtree_entries,
            )?;
            finish(
                decoder,
                bytes,
                MapNodeView::Radix {
                    domain,
                    prefix_nibbles,
                    prefix,
                    child_bitmap,
                    children,
                    subtree_entries,
                },
                consume,
            )
        },
        tag => Err(PhysicalModelError::UnknownTag(
            "physical-radix-map-node",
            tag,
        )),
    }
}

fn finish<T>(
    decoder: Decoder<'_>,
    bytes: &[u8],
    node: MapNodeView<'_, &[u8]>,
    consume: impl FnOnce(MapNodeView<'_, &[u8]>) -> T,
) -> Result<T, PhysicalModelError> {
    decoder.finish()?;
    let mut comparison = Encoder::comparing(bytes);
    node.encode_into(&mut comparison)?;
    comparison.finish_comparison()?;
    Ok(consume(node))
}
