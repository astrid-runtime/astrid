//! Canonical authenticated maps for physical profiles, records, and placements.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use crate::BlobId;

use super::PhysicalModelError;
use super::codec::{Decoder, Encoder};
use super::identity::{
    PhysicalIdentity, PhysicalMapNodeId, RepresentationProfileId, RepresentationRecordId,
    decode_map_node_id, decode_physical_digest, encode_map_node_id, encode_physical_digest,
};

mod legacy;
mod radix;

const LEGACY_MAP_NODE_VERSION: u16 = 1;
const RADIX_MAP_NODE_VERSION: u16 = 2;
const RADIX_PAGE_CAPACITY: usize = 1;
const DIGEST_NIBBLES: u8 = 64;
const TAGGED_PHYSICAL_IDENTITY_BYTES: usize = 40;
const SEARCH_KEY_BYTES: usize = 4 + TAGGED_PHYSICAL_IDENTITY_BYTES;
const SEARCH_KEY_BITS: u32 = 352;

/// Identity domain of one canonical physical map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PhysicalMapDomain {
    /// `RepresentationProfileId -> RepresentationProfile`.
    Profile,
    /// `RepresentationRecordId -> RepresentationRecord`.
    Representation,
    /// `BlobId -> PlacementEntry`.
    Placement,
}

impl PhysicalMapDomain {
    const fn code(self) -> u8 {
        match self {
            Self::Profile => 0,
            Self::Representation => 1,
            Self::Placement => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, PhysicalModelError> {
        match code {
            0 => Ok(Self::Profile),
            1 => Ok(Self::Representation),
            2 => Ok(Self::Placement),
            tag => Err(PhysicalModelError::UnknownTag("physical-map-domain", tag)),
        }
    }
}

/// Current in-memory key for a tagged physical identity.
///
/// The wire form remains length-tagged; this fixed-width value therefore does
/// not constrain a future decoder that supports successor digest widths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysicalMapKey([u8; 32]);

impl PhysicalMapKey {
    /// Construct a key from the current physical digest bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the current physical digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn search_key(self) -> [u8; SEARCH_KEY_BYTES] {
        let mut tagged = Encoder::new();
        encode_physical_digest(&mut tagged, &self.0);
        let tagged = tagged.finish();
        debug_assert_eq!(tagged.len(), TAGGED_PHYSICAL_IDENTITY_BYTES);
        let mut search = [0_u8; SEARCH_KEY_BYTES];
        search[..4].copy_from_slice(
            &u32::try_from(tagged.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        search[4..].copy_from_slice(&tagged);
        search
    }
}

impl From<RepresentationProfileId> for PhysicalMapKey {
    fn from(value: RepresentationProfileId) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<RepresentationRecordId> for PhysicalMapKey {
    fn from(value: RepresentationRecordId) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<BlobId> for PhysicalMapKey {
    fn from(value: BlobId) -> Self {
        Self(*value.as_bytes())
    }
}

/// One immutable node in a canonical path-copy physical map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PhysicalMapNode {
    /// One complete map entry.
    Leaf {
        /// Map domain, included in node identity.
        domain: PhysicalMapDomain,
        /// Tagged physical key.
        key: PhysicalMapKey,
        /// Canonical value bytes interpreted by the map domain.
        value: Vec<u8>,
    },
    /// Longest-common-prefix branch with exactly two children.
    Branch {
        /// Map domain, included in node identity.
        domain: PhysicalMapDomain,
        /// Number of meaningful most-significant prefix bits.
        prefix_bits: u32,
        /// Prefix bytes, with unused low bits zero.
        prefix: Vec<u8>,
        /// Child selected by a zero bit after the prefix.
        zero: PhysicalMapNodeId,
        /// Child selected by a one bit after the prefix.
        one: PhysicalMapNodeId,
        /// Exact number of reachable leaves.
        subtree_entries: u64,
    },
    /// A bounded, sorted page in the dense nibble-radix construction.
    Page {
        /// Map domain, included in node identity.
        domain: PhysicalMapDomain,
        /// Exactly one complete entry.
        entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    },
    /// A compressed nibble-radix branch with two or more children.
    Radix {
        /// Map domain, included in node identity.
        domain: PhysicalMapDomain,
        /// Number of complete key nibbles shared by every child.
        prefix_nibbles: u8,
        /// Shared digest prefix, with an unused low nibble cleared.
        prefix: Vec<u8>,
        /// Child selectors; identities follow set-bit order.
        child_bitmap: u16,
        /// Child identities in increasing selector order.
        children: Vec<PhysicalMapNodeId>,
        /// Exact number of reachable entries.
        subtree_entries: u64,
    },
}

impl PhysicalMapNode {
    const fn construction(&self) -> MapConstruction {
        match self {
            Self::Leaf { .. } | Self::Branch { .. } => MapConstruction::LegacyBinary,
            Self::Page { .. } | Self::Radix { .. } => MapConstruction::DenseRadix,
        }
    }

    /// Construct a canonical leaf.
    #[must_use]
    pub fn leaf(domain: PhysicalMapDomain, key: PhysicalMapKey, value: Vec<u8>) -> Self {
        Self::Leaf { domain, key, value }
    }

    /// Construct a checked canonical branch.
    ///
    /// # Errors
    ///
    /// Rejects impossible prefixes, aliasing children, and non-branch counts.
    pub fn branch(
        domain: PhysicalMapDomain,
        prefix_bits: u32,
        prefix: Vec<u8>,
        zero: PhysicalMapNodeId,
        one: PhysicalMapNodeId,
        subtree_entries: u64,
    ) -> Result<Self, PhysicalModelError> {
        legacy::validate_branch(prefix_bits, &prefix, zero, one, subtree_entries)?;
        Ok(Self::Branch {
            domain,
            prefix_bits,
            prefix,
            zero,
            one,
            subtree_entries,
        })
    }

    fn page(
        domain: PhysicalMapDomain,
        entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<Self, PhysicalModelError> {
        validate_page(&entries)?;
        Ok(Self::Page { domain, entries })
    }

    fn radix(
        domain: PhysicalMapDomain,
        prefix_nibbles: u8,
        prefix: Vec<u8>,
        child_bitmap: u16,
        children: Vec<PhysicalMapNodeId>,
        subtree_entries: u64,
    ) -> Result<Self, PhysicalModelError> {
        validate_radix(
            prefix_nibbles,
            &prefix,
            child_bitmap,
            &children,
            subtree_entries,
        )?;
        Ok(Self::Radix {
            domain,
            prefix_nibbles,
            prefix,
            child_bitmap,
            children,
            subtree_entries,
        })
    }

    /// Return the map domain included in this node's identity.
    #[must_use]
    pub const fn domain(&self) -> PhysicalMapDomain {
        match self {
            Self::Leaf { domain, .. }
            | Self::Branch { domain, .. }
            | Self::Page { domain, .. }
            | Self::Radix { domain, .. } => *domain,
        }
    }

    /// Return the exact leaf count authenticated by this node.
    #[must_use]
    pub const fn subtree_entries(&self) -> u64 {
        match self {
            Self::Leaf { .. } => 1,
            Self::Branch {
                subtree_entries, ..
            }
            | Self::Radix {
                subtree_entries, ..
            } => *subtree_entries,
            Self::Page { entries, .. } => entries.len() as u64,
        }
    }

    /// Encode the byte-exact format-one node grammar.
    ///
    /// # Errors
    ///
    /// Returns a length overflow when a leaf value cannot fit `u64`.
    pub fn encode(&self) -> Result<Vec<u8>, PhysicalModelError> {
        let mut encoder = Encoder::new();
        encoder.u16(match self {
            Self::Leaf { .. } | Self::Branch { .. } => LEGACY_MAP_NODE_VERSION,
            Self::Page { .. } | Self::Radix { .. } => RADIX_MAP_NODE_VERSION,
        });
        encoder.u8(self.domain().code());
        match self {
            Self::Leaf { key, value, .. } => {
                encoder.u8(0);
                encode_physical_digest(&mut encoder, key.as_bytes());
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
                encoder.u8(1);
                encoder.u32(*prefix_bits);
                encoder.raw(prefix);
                encode_map_node_id(&mut encoder, *zero);
                encode_map_node_id(&mut encoder, *one);
                encoder.u64(*subtree_entries);
            },
            Self::Page { entries, .. } => {
                encoder.u8(0);
                encoder
                    .u8(u8::try_from(entries.len())
                        .map_err(|_| PhysicalModelError::LengthOverflow)?);
                for (key, value) in entries {
                    encode_physical_digest(&mut encoder, key.as_bytes());
                    encoder.bytes(value)?;
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
                encoder.u8(1);
                encoder.u8(*prefix_nibbles);
                encoder.raw(prefix);
                encoder.u16(*child_bitmap);
                for child in children {
                    encode_map_node_id(&mut encoder, *child);
                }
                encoder.u64(*subtree_entries);
            },
        }
        Ok(encoder.finish())
    }

    /// Decode one canonical format-one node.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields, trailing bytes, and second encodings.
    pub fn decode(bytes: &[u8]) -> Result<Self, PhysicalModelError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u16()?;
        let domain = PhysicalMapDomain::from_code(decoder.u8()?)?;
        let node = match version {
            LEGACY_MAP_NODE_VERSION => match decoder.u8()? {
                0 => Self::leaf(
                    domain,
                    PhysicalMapKey::new(decode_physical_digest(&mut decoder)?),
                    decoder.bytes()?.to_vec(),
                ),
                1 => {
                    let prefix_bits = decoder.u32()?;
                    let prefix_bytes = legacy::prefix_byte_len(prefix_bits)?;
                    Self::branch(
                        domain,
                        prefix_bits,
                        decoder.take(prefix_bytes)?.to_vec(),
                        decode_map_node_id(&mut decoder)?,
                        decode_map_node_id(&mut decoder)?,
                        decoder.u64()?,
                    )?
                },
                tag => return Err(PhysicalModelError::UnknownTag("physical-map-node", tag)),
            },
            RADIX_MAP_NODE_VERSION => decode_radix_node(&mut decoder, domain)?,
            _ => {
                return Err(PhysicalModelError::InvalidMap(
                    "unsupported map-node version",
                ));
            },
        };
        decoder.finish()?;
        if node.encode()?.as_slice() != bytes {
            return Err(PhysicalModelError::NonCanonicalEncoding);
        }
        Ok(node)
    }

    /// Derive the domain-separated node identity.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the node cannot be represented.
    pub fn identify<I: PhysicalIdentity>(
        &self,
        identity: &I,
    ) -> Result<PhysicalMapNodeId, PhysicalModelError> {
        let context = match self {
            Self::Leaf { .. } | Self::Branch { .. } => "astrid-physical-map-node-v1\0",
            Self::Page { .. } | Self::Radix { .. } => "astrid-physical-radix-map-node-v1\0",
        };
        Ok(PhysicalMapNodeId::new(
            identity.identify(context, &self.encode()?),
        ))
    }
}

/// Canonical materialized view of one authenticated physical map.
///
/// Historical unreachable nodes may remain in `nodes`; validation and lookup
/// begin at `root`, so append-only path copying never makes old nodes live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPhysicalMap {
    domain: PhysicalMapDomain,
    construction: MapConstruction,
    root: Option<PhysicalMapNodeId>,
    nodes: BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    entry_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MapConstruction {
    LegacyBinary,
    DenseRadix,
}

impl CanonicalPhysicalMap {
    /// Build the unique canonical trie for a complete key/value set.
    ///
    /// # Errors
    ///
    /// Rejects duplicate keys and arithmetic overflow.
    pub fn build<I: PhysicalIdentity>(
        identity: &I,
        domain: PhysicalMapDomain,
        entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<Self, PhysicalModelError> {
        Self::build_with_construction(identity, domain, entries, MapConstruction::LegacyBinary)
    }

    /// Build the dense canonical nibble-radix construction.
    ///
    /// # Errors
    ///
    /// Rejects duplicate keys and arithmetic overflow.
    pub fn build_dense<I: PhysicalIdentity>(
        identity: &I,
        domain: PhysicalMapDomain,
        entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<Self, PhysicalModelError> {
        Self::build_with_construction(identity, domain, entries, MapConstruction::DenseRadix)
    }

    fn build_with_construction<I: PhysicalIdentity>(
        identity: &I,
        domain: PhysicalMapDomain,
        mut entries: Vec<(PhysicalMapKey, Vec<u8>)>,
        construction: MapConstruction,
    ) -> Result<Self, PhysicalModelError> {
        entries.sort_by_key(|(key, _)| *key);
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(PhysicalModelError::InvalidMap("duplicate leaf key"));
        }
        let entry_count =
            u64::try_from(entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?;
        let mut nodes = BTreeMap::new();
        let root = if entries.is_empty() {
            None
        } else {
            Some(match construction {
                MapConstruction::LegacyBinary => {
                    legacy::build(identity, domain, &entries, &mut nodes)?
                },
                MapConstruction::DenseRadix => {
                    radix::build(identity, domain, &entries, &mut nodes)?
                },
            })
        };
        Ok(Self {
            domain,
            construction,
            root,
            nodes,
            entry_count,
        })
    }

    /// Validate one root against an arena containing current and historical nodes.
    ///
    /// # Errors
    ///
    /// Rejects missing/cyclic nodes, identity mismatch, wrong domains, forged
    /// summaries, duplicate leaves, and every non-canonical trie shape.
    pub fn validate_root<I: PhysicalIdentity>(
        identity: &I,
        domain: PhysicalMapDomain,
        root: Option<PhysicalMapNodeId>,
        nodes: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    ) -> Result<u64, PhysicalModelError> {
        let Some(root) = root else {
            return Ok(0);
        };
        let construction = nodes
            .get(&root)
            .ok_or(PhysicalModelError::InvalidMap("missing map root"))?
            .construction();
        let mut stack = vec![root];
        let mut visited = BTreeSet::new();
        let mut entries = Vec::new();
        while let Some(node_id) = stack.pop() {
            if !visited.insert(node_id) {
                return Err(PhysicalModelError::InvalidMap(
                    "node is cyclic or shared by two parents",
                ));
            }
            let node = nodes
                .get(&node_id)
                .ok_or(PhysicalModelError::InvalidMap("missing map node"))?;
            if node.domain() != domain {
                return Err(PhysicalModelError::InvalidMap("map domain mismatch"));
            }
            if node.identify(identity)? != node_id {
                return Err(PhysicalModelError::InvalidMap("map-node identity mismatch"));
            }
            match node {
                PhysicalMapNode::Leaf { key, value, .. } => {
                    entries.push((*key, value.clone()));
                },
                PhysicalMapNode::Branch { zero, one, .. } => {
                    stack.push(*one);
                    stack.push(*zero);
                },
                PhysicalMapNode::Page {
                    entries: page_entries,
                    ..
                } => entries.extend(page_entries.iter().cloned()),
                PhysicalMapNode::Radix { children, .. } => {
                    stack.extend(children.iter().rev().copied());
                },
            }
        }
        let rebuilt = Self::build_with_construction(identity, domain, entries, construction)?;
        if rebuilt.root != Some(root) {
            return Err(PhysicalModelError::InvalidMap(
                "node graph is not the unique canonical trie",
            ));
        }
        Ok(rebuilt.entry_count)
    }

    /// Recover one active map while retaining historical arena nodes.
    ///
    /// # Errors
    ///
    /// Applies the same complete canonical validation as [`Self::validate_root`].
    pub fn recover<I: PhysicalIdentity>(
        identity: &I,
        domain: PhysicalMapDomain,
        root: Option<PhysicalMapNodeId>,
        nodes: BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    ) -> Result<Self, PhysicalModelError> {
        let entry_count = Self::validate_root(identity, domain, root, &nodes)?;
        let construction = root
            .and_then(|root| nodes.get(&root))
            .map_or(MapConstruction::DenseRadix, PhysicalMapNode::construction);
        Ok(Self {
            domain,
            construction,
            root,
            nodes,
            entry_count,
        })
    }

    /// Insert one immutable entry by path-copying only the affected trie path.
    ///
    /// Historical nodes remain available for older catalogue generations. An
    /// identical key/value is idempotent; reusing a key with unequal bytes is
    /// rejected as a physical identity collision.
    ///
    /// # Errors
    ///
    /// Rejects a collision, missing internal node, invalid stored domain, or
    /// count overflow without changing the active root.
    pub fn insert<I: PhysicalIdentity>(
        &mut self,
        identity: &I,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<bool, PhysicalModelError> {
        let (replacement, inserted) = if let Some(root) = self.root {
            match self.construction {
                MapConstruction::LegacyBinary => {
                    legacy::insert(identity, self.domain, &mut self.nodes, root, key, value)?
                },
                MapConstruction::DenseRadix => {
                    radix::insert(identity, self.domain, &mut self.nodes, root, key, value)?
                },
            }
        } else {
            let node = match self.construction {
                MapConstruction::LegacyBinary => PhysicalMapNode::leaf(self.domain, key, value),
                MapConstruction::DenseRadix => {
                    PhysicalMapNode::page(self.domain, vec![(key, value)])?
                },
            };
            let id = node.identify(identity)?;
            self.nodes.insert(id, node);
            (id, true)
        };
        if inserted {
            self.root = Some(replacement);
            self.entry_count = self
                .entry_count
                .checked_add(1)
                .ok_or(PhysicalModelError::LengthOverflow)?;
        }
        Ok(inserted)
    }

    /// Atomically rebuild the active canonical trie with additional entries.
    ///
    /// The resulting root is byte-identical to [`Self::build`] over the
    /// complete entry set. Historical nodes remain available for older roots,
    /// while only nodes reachable from the replacement root become active.
    /// This is intended for batches whose final-tree construction is cheaper
    /// than repeated path copying.
    ///
    /// # Errors
    ///
    /// Rejects unequal bytes under one key, malformed existing state, physical
    /// node-identity collisions, and arithmetic overflow without changing the
    /// active map.
    pub fn rebuild_with_entries<I: PhysicalIdentity>(
        &mut self,
        identity: &I,
        additions: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<u64, PhysicalModelError> {
        let mut entries = BTreeMap::<PhysicalMapKey, Vec<u8>>::new();
        if let Some(root) = self.root {
            let mut stack = vec![root];
            let mut visited = BTreeSet::new();
            while let Some(node_id) = stack.pop() {
                if !visited.insert(node_id) {
                    return Err(PhysicalModelError::InvalidMap(
                        "active map traversal revisited a node",
                    ));
                }
                match self
                    .nodes
                    .get(&node_id)
                    .ok_or(PhysicalModelError::InvalidMap("missing active map node"))?
                {
                    PhysicalMapNode::Leaf { key, value, .. } => {
                        if entries.insert(*key, value.clone()).is_some() {
                            return Err(PhysicalModelError::InvalidMap(
                                "active map has duplicate leaf keys",
                            ));
                        }
                    },
                    PhysicalMapNode::Branch { zero, one, .. } => {
                        stack.push(*one);
                        stack.push(*zero);
                    },
                    PhysicalMapNode::Page {
                        entries: page_entries,
                        ..
                    } => {
                        for (key, value) in page_entries {
                            if entries.insert(*key, value.clone()).is_some() {
                                return Err(PhysicalModelError::InvalidMap(
                                    "active map has duplicate page keys",
                                ));
                            }
                        }
                    },
                    PhysicalMapNode::Radix { children, .. } => {
                        stack.extend(children.iter().rev().copied());
                    },
                }
            }
        }
        if u64::try_from(entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?
            != self.entry_count
        {
            return Err(PhysicalModelError::InvalidMap(
                "active map count does not match its leaves",
            ));
        }

        let mut inserted = 0_u64;
        for (key, value) in additions {
            match entries.get(&key) {
                Some(existing) if existing == &value => {},
                Some(_) => {
                    return Err(PhysicalModelError::InvalidMap(
                        "leaf key has unequal canonical bytes",
                    ));
                },
                None => {
                    entries.insert(key, value);
                    inserted = inserted
                        .checked_add(1)
                        .ok_or(PhysicalModelError::LengthOverflow)?;
                },
            }
        }
        if inserted == 0 {
            return Ok(0);
        }

        let rebuilt = Self::build_with_construction(
            identity,
            self.domain,
            entries.into_iter().collect(),
            self.construction,
        )?;
        for (id, node) in &rebuilt.nodes {
            if self.nodes.get(id).is_some_and(|existing| existing != node) {
                return Err(PhysicalModelError::InvalidMap(
                    "physical map-node identity collision",
                ));
            }
        }
        self.nodes.extend(rebuilt.nodes);
        self.root = rebuilt.root;
        self.entry_count = rebuilt.entry_count;
        Ok(inserted)
    }

    /// Return the authenticated root, or `None` for an empty map.
    #[must_use]
    pub const fn root(&self) -> Option<PhysicalMapNodeId> {
        self.root
    }

    /// Return the exact number of leaves.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Borrow all nodes emitted while building this map.
    #[must_use]
    pub const fn nodes(&self) -> &BTreeMap<PhysicalMapNodeId, PhysicalMapNode> {
        &self.nodes
    }

    /// Look up one leaf through the authenticated trie.
    #[must_use]
    pub fn get(&self, key: PhysicalMapKey) -> Option<&[u8]> {
        let mut current = self.root?;
        let search = key.search_key();
        loop {
            match self.nodes.get(&current)? {
                PhysicalMapNode::Leaf {
                    key: stored, value, ..
                } => return (*stored == key).then_some(value.as_slice()),
                PhysicalMapNode::Branch {
                    prefix_bits,
                    prefix,
                    zero,
                    one,
                    ..
                } => {
                    if !legacy::matches_prefix(&search, *prefix_bits, prefix) {
                        return None;
                    }
                    current = if legacy::bit(&search, *prefix_bits) {
                        *one
                    } else {
                        *zero
                    };
                },
                PhysicalMapNode::Page { entries, .. } => {
                    return entries
                        .binary_search_by_key(&key, |(stored, _)| *stored)
                        .ok()
                        .map(|index| entries[index].1.as_slice());
                },
                PhysicalMapNode::Radix {
                    prefix_nibbles,
                    prefix,
                    child_bitmap,
                    children,
                    ..
                } => {
                    if radix_common_prefix(key, *prefix_nibbles, prefix) < *prefix_nibbles {
                        return None;
                    }
                    let selector = radix::nibble(key, *prefix_nibbles);
                    let mask = 1_u16 << selector;
                    if child_bitmap & mask == 0 {
                        return None;
                    }
                    let index =
                        usize::try_from((child_bitmap & mask.wrapping_sub(1)).count_ones()).ok()?;
                    current = *children.get(index)?;
                },
            }
        }
    }

    /// Return this map's fixed identity domain.
    #[must_use]
    pub const fn domain(&self) -> PhysicalMapDomain {
        self.domain
    }
}

fn decode_radix_node(
    decoder: &mut Decoder<'_>,
    domain: PhysicalMapDomain,
) -> Result<PhysicalMapNode, PhysicalModelError> {
    match decoder.u8()? {
        0 => {
            let count = usize::from(decoder.u8()?);
            if count == 0 || count > RADIX_PAGE_CAPACITY {
                return Err(PhysicalModelError::InvalidMap(
                    "radix page count is outside its bound",
                ));
            }
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(count)
                .map_err(|_| PhysicalModelError::LengthOverflow)?;
            for _ in 0..count {
                entries.push((
                    PhysicalMapKey::new(decode_physical_digest(decoder)?),
                    decoder.bytes()?.to_vec(),
                ));
            }
            PhysicalMapNode::page(domain, entries)
        },
        1 => {
            let prefix_nibbles = decoder.u8()?;
            let prefix = decoder
                .take(nibble_prefix_byte_len(prefix_nibbles))?
                .to_vec();
            let child_bitmap = decoder.u16()?;
            let child_count = usize::try_from(child_bitmap.count_ones())
                .map_err(|_| PhysicalModelError::LengthOverflow)?;
            let mut children = Vec::new();
            children
                .try_reserve_exact(child_count)
                .map_err(|_| PhysicalModelError::LengthOverflow)?;
            for _ in 0..child_count {
                children.push(decode_map_node_id(decoder)?);
            }
            PhysicalMapNode::radix(
                domain,
                prefix_nibbles,
                prefix,
                child_bitmap,
                children,
                decoder.u64()?,
            )
        },
        tag => Err(PhysicalModelError::UnknownTag(
            "physical-radix-map-node",
            tag,
        )),
    }
}

fn validate_page(entries: &[(PhysicalMapKey, Vec<u8>)]) -> Result<(), PhysicalModelError> {
    if entries.is_empty() || entries.len() > RADIX_PAGE_CAPACITY {
        return Err(PhysicalModelError::InvalidMap(
            "radix page count is outside its bound",
        ));
    }
    if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(PhysicalModelError::InvalidMap(
            "radix page keys are not strictly ordered",
        ));
    }
    Ok(())
}

pub(super) fn validate_radix(
    prefix_nibbles: u8,
    prefix: &[u8],
    child_bitmap: u16,
    children: &[PhysicalMapNodeId],
    subtree_entries: u64,
) -> Result<(), PhysicalModelError> {
    if prefix_nibbles >= DIGEST_NIBBLES {
        return Err(PhysicalModelError::InvalidMap(
            "radix prefix consumes the key",
        ));
    }
    if prefix.len() != nibble_prefix_byte_len(prefix_nibbles) {
        return Err(PhysicalModelError::InvalidMap(
            "radix prefix length mismatch",
        ));
    }
    if !prefix_nibbles.is_multiple_of(2) && prefix.last().is_some_and(|last| last & 0x0f != 0) {
        return Err(PhysicalModelError::InvalidMap(
            "radix prefix has a non-zero unused nibble",
        ));
    }
    let child_count = usize::try_from(child_bitmap.count_ones())
        .map_err(|_| PhysicalModelError::LengthOverflow)?;
    if child_count < 2
        || child_count != children.len()
        || subtree_entries <= RADIX_PAGE_CAPACITY as u64
    {
        return Err(PhysicalModelError::InvalidMap(
            "radix branch is non-canonical or incomplete",
        ));
    }
    if children.iter().copied().collect::<BTreeSet<_>>().len() != children.len() {
        return Err(PhysicalModelError::InvalidMap(
            "radix branch aliases its children",
        ));
    }
    Ok(())
}

fn nibble_prefix_byte_len(nibbles: u8) -> usize {
    usize::from(nibbles.div_ceil(2))
}

fn radix_common_prefix(key: PhysicalMapKey, prefix_nibbles: u8, prefix: &[u8]) -> u8 {
    let mut common = 0;
    while common < prefix_nibbles {
        let byte = prefix[usize::from(common / 2)];
        let expected = if common.is_multiple_of(2) {
            byte >> 4
        } else {
            byte & 0x0f
        };
        if radix::nibble(key, common) != expected {
            break;
        }
        common = common.saturating_add(1);
    }
    common
}
