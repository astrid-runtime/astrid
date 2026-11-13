//! Canonical authenticated maps for physical profiles, records, and placements.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::storage_model::BlobId;

use super::PhysicalModelError;
use super::codec::Encoder;
use super::identity::{
    PhysicalIdentity, PhysicalMapNodeId, RepresentationProfileId, RepresentationRecordId,
    encode_physical_digest,
};

mod decode;
mod encode;
mod legacy;
mod radix;
mod rebuild;
mod residency;
mod validation;

#[cfg(test)]
mod decode_tests;
#[cfg(test)]
mod lookup_tests;
#[cfg(test)]
mod rebuild_tests;

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
        match self {
            Self::Leaf { domain, key, value } => encode::leaf(*domain, key, value, &mut encoder)?,
            Self::Branch {
                domain,
                prefix_bits,
                prefix,
                zero,
                one,
                subtree_entries,
            } => {
                encode::branch(
                    *domain,
                    *prefix_bits,
                    prefix,
                    zero,
                    one,
                    *subtree_entries,
                    &mut encoder,
                );
            },
            Self::Page { domain, entries } => encode::page(*domain, entries, &mut encoder)?,
            Self::Radix {
                domain,
                prefix_nibbles,
                prefix,
                child_bitmap,
                children,
                subtree_entries,
            } => {
                encode::radix(
                    *domain,
                    *prefix_nibbles,
                    prefix,
                    *child_bitmap,
                    children,
                    *subtree_entries,
                    &mut encoder,
                );
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
        decode::with_decoded(bytes, decode::into_owned)?
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
        self.encode_and_identify(identity).map(|(_, id)| id)
    }

    /// Retain the exact canonical bytes used to derive the node identity.
    /// Metadata publication needs both; encoding them together avoids allocating
    /// and serializing the same node again after identification.
    pub(crate) fn encode_and_identify<I: PhysicalIdentity>(
        &self,
        identity: &I,
    ) -> Result<(Vec<u8>, PhysicalMapNodeId), PhysicalModelError> {
        let bytes = self.encode()?;
        let id = PhysicalMapNodeId::new(identity.identify(self.identity_context(), &bytes));
        Ok((bytes, id))
    }

    #[cfg(test)]
    pub(crate) fn count_encodings_during<T>(operation: impl FnOnce() -> T) -> (T, usize) {
        super::codec::reset_encoder_finishes();
        let value = operation();
        (value, super::codec::encoder_finishes())
    }

    /// Authenticate the original bytes after decode proves their canonical form.
    /// Recovery already owns these bytes, so encoding again for hashing would
    /// duplicate the byte comparison performed by `decode`.
    #[cfg(any(test, not(target_family = "wasm")))]
    pub(crate) fn decode_and_identify<I: PhysicalIdentity>(
        bytes: &[u8],
        identity: &I,
    ) -> Result<(Self, PhysicalMapNodeId), PhysicalModelError> {
        let node = Self::decode(bytes)?;
        let id = PhysicalMapNodeId::new(identity.identify(node.identity_context(), bytes));
        Ok((node, id))
    }

    /// Authenticate historical metadata and consume its links without allocation.
    #[cfg(any(test, not(target_family = "wasm")))]
    pub(crate) fn with_child_ids_and_identify<I: PhysicalIdentity, T>(
        bytes: &[u8],
        identity: &I,
        consume: impl FnOnce(PhysicalMapNodeId, &[PhysicalMapNodeId]) -> T,
    ) -> Result<T, PhysicalModelError> {
        decode::with_decoded(bytes, |node| {
            let id = PhysicalMapNodeId::new(identity.identify(node.identity_context(), bytes));
            node.with_child_ids(|children| consume(id, children))
        })
    }

    const fn identity_context(&self) -> &'static str {
        match self {
            Self::Leaf { .. } | Self::Branch { .. } => "astrid-physical-map-node-v1\0",
            Self::Page { .. } | Self::Radix { .. } => "astrid-physical-radix-map-node-v1\0",
        }
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
        validation::validate_root(identity, domain, root, nodes)
    }

    /// Recover one active map, retaining every node supplied by the caller.
    ///
    /// A caller that needs only the active view should supply its reachable
    /// closure. Historical-model callers may supply a larger arena to keep
    /// older roots available; this function does not prune that arena.
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
        let mut search = None;
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
                    let search = search.get_or_insert_with(|| key.search_key());
                    if !legacy::matches_prefix(search, *prefix_bits, prefix) {
                        return None;
                    }
                    current = if legacy::bit(search, *prefix_bits) {
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

fn validate_page<V>(entries: &[(PhysicalMapKey, V)]) -> Result<(), PhysicalModelError> {
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
    // The selector bitmap bounds this slice to sixteen children. Compare the
    // preceding IDs directly so validating borrowed nodes never allocates.
    if children
        .iter()
        .enumerate()
        .any(|(index, child)| children[..index].contains(child))
    {
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
