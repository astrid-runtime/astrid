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

const MAP_NODE_VERSION: u16 = 1;
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
}

impl PhysicalMapNode {
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
        validate_branch(prefix_bits, &prefix, zero, one, subtree_entries)?;
        Ok(Self::Branch {
            domain,
            prefix_bits,
            prefix,
            zero,
            one,
            subtree_entries,
        })
    }

    /// Return the map domain included in this node's identity.
    #[must_use]
    pub const fn domain(&self) -> PhysicalMapDomain {
        match self {
            Self::Leaf { domain, .. } | Self::Branch { domain, .. } => *domain,
        }
    }

    /// Return the exact leaf count authenticated by this node.
    #[must_use]
    pub const fn subtree_entries(&self) -> u64 {
        match self {
            Self::Leaf { .. } => 1,
            Self::Branch {
                subtree_entries, ..
            } => *subtree_entries,
        }
    }

    /// Borrow this leaf's key and value, or return `None` for a branch.
    #[must_use]
    pub fn leaf_entry(&self) -> Option<(PhysicalMapKey, &[u8])> {
        match self {
            Self::Leaf { key, value, .. } => Some((*key, value)),
            Self::Branch { .. } => None,
        }
    }

    /// Encode the byte-exact format-one node grammar.
    ///
    /// # Errors
    ///
    /// Returns a length overflow when a leaf value cannot fit `u64`.
    pub fn encode(&self) -> Result<Vec<u8>, PhysicalModelError> {
        let mut encoder = Encoder::new();
        encoder.u16(MAP_NODE_VERSION);
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
        if decoder.u16()? != MAP_NODE_VERSION {
            return Err(PhysicalModelError::InvalidMap(
                "unsupported map-node version",
            ));
        }
        let domain = PhysicalMapDomain::from_code(decoder.u8()?)?;
        let node = match decoder.u8()? {
            0 => Self::leaf(
                domain,
                PhysicalMapKey::new(decode_physical_digest(&mut decoder)?),
                decoder.bytes()?.to_vec(),
            ),
            1 => {
                let prefix_bits = decoder.u32()?;
                let prefix_bytes = prefix_byte_len(prefix_bits)?;
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
        Ok(PhysicalMapNodeId::new(identity.identify(
            "astrid-physical-map-node-v1\0",
            &self.encode()?,
        )))
    }
}

/// Canonical materialized view of one authenticated physical map.
///
/// Historical unreachable nodes may remain in `nodes`; validation and lookup
/// begin at `root`, so append-only path copying never makes old nodes live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPhysicalMap {
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    entry_count: u64,
}

/// Result of one path-copy map insertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalMapUpdate {
    inserted: bool,
    root: PhysicalMapNodeId,
    new_nodes: Vec<(PhysicalMapNodeId, PhysicalMapNode)>,
}

impl PhysicalMapUpdate {
    /// Return whether the key was newly inserted.
    #[must_use]
    pub const fn inserted(&self) -> bool {
        self.inserted
    }

    /// Return the resulting authenticated root.
    #[must_use]
    pub const fn root(&self) -> PhysicalMapNodeId {
        self.root
    }

    /// Borrow exactly the newly emitted path-copy nodes.
    #[must_use]
    pub fn new_nodes(&self) -> &[(PhysicalMapNodeId, PhysicalMapNode)] {
        &self.new_nodes
    }
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
        mut entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<Self, PhysicalModelError> {
        entries.sort_by_key(|(key, _)| key.search_key());
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(PhysicalModelError::InvalidMap("duplicate leaf key"));
        }
        let entry_count =
            u64::try_from(entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?;
        let mut nodes = BTreeMap::new();
        let root = if entries.is_empty() {
            None
        } else {
            Some(build_range(identity, domain, &entries, &mut nodes)?)
        };
        Ok(Self {
            domain,
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
            }
        }
        let rebuilt = Self::build(identity, domain, entries)?;
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
        Ok(Self {
            domain,
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
        self.insert_with_delta(identity, key, value)
            .map(|update| update.inserted)
    }

    /// Insert one entry and return exactly the newly emitted path-copy nodes.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::insert`] without changing the root
    /// when validation fails.
    pub fn insert_with_delta<I: PhysicalIdentity>(
        &mut self,
        identity: &I,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<PhysicalMapUpdate, PhysicalModelError> {
        let mut insertion = MapInsertion {
            identity,
            domain: self.domain,
            nodes: &mut self.nodes,
            new_nodes: Vec::new(),
        };
        let (replacement, inserted) = match self.root {
            Some(root) => insertion.insert_at(root, key, value)?,
            None => (insertion.insert_leaf(key, value)?, true),
        };
        if inserted {
            self.root = Some(replacement);
            self.entry_count = self
                .entry_count
                .checked_add(1)
                .ok_or(PhysicalModelError::LengthOverflow)?;
        }
        Ok(PhysicalMapUpdate {
            inserted,
            root: replacement,
            new_nodes: insertion.new_nodes,
        })
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

        let rebuilt = Self::build(identity, self.domain, entries.into_iter().collect())?;
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
                    if !matches_prefix(&search, *prefix_bits, prefix) {
                        return None;
                    }
                    current = if bit(&search, *prefix_bits) {
                        *one
                    } else {
                        *zero
                    };
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

struct LeafParts {
    key: PhysicalMapKey,
    value: Vec<u8>,
}

struct BranchParts {
    prefix_bits: u32,
    prefix: Vec<u8>,
    zero: PhysicalMapNodeId,
    one: PhysicalMapNodeId,
    subtree_entries: u64,
}

struct MapInsertion<'a, I> {
    identity: &'a I,
    domain: PhysicalMapDomain,
    nodes: &'a mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    new_nodes: Vec<(PhysicalMapNodeId, PhysicalMapNode)>,
}

impl<I: PhysicalIdentity> MapInsertion<'_, I> {
    fn insert_at(
        &mut self,
        node_id: PhysicalMapNodeId,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
        let node = self
            .nodes
            .get(&node_id)
            .cloned()
            .ok_or(PhysicalModelError::InvalidMap("missing insertion node"))?;
        if node.domain() != self.domain {
            return Err(PhysicalModelError::InvalidMap(
                "insertion crossed a map domain",
            ));
        }
        match node {
            PhysicalMapNode::Leaf {
                key: old,
                value: old_value,
                ..
            } => self.insert_at_leaf(
                node_id,
                &LeafParts {
                    key: old,
                    value: old_value,
                },
                key,
                value,
            ),
            PhysicalMapNode::Branch {
                prefix_bits,
                prefix,
                zero,
                one,
                subtree_entries,
                ..
            } => self.insert_at_branch(
                node_id,
                BranchParts {
                    prefix_bits,
                    prefix,
                    zero,
                    one,
                    subtree_entries,
                },
                key,
                value,
            ),
        }
    }

    fn insert_at_leaf(
        &mut self,
        node_id: PhysicalMapNodeId,
        existing: &LeafParts,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
        if existing.key == key {
            if existing.value == value {
                return Ok((node_id, false));
            }
            return Err(PhysicalModelError::InvalidMap(
                "leaf key has unequal canonical bytes",
            ));
        }
        let existing_search = existing.key.search_key();
        let new_search = key.search_key();
        let prefix_bits = common_prefix_bits(&existing_search, &new_search)?;
        let new_leaf_id = self.insert_leaf(key, value)?;
        let (zero, one) = ordered_children(node_id, new_leaf_id, &new_search, prefix_bits);
        let branch = PhysicalMapNode::branch(
            self.domain,
            prefix_bits,
            canonical_prefix(&new_search, prefix_bits)?,
            zero,
            one,
            2,
        )?;
        self.insert_node(branch)
            .map(|replacement| (replacement, true))
    }

    fn insert_at_branch(
        &mut self,
        node_id: PhysicalMapNodeId,
        branch: BranchParts,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
        let search = key.search_key();
        let common = common_prefix_with_prefix(&search, branch.prefix_bits, &branch.prefix)?;
        if common < branch.prefix_bits {
            return self.split_branch(node_id, &branch, key, value, &search, common);
        }
        let descend_one = bit(&search, branch.prefix_bits);
        let child = if descend_one { branch.one } else { branch.zero };
        let (child_replacement, inserted) = self.insert_at(child, key, value)?;
        if !inserted {
            return Ok((node_id, false));
        }
        let parent = PhysicalMapNode::branch(
            self.domain,
            branch.prefix_bits,
            branch.prefix,
            if descend_one {
                branch.zero
            } else {
                child_replacement
            },
            if descend_one {
                child_replacement
            } else {
                branch.one
            },
            increment_count(branch.subtree_entries)?,
        )?;
        self.insert_node(parent)
            .map(|replacement| (replacement, true))
    }

    fn split_branch(
        &mut self,
        node_id: PhysicalMapNodeId,
        branch: &BranchParts,
        key: PhysicalMapKey,
        value: Vec<u8>,
        search: &[u8],
        common: u32,
    ) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
        let new_leaf_id = self.insert_leaf(key, value)?;
        if bit(&branch.prefix, common) == bit(search, common) {
            return Err(PhysicalModelError::InvalidMap(
                "branch prefix split did not diverge",
            ));
        }
        let (zero, one) = ordered_children(node_id, new_leaf_id, search, common);
        let parent = PhysicalMapNode::branch(
            self.domain,
            common,
            canonical_prefix(search, common)?,
            zero,
            one,
            increment_count(branch.subtree_entries)?,
        )?;
        self.insert_node(parent)
            .map(|replacement| (replacement, true))
    }

    fn insert_leaf(
        &mut self,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<PhysicalMapNodeId, PhysicalModelError> {
        self.insert_node(PhysicalMapNode::leaf(self.domain, key, value))
    }

    fn insert_node(
        &mut self,
        node: PhysicalMapNode,
    ) -> Result<PhysicalMapNodeId, PhysicalModelError> {
        let id = node.identify(self.identity)?;
        if !self.nodes.contains_key(&id) {
            self.new_nodes.push((id, node.clone()));
            self.nodes.insert(id, node);
        }
        Ok(id)
    }
}

fn ordered_children(
    existing: PhysicalMapNodeId,
    inserted: PhysicalMapNodeId,
    inserted_key: &[u8],
    split_bit: u32,
) -> (PhysicalMapNodeId, PhysicalMapNodeId) {
    if bit(inserted_key, split_bit) {
        (existing, inserted)
    } else {
        (inserted, existing)
    }
}

fn increment_count(count: u64) -> Result<u64, PhysicalModelError> {
    count
        .checked_add(1)
        .ok_or(PhysicalModelError::LengthOverflow)
}

fn build_range<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    entries: &[(PhysicalMapKey, Vec<u8>)],
    nodes: &mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<PhysicalMapNodeId, PhysicalModelError> {
    if entries.len() == 1 {
        let node = PhysicalMapNode::leaf(domain, entries[0].0, entries[0].1.clone());
        let id = node.identify(identity)?;
        nodes.insert(id, node);
        return Ok(id);
    }

    let first = entries
        .first()
        .ok_or(PhysicalModelError::InvalidMap("empty branch range"))?
        .0
        .search_key();
    let last = entries
        .last()
        .ok_or(PhysicalModelError::InvalidMap("empty branch range"))?
        .0
        .search_key();
    let prefix_bits = common_prefix_bits(&first, &last)?;
    if prefix_bits >= SEARCH_KEY_BITS {
        return Err(PhysicalModelError::InvalidMap("duplicate branch key"));
    }
    let split = entries.partition_point(|(key, _)| !bit(&key.search_key(), prefix_bits));
    if split == 0 || split == entries.len() {
        return Err(PhysicalModelError::InvalidMap("canonical branch is unary"));
    }
    let zero = build_range(identity, domain, &entries[..split], nodes)?;
    let one = build_range(identity, domain, &entries[split..], nodes)?;
    let node = PhysicalMapNode::branch(
        domain,
        prefix_bits,
        canonical_prefix(&first, prefix_bits)?,
        zero,
        one,
        u64::try_from(entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?,
    )?;
    let id = node.identify(identity)?;
    nodes.insert(id, node);
    Ok(id)
}

fn validate_branch(
    prefix_bits: u32,
    prefix: &[u8],
    zero: PhysicalMapNodeId,
    one: PhysicalMapNodeId,
    subtree_entries: u64,
) -> Result<(), PhysicalModelError> {
    if prefix_bits >= SEARCH_KEY_BITS {
        return Err(PhysicalModelError::InvalidMap("branch prefix consumes key"));
    }
    if prefix.len() != prefix_byte_len(prefix_bits)? {
        return Err(PhysicalModelError::InvalidMap(
            "branch prefix length mismatch",
        ));
    }
    let remainder = prefix_bits % 8;
    if !prefix_bits.is_multiple_of(8)
        && prefix.last().is_some_and(|last| {
            let unused = 8_u32.saturating_sub(remainder);
            let unused_mask = 1_u8
                .checked_shl(unused)
                .and_then(|value| value.checked_sub(1))
                .unwrap_or(u8::MAX);
            *last & unused_mask != 0
        })
    {
        return Err(PhysicalModelError::InvalidMap(
            "branch prefix has non-zero unused bits",
        ));
    }
    if zero == one {
        return Err(PhysicalModelError::InvalidMap(
            "branch aliases its children",
        ));
    }
    if subtree_entries < 2 {
        return Err(PhysicalModelError::InvalidMap("branch is unary"));
    }
    Ok(())
}

fn prefix_byte_len(bits: u32) -> Result<usize, PhysicalModelError> {
    usize::try_from(bits.div_ceil(8)).map_err(|_| PhysicalModelError::LengthOverflow)
}

fn common_prefix_bits(left: &[u8], right: &[u8]) -> Result<u32, PhysicalModelError> {
    let equal_bytes = left
        .iter()
        .zip(right)
        .position(|(left, right)| left != right)
        .unwrap_or(left.len());
    let equal_bits = u32::try_from(equal_bytes)
        .map_err(|_| PhysicalModelError::LengthOverflow)?
        .checked_mul(8)
        .ok_or(PhysicalModelError::LengthOverflow)?;
    if equal_bytes == left.len() {
        return Ok(equal_bits);
    }
    let differing = left[equal_bytes] ^ right[equal_bytes];
    equal_bits
        .checked_add(differing.leading_zeros())
        .ok_or(PhysicalModelError::LengthOverflow)
}

fn common_prefix_with_prefix(
    key: &[u8],
    prefix_bits: u32,
    prefix: &[u8],
) -> Result<u32, PhysicalModelError> {
    let mut common = 0_u32;
    while common < prefix_bits {
        if bit(key, common) != bit(prefix, common) {
            return Ok(common);
        }
        common = common
            .checked_add(1)
            .ok_or(PhysicalModelError::LengthOverflow)?;
    }
    Ok(common)
}

fn canonical_prefix(key: &[u8], bits: u32) -> Result<Vec<u8>, PhysicalModelError> {
    let byte_len = prefix_byte_len(bits)?;
    let mut prefix = key[..byte_len].to_vec();
    if !bits.is_multiple_of(8)
        && let Some(last) = prefix.last_mut()
    {
        *last &= u8::MAX
            .checked_shl(8_u32.saturating_sub(bits % 8))
            .unwrap_or(0);
    }
    Ok(prefix)
}

fn matches_prefix(key: &[u8], bits: u32, expected: &[u8]) -> bool {
    canonical_prefix(key, bits).is_ok_and(|prefix| prefix == expected)
}

fn bit(key: &[u8], offset: u32) -> bool {
    let byte = usize::try_from(offset / 8).unwrap_or(usize::MAX);
    let shift = 7_u32.saturating_sub(offset % 8);
    key.get(byte).is_some_and(|value| value & (1 << shift) != 0)
}
