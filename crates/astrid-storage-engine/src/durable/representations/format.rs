//! Byte-exact physical metadata and representation-journal grammars.

use astrid_storage_model::{
    PhysicalIdentity, PhysicalMapNode, PhysicalMapNodeId, PlacementSet,
    RepresentationCatalogueRoot, RepresentationProfile, RepresentationRecord, RepresentationState,
    RepresentationStateId,
};

use super::super::DurableError;

pub(super) const METADATA_MAGIC: [u8; 8] = *b"ASTRPM1\0";
pub(super) const JOURNAL_MAGIC: [u8; 8] = *b"ASTREP1\0";
pub(super) const CURRENT_MAGIC: [u8; 8] = *b"ASTCUR1\0";
pub(super) const METADATA_FILE: &str = "representation metadata arena";
pub(super) const JOURNAL_FILE: &str = "representation state journal";
pub(super) const CURRENT_FILE: &str = "representation current pointer";

const BLAKE3_ALGORITHM: u16 = 1;
const PHYSICAL_CONSTRUCTION: u16 = 2;
const CURRENT_DIGEST_BYTES: u32 = 32;
const TAGGED_IDENTITY_BYTES: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum MetadataKind {
    Profile,
    Representation,
    MapNode,
    Catalogue,
    Placement,
    State,
}

impl MetadataKind {
    const fn code(self) -> u8 {
        match self {
            Self::Profile => 0,
            Self::Representation => 1,
            Self::MapNode => 2,
            Self::Catalogue => 3,
            Self::Placement => 4,
            Self::State => 5,
        }
    }

    fn decode(code: u8) -> Result<Self, DurableError> {
        match code {
            0 => Ok(Self::Profile),
            1 => Ok(Self::Representation),
            2 => Ok(Self::MapNode),
            3 => Ok(Self::Catalogue),
            4 => Ok(Self::Placement),
            5 => Ok(Self::State),
            _ => Err(DurableError::InvalidRepresentationState(
                "unknown metadata frame kind",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MetadataFrame {
    pub(super) kind: MetadataKind,
    pub(super) identity: [u8; 32],
    pub(super) value: Vec<u8>,
}

impl MetadataFrame {
    #[cfg(test)]
    pub(super) fn profile<I: PhysicalIdentity>(
        identity: &I,
        value: &RepresentationProfile,
    ) -> Result<Self, DurableError> {
        let id = value.identify(identity)?;
        Ok(Self::new(
            MetadataKind::Profile,
            *id.as_bytes(),
            value.encode()?,
        ))
    }

    pub(super) fn map_node<I: PhysicalIdentity>(
        identity: &I,
        value: &PhysicalMapNode,
    ) -> Result<Self, DurableError> {
        let id = value.identify(identity)?;
        Ok(Self::new(
            MetadataKind::MapNode,
            *id.as_bytes(),
            value.encode()?,
        ))
    }

    pub(super) fn catalogue<I: PhysicalIdentity>(
        identity: &I,
        value: RepresentationCatalogueRoot,
    ) -> Self {
        let id = value.identify(identity);
        Self::new(MetadataKind::Catalogue, *id.as_bytes(), value.encode())
    }

    pub(super) fn placement<I: PhysicalIdentity>(identity: &I, value: PlacementSet) -> Self {
        let id = value.identify(identity);
        Self::new(MetadataKind::Placement, *id.as_bytes(), value.encode())
    }

    pub(super) fn state<I: PhysicalIdentity>(identity: &I, value: RepresentationState) -> Self {
        let id = value.identify(identity);
        Self::new(MetadataKind::State, *id.as_bytes(), value.encode())
    }

    const fn new(kind: MetadataKind, identity: [u8; 32], value: Vec<u8>) -> Self {
        Self {
            kind,
            identity,
            value,
        }
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, DurableError> {
        let value_len =
            u64::try_from(self.value.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let mut bytes = Vec::new();
        let capacity = 1_usize
            .checked_add(TAGGED_IDENTITY_BYTES)
            .and_then(|total| total.checked_add(8))
            .and_then(|total| total.checked_add(self.value.len()))
            .ok_or(DurableError::EncodingOverflow)?;
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| DurableError::EncodingOverflow)?;
        bytes.push(self.kind.code());
        encode_physical_identity(&mut bytes, &self.identity);
        bytes.extend_from_slice(&value_len.to_le_bytes());
        bytes.extend_from_slice(&self.value);
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DurableError> {
        let mut reader = Reader::new(bytes);
        let kind = MetadataKind::decode(reader.u8()?)?;
        let identity = reader.physical_identity()?;
        let value = reader.length_prefixed()?.to_vec();
        reader.finish()?;
        let frame = Self::new(kind, identity, value);
        if frame.encode()?.as_slice() != bytes {
            return Err(DurableError::InvalidRepresentationState(
                "metadata frame is not canonical",
            ));
        }
        Ok(frame)
    }

    pub(super) fn verify<I: PhysicalIdentity>(&self, identity: &I) -> Result<(), DurableError> {
        let computed = match self.kind {
            MetadataKind::Profile => *RepresentationProfile::decode(&self.value)?
                .identify(identity)?
                .as_bytes(),
            MetadataKind::Representation => *RepresentationRecord::decode(&self.value)?
                .identify(identity)?
                .as_bytes(),
            MetadataKind::MapNode => *PhysicalMapNode::decode(&self.value)?
                .identify(identity)?
                .as_bytes(),
            MetadataKind::Catalogue => *RepresentationCatalogueRoot::decode(&self.value)?
                .identify(identity)
                .as_bytes(),
            MetadataKind::Placement => *PlacementSet::decode(&self.value)?
                .identify(identity)
                .as_bytes(),
            MetadataKind::State => *RepresentationState::decode(&self.value)?
                .identify(identity)
                .as_bytes(),
        };
        if computed != self.identity {
            return Err(DurableError::InvalidRepresentationState(
                "metadata identity does not match canonical value",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CurrentPointer {
    pub(super) journal_generation: u64,
    pub(super) checkpoint_digest: [u8; 32],
    pub(super) max_tail_frames: u32,
    pub(super) max_tail_bytes: u64,
}

impl CurrentPointer {
    pub(super) fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + TAGGED_IDENTITY_BYTES + 4 + 8);
        bytes.extend_from_slice(&self.journal_generation.to_le_bytes());
        encode_physical_identity(&mut bytes, &self.checkpoint_digest);
        bytes.extend_from_slice(&self.max_tail_frames.to_le_bytes());
        bytes.extend_from_slice(&self.max_tail_bytes.to_le_bytes());
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DurableError> {
        let mut reader = Reader::new(bytes);
        let value = Self {
            journal_generation: reader.u64()?,
            checkpoint_digest: reader.physical_identity()?,
            max_tail_frames: reader.u32()?,
            max_tail_bytes: reader.u64()?,
        };
        reader.finish()?;
        if value.journal_generation == 0 || value.max_tail_frames == 0 || value.max_tail_bytes == 0
        {
            return Err(DurableError::InvalidRepresentationState(
                "current pointer contains a zero bound or generation",
            ));
        }
        if value.encode().as_slice() != bytes {
            return Err(DurableError::InvalidRepresentationState(
                "current pointer is not canonical",
            ));
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum JournalEntry {
    StateCas {
        journal_generation: u64,
        expected: Option<RepresentationStateId>,
        replacement: RepresentationStateId,
    },
    Checkpoint {
        journal_generation: u64,
        active: Option<RepresentationStateId>,
        state_generation: u64,
        prior_journal_digest: Option<[u8; 32]>,
    },
}

impl JournalEntry {
    pub(super) fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::StateCas {
                journal_generation,
                expected,
                replacement,
            } => {
                bytes.push(0);
                bytes.extend_from_slice(&journal_generation.to_le_bytes());
                encode_optional_state(&mut bytes, expected);
                encode_physical_identity(&mut bytes, replacement.as_bytes());
            },
            Self::Checkpoint {
                journal_generation,
                active,
                state_generation,
                prior_journal_digest,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&journal_generation.to_le_bytes());
                encode_optional_state(&mut bytes, active);
                bytes.extend_from_slice(&state_generation.to_le_bytes());
                encode_optional_digest(&mut bytes, prior_journal_digest);
            },
        }
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DurableError> {
        let mut reader = Reader::new(bytes);
        let entry = match reader.u8()? {
            0 => Self::StateCas {
                journal_generation: reader.u64()?,
                expected: reader.optional_state()?,
                replacement: RepresentationStateId::new(reader.physical_identity()?),
            },
            1 => Self::Checkpoint {
                journal_generation: reader.u64()?,
                active: reader.optional_state()?,
                state_generation: reader.u64()?,
                prior_journal_digest: reader.optional_digest()?,
            },
            _ => {
                return Err(DurableError::InvalidRepresentationState(
                    "unknown representation journal entry",
                ));
            },
        };
        reader.finish()?;
        if entry.encode().as_slice() != bytes {
            return Err(DurableError::InvalidRepresentationState(
                "representation journal entry is not canonical",
            ));
        }
        Ok(entry)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Blake3PhysicalIdentity;

impl PhysicalIdentity for Blake3PhysicalIdentity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(material);
        *hasher.finalize().as_bytes()
    }

    fn identify_parts(&self, context: &'static str, parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        for part in parts {
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
    }
}

pub(super) fn journal_digest(bytes: &[u8]) -> [u8; 32] {
    Blake3PhysicalIdentity.identify("astrid-representation-journal-bytes-v1\0", bytes)
}

pub(super) fn map_node_id(bytes: [u8; 32]) -> PhysicalMapNodeId {
    PhysicalMapNodeId::new(bytes)
}

fn encode_physical_identity(bytes: &mut Vec<u8>, digest: &[u8; 32]) {
    bytes.extend_from_slice(&BLAKE3_ALGORITHM.to_le_bytes());
    bytes.extend_from_slice(&PHYSICAL_CONSTRUCTION.to_le_bytes());
    bytes.extend_from_slice(&CURRENT_DIGEST_BYTES.to_le_bytes());
    bytes.extend_from_slice(digest);
}

fn encode_optional_state(bytes: &mut Vec<u8>, value: Option<RepresentationStateId>) {
    match value {
        Some(value) => {
            bytes.push(1);
            encode_physical_identity(bytes, value.as_bytes());
        },
        None => bytes.push(0),
    }
}

fn encode_optional_digest(bytes: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            bytes.push(1);
            encode_physical_identity(bytes, &value);
        },
        None => bytes.push(0),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DurableError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DurableError::EncodingOverflow)?;
        let value =
            self.bytes
                .get(self.offset..end)
                .ok_or(DurableError::InvalidRepresentationState(
                    "truncated representation metadata",
                ))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, DurableError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(DurableError::InvalidRepresentationState(
                "truncated representation u8",
            ))
    }

    fn u32(&mut self) -> Result<u32, DurableError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| DurableError::EncodingOverflow)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, DurableError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DurableError::EncodingOverflow)?,
        ))
    }

    fn physical_identity(&mut self) -> Result<[u8; 32], DurableError> {
        let algorithm = u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| DurableError::EncodingOverflow)?,
        );
        let construction = u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| DurableError::EncodingOverflow)?,
        );
        let digest_length = self.u32()?;
        if algorithm != BLAKE3_ALGORITHM
            || construction != PHYSICAL_CONSTRUCTION
            || digest_length != CURRENT_DIGEST_BYTES
        {
            return Err(DurableError::InvalidRepresentationState(
                "unsupported physical identity envelope",
            ));
        }
        self.take(32)?
            .try_into()
            .map_err(|_| DurableError::EncodingOverflow)
    }

    fn length_prefixed(&mut self) -> Result<&'a [u8], DurableError> {
        let length = usize::try_from(self.u64()?).map_err(|_| DurableError::EncodingOverflow)?;
        self.take(length)
    }

    fn optional_state(&mut self) -> Result<Option<RepresentationStateId>, DurableError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self
                .physical_identity()
                .map(RepresentationStateId::new)
                .map(Some),
            _ => Err(DurableError::InvalidRepresentationState(
                "invalid optional state tag",
            )),
        }
    }

    fn optional_digest(&mut self) -> Result<Option<[u8; 32]>, DurableError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.physical_identity().map(Some),
            _ => Err(DurableError::InvalidRepresentationState(
                "invalid optional digest tag",
            )),
        }
    }

    fn finish(self) -> Result<(), DurableError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DurableError::InvalidRepresentationState(
                "trailing representation metadata bytes",
            ))
        }
    }
}
