//! Atomic pairing of one representation catalogue and one placement set.

use alloc::vec::Vec;

use super::PhysicalModelError;
use super::codec::{Decoder, Encoder};
use super::identity::{
    PhysicalIdentity, PlacementSetId, RepresentationCatalogueRootId, RepresentationStateId,
    decode_catalogue_root_id, decode_placement_set_id, decode_state_id, encode_catalogue_root_id,
    encode_placement_set_id, encode_state_id,
};

const STATE_VERSION: u16 = 1;

/// Canonical atomic physical-state transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepresentationState {
    generation: u64,
    previous: Option<RepresentationStateId>,
    catalogue: RepresentationCatalogueRootId,
    placements: PlacementSetId,
}

impl RepresentationState {
    /// Construct one generation-checked representation state.
    ///
    /// # Errors
    ///
    /// Creation starts at generation one without a predecessor; every later
    /// state names exactly one predecessor.
    pub fn new(
        generation: u64,
        previous: Option<RepresentationStateId>,
        catalogue: RepresentationCatalogueRootId,
        placements: PlacementSetId,
    ) -> Result<Self, PhysicalModelError> {
        if generation == 0 {
            return Err(PhysicalModelError::InvalidRepresentationState(
                "state generation is zero",
            ));
        }
        if (generation == 1) != previous.is_none() {
            return Err(PhysicalModelError::InvalidRepresentationState(
                "state predecessor and generation disagree",
            ));
        }
        Ok(Self {
            generation,
            previous,
            catalogue,
            placements,
        })
    }

    /// Return the state generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Return the journal predecessor identity.
    #[must_use]
    pub const fn previous(self) -> Option<RepresentationStateId> {
        self.previous
    }

    /// Return the authoritative catalogue root.
    #[must_use]
    pub const fn catalogue(self) -> RepresentationCatalogueRootId {
        self.catalogue
    }

    /// Return the authoritative placement set.
    #[must_use]
    pub const fn placements(self) -> PlacementSetId {
        self.placements
    }

    /// Encode the byte-exact format-one state grammar.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.u16(STATE_VERSION);
        encoder.u64(self.generation);
        match self.previous {
            Some(previous) => {
                encoder.u8(1);
                encode_state_id(&mut encoder, previous);
            },
            None => encoder.u8(0),
        }
        encode_catalogue_root_id(&mut encoder, self.catalogue);
        encode_placement_set_id(&mut encoder, self.placements);
        encoder.finish()
    }

    /// Decode one canonical format-one representation state.
    ///
    /// # Errors
    ///
    /// Rejects invalid generation shape, options, trailing bytes, and second
    /// encodings.
    pub fn decode(bytes: &[u8]) -> Result<Self, PhysicalModelError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.u16()? != STATE_VERSION {
            return Err(PhysicalModelError::InvalidRepresentationState(
                "unsupported state version",
            ));
        }
        let value = Self::new(
            decoder.u64()?,
            decoder.option(decode_state_id)?,
            decode_catalogue_root_id(&mut decoder)?,
            decode_placement_set_id(&mut decoder)?,
        )?;
        decoder.finish()?;
        if value.encode().as_slice() != bytes {
            return Err(PhysicalModelError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// Derive the domain-separated state identity.
    #[must_use]
    pub fn identify<I: PhysicalIdentity>(self, identity: &I) -> RepresentationStateId {
        RepresentationStateId::new(
            identity.identify("astrid-representation-state-v1\0", &self.encode()),
        )
    }
}
