//! Atomic roots for canonical representation profiles and records.

use alloc::vec::Vec;

use super::PhysicalModelError;
use super::codec::{Decoder, Encoder};
use super::identity::{
    PhysicalIdentity, PhysicalMapNodeId, RepresentationCatalogueRootId, decode_map_node_id,
    encode_map_node_id,
};

const CATALOGUE_VERSION: u16 = 1;

/// Canonical roots and exact entry counts of one representation catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepresentationCatalogueRoot {
    generation: u64,
    profiles_root: Option<PhysicalMapNodeId>,
    profile_count: u64,
    representations_root: Option<PhysicalMapNodeId>,
    representation_count: u64,
}

impl RepresentationCatalogueRoot {
    /// Construct one checked catalogue root.
    ///
    /// # Errors
    ///
    /// An absent map root must have count zero and a present root must have a
    /// non-zero count. Closure validation proves the exact positive count.
    pub fn new(
        generation: u64,
        profiles_root: Option<PhysicalMapNodeId>,
        profile_count: u64,
        representations_root: Option<PhysicalMapNodeId>,
        representation_count: u64,
    ) -> Result<Self, PhysicalModelError> {
        validate_root_count(profiles_root, profile_count, "profile")?;
        validate_root_count(representations_root, representation_count, "representation")?;
        Ok(Self {
            generation,
            profiles_root,
            profile_count,
            representations_root,
            representation_count,
        })
    }

    /// Return the catalogue generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Return the authenticated profile-map root.
    #[must_use]
    pub const fn profiles_root(self) -> Option<PhysicalMapNodeId> {
        self.profiles_root
    }

    /// Return the exact number of profile leaves.
    #[must_use]
    pub const fn profile_count(self) -> u64 {
        self.profile_count
    }

    /// Return the authenticated representation-map root.
    #[must_use]
    pub const fn representations_root(self) -> Option<PhysicalMapNodeId> {
        self.representations_root
    }

    /// Return the exact number of representation leaves.
    #[must_use]
    pub const fn representation_count(self) -> u64 {
        self.representation_count
    }

    /// Encode the byte-exact format-one catalogue root.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.u16(CATALOGUE_VERSION);
        encoder.u64(self.generation);
        encode_optional_node(&mut encoder, self.profiles_root);
        encoder.u64(self.profile_count);
        encode_optional_node(&mut encoder, self.representations_root);
        encoder.u64(self.representation_count);
        encoder.finish()
    }

    /// Decode one canonical format-one catalogue root.
    ///
    /// # Errors
    ///
    /// Rejects contradictory counts, invalid options, trailing bytes, and
    /// second encodings.
    pub fn decode(bytes: &[u8]) -> Result<Self, PhysicalModelError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.u16()? != CATALOGUE_VERSION {
            return Err(PhysicalModelError::InvalidCatalogue(
                "unsupported catalogue-root version",
            ));
        }
        let value = Self::new(
            decoder.u64()?,
            decoder.option(decode_map_node_id)?,
            decoder.u64()?,
            decoder.option(decode_map_node_id)?,
            decoder.u64()?,
        )?;
        decoder.finish()?;
        if value.encode().as_slice() != bytes {
            return Err(PhysicalModelError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// Derive the domain-separated catalogue-root identity.
    #[must_use]
    pub fn identify<I: PhysicalIdentity>(self, identity: &I) -> RepresentationCatalogueRootId {
        RepresentationCatalogueRootId::new(
            identity.identify("astrid-representation-catalogue-root-v1\0", &self.encode()),
        )
    }
}

fn encode_optional_node(encoder: &mut Encoder, node: Option<PhysicalMapNodeId>) {
    match node {
        Some(node) => {
            encoder.u8(1);
            encode_map_node_id(encoder, node);
        },
        None => encoder.u8(0),
    }
}

fn validate_root_count(
    root: Option<PhysicalMapNodeId>,
    count: u64,
    name: &'static str,
) -> Result<(), PhysicalModelError> {
    if root.is_some() != (count != 0) {
        return Err(PhysicalModelError::InvalidCatalogue(match name {
            "profile" => "profile root and count disagree",
            _ => "representation root and count disagree",
        }));
    }
    Ok(())
}
