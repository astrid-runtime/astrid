//! Exact logical coverage and deterministic physical reconstruction recipes.

use alloc::vec::Vec;

use crate::storage_model::{BlobId, InvocationId, ObjectId};

use super::PhysicalModelError;
use super::codec::{Decoder, Encoder};
use super::identity::{
    PhysicalIdentity, RepresentationProfileId, RepresentationRecordId, decode_blob_id,
    decode_object_id, decode_profile_id, encode_blob_id, encode_object_id, encode_profile_id,
};
use super::profile::{Dependency, ProfileKind, RepresentationProfile};

const REPRESENTATION_VERSION: u16 = 1;

/// Exact logical records recoverable from one physical representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// One complete canonical `ObjectRecord` encoding.
    Exact {
        /// Exact logical object reconstructed by the representation.
        object: ObjectId,
        /// Complete canonical `ObjectRecord` byte length.
        canonical_record_bytes: u64,
    },
}

impl Coverage {
    /// Construct exact one-object coverage.
    ///
    /// # Errors
    ///
    /// A complete canonical object record cannot have a zero byte length.
    pub fn exact(
        object: ObjectId,
        canonical_record_bytes: u64,
    ) -> Result<Self, PhysicalModelError> {
        let coverage = Self::Exact {
            object,
            canonical_record_bytes,
        };
        coverage.validate()?;
        Ok(coverage)
    }

    fn validate(&self) -> Result<(), PhysicalModelError> {
        match self {
            Self::Exact {
                canonical_record_bytes,
                ..
            } => {
                if *canonical_record_bytes == 0 {
                    return Err(PhysicalModelError::InvalidCoverage(
                        "exact canonical record length is zero",
                    ));
                }
            },
        }
        Ok(())
    }

    fn encode_into(&self, encoder: &mut Encoder) {
        match self {
            Self::Exact {
                object,
                canonical_record_bytes,
            } => {
                encoder.u8(0);
                encode_object_id(encoder, *object);
                encoder.u64(*canonical_record_bytes);
            },
        }
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, PhysicalModelError> {
        match decoder.u8()? {
            0 => Self::exact(decode_object_id(decoder)?, decoder.u64()?),
            tag => Err(PhysicalModelError::UnknownTag("coverage", tag)),
        }
    }
}

/// Deterministic recipe used to reconstruct canonical object records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recipe {
    /// One blob is already one complete canonical `ObjectRecord` encoding.
    DirectCanonical {
        /// Profile-bound canonical blob.
        blob: BlobId,
    },
    /// One pack range is one complete canonical `ObjectRecord` encoding.
    PackedSlice {
        /// Pack blob containing the canonical record.
        blob: BlobId,
        /// Byte offset within the decoded pack stream.
        offset: u64,
        /// Non-zero canonical record byte length.
        length: u64,
    },
    /// A pinned decoder expands one compressed canonical record.
    Compressed {
        /// Compressed profile-bound blob.
        blob: BlobId,
        /// Optional profile-bound trained dictionary.
        dictionary: Option<BlobId>,
    },
    /// A pinned transform applies one patch to a logical base object.
    Delta {
        /// Profile-bound delta patch.
        patch: BlobId,
        /// Exact logical base object selected through its own representation.
        base: ObjectId,
    },
    /// A deterministic derivation invocation reproduces one recorded output.
    Generated {
        /// Canonical derivation invocation.
        invocation: InvocationId,
        /// Zero-based output ordinal within its evidence.
        output_ordinal: u32,
        /// Canonical derivation evidence binding invocation to output.
        evidence: ObjectId,
    },
}

impl Recipe {
    fn encode_into(&self, encoder: &mut Encoder) {
        match self {
            Self::DirectCanonical { blob } => {
                encoder.u8(0);
                encode_blob_id(encoder, *blob);
            },
            Self::PackedSlice {
                blob,
                offset,
                length,
            } => {
                encoder.u8(1);
                encode_blob_id(encoder, *blob);
                encoder.u64(*offset);
                encoder.u64(*length);
            },
            Self::Compressed { blob, dictionary } => {
                encoder.u8(3);
                encode_blob_id(encoder, *blob);
                match dictionary {
                    Some(dictionary) => {
                        encoder.u8(1);
                        encode_blob_id(encoder, *dictionary);
                    },
                    None => encoder.u8(0),
                }
            },
            Self::Delta { patch, base } => {
                encoder.u8(4);
                encode_blob_id(encoder, *patch);
                encode_object_id(encoder, *base);
            },
            Self::Generated {
                invocation,
                output_ordinal,
                evidence,
            } => {
                encoder.u8(5);
                encode_object_id(encoder, invocation.object_id());
                encoder.u32(*output_ordinal);
                encode_object_id(encoder, *evidence);
            },
        }
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, PhysicalModelError> {
        match decoder.u8()? {
            0 => Ok(Self::DirectCanonical {
                blob: decode_blob_id(decoder)?,
            }),
            1 => {
                let recipe = Self::PackedSlice {
                    blob: decode_blob_id(decoder)?,
                    offset: decoder.u64()?,
                    length: decoder.u64()?,
                };
                if matches!(recipe, Self::PackedSlice { length: 0, .. }) {
                    return Err(PhysicalModelError::InvalidRecipe(
                        "packed slice length is zero",
                    ));
                }
                Ok(recipe)
            },
            3 => Ok(Self::Compressed {
                blob: decode_blob_id(decoder)?,
                dictionary: decoder.option(decode_blob_id)?,
            }),
            4 => Ok(Self::Delta {
                patch: decode_blob_id(decoder)?,
                base: decode_object_id(decoder)?,
            }),
            5 => Ok(Self::Generated {
                invocation: InvocationId::new(decode_object_id(decoder)?),
                output_ordinal: decoder.u32()?,
                evidence: decode_object_id(decoder)?,
            }),
            tag => Err(PhysicalModelError::UnknownTag("recipe", tag)),
        }
    }
}

/// Canonical physical recipe, exact logical coverage, and direct liveness edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepresentationRecord {
    profile: RepresentationProfileId,
    coverage: Coverage,
    recipe: Recipe,
    dependencies: Vec<Dependency>,
    canonical_output_bytes: u64,
    maximum_reconstruction_bytes: u64,
    verification_evidence: Option<ObjectId>,
}

impl RepresentationRecord {
    /// Construct a representation and derive its one canonical dependency set.
    ///
    /// # Errors
    ///
    /// Rejects incompatible coverage, missing evidence, impossible byte
    /// bounds, and recipes that could otherwise acquire a second encoding.
    pub fn new(
        profile: RepresentationProfileId,
        coverage: Coverage,
        recipe: Recipe,
        canonical_output_bytes: u64,
        maximum_reconstruction_bytes: u64,
        verification_evidence: Option<ObjectId>,
    ) -> Result<Self, PhysicalModelError> {
        coverage.validate()?;
        validate_recipe(
            &coverage,
            &recipe,
            canonical_output_bytes,
            maximum_reconstruction_bytes,
            verification_evidence,
        )?;
        let dependencies = derived_dependencies(profile, &recipe, verification_evidence);
        Ok(Self {
            profile,
            coverage,
            recipe,
            dependencies,
            canonical_output_bytes,
            maximum_reconstruction_bytes,
            verification_evidence,
        })
    }

    /// Return the exact profile governing this recipe.
    #[must_use]
    pub const fn profile(&self) -> RepresentationProfileId {
        self.profile
    }

    /// Borrow the exact logical coverage.
    #[must_use]
    pub const fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// Borrow the deterministic reconstruction recipe.
    #[must_use]
    pub const fn recipe(&self) -> &Recipe {
        &self.recipe
    }

    /// Borrow the complete sorted direct dependency set.
    #[must_use]
    pub fn dependencies(&self) -> &[Dependency] {
        &self.dependencies
    }

    /// Return the complete unique canonical output byte count.
    #[must_use]
    pub const fn canonical_output_bytes(&self) -> u64 {
        self.canonical_output_bytes
    }

    /// Return the admission ceiling for one complete reconstruction.
    #[must_use]
    pub const fn maximum_reconstruction_bytes(&self) -> u64 {
        self.maximum_reconstruction_bytes
    }

    /// Return the logical evidence object proving representation admission.
    #[must_use]
    pub const fn verification_evidence(&self) -> Option<ObjectId> {
        self.verification_evidence
    }

    /// Validate recipe/profile compatibility and profile-wide ceilings.
    ///
    /// # Errors
    ///
    /// Returns a profile or recipe error when the record names the wrong
    /// profile identity, recipe family, output ceiling, or dependency fanout.
    pub fn validate_against_profile<I: PhysicalIdentity>(
        &self,
        identity: &I,
        profile: &RepresentationProfile,
    ) -> Result<(), PhysicalModelError> {
        if profile.identify(identity)? != self.profile {
            return Err(PhysicalModelError::InvalidProfile(
                "record names a different profile identity",
            ));
        }
        let compatible = matches!(
            (profile.kind(), &self.recipe, &self.coverage),
            (
                ProfileKind::DirectCanonical,
                Recipe::DirectCanonical { .. },
                Coverage::Exact { .. }
            ) | (
                ProfileKind::PackedCanonical,
                Recipe::PackedSlice { .. },
                Coverage::Exact { .. }
            ) | (
                ProfileKind::Transform,
                Recipe::Compressed { .. } | Recipe::Delta { .. } | Recipe::Generated { .. },
                Coverage::Exact { .. }
            )
        );
        if !compatible {
            return Err(PhysicalModelError::InvalidRecipe(
                "recipe and coverage do not match the profile kind",
            ));
        }
        let bounds = profile.reconstruction_bounds();
        if self.maximum_reconstruction_bytes > bounds.maximum_output_bytes()
            || self.canonical_output_bytes > bounds.maximum_output_bytes()
        {
            return Err(PhysicalModelError::InvalidRecipe(
                "record exceeds profile output bounds",
            ));
        }
        let dependency_count = u32::try_from(self.dependencies.len())
            .map_err(|_| PhysicalModelError::LengthOverflow)?;
        if dependency_count > bounds.maximum_dependency_fanout() {
            return Err(PhysicalModelError::InvalidRecipe(
                "record exceeds profile dependency fanout",
            ));
        }
        Ok(())
    }

    /// Encode this record using the format-one canonical wire grammar.
    ///
    /// # Errors
    ///
    /// Returns [`PhysicalModelError::LengthOverflow`] when the dependency
    /// count does not fit its format-one `u64` length field.
    pub fn encode(&self) -> Result<Vec<u8>, PhysicalModelError> {
        self.encode_fields(&self.dependencies, self.verification_evidence)
    }

    pub(super) fn admission_subject_bytes(&self) -> Result<Vec<u8>, PhysicalModelError> {
        if matches!(self.recipe, Recipe::Generated { .. }) {
            return Err(PhysicalModelError::InvalidRecipe(
                "generated representation uses derivation evidence",
            ));
        }
        let dependencies = derived_dependencies(self.profile, &self.recipe, None);
        self.encode_fields(&dependencies, None)
    }

    fn encode_fields(
        &self,
        dependencies: &[Dependency],
        verification_evidence: Option<ObjectId>,
    ) -> Result<Vec<u8>, PhysicalModelError> {
        let mut encoder = Encoder::new();
        encoder.u16(REPRESENTATION_VERSION);
        encode_profile_id(&mut encoder, self.profile);
        self.coverage.encode_into(&mut encoder);
        self.recipe.encode_into(&mut encoder);
        encoder.count(dependencies.len())?;
        for dependency in dependencies {
            dependency.encode_into(&mut encoder);
        }
        encoder.u64(self.canonical_output_bytes);
        encoder.u64(self.maximum_reconstruction_bytes);
        encode_optional_object(&mut encoder, verification_evidence);
        Ok(encoder.finish())
    }

    /// Decode one byte-exact canonical format-one representation record.
    ///
    /// # Errors
    ///
    /// Rejects unknown tags, forged dependency arrays, invalid evidence,
    /// trailing bytes, and any encoding that does not reproduce itself.
    pub fn decode(bytes: &[u8]) -> Result<Self, PhysicalModelError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.u16()? != REPRESENTATION_VERSION {
            return Err(PhysicalModelError::InvalidRecipe(
                "unsupported representation-record version",
            ));
        }
        let profile = decode_profile_id(&mut decoder)?;
        let coverage = Coverage::decode_from(&mut decoder)?;
        let recipe = Recipe::decode_from(&mut decoder)?;
        let dependency_count = decoder.length()?;
        if dependency_count > decoder.remaining() / 41 {
            return Err(PhysicalModelError::Truncated);
        }
        let mut encoded_dependencies = Vec::new();
        encoded_dependencies
            .try_reserve(dependency_count)
            .map_err(|_| PhysicalModelError::LengthOverflow)?;
        for _ in 0..dependency_count {
            encoded_dependencies.push(Dependency::decode_from(&mut decoder)?);
        }
        if encoded_dependencies
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(PhysicalModelError::NonCanonicalCollection(
                "representation dependency",
            ));
        }
        let canonical_output_bytes = decoder.u64()?;
        let maximum_reconstruction_bytes = decoder.u64()?;
        let verification_evidence = decoder.option(decode_object_id)?;
        decoder.finish()?;
        let record = Self::new(
            profile,
            coverage,
            recipe,
            canonical_output_bytes,
            maximum_reconstruction_bytes,
            verification_evidence,
        )?;
        if record.dependencies != encoded_dependencies || record.encode()?.as_slice() != bytes {
            return Err(PhysicalModelError::NonCanonicalEncoding);
        }
        Ok(record)
    }

    /// Derive this record's domain-separated physical identity.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when this record cannot be represented by
    /// the format-one wire grammar.
    pub fn identify<I: PhysicalIdentity>(
        &self,
        identity: &I,
    ) -> Result<RepresentationRecordId, PhysicalModelError> {
        Ok(RepresentationRecordId::new(identity.identify(
            "astrid-representation-record-v1\0",
            &self.encode()?,
        )))
    }
}

fn encode_optional_object(encoder: &mut Encoder, value: Option<ObjectId>) {
    match value {
        Some(value) => {
            encoder.u8(1);
            encode_object_id(encoder, value);
        },
        None => encoder.u8(0),
    }
}

fn derived_dependencies(
    profile: RepresentationProfileId,
    recipe: &Recipe,
    verification_evidence: Option<ObjectId>,
) -> Vec<Dependency> {
    let mut dependencies = alloc::vec![Dependency::Profile(profile)];
    match recipe {
        Recipe::DirectCanonical { blob } | Recipe::PackedSlice { blob, .. } => {
            dependencies.push(Dependency::PhysicalBlob(*blob));
        },
        Recipe::Compressed { blob, dictionary } => {
            dependencies.push(Dependency::PhysicalBlob(*blob));
            if let Some(dictionary) = dictionary {
                dependencies.push(Dependency::PhysicalBlob(*dictionary));
            }
        },
        Recipe::Delta { patch, base } => {
            dependencies.push(Dependency::PhysicalBlob(*patch));
            dependencies.push(Dependency::LogicalObject(*base));
        },
        Recipe::Generated {
            invocation,
            evidence,
            ..
        } => {
            dependencies.push(Dependency::Invocation(*invocation));
            dependencies.push(Dependency::Evidence(*evidence));
        },
    }
    if let Some(evidence) = verification_evidence {
        dependencies.push(Dependency::Evidence(evidence));
    }
    dependencies.sort_unstable();
    dependencies.dedup();
    dependencies
}

fn validate_recipe(
    coverage: &Coverage,
    recipe: &Recipe,
    canonical_output_bytes: u64,
    maximum_reconstruction_bytes: u64,
    verification_evidence: Option<ObjectId>,
) -> Result<(), PhysicalModelError> {
    if maximum_reconstruction_bytes == 0 {
        return Err(PhysicalModelError::InvalidRecipe(
            "maximum reconstruction bytes is zero",
        ));
    }
    if canonical_output_bytes > maximum_reconstruction_bytes {
        return Err(PhysicalModelError::ReconstructionBoundTooSmall);
    }
    if let Coverage::Exact {
        canonical_record_bytes,
        ..
    } = coverage
        && canonical_output_bytes != *canonical_record_bytes
    {
        return Err(PhysicalModelError::InvalidRecipe(
            "exact output byte count differs from coverage",
        ));
    }
    match recipe {
        Recipe::DirectCanonical { .. } => {
            if !matches!(coverage, Coverage::Exact { .. }) {
                return Err(PhysicalModelError::InvalidRecipe(
                    "direct recipe requires exact coverage",
                ));
            }
        },
        Recipe::PackedSlice { offset, length, .. } => {
            if *length == 0
                || offset.checked_add(*length).is_none()
                || !matches!(coverage, Coverage::Exact { .. })
            {
                return Err(PhysicalModelError::InvalidRecipe(
                    "packed recipe requires a bounded non-zero exact slice",
                ));
            }
            if *length != canonical_output_bytes {
                return Err(PhysicalModelError::InvalidRecipe(
                    "packed slice length differs from canonical output",
                ));
            }
            if verification_evidence.is_none() {
                return Err(PhysicalModelError::InvalidRecipe(
                    "packed recipe requires admission evidence",
                ));
            }
        },
        Recipe::Compressed { .. } | Recipe::Delta { .. } => {
            if !matches!(coverage, Coverage::Exact { .. }) {
                return Err(PhysicalModelError::InvalidRecipe(
                    "transform recipe requires exact coverage",
                ));
            }
            if verification_evidence.is_none() {
                return Err(PhysicalModelError::InvalidRecipe(
                    "transform recipe requires admission evidence",
                ));
            }
        },
        Recipe::Generated { evidence, .. } => {
            if !matches!(coverage, Coverage::Exact { .. }) {
                return Err(PhysicalModelError::InvalidRecipe(
                    "generated recipe requires exact coverage",
                ));
            }
            if verification_evidence != Some(*evidence) {
                return Err(PhysicalModelError::InvalidRecipe(
                    "generated evidence does not match verification evidence",
                ));
            }
        },
    }
    Ok(())
}
