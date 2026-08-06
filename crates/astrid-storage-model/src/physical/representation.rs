//! Exact logical coverage and deterministic physical reconstruction recipes.

use alloc::vec::Vec;

use crate::{BlobId, InvocationId, ObjectId};

use super::PhysicalModelError;
use super::codec::{Decoder, Encoder};
use super::identity::{
    PhysicalIdentity, RepresentationProfileId, RepresentationRecordId, decode_blob_id,
    decode_object_id, decode_profile_id, encode_blob_id, encode_object_id, encode_profile_id,
};
use super::profile::{Dependency, ProfileKind, RepresentationProfile};

const REPRESENTATION_VERSION: u16 = 1;
const FASTCDC_ALGORITHM: u8 = 1;
const FASTCDC_REVISION: u16 = 1;
const FASTCDC_NORMALIZATION: u8 = 1;

/// Canonical identity-bearing `FastCDC` profile copied from a File descriptor.
///
/// This physical-model value carries the same frozen fields as the logical
/// content model without making the lower-level model depend on its decoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalChunkingProfile {
    minimum_bytes: u32,
    average_bytes: u32,
    maximum_bytes: u32,
    gear_seed: u64,
}

impl CanonicalChunkingProfile {
    /// Astrid's pinned 16/64/256 `KiB` `FastCDC` format-one profile.
    pub const ASTRID_V1: Self = Self {
        minimum_bytes: 16 * 1024,
        average_bytes: 64 * 1024,
        maximum_bytes: 256 * 1024,
        gear_seed: 0,
    };

    /// Construct a validated pinned `FastCDC` 2020 profile.
    ///
    /// # Errors
    ///
    /// Returns [`PhysicalModelError::InvalidCoverage`] when the sizes are
    /// outside the frozen implementation bounds or are not strictly ordered.
    pub fn fastcdc_v2020(
        minimum_bytes: u32,
        average_bytes: u32,
        maximum_bytes: u32,
        gear_seed: u64,
    ) -> Result<Self, PhysicalModelError> {
        if !(64..=1_048_576).contains(&minimum_bytes)
            || !(256..=4_194_304).contains(&average_bytes)
            || !(1024..=16_777_216).contains(&maximum_bytes)
        {
            return Err(PhysicalModelError::InvalidCoverage(
                "chunk sizes are outside FastCDC 2020 bounds",
            ));
        }
        if !(minimum_bytes < average_bytes && average_bytes < maximum_bytes) {
            return Err(PhysicalModelError::InvalidCoverage(
                "chunk sizes are not strictly increasing",
            ));
        }
        if !average_bytes.is_power_of_two() {
            return Err(PhysicalModelError::InvalidCoverage(
                "average chunk size is not a power of two",
            ));
        }
        Ok(Self {
            minimum_bytes,
            average_bytes,
            maximum_bytes,
            gear_seed,
        })
    }

    /// Return the minimum chunk size.
    #[must_use]
    pub const fn minimum_bytes(self) -> u32 {
        self.minimum_bytes
    }

    /// Return the target average chunk size.
    #[must_use]
    pub const fn average_bytes(self) -> u32 {
        self.average_bytes
    }

    /// Return the maximum chunk size.
    #[must_use]
    pub const fn maximum_bytes(self) -> u32 {
        self.maximum_bytes
    }

    /// Return the pinned gear-table seed.
    #[must_use]
    pub const fn gear_seed(self) -> u64 {
        self.gear_seed
    }

    fn encode_into(self, encoder: &mut Encoder) {
        encoder.u8(FASTCDC_ALGORITHM);
        encoder.u16(FASTCDC_REVISION);
        encoder.u8(FASTCDC_NORMALIZATION);
        encoder.u32(self.minimum_bytes);
        encoder.u32(self.average_bytes);
        encoder.u32(self.maximum_bytes);
        encoder.u64(self.gear_seed);
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, PhysicalModelError> {
        if decoder.u8()? != FASTCDC_ALGORITHM
            || decoder.u16()? != FASTCDC_REVISION
            || decoder.u8()? != FASTCDC_NORMALIZATION
        {
            return Err(PhysicalModelError::InvalidCoverage(
                "unsupported chunking profile",
            ));
        }
        Self::fastcdc_v2020(
            decoder.u32()?,
            decoder.u32()?,
            decoder.u32()?,
            decoder.u64()?,
        )
    }
}

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
    /// Canonical chunk records reconstructed from one contiguous file stream.
    CanonicalFileChunks {
        /// Canonical File object whose DAG fixes chunk order and lengths.
        file: ObjectId,
        /// Canonical File content root, absent only for an empty file.
        content_root: Option<ObjectId>,
        /// Exact user-visible file length.
        logical_bytes: u64,
        /// Exact logical chunk occurrence count.
        chunk_count: u64,
        /// Identity-bearing chunking profile copied from the canonical File.
        chunking_profile: CanonicalChunkingProfile,
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

    /// Construct compact canonical File/Chunk coverage.
    ///
    /// # Errors
    ///
    /// Rejects empty/non-empty shape contradictions and impossible one-chunk
    /// threshold claims. Admission later compares every field to the File DAG.
    pub fn canonical_file_chunks(
        file: ObjectId,
        content_root: Option<ObjectId>,
        logical_bytes: u64,
        chunk_count: u64,
        chunking_profile: CanonicalChunkingProfile,
    ) -> Result<Self, PhysicalModelError> {
        let coverage = Self::CanonicalFileChunks {
            file,
            content_root,
            logical_bytes,
            chunk_count,
            chunking_profile,
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
            Self::CanonicalFileChunks {
                content_root,
                logical_bytes,
                chunk_count,
                chunking_profile,
                ..
            } => {
                if *logical_bytes == 0 {
                    if content_root.is_some() || *chunk_count != 0 {
                        return Err(PhysicalModelError::InvalidCoverage(
                            "empty file has content coverage",
                        ));
                    }
                } else {
                    if content_root.is_none() || *chunk_count == 0 {
                        return Err(PhysicalModelError::InvalidCoverage(
                            "non-empty file omits content coverage",
                        ));
                    }
                    let fits_one_chunk =
                        *logical_bytes <= u64::from(chunking_profile.maximum_bytes());
                    if (*chunk_count == 1) != fits_one_chunk {
                        return Err(PhysicalModelError::InvalidCoverage(
                            "file violates the whole-object chunk threshold",
                        ));
                    }
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
            Self::CanonicalFileChunks {
                file,
                content_root,
                logical_bytes,
                chunk_count,
                chunking_profile,
            } => {
                encoder.u8(1);
                encode_object_id(encoder, *file);
                encode_optional_object(encoder, *content_root);
                encoder.u64(*logical_bytes);
                encoder.u64(*chunk_count);
                chunking_profile.encode_into(encoder);
            },
        }
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, PhysicalModelError> {
        match decoder.u8()? {
            0 => Self::exact(decode_object_id(decoder)?, decoder.u64()?),
            1 => Self::canonical_file_chunks(
                decode_object_id(decoder)?,
                decoder.option(decode_object_id)?,
                decoder.u64()?,
                decoder.u64()?,
                CanonicalChunkingProfile::decode_from(decoder)?,
            ),
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
    /// One raw blob is a canonical File's contiguous payload stream.
    ContiguousFile {
        /// Profile-bound raw file blob.
        blob: BlobId,
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
            Self::ContiguousFile { blob } => {
                encoder.u8(2);
                encode_blob_id(encoder, *blob);
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
            2 => Ok(Self::ContiguousFile {
                blob: decode_blob_id(decoder)?,
            }),
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
                ProfileKind::ContiguousFile,
                Recipe::ContiguousFile { .. },
                Coverage::CanonicalFileChunks { .. }
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
        Recipe::DirectCanonical { blob }
        | Recipe::PackedSlice { blob, .. }
        | Recipe::ContiguousFile { blob } => {
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
    match coverage {
        Coverage::Exact {
            canonical_record_bytes,
            ..
        } if canonical_output_bytes != *canonical_record_bytes => {
            return Err(PhysicalModelError::InvalidRecipe(
                "exact output byte count differs from coverage",
            ));
        },
        Coverage::CanonicalFileChunks { chunk_count, .. }
            if (*chunk_count == 0) != (canonical_output_bytes == 0) =>
        {
            return Err(PhysicalModelError::InvalidRecipe(
                "file chunk output byte count contradicts chunk count",
            ));
        },
        _ => {},
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
        Recipe::ContiguousFile { .. } => {
            if !matches!(coverage, Coverage::CanonicalFileChunks { .. }) {
                return Err(PhysicalModelError::InvalidRecipe(
                    "contiguous recipe requires canonical file coverage",
                ));
            }
            if verification_evidence.is_none() {
                return Err(PhysicalModelError::InvalidRecipe(
                    "contiguous recipe requires admission evidence",
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
