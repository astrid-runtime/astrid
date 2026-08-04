//! Immutable physical representation profiles and dependency typing.

use alloc::vec::Vec;

use crate::{BlobId, InvocationId, ObjectId};

use super::PhysicalModelError;
use super::codec::{Decoder, Encoder};
use super::identity::{
    PhysicalIdentity, RepresentationProfileId, RepresentationRecordId, decode_blob_id,
    decode_object_id, decode_profile_id, decode_record_id, encode_blob_id, encode_object_id,
    encode_profile_id, encode_record_id,
};

const PROFILE_VERSION: u16 = 1;
const BOUNDS_VERSION: u16 = 1;

/// Execution and expansion ceilings pinned by one representation profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconstructionBounds {
    dependency_depth: u32,
    dependency_fanout: u32,
    encoded_bytes: u64,
    output_bytes: u64,
    fuel: u64,
    resident_bytes: u64,
    elapsed_micros: u64,
}

impl ReconstructionBounds {
    /// Construct non-zero reconstruction ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`PhysicalModelError::ZeroReconstructionBound`] for the first
    /// zero field. These are execution ceilings, not store or user quotas.
    pub fn new(
        maximum_dependency_depth: u32,
        maximum_dependency_fanout: u32,
        maximum_encoded_bytes: u64,
        maximum_output_bytes: u64,
        maximum_fuel: u64,
        maximum_resident_bytes: u64,
        maximum_elapsed_micros: u64,
    ) -> Result<Self, PhysicalModelError> {
        for (name, value) in [
            ("maximum_encoded_bytes", maximum_encoded_bytes),
            ("maximum_output_bytes", maximum_output_bytes),
            ("maximum_fuel", maximum_fuel),
            ("maximum_resident_bytes", maximum_resident_bytes),
            ("maximum_elapsed_micros", maximum_elapsed_micros),
        ] {
            if value == 0 {
                return Err(PhysicalModelError::ZeroReconstructionBound(name));
            }
        }
        if maximum_dependency_depth == 0 {
            return Err(PhysicalModelError::ZeroReconstructionBound(
                "maximum_dependency_depth",
            ));
        }
        if maximum_dependency_fanout == 0 {
            return Err(PhysicalModelError::ZeroReconstructionBound(
                "maximum_dependency_fanout",
            ));
        }
        Ok(Self {
            dependency_depth: maximum_dependency_depth,
            dependency_fanout: maximum_dependency_fanout,
            encoded_bytes: maximum_encoded_bytes,
            output_bytes: maximum_output_bytes,
            fuel: maximum_fuel,
            resident_bytes: maximum_resident_bytes,
            elapsed_micros: maximum_elapsed_micros,
        })
    }

    /// Return the maximum dependency-graph depth.
    #[must_use]
    pub const fn maximum_dependency_depth(self) -> u32 {
        self.dependency_depth
    }

    /// Return the maximum direct dependency fanout.
    #[must_use]
    pub const fn maximum_dependency_fanout(self) -> u32 {
        self.dependency_fanout
    }

    /// Return the maximum encoded input bytes consumed by one replay.
    #[must_use]
    pub const fn maximum_encoded_bytes(self) -> u64 {
        self.encoded_bytes
    }

    /// Return the maximum canonical output bytes produced by one replay.
    #[must_use]
    pub const fn maximum_output_bytes(self) -> u64 {
        self.output_bytes
    }

    /// Return the maximum transform fuel consumed by one replay.
    #[must_use]
    pub const fn maximum_fuel(self) -> u64 {
        self.fuel
    }

    /// Return the maximum resident bytes consumed by one replay.
    #[must_use]
    pub const fn maximum_resident_bytes(self) -> u64 {
        self.resident_bytes
    }

    /// Return the maximum elapsed microseconds consumed by one replay.
    #[must_use]
    pub const fn maximum_elapsed_micros(self) -> u64 {
        self.elapsed_micros
    }

    pub(super) fn encode_into(self, encoder: &mut Encoder) {
        encoder.u16(BOUNDS_VERSION);
        encoder.u32(self.dependency_depth);
        encoder.u32(self.dependency_fanout);
        encoder.u64(self.encoded_bytes);
        encoder.u64(self.output_bytes);
        encoder.u64(self.fuel);
        encoder.u64(self.resident_bytes);
        encoder.u64(self.elapsed_micros);
    }

    pub(super) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, PhysicalModelError> {
        if decoder.u16()? != BOUNDS_VERSION {
            return Err(PhysicalModelError::InvalidProfile(
                "unsupported reconstruction-bounds version",
            ));
        }
        Self::new(
            decoder.u32()?,
            decoder.u32()?,
            decoder.u64()?,
            decoder.u64()?,
            decoder.u64()?,
            decoder.u64()?,
            decoder.u64()?,
        )
    }
}

/// Built-in or transform-backed profile family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileKind {
    /// Complete canonical object bytes in one blob.
    DirectCanonical,
    /// Canonical object bytes held as a slice of a pack blob.
    PackedCanonical,
    /// One contiguous file byte stream covering canonical chunk objects.
    ContiguousFile,
    /// A pinned deterministic transform reconstructs canonical bytes.
    Transform,
}

impl ProfileKind {
    const fn code(self) -> u8 {
        match self {
            Self::DirectCanonical => 0,
            Self::PackedCanonical => 1,
            Self::ContiguousFile => 2,
            Self::Transform => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, PhysicalModelError> {
        match code {
            0 => Ok(Self::DirectCanonical),
            1 => Ok(Self::PackedCanonical),
            2 => Ok(Self::ContiguousFile),
            3 => Ok(Self::Transform),
            _ => Err(PhysicalModelError::UnknownTag("profile-kind", code)),
        }
    }
}

/// Dependency admitted in a profile's immutable transform environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProfileDependency {
    /// Canonical logical object required by the profile or transform contract.
    LogicalObject(ObjectId),
    /// Profile-wide encoded blob such as a trained dictionary.
    PhysicalBlob(BlobId),
}

impl ProfileDependency {
    fn canonical_key(self) -> (u8, [u8; 32]) {
        match self {
            Self::LogicalObject(object) => (0, *object.as_bytes()),
            Self::PhysicalBlob(blob) => (1, *blob.as_bytes()),
        }
    }

    fn encode_into(self, encoder: &mut Encoder) {
        match self {
            Self::LogicalObject(object) => {
                encoder.u8(0);
                encode_object_id(encoder, object);
            },
            Self::PhysicalBlob(blob) => {
                encoder.u8(1);
                encode_blob_id(encoder, blob);
            },
        }
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, PhysicalModelError> {
        match decoder.u8()? {
            0 => decode_object_id(decoder).map(Self::LogicalObject),
            1 => decode_blob_id(decoder).map(Self::PhysicalBlob),
            tag => Err(PhysicalModelError::UnknownTag("profile-dependency", tag)),
        }
    }
}

impl Ord for ProfileDependency {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.canonical_key().cmp(&other.canonical_key())
    }
}

impl PartialOrd for ProfileDependency {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Direct dependency of one representation record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dependency {
    /// Canonical logical object needed by replay.
    LogicalObject(ObjectId),
    /// Encoded physical blob needed by replay.
    PhysicalBlob(BlobId),
    /// Another representation record needed by replay.
    Representation(RepresentationRecordId),
    /// Profile record governing replay semantics.
    Profile(RepresentationProfileId),
    /// Deterministic invocation whose output can be replayed.
    Invocation(InvocationId),
    /// Logical evidence object proving admission or execution.
    Evidence(ObjectId),
}

impl Dependency {
    fn canonical_key(self) -> (u8, [u8; 32]) {
        match self {
            Self::LogicalObject(object) => (0, *object.as_bytes()),
            Self::PhysicalBlob(blob) => (1, *blob.as_bytes()),
            Self::Representation(record) => (2, *record.as_bytes()),
            Self::Profile(profile) => (3, *profile.as_bytes()),
            Self::Invocation(invocation) => (4, *invocation.object_id().as_bytes()),
            Self::Evidence(evidence) => (5, *evidence.as_bytes()),
        }
    }

    pub(super) fn encode_into(self, encoder: &mut Encoder) {
        match self {
            Self::LogicalObject(object) => {
                encoder.u8(0);
                encode_object_id(encoder, object);
            },
            Self::PhysicalBlob(blob) => {
                encoder.u8(1);
                encode_blob_id(encoder, blob);
            },
            Self::Representation(record) => {
                encoder.u8(2);
                encode_record_id(encoder, record);
            },
            Self::Profile(profile) => {
                encoder.u8(3);
                encode_profile_id(encoder, profile);
            },
            Self::Invocation(invocation) => {
                encoder.u8(4);
                encode_object_id(encoder, invocation.object_id());
            },
            Self::Evidence(evidence) => {
                encoder.u8(5);
                encode_object_id(encoder, evidence);
            },
        }
    }

    pub(super) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, PhysicalModelError> {
        match decoder.u8()? {
            0 => decode_object_id(decoder).map(Self::LogicalObject),
            1 => decode_blob_id(decoder).map(Self::PhysicalBlob),
            2 => decode_record_id(decoder).map(Self::Representation),
            3 => decode_profile_id(decoder).map(Self::Profile),
            4 => decode_object_id(decoder).map(|id| Self::Invocation(InvocationId::new(id))),
            5 => decode_object_id(decoder).map(Self::Evidence),
            tag => Err(PhysicalModelError::UnknownTag("dependency", tag)),
        }
    }
}

impl Ord for Dependency {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.canonical_key().cmp(&other.canonical_key())
    }
}

impl PartialOrd for Dependency {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Immutable profile that pins decoder semantics, dependencies, and bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepresentationProfile {
    kind: ProfileKind,
    decoder_or_generator: Option<ObjectId>,
    transform_contract: Option<ObjectId>,
    runtime_semantic_profile: Option<ObjectId>,
    canonical_parameters: Vec<u8>,
    immutable_dependencies: Vec<ProfileDependency>,
    reconstruction_bounds: ReconstructionBounds,
    frozen_specification: ObjectId,
}

impl RepresentationProfile {
    /// Construct one built-in engine profile.
    ///
    /// # Errors
    ///
    /// Returns [`PhysicalModelError::InvalidProfile`] for
    /// [`ProfileKind::Transform`], which requires the explicit transform
    /// constructor.
    pub fn new_builtin(
        kind: ProfileKind,
        reconstruction_bounds: ReconstructionBounds,
        frozen_specification: ObjectId,
    ) -> Result<Self, PhysicalModelError> {
        if kind == ProfileKind::Transform {
            return Err(PhysicalModelError::InvalidProfile(
                "transform profile requires pinned transform fields",
            ));
        }
        let profile = Self {
            kind,
            decoder_or_generator: None,
            transform_contract: None,
            runtime_semantic_profile: None,
            canonical_parameters: Vec::new(),
            immutable_dependencies: alloc::vec![ProfileDependency::LogicalObject(
                frozen_specification,
            )],
            reconstruction_bounds,
            frozen_specification,
        };
        profile.validate_parts()?;
        Ok(profile)
    }

    /// Construct a transform profile and canonicalize its dependency set.
    ///
    /// Named transform fields and the frozen specification are inserted as
    /// logical dependencies. `contract_dependencies` adds only the typed slots
    /// required by the pinned transform contract.
    ///
    /// # Errors
    ///
    /// Returns [`PhysicalModelError::InvalidProfile`] when the complete
    /// immutable dependency set exceeds the profile's own fanout bound.
    pub fn new_transform(
        decoder_or_generator: ObjectId,
        transform_contract: ObjectId,
        runtime_semantic_profile: ObjectId,
        canonical_parameters: Vec<u8>,
        mut contract_dependencies: Vec<ProfileDependency>,
        reconstruction_bounds: ReconstructionBounds,
        frozen_specification: ObjectId,
    ) -> Result<Self, PhysicalModelError> {
        contract_dependencies.extend_from_slice(&[
            ProfileDependency::LogicalObject(decoder_or_generator),
            ProfileDependency::LogicalObject(transform_contract),
            ProfileDependency::LogicalObject(runtime_semantic_profile),
            ProfileDependency::LogicalObject(frozen_specification),
        ]);
        contract_dependencies.sort_unstable();
        contract_dependencies.dedup();
        let profile = Self {
            kind: ProfileKind::Transform,
            decoder_or_generator: Some(decoder_or_generator),
            transform_contract: Some(transform_contract),
            runtime_semantic_profile: Some(runtime_semantic_profile),
            canonical_parameters,
            immutable_dependencies: contract_dependencies,
            reconstruction_bounds,
            frozen_specification,
        };
        profile.validate_parts()?;
        Ok(profile)
    }

    /// Return the profile family.
    #[must_use]
    pub const fn kind(&self) -> ProfileKind {
        self.kind
    }

    /// Return the pinned decoder or generator, when transform-backed.
    #[must_use]
    pub const fn decoder_or_generator(&self) -> Option<ObjectId> {
        self.decoder_or_generator
    }

    /// Return the pinned transform contract, when transform-backed.
    #[must_use]
    pub const fn transform_contract(&self) -> Option<ObjectId> {
        self.transform_contract
    }

    /// Return the pinned runtime semantic profile, when transform-backed.
    #[must_use]
    pub const fn runtime_semantic_profile(&self) -> Option<ObjectId> {
        self.runtime_semantic_profile
    }

    /// Borrow canonical scalar parameters interpreted by the pinned contract.
    #[must_use]
    pub fn canonical_parameters(&self) -> &[u8] {
        &self.canonical_parameters
    }

    /// Borrow the complete sorted immutable dependency set.
    #[must_use]
    pub fn immutable_dependencies(&self) -> &[ProfileDependency] {
        &self.immutable_dependencies
    }

    /// Return the pinned reconstruction ceilings.
    #[must_use]
    pub const fn reconstruction_bounds(&self) -> ReconstructionBounds {
        self.reconstruction_bounds
    }

    /// Return the in-band specification object that freezes this profile.
    #[must_use]
    pub const fn frozen_specification(&self) -> ObjectId {
        self.frozen_specification
    }

    /// Encode this profile using the format-one canonical wire grammar.
    ///
    /// # Errors
    ///
    /// Returns [`PhysicalModelError::LengthOverflow`] when a byte string or
    /// dependency count does not fit its format-one `u64` length field.
    pub fn encode(&self) -> Result<Vec<u8>, PhysicalModelError> {
        let mut encoder = Encoder::new();
        encoder.u16(PROFILE_VERSION);
        encoder.u8(self.kind.code());
        encode_optional_object(&mut encoder, self.decoder_or_generator);
        encode_optional_object(&mut encoder, self.transform_contract);
        encode_optional_object(&mut encoder, self.runtime_semantic_profile);
        encoder.bytes(&self.canonical_parameters)?;
        encoder.count(self.immutable_dependencies.len())?;
        for dependency in &self.immutable_dependencies {
            dependency.encode_into(&mut encoder);
        }
        self.reconstruction_bounds.encode_into(&mut encoder);
        encode_object_id(&mut encoder, self.frozen_specification);
        Ok(encoder.finish())
    }

    /// Decode one byte-exact canonical format-one profile.
    ///
    /// # Errors
    ///
    /// Rejects unknown tags, non-canonical dependency order, incompatible
    /// fields, trailing bytes, and any encoding that does not reproduce itself.
    pub fn decode(bytes: &[u8]) -> Result<Self, PhysicalModelError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.u16()? != PROFILE_VERSION {
            return Err(PhysicalModelError::InvalidProfile(
                "unsupported representation-profile version",
            ));
        }
        let kind = ProfileKind::from_code(decoder.u8()?)?;
        let decoder_or_generator = decoder.option(decode_object_id)?;
        let transform_contract = decoder.option(decode_object_id)?;
        let runtime_semantic_profile = decoder.option(decode_object_id)?;
        let canonical_parameters = decoder.bytes()?.to_vec();
        let dependency_count = decoder.length()?;
        if dependency_count > decoder.remaining() / 41 {
            return Err(PhysicalModelError::Truncated);
        }
        let mut immutable_dependencies = Vec::new();
        immutable_dependencies
            .try_reserve(dependency_count)
            .map_err(|_| PhysicalModelError::LengthOverflow)?;
        for _ in 0..dependency_count {
            immutable_dependencies.push(ProfileDependency::decode_from(&mut decoder)?);
        }
        let reconstruction_bounds = ReconstructionBounds::decode_from(&mut decoder)?;
        let frozen_specification = decode_object_id(&mut decoder)?;
        decoder.finish()?;
        let profile = Self {
            kind,
            decoder_or_generator,
            transform_contract,
            runtime_semantic_profile,
            canonical_parameters,
            immutable_dependencies,
            reconstruction_bounds,
            frozen_specification,
        };
        profile.validate_parts()?;
        if profile.encode()?.as_slice() != bytes {
            return Err(PhysicalModelError::NonCanonicalEncoding);
        }
        Ok(profile)
    }

    /// Derive this profile's domain-separated physical identity.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when this profile cannot be represented by
    /// the format-one wire grammar.
    pub fn identify<I: PhysicalIdentity>(
        &self,
        identity: &I,
    ) -> Result<RepresentationProfileId, PhysicalModelError> {
        Ok(RepresentationProfileId::new(identity.identify(
            "astrid-representation-profile-v1\0",
            &self.encode()?,
        )))
    }

    fn validate_parts(&self) -> Result<(), PhysicalModelError> {
        if self
            .immutable_dependencies
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(PhysicalModelError::NonCanonicalCollection(
                "profile dependency",
            ));
        }
        let frozen = ProfileDependency::LogicalObject(self.frozen_specification);
        if self.kind == ProfileKind::Transform {
            let required = [
                self.decoder_or_generator,
                self.transform_contract,
                self.runtime_semantic_profile,
            ];
            if required.iter().any(Option::is_none) {
                return Err(PhysicalModelError::InvalidProfile(
                    "transform profile omitted a pinned transform field",
                ));
            }
            for object in required.into_iter().flatten() {
                if self
                    .immutable_dependencies
                    .binary_search(&ProfileDependency::LogicalObject(object))
                    .is_err()
                {
                    return Err(PhysicalModelError::InvalidProfile(
                        "transform field is absent from immutable dependencies",
                    ));
                }
            }
            if self.immutable_dependencies.binary_search(&frozen).is_err() {
                return Err(PhysicalModelError::InvalidProfile(
                    "frozen specification is absent from immutable dependencies",
                ));
            }
        } else if self.decoder_or_generator.is_some()
            || self.transform_contract.is_some()
            || self.runtime_semantic_profile.is_some()
            || !self.canonical_parameters.is_empty()
            || self.immutable_dependencies != [frozen]
        {
            return Err(PhysicalModelError::InvalidProfile(
                "built-in profile carried transform-only fields",
            ));
        }
        let dependency_count = u32::try_from(self.immutable_dependencies.len())
            .map_err(|_| PhysicalModelError::LengthOverflow)?;
        if dependency_count > self.reconstruction_bounds.maximum_dependency_fanout() {
            return Err(PhysicalModelError::InvalidProfile(
                "profile dependencies exceed reconstruction fanout",
            ));
        }
        Ok(())
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
