//! Canonical evidence for server-verified alternate physical representations.

use alloc::vec::Vec;

use crate::{BlobId, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord};

use super::codec::{Decoder, Encoder};
use super::identity::{
    PhysicalIdentity, decode_blob_id, encode_blob_id, encode_object_id, encode_physical_digest,
};
use super::{PhysicalModelError, Recipe, RepresentationRecord};

const MAGIC: &[u8; 8] = b"ASTRAE1\0";
const VERSION: u16 = 1;

/// Normalized identity of a representation record before it names its evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepresentationAdmissionSubjectId([u8; 32]);

impl RepresentationAdmissionSubjectId {
    /// Derive the normalized subject identity for a non-generated representation.
    ///
    /// # Errors
    ///
    /// Returns an encoding error or rejects generated recipes, whose derivation
    /// evidence follows a different grammar.
    pub fn identify<I: PhysicalIdentity>(
        identity: &I,
        representation: &RepresentationRecord,
    ) -> Result<Self, PhysicalModelError> {
        let bytes = representation.admission_subject_bytes()?;
        Ok(Self(identity.identify(
            "astrid-representation-admission-subject-v1\0",
            &bytes,
        )))
    }

    /// Borrow the current physical digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One uniquely emitted logical output in coverage traversal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepresentationOutputObservation {
    object: ObjectId,
    canonical_record_bytes: u64,
}

impl RepresentationOutputObservation {
    /// Construct one observed canonical output.
    #[must_use]
    pub const fn new(object: ObjectId, canonical_record_bytes: u64) -> Self {
        Self {
            object,
            canonical_record_bytes,
        }
    }

    /// Return the reconstructed logical object.
    #[must_use]
    pub const fn object(self) -> ObjectId {
        self.object
    }

    /// Return the complete canonical record byte length.
    #[must_use]
    pub const fn canonical_record_bytes(self) -> u64 {
        self.canonical_record_bytes
    }
}

/// Digest of the unique reconstructed outputs in coverage traversal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepresentationAdmissionTranscript([u8; 32]);

impl RepresentationAdmissionTranscript {
    /// Derive a transcript from the exact ordered output observations.
    ///
    /// # Errors
    ///
    /// Returns a length overflow when the output count cannot fit the frozen
    /// format-one `u64` field.
    pub fn identify<I: PhysicalIdentity>(
        identity: &I,
        outputs: &[RepresentationOutputObservation],
    ) -> Result<Self, PhysicalModelError> {
        let mut material = Vec::new();
        let count = u64::try_from(outputs.len()).map_err(|_| PhysicalModelError::LengthOverflow)?;
        material.extend_from_slice(&count.to_le_bytes());
        for output in outputs {
            let mut encoded = Encoder::new();
            encode_object_id(&mut encoded, output.object);
            material.extend_from_slice(&encoded.finish());
            material.extend_from_slice(&output.canonical_record_bytes.to_le_bytes());
        }
        Ok(Self(identity.identify(
            "astrid-representation-admission-transcript-v1\0",
            &material,
        )))
    }

    /// Borrow the current physical digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Verification method corresponding to one physical recipe family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepresentationAdmissionMethod {
    /// Complete canonical object bytes.
    Direct,
    /// Canonical object bytes in a pack slice.
    PackedSlice,
    /// Raw contiguous file bytes reconstructed as canonical chunks.
    ContiguousFile,
    /// Compressed canonical object bytes.
    Compressed,
    /// Delta reconstruction against a logical base.
    Delta,
}

impl RepresentationAdmissionMethod {
    const fn code(self) -> u8 {
        match self {
            Self::Direct => 0,
            Self::PackedSlice => 1,
            Self::ContiguousFile => 2,
            Self::Compressed => 3,
            Self::Delta => 4,
        }
    }

    fn decode(code: u8) -> Result<Self, PhysicalModelError> {
        match code {
            0 => Ok(Self::Direct),
            1 => Ok(Self::PackedSlice),
            2 => Ok(Self::ContiguousFile),
            3 => Ok(Self::Compressed),
            4 => Ok(Self::Delta),
            other => Err(PhysicalModelError::UnknownTag(
                "representation-admission method",
                other,
            )),
        }
    }

    /// Return the method required by a non-generated recipe.
    ///
    /// # Errors
    ///
    /// Generated recipes use derivation evidence and are rejected here.
    pub fn for_recipe(recipe: &Recipe) -> Result<Self, PhysicalModelError> {
        match recipe {
            Recipe::DirectCanonical { .. } => Ok(Self::Direct),
            Recipe::PackedSlice { .. } => Ok(Self::PackedSlice),
            Recipe::ContiguousFile { .. } => Ok(Self::ContiguousFile),
            Recipe::Compressed { .. } => Ok(Self::Compressed),
            Recipe::Delta { .. } => Ok(Self::Delta),
            Recipe::Generated { .. } => Err(PhysicalModelError::InvalidRecipe(
                "generated representation uses derivation evidence",
            )),
        }
    }
}

/// Canonical receipt proving server-side reconstruction of an alternate encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepresentationAdmissionEvidence {
    subject: RepresentationAdmissionSubjectId,
    method: RepresentationAdmissionMethod,
    primary_blob: BlobId,
    observed_encoded_bytes: u64,
    observed_output_bytes: u64,
    transcript: RepresentationAdmissionTranscript,
}

impl RepresentationAdmissionEvidence {
    /// Construct checked admission evidence for one representation.
    ///
    /// # Errors
    ///
    /// Rejects a method that does not match the representation recipe or byte
    /// observations that contradict its declared reconstruction bounds.
    pub fn new<I: PhysicalIdentity>(
        identity: &I,
        representation: &RepresentationRecord,
        primary_blob: BlobId,
        observed_encoded_bytes: u64,
        outputs: &[RepresentationOutputObservation],
    ) -> Result<Self, PhysicalModelError> {
        let method = RepresentationAdmissionMethod::for_recipe(representation.recipe())?;
        let recipe_blob = match representation.recipe() {
            Recipe::DirectCanonical { blob }
            | Recipe::PackedSlice { blob, .. }
            | Recipe::ContiguousFile { blob }
            | Recipe::Compressed { blob, .. } => *blob,
            Recipe::Delta { patch, .. } => *patch,
            Recipe::Generated { .. } => {
                return Err(PhysicalModelError::InvalidRecipe(
                    "generated representation uses derivation evidence",
                ));
            },
        };
        if recipe_blob != primary_blob {
            return Err(PhysicalModelError::InvalidRecipe(
                "admission evidence names a different primary blob",
            ));
        }
        let observed_output_bytes = outputs.iter().try_fold(0_u64, |total, output| {
            total
                .checked_add(output.canonical_record_bytes)
                .ok_or(PhysicalModelError::LengthOverflow)
        })?;
        if observed_output_bytes != representation.canonical_output_bytes() {
            return Err(PhysicalModelError::InvalidRecipe(
                "admission output bytes disagree with representation",
            ));
        }
        Ok(Self {
            subject: RepresentationAdmissionSubjectId::identify(identity, representation)?,
            method,
            primary_blob,
            observed_encoded_bytes,
            observed_output_bytes,
            transcript: RepresentationAdmissionTranscript::identify(identity, outputs)?,
        })
    }

    /// Return the normalized representation subject.
    #[must_use]
    pub const fn subject(self) -> RepresentationAdmissionSubjectId {
        self.subject
    }

    /// Return the verification method.
    #[must_use]
    pub const fn method(self) -> RepresentationAdmissionMethod {
        self.method
    }

    /// Return the primary encoded blob.
    #[must_use]
    pub const fn primary_blob(self) -> BlobId {
        self.primary_blob
    }

    /// Return the observed encoded byte length.
    #[must_use]
    pub const fn observed_encoded_bytes(self) -> u64 {
        self.observed_encoded_bytes
    }

    /// Return the observed canonical output byte length.
    #[must_use]
    pub const fn observed_output_bytes(self) -> u64 {
        self.observed_output_bytes
    }

    /// Return the output transcript digest.
    #[must_use]
    pub const fn transcript(self) -> RepresentationAdmissionTranscript {
        self.transcript
    }

    /// Encode the byte-exact format-one evidence grammar.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.raw(MAGIC);
        encoder.u16(VERSION);
        encode_physical_digest(&mut encoder, self.subject.as_bytes());
        encoder.u8(self.method.code());
        encode_blob_id(&mut encoder, self.primary_blob);
        encoder.u64(self.observed_encoded_bytes);
        encoder.u64(self.observed_output_bytes);
        encode_physical_digest(&mut encoder, self.transcript.as_bytes());
        encoder.finish()
    }

    /// Decode one canonical format-one admission-evidence value.
    ///
    /// # Errors
    ///
    /// Rejects wrong magic/version, identity schemes, tags, trailing bytes, or
    /// a second encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, PhysicalModelError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(MAGIC.len())? != MAGIC {
            return Err(PhysicalModelError::InvalidRecipe(
                "representation-admission evidence magic mismatch",
            ));
        }
        if decoder.u16()? != VERSION {
            return Err(PhysicalModelError::InvalidRecipe(
                "unsupported representation-admission evidence version",
            ));
        }
        let evidence = Self {
            subject: RepresentationAdmissionSubjectId(super::identity::decode_physical_digest(
                &mut decoder,
            )?),
            method: RepresentationAdmissionMethod::decode(decoder.u8()?)?,
            primary_blob: decode_blob_id(&mut decoder)?,
            observed_encoded_bytes: decoder.u64()?,
            observed_output_bytes: decoder.u64()?,
            transcript: RepresentationAdmissionTranscript(super::identity::decode_physical_digest(
                &mut decoder,
            )?),
        };
        decoder.finish()?;
        if evidence.encode().as_slice() != bytes {
            return Err(PhysicalModelError::NonCanonicalEncoding);
        }
        Ok(evidence)
    }

    /// Wrap the evidence in its canonical logical object record.
    ///
    /// # Errors
    ///
    /// Returns a model error only if the fixed evidence object shape ceases to
    /// satisfy the generic object invariants.
    pub fn object_record(self) -> Result<ObjectRecord, crate::ModelError> {
        ObjectRecord::new(
            ObjectKind::Evidence,
            ObjectFormatVersion::V1,
            self.encode(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CanonicalChunkingProfile, Coverage, Recipe, ReconstructionBounds, RepresentationProfile,
        RepresentationRecord,
    };

    struct TestIdentity;

    impl PhysicalIdentity for TestIdentity {
        fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new_derive_key(context);
            hasher.update(material);
            *hasher.finalize().as_bytes()
        }
    }

    fn object(byte: u8) -> ObjectId {
        ObjectId::new([byte; 32])
    }

    #[test]
    fn evidence_round_trips_and_binds_the_normalized_subject() {
        let identity = TestIdentity;
        let bounds = ReconstructionBounds::new(1, 2, 1024, 1024, 1, 1024, 1).unwrap();
        let profile = RepresentationProfile::new_builtin(
            super::super::ProfileKind::ContiguousFile,
            bounds,
            object(1),
        )
        .unwrap();
        let profile_id = profile.identify(&identity).unwrap();
        let blob = BlobId::identify(&identity, profile_id, b"content bytes").unwrap();
        let coverage = Coverage::canonical_file_chunks(
            object(2),
            Some(object(3)),
            13,
            1,
            CanonicalChunkingProfile::ASTRID_V1,
        )
        .unwrap();
        let first = RepresentationRecord::new(
            profile_id,
            coverage.clone(),
            Recipe::ContiguousFile { blob },
            32,
            32,
            Some(object(4)),
        )
        .unwrap();
        let second = RepresentationRecord::new(
            profile_id,
            coverage,
            Recipe::ContiguousFile { blob },
            32,
            32,
            Some(object(5)),
        )
        .unwrap();
        assert_eq!(
            RepresentationAdmissionSubjectId::identify(&identity, &first).unwrap(),
            RepresentationAdmissionSubjectId::identify(&identity, &second).unwrap()
        );

        let outputs = [RepresentationOutputObservation::new(object(6), 32)];
        let evidence =
            RepresentationAdmissionEvidence::new(&identity, &first, blob, 13, &outputs).unwrap();
        let encoded = evidence.encode();
        assert_eq!(
            RepresentationAdmissionEvidence::decode(&encoded).unwrap(),
            evidence
        );
        let record = evidence.object_record().unwrap();
        assert_eq!(record.kind(), ObjectKind::Evidence);
        assert_eq!(record.canonical_bytes(), encoded);
    }

    #[test]
    fn evidence_rejects_a_different_primary_blob() {
        let identity = TestIdentity;
        let bounds = ReconstructionBounds::new(1, 2, 1024, 1024, 1, 1024, 1).unwrap();
        let profile = RepresentationProfile::new_builtin(
            super::super::ProfileKind::ContiguousFile,
            bounds,
            object(1),
        )
        .unwrap();
        let profile_id = profile.identify(&identity).unwrap();
        let blob = BlobId::identify(&identity, profile_id, b"content bytes").unwrap();
        let representation = RepresentationRecord::new(
            profile_id,
            Coverage::canonical_file_chunks(
                object(2),
                Some(object(3)),
                13,
                1,
                CanonicalChunkingProfile::ASTRID_V1,
            )
            .unwrap(),
            Recipe::ContiguousFile { blob },
            32,
            32,
            Some(object(4)),
        )
        .unwrap();
        let output = [RepresentationOutputObservation::new(object(6), 32)];
        let error = RepresentationAdmissionEvidence::new(
            &identity,
            &representation,
            BlobId::new([9; 32]),
            13,
            &output,
        )
        .unwrap_err();
        assert!(matches!(error, PhysicalModelError::InvalidRecipe(_)));
    }
}
