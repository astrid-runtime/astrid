//! Durable evidence that binds one verified derivation to its outputs.

use alloc::{vec, vec::Vec};
use core::fmt;

use super::{
    AuthorityEpochId, ComputationSharingDomainId, DerivationContractId, DerivationInvocation,
    DerivationModelError, EngineBuildId, ExecutionClass, ExecutionMeasurementsId, InvocationId,
    InvocationInput, ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity,
    ObjectKind, ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel,
    RuntimeSemanticProfileId, TransformId,
};

const INVOCATION_LABEL: &[u8] = b"00-invocation";
const TRANSFORM_LABEL: &[u8] = b"01-transform";
const TRANSFORM_CONTRACT_LABEL: &[u8] = b"02-transform-contract";
const RUNTIME_LABEL: &[u8] = b"03-runtime-semantic-profile";
const ENGINE_BUILD_LABEL: &[u8] = b"04-engine-build";
const MEASUREMENTS_LABEL: &[u8] = b"05-execution-measurements";
const AUTHORITY_EPOCH_LABEL: &[u8] = b"06-authority-epoch";
const SHARING_DOMAIN_LABEL: &[u8] = b"07-computation-sharing-domain";
const VERIFIER_LABEL: &[u8] = b"08-verifier-evidence";
const INPUT_PREFIX: &[u8] = b"10-input/";
const OUTPUT_PREFIX: &[u8] = b"20-output/";

/// Identity of optional verifier or reference-execution evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifierEvidenceId(ObjectId);

impl VerifierEvidenceId {
    /// Construct a verifier-evidence identifier.
    #[must_use]
    pub const fn new(object: ObjectId) -> Self {
        Self(object)
    }

    /// Return the underlying logical object identity.
    #[must_use]
    pub const fn object_id(self) -> ObjectId {
        self.0
    }
}

/// One explicitly labelled result in derivation output order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationOutput {
    label: Vec<u8>,
    object: ObjectId,
}

impl DerivationOutput {
    /// Construct a derivation output.
    ///
    /// # Errors
    ///
    /// Returns [`DerivationEvidenceError::EmptyOutputLabel`] when `label` is
    /// empty.
    pub fn new(label: Vec<u8>, object: ObjectId) -> Result<Self, DerivationEvidenceError> {
        if label.is_empty() {
            return Err(DerivationEvidenceError::EmptyOutputLabel);
        }
        Ok(Self { label, object })
    }

    /// Borrow the identity-bearing output label.
    #[must_use]
    pub fn label(&self) -> &[u8] {
        &self.label
    }

    /// Return the output object identity.
    #[must_use]
    pub const fn object(&self) -> ObjectId {
        self.object
    }
}

/// Immutable, canonical record of one governed derivation execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationEvidence {
    invocation: InvocationId,
    execution_class: ExecutionClass,
    transform: TransformId,
    transform_contract: DerivationContractId,
    runtime_semantic_profile: RuntimeSemanticProfileId,
    engine_build: EngineBuildId,
    inputs: Vec<InvocationInput>,
    outputs: Vec<DerivationOutput>,
    execution_measurements: ExecutionMeasurementsId,
    verifier_evidence: Option<VerifierEvidenceId>,
    authority_epoch: AuthorityEpochId,
    sharing_domain: ComputationSharingDomainId,
}

impl DerivationEvidence {
    /// Construct evidence from the invocation that was actually executed.
    ///
    /// The constructor copies all duplicated invocation fields so callers
    /// cannot accidentally issue structurally drifting evidence.
    ///
    /// # Errors
    ///
    /// Returns [`DerivationEvidenceError::NoOutputs`] when no output identity
    /// is recorded.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invocation: InvocationId,
        invocation_model: &DerivationInvocation,
        engine_build: EngineBuildId,
        outputs: Vec<DerivationOutput>,
        execution_measurements: ExecutionMeasurementsId,
        verifier_evidence: Option<VerifierEvidenceId>,
        authority_epoch: AuthorityEpochId,
        sharing_domain: ComputationSharingDomainId,
    ) -> Result<Self, DerivationEvidenceError> {
        if outputs.is_empty() {
            return Err(DerivationEvidenceError::NoOutputs);
        }
        Ok(Self {
            invocation,
            execution_class: invocation_model.execution_class(),
            transform: invocation_model.transform(),
            transform_contract: invocation_model.transform_contract(),
            runtime_semantic_profile: invocation_model.runtime_semantic_profile(),
            engine_build,
            inputs: invocation_model.inputs().to_vec(),
            outputs,
            execution_measurements,
            verifier_evidence,
            authority_epoch,
            sharing_domain,
        })
    }

    /// Return the exact invocation identity.
    #[must_use]
    pub const fn invocation(&self) -> InvocationId {
        self.invocation
    }

    /// Return the recorded execution class.
    #[must_use]
    pub const fn execution_class(&self) -> ExecutionClass {
        self.execution_class
    }

    /// Return the exact transform identity.
    #[must_use]
    pub const fn transform(&self) -> TransformId {
        self.transform
    }

    /// Return the registered transform contract.
    #[must_use]
    pub const fn transform_contract(&self) -> DerivationContractId {
        self.transform_contract
    }

    /// Return the runtime semantic profile.
    #[must_use]
    pub const fn runtime_semantic_profile(&self) -> RuntimeSemanticProfileId {
        self.runtime_semantic_profile
    }

    /// Return the engine build that actually executed the invocation.
    #[must_use]
    pub const fn engine_build(&self) -> EngineBuildId {
        self.engine_build
    }

    /// Borrow the ordered invocation inputs copied into the evidence.
    #[must_use]
    pub fn inputs(&self) -> &[InvocationInput] {
        &self.inputs
    }

    /// Borrow ordered derivation outputs.
    #[must_use]
    pub fn outputs(&self) -> &[DerivationOutput] {
        &self.outputs
    }

    /// Return canonical execution measurements.
    #[must_use]
    pub const fn execution_measurements(&self) -> ExecutionMeasurementsId {
        self.execution_measurements
    }

    /// Return optional verifier or reference-execution evidence.
    #[must_use]
    pub const fn verifier_evidence(&self) -> Option<VerifierEvidenceId> {
        self.verifier_evidence
    }

    /// Return the authority-policy epoch used for admission.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpochId {
        self.authority_epoch
    }

    /// Return the computation-sharing domain used for admission.
    #[must_use]
    pub const fn sharing_domain(&self) -> ComputationSharingDomainId {
        self.sharing_domain
    }

    /// Verify all duplicated fields against the identified invocation.
    ///
    /// # Errors
    ///
    /// Returns an invocation encoding or mismatch error when the supplied
    /// invocation is not exactly the one this evidence records.
    pub fn validate_invocation<I: ObjectIdentity>(
        &self,
        invocation: &DerivationInvocation,
        identity: &I,
    ) -> Result<(), DerivationEvidenceError> {
        let actual_id = invocation
            .identify(identity)
            .map_err(DerivationEvidenceError::InvalidInvocation)?;
        if actual_id != self.invocation
            || invocation.execution_class() != self.execution_class
            || invocation.transform() != self.transform
            || invocation.transform_contract() != self.transform_contract
            || invocation.runtime_semantic_profile() != self.runtime_semantic_profile
            || invocation.inputs() != self.inputs
        {
            return Err(DerivationEvidenceError::InvocationMismatch);
        }
        Ok(())
    }

    /// Encode this evidence as one canonical logical object record.
    ///
    /// Output references use `Derived`, so evidence alone never keeps a large
    /// result alive. Retention remains an explicit principal-root or pin
    /// decision.
    ///
    /// # Errors
    ///
    /// Returns an arithmetic or object-record error if canonical labels cannot
    /// be represented.
    pub fn to_object_record(&self) -> Result<ObjectRecord, DerivationEvidenceError> {
        let mut references = vec![
            ObjectReference::owns(
                ReferenceLabel::new(INVOCATION_LABEL.to_vec()),
                self.invocation.object_id(),
            ),
            evidence_reference(TRANSFORM_LABEL, self.transform.object_id()),
            evidence_reference(
                TRANSFORM_CONTRACT_LABEL,
                self.transform_contract.object_id(),
            ),
            evidence_reference(RUNTIME_LABEL, self.runtime_semantic_profile.object_id()),
            evidence_reference(ENGINE_BUILD_LABEL, self.engine_build.object_id()),
            evidence_reference(MEASUREMENTS_LABEL, self.execution_measurements.object_id()),
            evidence_reference(AUTHORITY_EPOCH_LABEL, self.authority_epoch.object_id()),
            evidence_reference(SHARING_DOMAIN_LABEL, self.sharing_domain.object_id()),
        ];
        if let Some(verifier) = self.verifier_evidence {
            references.push(evidence_reference(VERIFIER_LABEL, verifier.object_id()));
        }
        for (index, input) in self.inputs.iter().enumerate() {
            references.push(ObjectReference::new(
                indexed_label(INPUT_PREFIX, index, input.label())?,
                input.object(),
                ReferenceKind::Evidence,
            ));
        }
        for (index, output) in self.outputs.iter().enumerate() {
            references.push(ObjectReference::new(
                indexed_label(OUTPUT_PREFIX, index, output.label())?,
                output.object(),
                ReferenceKind::Derived,
            ));
        }
        ObjectRecord::new(
            ObjectKind::DerivationEvidence,
            ObjectFormatVersion::V1,
            vec![
                self.execution_class.code(),
                u8::from(self.verifier_evidence.is_some()),
            ],
            references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(DerivationEvidenceError::InvalidObjectRecord)
    }

    /// Compute the evidence identity through the configured object identity.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if the canonical object cannot be built.
    pub fn identify<I: ObjectIdentity>(
        &self,
        identity: &I,
    ) -> Result<ObjectId, DerivationEvidenceError> {
        self.to_object_record()
            .map(|record| identity.identify(&record))
    }

    /// Decode and fully canonicalize one derivation evidence object.
    ///
    /// # Errors
    ///
    /// Rejects malformed payloads, references, optional fields, collection
    /// ordinals, and non-canonical encodings.
    pub fn from_object_record(record: &ObjectRecord) -> Result<Self, DerivationEvidenceError> {
        validate_record_header(record)?;
        let execution_class = ExecutionClass::from_code(record.canonical_bytes()[0])
            .ok_or(DerivationEvidenceError::UnknownExecutionClass)?;
        let verifier_present = match record.canonical_bytes()[1] {
            0 => false,
            1 => true,
            _ => return Err(DerivationEvidenceError::InvalidOptionMask),
        };

        let mut fields = EvidenceFields::default();
        for reference in record.references() {
            fields.decode_reference(reference)?;
        }
        let evidence = fields.finish(execution_class, verifier_present)?;
        if evidence.to_object_record()? != *record {
            return Err(DerivationEvidenceError::NonCanonicalObjectRecord);
        }
        Ok(evidence)
    }
}

#[derive(Default)]
struct EvidenceFields {
    invocation: Option<InvocationId>,
    transform: Option<TransformId>,
    transform_contract: Option<DerivationContractId>,
    runtime_semantic_profile: Option<RuntimeSemanticProfileId>,
    engine_build: Option<EngineBuildId>,
    inputs: Vec<InvocationInput>,
    outputs: Vec<DerivationOutput>,
    execution_measurements: Option<ExecutionMeasurementsId>,
    verifier_evidence: Option<VerifierEvidenceId>,
    authority_epoch: Option<AuthorityEpochId>,
    sharing_domain: Option<ComputationSharingDomainId>,
}

impl EvidenceFields {
    fn decode_reference(
        &mut self,
        reference: &ObjectReference,
    ) -> Result<(), DerivationEvidenceError> {
        let label = reference.label().as_bytes();
        if label.starts_with(INPUT_PREFIX) {
            return self.decode_input(reference, label);
        }
        if label.starts_with(OUTPUT_PREFIX) {
            return self.decode_output(reference, label);
        }
        self.decode_fixed(reference, label)
    }

    fn decode_input(
        &mut self,
        reference: &ObjectReference,
        label: &[u8],
    ) -> Result<(), DerivationEvidenceError> {
        require_kind(reference, ReferenceKind::Evidence)?;
        let semantic_label = validate_indexed_label(INPUT_PREFIX, label, self.inputs.len())?;
        self.inputs.push(
            InvocationInput::new(semantic_label.to_vec(), reference.target())
                .map_err(DerivationEvidenceError::InvalidInvocation)?,
        );
        Ok(())
    }

    fn decode_output(
        &mut self,
        reference: &ObjectReference,
        label: &[u8],
    ) -> Result<(), DerivationEvidenceError> {
        require_kind(reference, ReferenceKind::Derived)?;
        let semantic_label = validate_indexed_label(OUTPUT_PREFIX, label, self.outputs.len())?;
        self.outputs.push(DerivationOutput::new(
            semantic_label.to_vec(),
            reference.target(),
        )?);
        Ok(())
    }

    fn decode_fixed(
        &mut self,
        reference: &ObjectReference,
        label: &[u8],
    ) -> Result<(), DerivationEvidenceError> {
        let target = reference.target();
        match label {
            INVOCATION_LABEL => {
                require_kind(reference, ReferenceKind::Owns)?;
                set_once(&mut self.invocation, InvocationId::new(target))
            },
            TRANSFORM_LABEL => {
                require_kind(reference, ReferenceKind::Evidence)?;
                set_once(&mut self.transform, TransformId::new(target))
            },
            TRANSFORM_CONTRACT_LABEL => {
                require_kind(reference, ReferenceKind::Evidence)?;
                set_once(
                    &mut self.transform_contract,
                    DerivationContractId::new(target),
                )
            },
            RUNTIME_LABEL => {
                require_kind(reference, ReferenceKind::Evidence)?;
                set_once(
                    &mut self.runtime_semantic_profile,
                    RuntimeSemanticProfileId::new(target),
                )
            },
            ENGINE_BUILD_LABEL => {
                require_kind(reference, ReferenceKind::Evidence)?;
                set_once(&mut self.engine_build, EngineBuildId::new(target))
            },
            MEASUREMENTS_LABEL => {
                require_kind(reference, ReferenceKind::Evidence)?;
                set_once(
                    &mut self.execution_measurements,
                    ExecutionMeasurementsId::new(target),
                )
            },
            AUTHORITY_EPOCH_LABEL => {
                require_kind(reference, ReferenceKind::Evidence)?;
                set_once(&mut self.authority_epoch, AuthorityEpochId::new(target))
            },
            SHARING_DOMAIN_LABEL => {
                require_kind(reference, ReferenceKind::Evidence)?;
                set_once(
                    &mut self.sharing_domain,
                    ComputationSharingDomainId::new(target),
                )
            },
            VERIFIER_LABEL => {
                require_kind(reference, ReferenceKind::Evidence)?;
                set_once(&mut self.verifier_evidence, VerifierEvidenceId::new(target))
            },
            _ => Err(DerivationEvidenceError::UnknownCanonicalField),
        }
    }

    fn finish(
        self,
        execution_class: ExecutionClass,
        verifier_present: bool,
    ) -> Result<DerivationEvidence, DerivationEvidenceError> {
        if self.outputs.is_empty() {
            return Err(DerivationEvidenceError::NoOutputs);
        }
        if self.verifier_evidence.is_some() != verifier_present {
            return Err(DerivationEvidenceError::InvalidOptionMask);
        }
        Ok(DerivationEvidence {
            invocation: required(self.invocation, "invocation")?,
            execution_class,
            transform: required(self.transform, "transform")?,
            transform_contract: required(self.transform_contract, "transform_contract")?,
            runtime_semantic_profile: required(
                self.runtime_semantic_profile,
                "runtime_semantic_profile",
            )?,
            engine_build: required(self.engine_build, "engine_build")?,
            inputs: self.inputs,
            outputs: self.outputs,
            execution_measurements: required(
                self.execution_measurements,
                "execution_measurements",
            )?,
            verifier_evidence: self.verifier_evidence,
            authority_epoch: required(self.authority_epoch, "authority_epoch")?,
            sharing_domain: required(self.sharing_domain, "sharing_domain")?,
        })
    }
}

/// Canonical derivation-evidence validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DerivationEvidenceError {
    /// A result used an empty semantic label.
    EmptyOutputLabel,
    /// Evidence recorded no result objects.
    NoOutputs,
    /// The object did not use the derivation evidence schema.
    WrongObjectKind,
    /// The object used a non-v1 format version.
    UnsupportedFormatVersion,
    /// The object payload or metadata class was malformed.
    InvalidCanonicalPayload,
    /// The execution-class code was unknown.
    UnknownExecutionClass,
    /// Optional-field presence did not agree with references.
    InvalidOptionMask,
    /// A required field was absent.
    MissingCanonicalField(&'static str),
    /// A field occurred more than once.
    DuplicateCanonicalField,
    /// A reference label was not part of the schema.
    UnknownCanonicalField,
    /// A reference carried the wrong ownership relation.
    InvalidReferenceKind,
    /// An indexed label had a malformed or non-contiguous ordinal.
    InvalidIndexedLabel,
    /// The decoded value did not reproduce the exact object record.
    NonCanonicalObjectRecord,
    /// Evidence duplicated fields that disagree with its invocation.
    InvocationMismatch,
    /// The embedded invocation could not be canonically encoded.
    InvalidInvocation(DerivationModelError),
    /// Constructing the logical evidence object failed.
    InvalidObjectRecord(ModelError),
}

impl fmt::Display for DerivationEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyOutputLabel => formatter.write_str("derivation output label is empty"),
            Self::NoOutputs => formatter.write_str("derivation evidence has no outputs"),
            Self::WrongObjectKind => formatter.write_str("wrong derivation evidence object kind"),
            Self::UnsupportedFormatVersion => {
                formatter.write_str("unsupported derivation evidence format version")
            },
            Self::InvalidCanonicalPayload => {
                formatter.write_str("invalid derivation evidence canonical payload")
            },
            Self::UnknownExecutionClass => {
                formatter.write_str("unknown derivation evidence execution class")
            },
            Self::InvalidOptionMask => {
                formatter.write_str("invalid derivation evidence optional-field mask")
            },
            Self::MissingCanonicalField(field) => {
                write!(formatter, "missing derivation evidence field {field}")
            },
            Self::DuplicateCanonicalField => {
                formatter.write_str("duplicate derivation evidence field")
            },
            Self::UnknownCanonicalField => formatter.write_str("unknown derivation evidence field"),
            Self::InvalidReferenceKind => {
                formatter.write_str("invalid derivation evidence reference kind")
            },
            Self::InvalidIndexedLabel => {
                formatter.write_str("invalid derivation evidence indexed label")
            },
            Self::NonCanonicalObjectRecord => {
                formatter.write_str("derivation evidence object is not canonical")
            },
            Self::InvocationMismatch => {
                formatter.write_str("derivation evidence disagrees with its invocation")
            },
            Self::InvalidInvocation(error) => {
                write!(formatter, "invalid derivation invocation: {error}")
            },
            Self::InvalidObjectRecord(error) => {
                write!(formatter, "invalid derivation evidence object: {error}")
            },
        }
    }
}

fn evidence_reference(label: &[u8], target: ObjectId) -> ObjectReference {
    ObjectReference::new(
        ReferenceLabel::new(label.to_vec()),
        target,
        ReferenceKind::Evidence,
    )
}

fn indexed_label(
    prefix: &[u8],
    index: usize,
    suffix: &[u8],
) -> Result<ReferenceLabel, DerivationEvidenceError> {
    let index = u64::try_from(index).map_err(|_| DerivationEvidenceError::InvalidIndexedLabel)?;
    let mut label = prefix.to_vec();
    label.extend_from_slice(&index.to_be_bytes());
    label.push(0);
    label.extend_from_slice(suffix);
    Ok(ReferenceLabel::new(label))
}

fn validate_indexed_label<'a>(
    prefix: &[u8],
    label: &'a [u8],
    expected_index: usize,
) -> Result<&'a [u8], DerivationEvidenceError> {
    let index_end = prefix
        .len()
        .checked_add(8)
        .ok_or(DerivationEvidenceError::InvalidIndexedLabel)?;
    let suffix_start = index_end
        .checked_add(1)
        .ok_or(DerivationEvidenceError::InvalidIndexedLabel)?;
    if label.len() <= suffix_start || !label.starts_with(prefix) || label.get(index_end) != Some(&0)
    {
        return Err(DerivationEvidenceError::InvalidIndexedLabel);
    }
    let ordinal: [u8; 8] = label[prefix.len()..index_end]
        .try_into()
        .map_err(|_| DerivationEvidenceError::InvalidIndexedLabel)?;
    let expected =
        u64::try_from(expected_index).map_err(|_| DerivationEvidenceError::InvalidIndexedLabel)?;
    if u64::from_be_bytes(ordinal) != expected {
        return Err(DerivationEvidenceError::InvalidIndexedLabel);
    }
    Ok(&label[suffix_start..])
}

fn validate_record_header(record: &ObjectRecord) -> Result<(), DerivationEvidenceError> {
    if record.kind() != ObjectKind::DerivationEvidence {
        return Err(DerivationEvidenceError::WrongObjectKind);
    }
    if record.format_version() != ObjectFormatVersion::V1 {
        return Err(DerivationEvidenceError::UnsupportedFormatVersion);
    }
    if record.canonical_bytes().len() != 2
        || record.logical_bytes() != 0
        || record.class() != ObjectClass::Metadata
    {
        return Err(DerivationEvidenceError::InvalidCanonicalPayload);
    }
    Ok(())
}

fn require_kind(
    reference: &ObjectReference,
    expected: ReferenceKind,
) -> Result<(), DerivationEvidenceError> {
    if reference.kind() != expected {
        return Err(DerivationEvidenceError::InvalidReferenceKind);
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), DerivationEvidenceError> {
    if slot.replace(value).is_some() {
        return Err(DerivationEvidenceError::DuplicateCanonicalField);
    }
    Ok(())
}

fn required<T>(slot: Option<T>, name: &'static str) -> Result<T, DerivationEvidenceError> {
    slot.ok_or(DerivationEvidenceError::MissingCanonicalField(name))
}
