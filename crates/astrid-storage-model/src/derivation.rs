//! Canonical identity model for deterministic derivations.

use alloc::{vec, vec::Vec};
use core::fmt;

use super::{
    ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity, ObjectKind,
    ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel,
};

const TRANSFORM_LABEL: &[u8] = b"00-transform";
const TRANSFORM_CONTRACT_LABEL: &[u8] = b"01-transform-contract";
const PARAMETERS_LABEL: &[u8] = b"02-canonical-parameters";
const RUNTIME_LABEL: &[u8] = b"03-runtime-semantic-profile";
const OUTPUT_LABEL: &[u8] = b"04-output-contract";
const SNAPSHOT_LABEL: &[u8] = b"05-provenance-snapshot";
const SEED_LABEL: &[u8] = b"06-deterministic-seed";
const INPUT_PREFIX: &[u8] = b"10-input/";

const WASM_CORE_LABEL: &[u8] = b"00-wasm-core";
const COMPONENT_MODEL_LABEL: &[u8] = b"01-component-model";
const FLOAT_LABEL: &[u8] = b"02-float";
const THREADS_LABEL: &[u8] = b"03-threads";
const RESOURCE_FAILURE_LABEL: &[u8] = b"04-resource-failure";
const PROPOSAL_PREFIX: &[u8] = b"10-proposal/";
const HOST_FUNCTION_PREFIX: &[u8] = b"20-host-function/";

macro_rules! object_id_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(ObjectId);

        impl $name {
            /// Construct the domain identifier from a logical object identity.
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
    };
}

object_id_newtype!(
    /// Identity of the exact transform capsule or immutable executable closure.
    TransformId
);
object_id_newtype!(
    /// Identity of a registered deterministic transform contract.
    DerivationContractId
);
object_id_newtype!(
    /// Identity of a typed canonical parameter object.
    CanonicalParametersId
);
object_id_newtype!(
    /// Identity of a contract governing derivation output.
    OutputContractId
);
object_id_newtype!(
    /// Identity of one semantics-visible runtime profile.
    RuntimeSemanticProfileId
);
object_id_newtype!(
    /// Identity of a semantics contract referenced by a runtime profile.
    SemanticContractId
);
object_id_newtype!(
    /// Identity of an immutable provenance snapshot.
    SnapshotId
);
object_id_newtype!(
    /// Identity of explicit deterministic seed material.
    DeterministicSeedId
);
object_id_newtype!(
    /// Identity of one complete canonical derivation invocation.
    InvocationId
);

/// Reuse class of one computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionClass {
    /// The computation observes only identified immutable inputs.
    Pure,
    /// Mutable observations are represented by an identified snapshot.
    SnapshotBound,
    /// The operation changes authority or an external system and is never
    /// skipped on a memo hit.
    Effectful,
    /// Undeclared entropy or environment makes the operation non-reusable.
    Nondeterministic,
}

impl ExecutionClass {
    /// Return the stable canonical code for this class.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Pure => 0,
            Self::SnapshotBound => 1,
            Self::Effectful => 2,
            Self::Nondeterministic => 3,
        }
    }

    /// Decode a stable canonical class code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Pure),
            1 => Some(Self::SnapshotBound),
            2 => Some(Self::Effectful),
            3 => Some(Self::Nondeterministic),
            _ => None,
        }
    }

    /// Return whether a successfully admitted invocation may populate Muninn.
    #[must_use]
    pub const fn is_memoizable(self) -> bool {
        matches!(self, Self::Pure | Self::SnapshotBound)
    }
}

/// One explicitly labelled input in invocation order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationInput {
    label: Vec<u8>,
    object: ObjectId,
}

impl InvocationInput {
    /// Construct an invocation input.
    ///
    /// # Errors
    ///
    /// Returns [`DerivationModelError::EmptyInputLabel`] when `label` is
    /// empty.
    pub fn new(label: Vec<u8>, object: ObjectId) -> Result<Self, DerivationModelError> {
        if label.is_empty() {
            return Err(DerivationModelError::EmptyInputLabel);
        }
        Ok(Self { label, object })
    }

    /// Borrow the identity-bearing input label.
    #[must_use]
    pub fn label(&self) -> &[u8] {
        &self.label
    }

    /// Return the input object identity.
    #[must_use]
    pub const fn object(&self) -> ObjectId {
        self.object
    }
}

/// One host function and its semantics contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostFunctionSemanticBinding {
    name: Vec<u8>,
    semantics: SemanticContractId,
}

impl HostFunctionSemanticBinding {
    /// Construct a host-function semantics binding.
    ///
    /// # Errors
    ///
    /// Returns [`DerivationModelError::EmptyHostFunctionName`] when `name` is
    /// empty.
    pub fn new(name: Vec<u8>, semantics: SemanticContractId) -> Result<Self, DerivationModelError> {
        if name.is_empty() {
            return Err(DerivationModelError::EmptyHostFunctionName);
        }
        Ok(Self { name, semantics })
    }

    /// Borrow the canonical host-function name.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Return the semantics contract.
    #[must_use]
    pub const fn semantics(&self) -> SemanticContractId {
        self.semantics
    }
}

/// Semantics-visible execution surface shared by compatible engine builds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSemanticProfile {
    wasm_core: SemanticContractId,
    component_model: Option<SemanticContractId>,
    enabled_proposals: Vec<SemanticContractId>,
    host_functions: Vec<HostFunctionSemanticBinding>,
    float_semantics: SemanticContractId,
    thread_semantics: SemanticContractId,
    resource_failure_semantics: SemanticContractId,
}

impl RuntimeSemanticProfile {
    /// Construct a canonical runtime semantic profile.
    ///
    /// `enabled_proposals` must be strictly increasing by contract identity.
    /// `host_functions` must be strictly increasing by canonical function
    /// name. Requiring callers to provide canonical order prevents a second
    /// accepted representation of the same profile.
    ///
    /// # Errors
    ///
    /// Returns a canonical-order error when either collection is unordered or
    /// duplicated.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wasm_core: SemanticContractId,
        component_model: Option<SemanticContractId>,
        enabled_proposals: Vec<SemanticContractId>,
        host_functions: Vec<HostFunctionSemanticBinding>,
        float_semantics: SemanticContractId,
        thread_semantics: SemanticContractId,
        resource_failure_semantics: SemanticContractId,
    ) -> Result<Self, DerivationModelError> {
        if enabled_proposals.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(DerivationModelError::NonCanonicalProposals);
        }
        if host_functions
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(DerivationModelError::NonCanonicalHostFunctions);
        }
        Ok(Self {
            wasm_core,
            component_model,
            enabled_proposals,
            host_functions,
            float_semantics,
            thread_semantics,
            resource_failure_semantics,
        })
    }

    /// Return the WebAssembly core semantics contract.
    #[must_use]
    pub const fn wasm_core(&self) -> SemanticContractId {
        self.wasm_core
    }

    /// Return the optional component-model semantics contract.
    #[must_use]
    pub const fn component_model(&self) -> Option<SemanticContractId> {
        self.component_model
    }

    /// Borrow enabled proposal contracts in canonical order.
    #[must_use]
    pub fn enabled_proposals(&self) -> &[SemanticContractId] {
        &self.enabled_proposals
    }

    /// Borrow host-function contracts in canonical name order.
    #[must_use]
    pub fn host_functions(&self) -> &[HostFunctionSemanticBinding] {
        &self.host_functions
    }

    /// Return the floating-point semantics contract.
    #[must_use]
    pub const fn float_semantics(&self) -> SemanticContractId {
        self.float_semantics
    }

    /// Return the thread and scheduling semantics contract.
    #[must_use]
    pub const fn thread_semantics(&self) -> SemanticContractId {
        self.thread_semantics
    }

    /// Return the deterministic resource-failure semantics contract.
    #[must_use]
    pub const fn resource_failure_semantics(&self) -> SemanticContractId {
        self.resource_failure_semantics
    }

    /// Encode the profile as one canonical logical object record.
    ///
    /// # Errors
    ///
    /// Returns an arithmetic or object-record error if the canonical labels
    /// cannot be represented.
    pub fn to_object_record(&self) -> Result<ObjectRecord, DerivationModelError> {
        let mut references = Vec::new();
        references.push(owned_reference(WASM_CORE_LABEL, self.wasm_core.object_id()));
        if let Some(component_model) = self.component_model {
            references.push(owned_reference(
                COMPONENT_MODEL_LABEL,
                component_model.object_id(),
            ));
        }
        references.push(owned_reference(
            FLOAT_LABEL,
            self.float_semantics.object_id(),
        ));
        references.push(owned_reference(
            THREADS_LABEL,
            self.thread_semantics.object_id(),
        ));
        references.push(owned_reference(
            RESOURCE_FAILURE_LABEL,
            self.resource_failure_semantics.object_id(),
        ));
        for (index, proposal) in self.enabled_proposals.iter().enumerate() {
            references.push(ObjectReference::owns(
                indexed_label(PROPOSAL_PREFIX, index, &[])?,
                proposal.object_id(),
            ));
        }
        for host_function in &self.host_functions {
            references.push(ObjectReference::owns(
                prefixed_label(HOST_FUNCTION_PREFIX, host_function.name()),
                host_function.semantics.object_id(),
            ));
        }

        ObjectRecord::new(
            ObjectKind::RuntimeSemanticProfile,
            ObjectFormatVersion::V1,
            vec![u8::from(self.component_model.is_some())],
            references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(DerivationModelError::InvalidObjectRecord)
    }

    /// Compute the profile identity through the configured object identity.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if the canonical object cannot be built.
    pub fn identify<I: ObjectIdentity>(
        &self,
        identity: &I,
    ) -> Result<RuntimeSemanticProfileId, DerivationModelError> {
        self.to_object_record()
            .map(|record| RuntimeSemanticProfileId::new(identity.identify(&record)))
    }

    /// Decode and fully canonicalize one profile object.
    ///
    /// # Errors
    ///
    /// Rejects the wrong object kind, malformed labels, missing required
    /// fields, invalid reference kinds, and non-canonical collections.
    pub fn from_object_record(record: &ObjectRecord) -> Result<Self, DerivationModelError> {
        validate_record_header(record, ObjectKind::RuntimeSemanticProfile, 1)?;
        let component_model_present = match record.canonical_bytes()[0] {
            0 => false,
            1 => true,
            _ => return Err(DerivationModelError::InvalidOptionMask),
        };

        let mut wasm_core = None;
        let mut component_model = None;
        let mut float_semantics = None;
        let mut thread_semantics = None;
        let mut resource_failure_semantics = None;
        let mut proposals = Vec::new();
        let mut host_functions = Vec::new();

        for reference in record.references() {
            if reference.kind() != ReferenceKind::Owns {
                return Err(DerivationModelError::InvalidReferenceKind);
            }
            let label = reference.label().as_bytes();
            match label {
                WASM_CORE_LABEL => {
                    set_once(&mut wasm_core, SemanticContractId::new(reference.target()))?;
                },
                COMPONENT_MODEL_LABEL => {
                    set_once(
                        &mut component_model,
                        SemanticContractId::new(reference.target()),
                    )?;
                },
                FLOAT_LABEL => {
                    set_once(
                        &mut float_semantics,
                        SemanticContractId::new(reference.target()),
                    )?;
                },
                THREADS_LABEL => {
                    set_once(
                        &mut thread_semantics,
                        SemanticContractId::new(reference.target()),
                    )?;
                },
                RESOURCE_FAILURE_LABEL => {
                    set_once(
                        &mut resource_failure_semantics,
                        SemanticContractId::new(reference.target()),
                    )?;
                },
                _ if label.starts_with(PROPOSAL_PREFIX) => {
                    let suffix =
                        validate_indexed_label(PROPOSAL_PREFIX, label, proposals.len(), &[])?;
                    if !suffix.is_empty() {
                        return Err(DerivationModelError::InvalidIndexedLabel);
                    }
                    proposals.push(SemanticContractId::new(reference.target()));
                },
                _ if label.starts_with(HOST_FUNCTION_PREFIX) => {
                    let name = &label[HOST_FUNCTION_PREFIX.len()..];
                    host_functions.push(HostFunctionSemanticBinding::new(
                        name.to_vec(),
                        SemanticContractId::new(reference.target()),
                    )?);
                },
                _ => return Err(DerivationModelError::UnknownCanonicalField),
            }
        }

        let profile = Self::new(
            required(wasm_core, "wasm_core")?,
            component_model,
            proposals,
            host_functions,
            required(float_semantics, "float_semantics")?,
            required(thread_semantics, "thread_semantics")?,
            required(resource_failure_semantics, "resource_failure_semantics")?,
        )?;
        if profile.component_model.is_some() != component_model_present {
            return Err(DerivationModelError::InvalidOptionMask);
        }
        if profile.to_object_record()? != *record {
            return Err(DerivationModelError::NonCanonicalObjectRecord);
        }
        Ok(profile)
    }
}

/// Complete canonical request for one derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationInvocation {
    execution_class: ExecutionClass,
    transform: TransformId,
    transform_contract: DerivationContractId,
    inputs: Vec<InvocationInput>,
    canonical_parameters: CanonicalParametersId,
    runtime_semantic_profile: RuntimeSemanticProfileId,
    output_contract: OutputContractId,
    snapshot: Option<SnapshotId>,
    seed: Option<DeterministicSeedId>,
}

impl DerivationInvocation {
    /// Construct a complete derivation invocation.
    ///
    /// Input sequence order is identity-bearing. A pure invocation cannot
    /// carry a mutable provenance snapshot, while a snapshot-bound invocation
    /// must carry one.
    ///
    /// # Errors
    ///
    /// Returns a class/snapshot error when those invariants conflict.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_class: ExecutionClass,
        transform: TransformId,
        transform_contract: DerivationContractId,
        inputs: Vec<InvocationInput>,
        canonical_parameters: CanonicalParametersId,
        runtime_semantic_profile: RuntimeSemanticProfileId,
        output_contract: OutputContractId,
        snapshot: Option<SnapshotId>,
        seed: Option<DeterministicSeedId>,
    ) -> Result<Self, DerivationModelError> {
        match (execution_class, snapshot) {
            (ExecutionClass::Pure, Some(_)) => {
                return Err(DerivationModelError::PureInvocationHasSnapshot);
            },
            (ExecutionClass::SnapshotBound, None) => {
                return Err(DerivationModelError::SnapshotBoundInvocationMissingSnapshot);
            },
            _ => {},
        }
        Ok(Self {
            execution_class,
            transform,
            transform_contract,
            inputs,
            canonical_parameters,
            runtime_semantic_profile,
            output_contract,
            snapshot,
            seed,
        })
    }

    /// Return the execution class.
    #[must_use]
    pub const fn execution_class(&self) -> ExecutionClass {
        self.execution_class
    }

    /// Return the exact transform capsule or immutable executable closure.
    #[must_use]
    pub const fn transform(&self) -> TransformId {
        self.transform
    }

    /// Return the transform contract.
    #[must_use]
    pub const fn transform_contract(&self) -> DerivationContractId {
        self.transform_contract
    }

    /// Borrow ordered, labelled inputs.
    #[must_use]
    pub fn inputs(&self) -> &[InvocationInput] {
        &self.inputs
    }

    /// Return the canonical parameter object.
    #[must_use]
    pub const fn canonical_parameters(&self) -> CanonicalParametersId {
        self.canonical_parameters
    }

    /// Return the runtime semantic profile.
    #[must_use]
    pub const fn runtime_semantic_profile(&self) -> RuntimeSemanticProfileId {
        self.runtime_semantic_profile
    }

    /// Return the output contract.
    #[must_use]
    pub const fn output_contract(&self) -> OutputContractId {
        self.output_contract
    }

    /// Return the optional provenance snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> Option<SnapshotId> {
        self.snapshot
    }

    /// Return the optional explicit deterministic seed.
    #[must_use]
    pub const fn seed(&self) -> Option<DeterministicSeedId> {
        self.seed
    }

    /// Return whether a successful execution may populate Muninn.
    #[must_use]
    pub const fn is_memoizable(&self) -> bool {
        self.execution_class.is_memoizable()
    }

    /// Encode the invocation as one canonical logical object record.
    ///
    /// # Errors
    ///
    /// Returns an arithmetic or object-record error if the canonical labels
    /// cannot be represented.
    pub fn to_object_record(&self) -> Result<ObjectRecord, DerivationModelError> {
        let mut references = vec![
            ObjectReference::owns(
                ReferenceLabel::new(TRANSFORM_LABEL.to_vec()),
                self.transform.object_id(),
            ),
            ObjectReference::owns(
                ReferenceLabel::new(TRANSFORM_CONTRACT_LABEL.to_vec()),
                self.transform_contract.object_id(),
            ),
            ObjectReference::owns(
                ReferenceLabel::new(PARAMETERS_LABEL.to_vec()),
                self.canonical_parameters.object_id(),
            ),
            ObjectReference::owns(
                ReferenceLabel::new(RUNTIME_LABEL.to_vec()),
                self.runtime_semantic_profile.object_id(),
            ),
            ObjectReference::owns(
                ReferenceLabel::new(OUTPUT_LABEL.to_vec()),
                self.output_contract.object_id(),
            ),
        ];
        if let Some(snapshot) = self.snapshot {
            references.push(ObjectReference::new(
                ReferenceLabel::new(SNAPSHOT_LABEL.to_vec()),
                snapshot.object_id(),
                ReferenceKind::Evidence,
            ));
        }
        if let Some(seed) = self.seed {
            references.push(ObjectReference::owns(
                ReferenceLabel::new(SEED_LABEL.to_vec()),
                seed.object_id(),
            ));
        }
        for (index, input) in self.inputs.iter().enumerate() {
            references.push(ObjectReference::new(
                indexed_label(INPUT_PREFIX, index, input.label())?,
                input.object(),
                ReferenceKind::Evidence,
            ));
        }

        ObjectRecord::new(
            ObjectKind::DerivationInvocation,
            ObjectFormatVersion::V1,
            vec![
                self.execution_class.code(),
                u8::from(self.snapshot.is_some()) | (u8::from(self.seed.is_some()) << 1),
            ],
            references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(DerivationModelError::InvalidObjectRecord)
    }

    /// Compute the invocation identity through the configured object identity.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if the canonical object cannot be built.
    pub fn identify<I: ObjectIdentity>(
        &self,
        identity: &I,
    ) -> Result<InvocationId, DerivationModelError> {
        self.to_object_record()
            .map(|record| InvocationId::new(identity.identify(&record)))
    }

    /// Decode and fully canonicalize one invocation object.
    ///
    /// # Errors
    ///
    /// Rejects the wrong kind, malformed labels, missing fields, invalid
    /// reference kinds, non-contiguous input ordinals, and execution-class
    /// violations.
    pub fn from_object_record(record: &ObjectRecord) -> Result<Self, DerivationModelError> {
        validate_record_header(record, ObjectKind::DerivationInvocation, 2)?;
        let execution_class = ExecutionClass::from_code(record.canonical_bytes()[0])
            .ok_or(DerivationModelError::UnknownExecutionClass)?;
        let option_mask = record.canonical_bytes()[1];
        if option_mask & !0b11 != 0 {
            return Err(DerivationModelError::InvalidOptionMask);
        }

        let mut transform = None;
        let mut transform_contract = None;
        let mut canonical_parameters = None;
        let mut runtime_semantic_profile = None;
        let mut output_contract = None;
        let mut snapshot = None;
        let mut seed = None;
        let mut inputs = Vec::new();

        for reference in record.references() {
            let label = reference.label().as_bytes();
            match label {
                TRANSFORM_LABEL => {
                    require_reference_kind(reference, ReferenceKind::Owns)?;
                    set_once(&mut transform, TransformId::new(reference.target()))?;
                },
                TRANSFORM_CONTRACT_LABEL => {
                    require_reference_kind(reference, ReferenceKind::Owns)?;
                    set_once(
                        &mut transform_contract,
                        DerivationContractId::new(reference.target()),
                    )?;
                },
                PARAMETERS_LABEL => {
                    require_reference_kind(reference, ReferenceKind::Owns)?;
                    set_once(
                        &mut canonical_parameters,
                        CanonicalParametersId::new(reference.target()),
                    )?;
                },
                RUNTIME_LABEL => {
                    require_reference_kind(reference, ReferenceKind::Owns)?;
                    set_once(
                        &mut runtime_semantic_profile,
                        RuntimeSemanticProfileId::new(reference.target()),
                    )?;
                },
                OUTPUT_LABEL => {
                    require_reference_kind(reference, ReferenceKind::Owns)?;
                    set_once(
                        &mut output_contract,
                        OutputContractId::new(reference.target()),
                    )?;
                },
                SNAPSHOT_LABEL => {
                    require_reference_kind(reference, ReferenceKind::Evidence)?;
                    set_once(&mut snapshot, SnapshotId::new(reference.target()))?;
                },
                SEED_LABEL => {
                    require_reference_kind(reference, ReferenceKind::Owns)?;
                    set_once(&mut seed, DeterministicSeedId::new(reference.target()))?;
                },
                _ if label.starts_with(INPUT_PREFIX) => {
                    require_reference_kind(reference, ReferenceKind::Evidence)?;
                    let input_label =
                        validate_indexed_label(INPUT_PREFIX, label, inputs.len(), &[])?;
                    inputs.push(InvocationInput::new(
                        input_label.to_vec(),
                        reference.target(),
                    )?);
                },
                _ => return Err(DerivationModelError::UnknownCanonicalField),
            }
        }

        let invocation = Self::new(
            execution_class,
            required(transform, "transform")?,
            required(transform_contract, "transform_contract")?,
            inputs,
            required(canonical_parameters, "canonical_parameters")?,
            required(runtime_semantic_profile, "runtime_semantic_profile")?,
            required(output_contract, "output_contract")?,
            snapshot,
            seed,
        )?;
        let decoded_option_mask =
            u8::from(invocation.snapshot.is_some()) | (u8::from(invocation.seed.is_some()) << 1);
        if decoded_option_mask != option_mask {
            return Err(DerivationModelError::InvalidOptionMask);
        }
        if invocation.to_object_record()? != *record {
            return Err(DerivationModelError::NonCanonicalObjectRecord);
        }
        Ok(invocation)
    }
}

/// Canonical derivation-model validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DerivationModelError {
    /// An invocation input used an empty semantic label.
    EmptyInputLabel,
    /// A host-function binding used an empty canonical name.
    EmptyHostFunctionName,
    /// Enabled proposal contracts were unordered or duplicated.
    NonCanonicalProposals,
    /// Host-function bindings were unordered or duplicated.
    NonCanonicalHostFunctions,
    /// A pure invocation incorrectly carried a mutable snapshot.
    PureInvocationHasSnapshot,
    /// A snapshot-bound invocation omitted its provenance snapshot.
    SnapshotBoundInvocationMissingSnapshot,
    /// A canonical collection length did not fit the frozen encoding.
    LengthOverflow,
    /// The object kind did not match the requested canonical schema.
    WrongObjectKind {
        /// Required semantic kind.
        expected: ObjectKind,
        /// Kind present in the object.
        actual: ObjectKind,
    },
    /// The object used a format version not accepted by this model.
    UnsupportedFormatVersion,
    /// Canonical object bytes had the wrong fixed length.
    InvalidCanonicalPayload,
    /// An execution-class code was unknown.
    UnknownExecutionClass,
    /// Optional-field presence bits were non-canonical or disagreed with references.
    InvalidOptionMask,
    /// A required field was absent.
    MissingCanonicalField(&'static str),
    /// A field occurred more than once.
    DuplicateCanonicalField,
    /// A reference label did not belong to the selected schema.
    UnknownCanonicalField,
    /// A reference had the wrong reachability meaning.
    InvalidReferenceKind,
    /// An indexed canonical label had the wrong ordinal or suffix.
    InvalidIndexedLabel,
    /// The decoded value did not reproduce the exact object record.
    NonCanonicalObjectRecord,
    /// Constructing the underlying logical object failed.
    InvalidObjectRecord(ModelError),
}

impl fmt::Display for DerivationModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInputLabel => formatter.write_str("invocation input label is empty"),
            Self::EmptyHostFunctionName => {
                formatter.write_str("host-function semantic name is empty")
            },
            Self::NonCanonicalProposals => {
                formatter.write_str("runtime proposals are not strictly ordered")
            },
            Self::NonCanonicalHostFunctions => {
                formatter.write_str("host functions are not strictly ordered")
            },
            Self::PureInvocationHasSnapshot => {
                formatter.write_str("pure invocation carries a provenance snapshot")
            },
            Self::SnapshotBoundInvocationMissingSnapshot => {
                formatter.write_str("snapshot-bound invocation has no provenance snapshot")
            },
            Self::LengthOverflow => {
                formatter.write_str("canonical derivation collection length overflow")
            },
            Self::WrongObjectKind { expected, actual } => {
                write!(
                    formatter,
                    "wrong derivation object kind: expected {expected:?}, actual {actual:?}"
                )
            },
            Self::UnsupportedFormatVersion => {
                formatter.write_str("unsupported derivation object format version")
            },
            Self::InvalidCanonicalPayload => {
                formatter.write_str("invalid derivation canonical payload")
            },
            Self::UnknownExecutionClass => formatter.write_str("unknown execution class"),
            Self::InvalidOptionMask => {
                formatter.write_str("invalid derivation optional-field presence mask")
            },
            Self::MissingCanonicalField(field) => {
                write!(formatter, "missing canonical derivation field {field}")
            },
            Self::DuplicateCanonicalField => {
                formatter.write_str("duplicate canonical derivation field")
            },
            Self::UnknownCanonicalField => {
                formatter.write_str("unknown canonical derivation field")
            },
            Self::InvalidReferenceKind => {
                formatter.write_str("invalid canonical derivation reference kind")
            },
            Self::InvalidIndexedLabel => {
                formatter.write_str("invalid canonical derivation indexed label")
            },
            Self::NonCanonicalObjectRecord => {
                formatter.write_str("derivation object is not canonical")
            },
            Self::InvalidObjectRecord(error) => {
                write!(formatter, "invalid derivation object record: {error}")
            },
        }
    }
}

fn owned_reference(label: &[u8], target: ObjectId) -> ObjectReference {
    ObjectReference::owns(ReferenceLabel::new(label.to_vec()), target)
}

fn prefixed_label(prefix: &[u8], suffix: &[u8]) -> ReferenceLabel {
    let mut label = prefix.to_vec();
    label.extend_from_slice(suffix);
    ReferenceLabel::new(label)
}

fn indexed_label(
    prefix: &[u8],
    index: usize,
    suffix: &[u8],
) -> Result<ReferenceLabel, DerivationModelError> {
    let index = u64::try_from(index).map_err(|_| DerivationModelError::LengthOverflow)?;
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
    required_suffix: &[u8],
) -> Result<&'a [u8], DerivationModelError> {
    let index_end = prefix
        .len()
        .checked_add(8)
        .ok_or(DerivationModelError::LengthOverflow)?;
    let separator = index_end
        .checked_add(1)
        .ok_or(DerivationModelError::LengthOverflow)?;
    if label.len() < separator || label.get(index_end) != Some(&0) || !label.starts_with(prefix) {
        return Err(DerivationModelError::InvalidIndexedLabel);
    }
    let encoded_index: [u8; 8] = label[prefix.len()..index_end]
        .try_into()
        .map_err(|_| DerivationModelError::InvalidIndexedLabel)?;
    let expected_index =
        u64::try_from(expected_index).map_err(|_| DerivationModelError::LengthOverflow)?;
    let suffix = &label[separator..];
    if u64::from_be_bytes(encoded_index) != expected_index
        || (!required_suffix.is_empty() && suffix != required_suffix)
    {
        return Err(DerivationModelError::InvalidIndexedLabel);
    }
    Ok(suffix)
}

fn validate_record_header(
    record: &ObjectRecord,
    expected_kind: ObjectKind,
    payload_len: usize,
) -> Result<(), DerivationModelError> {
    if record.kind() != expected_kind {
        return Err(DerivationModelError::WrongObjectKind {
            expected: expected_kind,
            actual: record.kind(),
        });
    }
    if record.format_version() != ObjectFormatVersion::V1 {
        return Err(DerivationModelError::UnsupportedFormatVersion);
    }
    if record.canonical_bytes().len() != payload_len
        || record.logical_bytes() != 0
        || record.class() != ObjectClass::Metadata
    {
        return Err(DerivationModelError::InvalidCanonicalPayload);
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), DerivationModelError> {
    if slot.replace(value).is_some() {
        return Err(DerivationModelError::DuplicateCanonicalField);
    }
    Ok(())
}

fn required<T>(slot: Option<T>, name: &'static str) -> Result<T, DerivationModelError> {
    slot.ok_or(DerivationModelError::MissingCanonicalField(name))
}

fn require_reference_kind(
    reference: &ObjectReference,
    expected: ReferenceKind,
) -> Result<(), DerivationModelError> {
    if reference.kind() != expected {
        return Err(DerivationModelError::InvalidReferenceKind);
    }
    Ok(())
}
