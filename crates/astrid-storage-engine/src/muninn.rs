//! Disposable lookup index over independently verified derivation evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;

use astrid_storage_model::{
    ComputationSharingDomainId, DerivationEvidence, DerivationEvidenceError, DerivationInvocation,
    DerivationModelError, InvocationId, ObjectId, ObjectIdentity, ObjectRecord,
};
use parking_lot::RwLock;

/// Evidence whose identity, invocation, and complete output closures have been
/// recomputed by the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDerivationEvidence {
    evidence: ObjectId,
    invocation: InvocationId,
    sharing_domain: ComputationSharingDomainId,
    outputs: Vec<ObjectId>,
}

impl VerifiedDerivationEvidence {
    /// Return the durable evidence identity.
    #[must_use]
    pub const fn evidence(&self) -> ObjectId {
        self.evidence
    }

    /// Return the complete invocation identity.
    #[must_use]
    pub const fn invocation(&self) -> InvocationId {
        self.invocation
    }

    /// Return the computation-sharing domain recorded at admission.
    #[must_use]
    pub const fn sharing_domain(&self) -> ComputationSharingDomainId {
        self.sharing_domain
    }

    /// Borrow ordered result identities.
    #[must_use]
    pub fn outputs(&self) -> &[ObjectId] {
        &self.outputs
    }
}

/// Verify the complete durable relation before it may enter Muninn.
///
/// `output_closure` must be exactly the union of every output's complete Owns
/// closure. Every declared identifier is recomputed, cycles and missing
/// objects fail closed, and effectful or nondeterministic invocations are
/// rejected from reuse.
///
/// This verifies storage and invocation integrity. Governed execution remains
/// responsible for establishing that the evidence came from an authorized
/// sandbox run; this function does not turn a stored claim into authority.
///
/// # Errors
///
/// Returns a typed verification error for identity substitution, malformed
/// canonical records, invocation drift, ineligible execution classes, or an
/// incomplete/cyclic/extraneous output closure.
pub fn verify_derivation_evidence<I: ObjectIdentity>(
    identity: &I,
    evidence_id: ObjectId,
    evidence_record: &ObjectRecord,
    invocation_record: &ObjectRecord,
    output_closure: &BTreeMap<ObjectId, ObjectRecord>,
) -> Result<VerifiedDerivationEvidence, MuninnVerificationError> {
    if identity.identify(evidence_record) != evidence_id {
        return Err(MuninnVerificationError::EvidenceIdentityMismatch);
    }
    let evidence = DerivationEvidence::from_object_record(evidence_record)
        .map_err(MuninnVerificationError::InvalidEvidence)?;
    if identity.identify(invocation_record) != evidence.invocation().object_id() {
        return Err(MuninnVerificationError::InvocationIdentityMismatch);
    }
    let invocation = DerivationInvocation::from_object_record(invocation_record)
        .map_err(MuninnVerificationError::InvalidInvocation)?;
    evidence
        .validate_invocation(&invocation, identity)
        .map_err(MuninnVerificationError::InvalidEvidence)?;
    if !invocation.is_memoizable() {
        return Err(MuninnVerificationError::ExecutionClassNotMemoizable);
    }

    for (declared, record) in output_closure {
        if identity.identify(record) != *declared {
            return Err(MuninnVerificationError::OutputIdentityMismatch(*declared));
        }
    }
    let outputs: Vec<_> = evidence
        .outputs()
        .iter()
        .map(astrid_storage_model::DerivationOutput::object)
        .collect();
    let reachable = validate_complete_output_closure(&outputs, output_closure)?;
    if reachable.len() != output_closure.len() {
        return Err(MuninnVerificationError::ExtraneousOutputRecord);
    }

    Ok(VerifiedDerivationEvidence {
        evidence: evidence_id,
        invocation: evidence.invocation(),
        sharing_domain: evidence.sharing_domain(),
        outputs,
    })
}

/// Reuse state of one disposable Muninn entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuninnTrustState {
    /// Structurally verified and eligible for a policy-authorized hit.
    Verified,
    /// Excluded after a mismatch or unresolved integrity signal.
    Suspect,
    /// Excluded because transform, profile, or authority was revoked.
    Revoked,
    /// Excluded because snapshot or policy validity ended.
    Expired,
}

/// Read-only result of an eligible Muninn lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuninnHit {
    evidence: ObjectId,
    outputs: Vec<ObjectId>,
}

impl MuninnHit {
    /// Return the durable evidence that justifies this hit.
    #[must_use]
    pub const fn evidence(&self) -> ObjectId {
        self.evidence
    }

    /// Borrow ordered result identities.
    #[must_use]
    pub fn outputs(&self) -> &[ObjectId] {
        &self.outputs
    }
}

/// Outcome of admitting verified evidence into the disposable index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuninnAdmission {
    /// A new invocation entry was indexed.
    Inserted,
    /// The exact same outputs were already indexed with supporting evidence.
    AlreadyPresent,
    /// The injected index budget was exhausted; execution remains valid.
    CapacityExhausted,
    /// The invocation was already bound to different outputs.
    Conflict {
        /// Existing durable evidence identity.
        existing: ObjectId,
        /// Conflicting durable evidence identity.
        incoming: ObjectId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MuninnEntry {
    evidence: ObjectId,
    outputs: Vec<ObjectId>,
    trust: MuninnTrustState,
    last_spot_check: Option<ObjectId>,
    resident: bool,
}

/// Process-local, correctness-independent Muninn lookup table.
///
/// Capacity has no library default: native composition must inject a bounded
/// operator policy, and the common resource authority may replace this simple
/// entry budget without changing evidence or lookup semantics. Exhaustion and
/// eviction never fail a valid derivation; they only remove the acceleration.
///
/// This first implementation retains one bounded observation slot for every
/// key it has admitted, even after eviction. That prevents eviction or
/// `clear()` from forgetting a previously observed conflicting result. Freed
/// resident slots are therefore not reused for different invocation keys.
/// Replacement policies arrive with the resource authority; an off-side
/// rebuild must scan all retained evidence before its index becomes visible.
#[derive(Debug)]
pub struct InMemoryMuninnIndex {
    capacity: NonZeroUsize,
    slots: RwLock<BTreeMap<(ComputationSharingDomainId, InvocationId), MuninnEntry>>,
}

impl InMemoryMuninnIndex {
    /// Construct an empty index with an explicitly injected entry budget.
    ///
    /// This is appropriate when no retained derivation evidence exists. A
    /// restart with retained evidence must use
    /// [`Self::from_retained_evidence`] so no partially rebuilt table becomes
    /// visible.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            slots: RwLock::new(BTreeMap::new()),
        }
    }

    /// Rebuild an index off-side from the complete retained evidence set.
    ///
    /// The returned index is not observable until every item has been
    /// admitted, so input order cannot expose one side of a conflict during
    /// recovery. Unknown keys after the bounded observation budget is full
    /// remain uncached for this index generation.
    #[must_use]
    pub fn from_retained_evidence<'a>(
        capacity: NonZeroUsize,
        evidence: impl IntoIterator<Item = &'a VerifiedDerivationEvidence>,
    ) -> Self {
        let index = Self::new(capacity);
        for verified in evidence {
            let _ = index.admit(verified);
        }
        index
    }

    /// Return the injected entry budget.
    #[must_use]
    pub const fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    /// Return the current number of disposable entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots
            .read()
            .values()
            .filter(|entry| entry.resident)
            .count()
    }

    /// Return whether the disposable index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Admit evidence only after [`verify_derivation_evidence`] succeeds.
    ///
    /// A conflicting result marks the old entry suspect and never replaces it
    /// silently. Capacity exhaustion returns an outcome rather than an error
    /// because the uncached execution result remains valid.
    #[must_use]
    pub fn admit(&self, verified: &VerifiedDerivationEvidence) -> MuninnAdmission {
        let key = (verified.sharing_domain, verified.invocation);
        let mut slots = self.slots.write();
        if let Some(existing) = slots.get_mut(&key) {
            if existing.outputs == verified.outputs {
                if existing.trust == MuninnTrustState::Verified {
                    existing.resident = true;
                }
                return MuninnAdmission::AlreadyPresent;
            }
            existing.trust = MuninnTrustState::Suspect;
            existing.resident = false;
            return MuninnAdmission::Conflict {
                existing: existing.evidence,
                incoming: verified.evidence,
            };
        }
        if slots.len() >= self.capacity.get() {
            return MuninnAdmission::CapacityExhausted;
        }
        slots.insert(
            key,
            MuninnEntry {
                evidence: verified.evidence,
                outputs: verified.outputs.clone(),
                trust: MuninnTrustState::Verified,
                last_spot_check: None,
                resident: true,
            },
        );
        MuninnAdmission::Inserted
    }

    /// Look up one invocation inside one computation-sharing domain.
    ///
    /// Only verified entries are returned. Callers must authorize access and
    /// re-check current contract, closure, and policy eligibility before
    /// returning any result bytes.
    #[must_use]
    pub fn lookup(
        &self,
        domain: ComputationSharingDomainId,
        invocation: InvocationId,
    ) -> Option<MuninnHit> {
        let slots = self.slots.read();
        let entry = slots.get(&(domain, invocation))?;
        if !entry.resident || entry.trust != MuninnTrustState::Verified {
            return None;
        }
        Some(MuninnHit {
            evidence: entry.evidence,
            outputs: entry.outputs.clone(),
        })
    }

    /// Change disposable trust state after governed policy or audit checks.
    ///
    /// `spot_check_evidence` identifies the audit record that justified the
    /// transition when one exists.
    #[must_use]
    pub fn set_trust_state(
        &self,
        domain: ComputationSharingDomainId,
        invocation: InvocationId,
        trust: MuninnTrustState,
        spot_check_evidence: Option<ObjectId>,
    ) -> bool {
        let mut slots = self.slots.write();
        let Some(entry) = slots.get_mut(&(domain, invocation)) else {
            return false;
        };
        if trust == MuninnTrustState::Verified
            && entry.trust != MuninnTrustState::Verified
            && spot_check_evidence.is_none()
        {
            return false;
        }
        entry.trust = trust;
        if spot_check_evidence.is_some() {
            entry.last_spot_check = spot_check_evidence;
        }
        if trust == MuninnTrustState::Verified {
            entry.resident = true;
        }
        true
    }

    /// Evict one reusable entry while retaining its bounded conflict guard.
    #[must_use]
    pub fn evict(&self, domain: ComputationSharingDomainId, invocation: InvocationId) -> bool {
        let mut slots = self.slots.write();
        let Some(entry) = slots.get_mut(&(domain, invocation)) else {
            return false;
        };
        let was_resident = entry.resident;
        entry.resident = false;
        was_resident
    }

    /// Drop all reusable entries while retaining bounded conflict guards.
    ///
    /// To discard the guards as well, build a fresh index off-side from the
    /// complete retained evidence set and publish it only after that scan
    /// finishes.
    pub fn clear(&self) {
        for entry in self.slots.write().values_mut() {
            entry.resident = false;
        }
    }
}

/// Failure while rebuilding or admitting a durable derivation relation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MuninnVerificationError {
    /// The evidence record did not hash to its declared identity.
    EvidenceIdentityMismatch,
    /// The invocation record did not hash to the identity named by evidence.
    InvocationIdentityMismatch,
    /// The evidence object was malformed or drifted from the invocation.
    InvalidEvidence(DerivationEvidenceError),
    /// The invocation object was malformed.
    InvalidInvocation(DerivationModelError),
    /// Effectful or nondeterministic execution was offered for reuse.
    ExecutionClassNotMemoizable,
    /// An output-closure record did not hash to its declared identity.
    OutputIdentityMismatch(ObjectId),
    /// A result or owned descendant was absent.
    MissingOutputObject(ObjectId),
    /// An output Owns graph contained a cycle.
    CyclicOutputClosure(ObjectId),
    /// The supplied closure contained an object not reachable from any output.
    ExtraneousOutputRecord,
}

impl std::fmt::Display for MuninnVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EvidenceIdentityMismatch => {
                formatter.write_str("derivation evidence identity mismatch")
            },
            Self::InvocationIdentityMismatch => {
                formatter.write_str("derivation invocation identity mismatch")
            },
            Self::InvalidEvidence(error) => {
                write!(formatter, "invalid derivation evidence: {error}")
            },
            Self::InvalidInvocation(error) => {
                write!(formatter, "invalid derivation invocation: {error}")
            },
            Self::ExecutionClassNotMemoizable => {
                formatter.write_str("derivation execution class is not memoizable")
            },
            Self::OutputIdentityMismatch(id) => {
                write!(formatter, "derivation output identity mismatch at {id:?}")
            },
            Self::MissingOutputObject(id) => {
                write!(formatter, "derivation output closure is missing {id:?}")
            },
            Self::CyclicOutputClosure(id) => {
                write!(formatter, "derivation output closure is cyclic at {id:?}")
            },
            Self::ExtraneousOutputRecord => {
                formatter.write_str("derivation output closure contains extraneous records")
            },
        }
    }
}

pub(super) fn validate_complete_output_closure(
    outputs: &[ObjectId],
    records: &BTreeMap<ObjectId, ObjectRecord>,
) -> Result<BTreeSet<ObjectId>, MuninnVerificationError> {
    let mut marks = BTreeMap::<ObjectId, u8>::new();
    let mut reachable = BTreeSet::new();
    for output in outputs {
        let mut work = vec![(*output, false)];
        while let Some((id, expanded)) = work.pop() {
            if expanded {
                marks.insert(id, 2);
                continue;
            }
            match marks.get(&id) {
                Some(1) => return Err(MuninnVerificationError::CyclicOutputClosure(id)),
                Some(2) => continue,
                _ => {},
            }
            let record = records
                .get(&id)
                .ok_or(MuninnVerificationError::MissingOutputObject(id))?;
            marks.insert(id, 1);
            reachable.insert(id);
            work.push((id, true));
            let children: Vec<_> = record.owning_references().collect();
            work.extend(children.into_iter().rev().map(|child| (child, false)));
        }
    }
    Ok(reachable)
}
