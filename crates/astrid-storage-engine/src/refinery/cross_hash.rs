//! Construction-diverse custody witnesses over verified object closures.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fmt;

use astrid_storage_model::{
    ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity, ObjectKind,
    ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel,
};
use sha2::{Digest, Sha384};

use super::{
    ProposedRefineryOutput, RefineryBatchContext, RefineryPass, RefineryPassDescriptorId,
    RefineryProposalError, RefineryProposalSink, RefineryRunError, VerifiedRefineryObject,
    run_refinery_observer,
};

mod verify;

pub use verify::verify_sha384_attestation;

const TREE_FANOUT: usize = 128;
const MAX_TREE_LEVEL: u16 = 10;
const CURRENT_IDENTITY_ALGORITHM: u16 = 1;
const CURRENT_IDENTITY_CONSTRUCTION: u16 = 1;
const CURRENT_IDENTITY_LENGTH: u32 = 32;
const ED25519_SIGNATURE_ALGORITHM: u16 = 1;
const LEAF_MAGIC: &[u8] = b"astrid-sha384-leaf-v1\0";
const NODE_MAGIC: &[u8] = b"astrid-sha384-node-v1\0";
const ATTESTATION_MAGIC: &[u8] = b"astrid-sha384-attestation-v1\0";
const OBJECT_DOMAIN: &[u8] = b"astrid sha384 object witness v1\0";
const LEAF_DOMAIN: &[u8] = b"astrid sha384 leaf v1\0";
const NODE_DOMAIN: &[u8] = b"astrid sha384 node v1\0";
const STATEMENT_DOMAIN: &[u8] = b"astrid sha384 attestation statement v1\0";
const PASS_DESCRIPTOR_LABEL: &[u8] = b"00-pass-descriptor";
const SNAPSHOT_LABEL: &[u8] = b"01-snapshot";
const ROOT_LABEL_PREFIX: &[u8] = b"10-root/";
const TREE_LABEL: &[u8] = b"20-tree";
const SOURCE_LABEL_PREFIX: &[u8] = b"source/";
const CHILD_LABEL_PREFIX: &[u8] = b"child/";

type Sha384Digest = [u8; 48];

/// Authority that signs one canonical SHA-384 custody statement.
///
/// Signing keys stay at the integration authority boundary. The storage
/// engine receives only the public key and signature bytes.
pub trait CrossHashSigner {
    /// Signing failure reported by the authority implementation.
    type Error;

    /// Return the Ed25519 public key authorized for this ceremony.
    fn public_key(&self) -> [u8; 32];

    /// Sign the exact canonical statement.
    ///
    /// # Errors
    ///
    /// Returns an authority-specific signing failure.
    fn sign(&self, statement: &[u8]) -> Result<[u8; 64], Self::Error>;
}

/// Signature verifier used when admitting or independently checking Evidence.
pub trait CrossHashVerifier {
    /// Verify one Ed25519 signature under the registered pass authority.
    fn verify(
        &self,
        descriptor: RefineryPassDescriptorId,
        public_key: &[u8; 32],
        statement: &[u8],
        signature: &[u8; 64],
    ) -> bool;
}

/// Verified, export-ready summary of one closure attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossHashAttestation {
    descriptor: RefineryPassDescriptorId,
    snapshot: super::RefinerySnapshotId,
    placement_epoch: u64,
    roots: Vec<ObjectId>,
    object_count: u64,
    tree_digest: Sha384Digest,
    tree: ObjectId,
    public_key: [u8; 32],
    signature: [u8; 64],
}

impl CrossHashAttestation {
    /// Return the pinned Refinery pass descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> RefineryPassDescriptorId {
        self.descriptor
    }

    /// Return the immutable input snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> super::RefinerySnapshotId {
        self.snapshot
    }

    /// Return the observed physical placement epoch.
    #[must_use]
    pub const fn placement_epoch(&self) -> u64 {
        self.placement_epoch
    }

    /// Borrow the selected roots in canonical identity order.
    #[must_use]
    pub fn roots(&self) -> &[ObjectId] {
        &self.roots
    }

    /// Return the number of distinct objects in the exact owning closure.
    #[must_use]
    pub const fn object_count(&self) -> u64 {
        self.object_count
    }

    /// Return the construction-diverse tree digest.
    #[must_use]
    pub const fn tree_digest(&self) -> &[u8; 48] {
        &self.tree_digest
    }

    /// Return the root Evidence object for the deterministic digest tree.
    #[must_use]
    pub const fn tree(&self) -> ObjectId {
        self.tree
    }

    /// Return the Ed25519 ceremony public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Return the Ed25519 ceremony signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Failure while producing or verifying SHA-384 custody Evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sha384AttestationError<E> {
    /// No root was selected.
    NoRoots,
    /// Root identities were not strictly increasing.
    NonCanonicalRoots,
    /// Input objects were not strictly increasing by identity.
    NonCanonicalObjectOrder,
    /// A selected root or owning descendant was absent.
    MissingObject(ObjectId),
    /// The selected owning graph contains a cycle.
    ObjectCycle(ObjectId),
    /// The stream contains an object outside the selected closure.
    ExtraneousObject(ObjectId),
    /// An object does not match its declared identity.
    ObjectIdentityMismatch(ObjectId),
    /// A byte or retained-output resource ceiling was exceeded.
    ResourceBudgetExceeded,
    /// A retained-size calculation overflowed.
    ArithmeticOverflow,
    /// The authority could not sign the ceremony.
    Signer(E),
    /// A generated Evidence record violated the object grammar.
    InvalidEvidenceRecord(ModelError),
    /// The proposal sink rejected a generated Evidence record.
    Proposal(RefineryProposalError),
    /// Evidence bytes or references are not the one canonical representation.
    NonCanonicalEvidence,
    /// The attestation signature is invalid.
    InvalidSignature,
}

impl<E: fmt::Display> fmt::Display for Sha384AttestationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoots => formatter.write_str("SHA-384 attestation has no selected roots"),
            Self::NonCanonicalRoots => {
                formatter.write_str("SHA-384 roots are not in canonical identity order")
            },
            Self::NonCanonicalObjectOrder => {
                formatter.write_str("SHA-384 input objects are not in canonical identity order")
            },
            Self::MissingObject(id) => write!(formatter, "SHA-384 closure misses object {id:?}"),
            Self::ObjectCycle(id) => write!(formatter, "SHA-384 closure cycles at {id:?}"),
            Self::ExtraneousObject(id) => {
                write!(
                    formatter,
                    "SHA-384 closure contains extraneous object {id:?}"
                )
            },
            Self::ObjectIdentityMismatch(id) => {
                write!(formatter, "SHA-384 object identity mismatch at {id:?}")
            },
            Self::ResourceBudgetExceeded => {
                formatter.write_str("SHA-384 Refinery resource budget exceeded")
            },
            Self::ArithmeticOverflow => formatter.write_str("SHA-384 accounting overflow"),
            Self::Signer(error) => write!(formatter, "SHA-384 signing failed: {error}"),
            Self::InvalidEvidenceRecord(error) => {
                write!(formatter, "invalid SHA-384 Evidence record: {error}")
            },
            Self::Proposal(error) => write!(formatter, "SHA-384 proposal failed: {error}"),
            Self::NonCanonicalEvidence => formatter.write_str("non-canonical SHA-384 Evidence"),
            Self::InvalidSignature => formatter.write_str("invalid SHA-384 ceremony signature"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ObjectWitness {
    object: ObjectId,
    digest: Sha384Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TreeSummary {
    id: ObjectId,
    digest: Sha384Digest,
    object_count: u64,
    level: u16,
}

struct TreeBuilder<'a, I> {
    identity: &'a I,
    leaf: Vec<ObjectWitness>,
    pending: Vec<Vec<TreeSummary>>,
    emitted: Vec<ObjectRecord>,
}

impl<'a, I: ObjectIdentity> TreeBuilder<'a, I> {
    fn new(identity: &'a I) -> Self {
        Self {
            identity,
            leaf: Vec::with_capacity(TREE_FANOUT),
            pending: Vec::new(),
            emitted: Vec::new(),
        }
    }

    fn push(&mut self, witness: ObjectWitness) -> Result<(), ModelError> {
        self.leaf.push(witness);
        if self.leaf.len() == TREE_FANOUT {
            self.flush_leaf()?;
        }
        Ok(())
    }

    fn drain_emitted(&mut self) -> impl Iterator<Item = ObjectRecord> + '_ {
        self.emitted.drain(..)
    }

    fn finish(&mut self) -> Result<TreeSummary, Sha384AttestationError<Infallible>> {
        self.flush_leaf()
            .map_err(Sha384AttestationError::InvalidEvidenceRecord)?;
        loop {
            let mut occupied = self
                .pending
                .iter()
                .enumerate()
                .filter(|(_, entries)| !entries.is_empty());
            let Some((lowest, _)) = occupied.next() else {
                return Err(Sha384AttestationError::NonCanonicalEvidence);
            };
            if occupied.next().is_none() && self.pending[lowest].len() == 1 {
                return self.pending[lowest]
                    .pop()
                    .ok_or(Sha384AttestationError::NonCanonicalEvidence);
            }
            let children = std::mem::take(&mut self.pending[lowest]);
            self.emit_node(&children)
                .map_err(Sha384AttestationError::InvalidEvidenceRecord)?;
        }
    }

    fn flush_leaf(&mut self) -> Result<(), ModelError> {
        if self.leaf.is_empty() {
            return Ok(());
        }
        let entries = std::mem::take(&mut self.leaf);
        let digest = leaf_digest(&entries);
        let canonical = encode_leaf(&entries, digest);
        let references = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                ObjectReference::new(
                    indexed_label(SOURCE_LABEL_PREFIX, index),
                    entry.object,
                    ReferenceKind::Evidence,
                )
            })
            .collect();
        let record = evidence_record(canonical, references)?;
        let summary = TreeSummary {
            id: self.identity.identify(&record),
            digest,
            object_count: u64::try_from(entries.len())
                .map_err(|_| ModelError::ArithmeticOverflow)?,
            level: 0,
        };
        self.emitted.push(record);
        self.push_summary(summary)
    }

    fn push_summary(&mut self, summary: TreeSummary) -> Result<(), ModelError> {
        let level = usize::from(summary.level);
        if self.pending.len() <= level {
            self.pending.resize_with(level + 1, Vec::new);
        }
        self.pending[level].push(summary);
        if self.pending[level].len() == TREE_FANOUT {
            let children = std::mem::take(&mut self.pending[level]);
            self.emit_node(&children)?;
        }
        Ok(())
    }

    fn emit_node(&mut self, children: &[TreeSummary]) -> Result<(), ModelError> {
        let child_level = children
            .first()
            .map(|child| child.level)
            .ok_or(ModelError::ArithmeticOverflow)?;
        let level = child_level
            .checked_add(1)
            .ok_or(ModelError::ArithmeticOverflow)?;
        if level > MAX_TREE_LEVEL || children.iter().any(|child| child.level != child_level) {
            return Err(ModelError::ArithmeticOverflow);
        }
        let object_count = children.iter().try_fold(0_u64, |total, child| {
            total
                .checked_add(child.object_count)
                .ok_or(ModelError::ArithmeticOverflow)
        })?;
        let digest = node_digest(level, object_count, children);
        let canonical = encode_node(level, object_count, children, digest);
        let references = children
            .iter()
            .enumerate()
            .map(|(index, child)| {
                ObjectReference::owns(indexed_label(CHILD_LABEL_PREFIX, index), child.id)
            })
            .collect();
        let record = evidence_record(canonical, references)?;
        let summary = TreeSummary {
            id: self.identity.identify(&record),
            digest,
            object_count,
            level,
        };
        self.emitted.push(record);
        self.push_summary(summary)
    }
}

struct Sha384Pass<'a, I, S> {
    signer: &'a S,
    descriptor: RefineryPassDescriptorId,
    roots: Vec<ObjectId>,
    context: Option<RefineryBatchContext>,
    tree: TreeBuilder<'a, I>,
    previous: Option<ObjectId>,
    input_bytes: u64,
    output_bytes: u64,
}

impl<I: ObjectIdentity, S: CrossHashSigner> Sha384Pass<'_, I, S> {
    fn emit_pending(
        &mut self,
        proposals: &mut RefineryProposalSink,
    ) -> Result<(), Sha384AttestationError<S::Error>> {
        for record in self.tree.drain_emitted() {
            self.output_bytes = self
                .output_bytes
                .checked_add(
                    record
                        .retained_bytes()
                        .map_err(Sha384AttestationError::InvalidEvidenceRecord)?,
                )
                .ok_or(Sha384AttestationError::ArithmeticOverflow)?;
            let budget = self
                .context
                .ok_or(Sha384AttestationError::NonCanonicalEvidence)?
                .budget();
            if self.output_bytes > budget.retained_output_bytes() {
                return Err(Sha384AttestationError::ResourceBudgetExceeded);
            }
            proposals
                .propose_evidence(record)
                .map_err(Sha384AttestationError::Proposal)?;
        }
        Ok(())
    }
}

impl<I: ObjectIdentity + Sync, S: CrossHashSigner + Sync> RefineryPass for Sha384Pass<'_, I, S> {
    type Error = Sha384AttestationError<S::Error>;

    fn descriptor(&self) -> RefineryPassDescriptorId {
        self.descriptor
    }

    fn begin(&mut self, context: RefineryBatchContext) -> Result<(), Self::Error> {
        self.context = Some(context);
        Ok(())
    }

    fn observe(
        &mut self,
        object: VerifiedRefineryObject<'_>,
        proposals: &mut RefineryProposalSink,
    ) -> Result<(), Self::Error> {
        if self
            .previous
            .is_some_and(|previous| previous >= object.id())
        {
            return Err(Sha384AttestationError::NonCanonicalObjectOrder);
        }
        self.previous = Some(object.id());
        let retained = object
            .as_record()
            .retained_bytes()
            .map_err(Sha384AttestationError::InvalidEvidenceRecord)?;
        self.input_bytes = self
            .input_bytes
            .checked_add(retained)
            .ok_or(Sha384AttestationError::ArithmeticOverflow)?;
        let context = self
            .context
            .ok_or(Sha384AttestationError::NonCanonicalEvidence)?;
        if self.input_bytes > context.budget().bytes_read() {
            return Err(Sha384AttestationError::ResourceBudgetExceeded);
        }
        self.tree
            .push(ObjectWitness {
                object: object.id(),
                digest: object_digest(object.id(), object.as_record()),
            })
            .map_err(Sha384AttestationError::InvalidEvidenceRecord)?;
        self.emit_pending(proposals)
    }

    fn finish(&mut self, proposals: &mut RefineryProposalSink) -> Result<(), Self::Error> {
        let tree = self.tree.finish().map_err(unit_error)?;
        self.emit_pending(proposals)?;
        let context = self
            .context
            .ok_or(Sha384AttestationError::NonCanonicalEvidence)?;
        let public_key = self.signer.public_key();
        let statement = attestation_statement(
            self.descriptor,
            context,
            &self.roots,
            tree.object_count,
            tree.digest,
            public_key,
        );
        let signature = self
            .signer
            .sign(&statement)
            .map_err(Sha384AttestationError::Signer)?;
        let record = attestation_record(
            self.descriptor,
            context,
            &self.roots,
            tree,
            public_key,
            signature,
        )
        .map_err(Sha384AttestationError::InvalidEvidenceRecord)?;
        self.output_bytes = self
            .output_bytes
            .checked_add(
                record
                    .retained_bytes()
                    .map_err(Sha384AttestationError::InvalidEvidenceRecord)?,
            )
            .ok_or(Sha384AttestationError::ArithmeticOverflow)?;
        if self.output_bytes > context.budget().retained_output_bytes() {
            return Err(Sha384AttestationError::ResourceBudgetExceeded);
        }
        proposals
            .propose_evidence(record)
            .map_err(Sha384AttestationError::Proposal)
    }

    fn checkpoint(&self) -> Option<super::RefineryCheckpointId> {
        None
    }
}

/// Produce canonical SHA-384 Evidence for one exact, verified owning closure.
///
/// Roots and input objects must both be strictly ordered. The input must equal
/// the union of the roots' `Owns` closures: omission and unrelated additions
/// fail before the observer runs. Generated records remain untrusted proposals
/// and require normal engine admission and publication.
///
/// # Errors
///
/// Returns a typed closure, identity, resource, signing, or evidence error.
pub fn attest_sha384_closure<I, S>(
    identity: &I,
    signer: &S,
    descriptor: RefineryPassDescriptorId,
    context: RefineryBatchContext,
    roots: &[ObjectId],
    objects: &[(ObjectId, ObjectRecord)],
) -> Result<Vec<ProposedRefineryOutput>, Sha384AttestationError<S::Error>>
where
    I: ObjectIdentity + Sync,
    S: CrossHashSigner + Sync,
{
    validate_exact_closure(identity, roots, objects)?;
    let mut pass = Sha384Pass {
        signer,
        descriptor,
        roots: roots.to_vec(),
        context: None,
        tree: TreeBuilder::new(identity),
        previous: None,
        input_bytes: 0,
        output_bytes: 0,
    };
    run_refinery_observer(identity, &mut pass, context, objects).map_err(|error| match error {
        RefineryRunError::ObjectIdentityMismatch(id) => {
            Sha384AttestationError::ObjectIdentityMismatch(id)
        },
        RefineryRunError::Pass(error) => error,
    })
}

fn validate_exact_closure<I, E>(
    identity: &I,
    roots: &[ObjectId],
    objects: &[(ObjectId, ObjectRecord)],
) -> Result<(), Sha384AttestationError<E>>
where
    I: ObjectIdentity,
{
    validate_roots(roots)?;
    if objects.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(Sha384AttestationError::NonCanonicalObjectOrder);
    }
    let mut records = BTreeMap::new();
    for (declared, record) in objects {
        if identity.identify(record) != *declared {
            return Err(Sha384AttestationError::ObjectIdentityMismatch(*declared));
        }
        records.insert(*declared, record);
    }
    let closure = owning_closure(&records, roots)?;
    for object in records.keys() {
        if !closure.contains(object) {
            return Err(Sha384AttestationError::ExtraneousObject(*object));
        }
    }
    Ok(())
}

fn validate_roots<E>(roots: &[ObjectId]) -> Result<(), Sha384AttestationError<E>> {
    if roots.is_empty() {
        return Err(Sha384AttestationError::NoRoots);
    }
    if u16::try_from(roots.len()).is_err() {
        return Err(Sha384AttestationError::ArithmeticOverflow);
    }
    if roots.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Sha384AttestationError::NonCanonicalRoots);
    }
    Ok(())
}

fn owning_closure<E>(
    records: &BTreeMap<ObjectId, &ObjectRecord>,
    roots: &[ObjectId],
) -> Result<BTreeSet<ObjectId>, Sha384AttestationError<E>> {
    let mut marks = BTreeMap::<ObjectId, u8>::new();
    for root in roots {
        let mut stack = vec![(*root, false)];
        while let Some((id, leaving)) = stack.pop() {
            if leaving {
                marks.insert(id, 2);
                continue;
            }
            match marks.get(&id).copied() {
                Some(1) => return Err(Sha384AttestationError::ObjectCycle(id)),
                Some(2) => continue,
                _ => {},
            }
            let record = records
                .get(&id)
                .ok_or(Sha384AttestationError::MissingObject(id))?;
            marks.insert(id, 1);
            stack.push((id, true));
            for child in record.owning_references().rev() {
                stack.push((child, false));
            }
        }
    }
    Ok(marks.into_keys().collect())
}

fn evidence_record(
    canonical: Vec<u8>,
    references: Vec<ObjectReference>,
) -> Result<ObjectRecord, ModelError> {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        canonical,
        references,
        0,
        ObjectClass::Metadata,
    )
}

fn object_digest(id: ObjectId, record: &ObjectRecord) -> Sha384Digest {
    let mut hasher = Sha384::new();
    hasher.update(OBJECT_DOMAIN);
    update_current_identity(&mut hasher, id);
    update_record_envelope(&mut hasher, record);
    hasher.finalize().into()
}

fn leaf_digest(entries: &[ObjectWitness]) -> Sha384Digest {
    let mut hasher = Sha384::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(
        u16::try_from(entries.len())
            .unwrap_or_default()
            .to_le_bytes(),
    );
    for entry in entries {
        update_current_identity(&mut hasher, entry.object);
        hasher.update(entry.digest);
    }
    hasher.finalize().into()
}

fn node_digest(level: u16, object_count: u64, children: &[TreeSummary]) -> Sha384Digest {
    let mut hasher = Sha384::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(level.to_le_bytes());
    hasher.update(
        u16::try_from(children.len())
            .unwrap_or_default()
            .to_le_bytes(),
    );
    hasher.update(object_count.to_le_bytes());
    for child in children {
        hasher.update(child.object_count.to_le_bytes());
        hasher.update(child.digest);
    }
    hasher.finalize().into()
}

fn encode_leaf(entries: &[ObjectWitness], digest: Sha384Digest) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(LEAF_MAGIC);
    bytes.extend_from_slice(
        &u16::try_from(entries.len())
            .unwrap_or_default()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&digest);
    for entry in entries {
        push_current_identity(&mut bytes, entry.object);
        bytes.extend_from_slice(&entry.digest);
    }
    bytes
}

fn encode_node(
    level: u16,
    object_count: u64,
    children: &[TreeSummary],
    digest: Sha384Digest,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(NODE_MAGIC);
    bytes.extend_from_slice(&level.to_le_bytes());
    bytes.extend_from_slice(
        &u16::try_from(children.len())
            .unwrap_or_default()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&object_count.to_le_bytes());
    bytes.extend_from_slice(&digest);
    for child in children {
        bytes.extend_from_slice(&child.object_count.to_le_bytes());
        bytes.extend_from_slice(&child.digest);
    }
    bytes
}

fn attestation_record(
    descriptor: RefineryPassDescriptorId,
    context: RefineryBatchContext,
    roots: &[ObjectId],
    tree: TreeSummary,
    public_key: [u8; 32],
    signature: [u8; 64],
) -> Result<ObjectRecord, ModelError> {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(ATTESTATION_MAGIC);
    canonical.extend_from_slice(&ED25519_SIGNATURE_ALGORITHM.to_le_bytes());
    canonical.extend_from_slice(&u16::try_from(roots.len()).unwrap_or_default().to_le_bytes());
    canonical.extend_from_slice(&tree.object_count.to_le_bytes());
    canonical.extend_from_slice(&context.placement_epoch().get().to_le_bytes());
    canonical.extend_from_slice(&tree.digest);
    push_current_identity(&mut canonical, descriptor.object_id());
    push_current_identity(&mut canonical, context.snapshot().object_id());
    for root in roots {
        push_current_identity(&mut canonical, *root);
    }
    canonical.extend_from_slice(&public_key);
    canonical.extend_from_slice(&signature);

    let mut references = Vec::new();
    references.push(ObjectReference::new(
        ReferenceLabel::new(PASS_DESCRIPTOR_LABEL.to_vec()),
        descriptor.object_id(),
        ReferenceKind::Evidence,
    ));
    references.push(ObjectReference::new(
        ReferenceLabel::new(SNAPSHOT_LABEL.to_vec()),
        context.snapshot().object_id(),
        ReferenceKind::Evidence,
    ));
    references.extend(roots.iter().enumerate().map(|(index, root)| {
        ObjectReference::new(
            indexed_label(ROOT_LABEL_PREFIX, index),
            *root,
            ReferenceKind::Evidence,
        )
    }));
    references.push(ObjectReference::owns(
        ReferenceLabel::new(TREE_LABEL.to_vec()),
        tree.id,
    ));
    evidence_record(canonical, references)
}

fn attestation_statement(
    descriptor: RefineryPassDescriptorId,
    context: RefineryBatchContext,
    roots: &[ObjectId],
    object_count: u64,
    tree_digest: Sha384Digest,
    public_key: [u8; 32],
) -> Vec<u8> {
    let mut statement = Vec::new();
    statement.extend_from_slice(STATEMENT_DOMAIN);
    push_current_identity(&mut statement, descriptor.object_id());
    push_current_identity(&mut statement, context.snapshot().object_id());
    statement.extend_from_slice(&context.placement_epoch().get().to_le_bytes());
    statement.extend_from_slice(&u16::try_from(roots.len()).unwrap_or_default().to_le_bytes());
    for root in roots {
        push_current_identity(&mut statement, *root);
    }
    statement.extend_from_slice(&object_count.to_le_bytes());
    statement.extend_from_slice(&tree_digest);
    statement.extend_from_slice(&ED25519_SIGNATURE_ALGORITHM.to_le_bytes());
    statement.extend_from_slice(&public_key);
    statement
}

fn update_record_envelope(hasher: &mut Sha384, record: &ObjectRecord) {
    hasher.update(record.kind().code().to_le_bytes());
    hasher.update(record.format_version().get().to_le_bytes());
    hasher.update([record.class().code()]);
    hasher.update(record.logical_bytes().to_le_bytes());
    hasher.update(
        u64::try_from(record.canonical_bytes().len())
            .unwrap_or_default()
            .to_le_bytes(),
    );
    hasher.update(record.canonical_bytes());
    hasher.update(
        u64::try_from(record.references().len())
            .unwrap_or_default()
            .to_le_bytes(),
    );
    for reference in record.references() {
        hasher.update(
            u64::try_from(reference.label().as_bytes().len())
                .unwrap_or_default()
                .to_le_bytes(),
        );
        hasher.update(reference.label().as_bytes());
        update_current_identity(hasher, reference.target());
        hasher.update([reference.kind().code()]);
    }
}

fn push_current_identity(bytes: &mut Vec<u8>, id: ObjectId) {
    bytes.extend_from_slice(&CURRENT_IDENTITY_ALGORITHM.to_le_bytes());
    bytes.extend_from_slice(&CURRENT_IDENTITY_CONSTRUCTION.to_le_bytes());
    bytes.extend_from_slice(&CURRENT_IDENTITY_LENGTH.to_le_bytes());
    bytes.extend_from_slice(id.as_bytes());
}

fn update_current_identity(hasher: &mut Sha384, id: ObjectId) {
    hasher.update(CURRENT_IDENTITY_ALGORITHM.to_le_bytes());
    hasher.update(CURRENT_IDENTITY_CONSTRUCTION.to_le_bytes());
    hasher.update(CURRENT_IDENTITY_LENGTH.to_le_bytes());
    hasher.update(id.as_bytes());
}

fn indexed_label(prefix: &[u8], index: usize) -> ReferenceLabel {
    let mut label = Vec::new();
    label.extend_from_slice(prefix);
    label.extend_from_slice(&u16::try_from(index).unwrap_or_default().to_be_bytes());
    ReferenceLabel::new(label)
}

fn unit_error<E>(error: Sha384AttestationError<Infallible>) -> Sha384AttestationError<E> {
    match error {
        Sha384AttestationError::NoRoots => Sha384AttestationError::NoRoots,
        Sha384AttestationError::NonCanonicalRoots => Sha384AttestationError::NonCanonicalRoots,
        Sha384AttestationError::NonCanonicalObjectOrder => {
            Sha384AttestationError::NonCanonicalObjectOrder
        },
        Sha384AttestationError::MissingObject(id) => Sha384AttestationError::MissingObject(id),
        Sha384AttestationError::ObjectCycle(id) => Sha384AttestationError::ObjectCycle(id),
        Sha384AttestationError::ExtraneousObject(id) => {
            Sha384AttestationError::ExtraneousObject(id)
        },
        Sha384AttestationError::ObjectIdentityMismatch(id) => {
            Sha384AttestationError::ObjectIdentityMismatch(id)
        },
        Sha384AttestationError::ResourceBudgetExceeded => {
            Sha384AttestationError::ResourceBudgetExceeded
        },
        Sha384AttestationError::ArithmeticOverflow => Sha384AttestationError::ArithmeticOverflow,
        Sha384AttestationError::InvalidEvidenceRecord(error) => {
            Sha384AttestationError::InvalidEvidenceRecord(error)
        },
        Sha384AttestationError::Proposal(error) => Sha384AttestationError::Proposal(error),
        Sha384AttestationError::NonCanonicalEvidence => {
            Sha384AttestationError::NonCanonicalEvidence
        },
        Sha384AttestationError::InvalidSignature => Sha384AttestationError::InvalidSignature,
        Sha384AttestationError::Signer(error) => match error {},
    }
}
