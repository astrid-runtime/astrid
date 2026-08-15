//! Admission and archival verification for SHA-384 closure evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord,
    ReferenceKind,
};

use super::{
    ATTESTATION_MAGIC, CHILD_LABEL_PREFIX, CrossHashAttestation, CrossHashVerifier,
    ED25519_SIGNATURE_ALGORITHM, LEAF_MAGIC, MAX_TREE_LEVEL, NODE_MAGIC, ObjectWitness,
    PASS_DESCRIPTOR_LABEL, ROOT_LABEL_PREFIX, RefineryBatchContext, RefineryPassDescriptorId,
    SNAPSHOT_LABEL, SOURCE_LABEL_PREFIX, Sha384AttestationError, Sha384Digest, TREE_FANOUT,
    TREE_LABEL, TreeBuilder, TreeSummary, attestation_statement, indexed_label, leaf_digest,
    node_digest, object_digest, owning_closure, validate_roots,
};

/// Verify a canonical SHA-384 evidence tree and its ceremony signature.
///
/// `records` must contain the attestation, its Evidence tree, and every source
/// object named by the exact selected root closure. This is also the semantic
/// source for an optional archival manifest; no second hash pipeline is
/// required.
///
/// # Errors
///
/// Returns a typed canonical-form, closure, identity, digest, or signature
/// failure.
pub fn verify_sha384_attestation<I, V>(
    identity: &I,
    verifier: &V,
    attestation: ObjectId,
    records: &BTreeMap<ObjectId, ObjectRecord>,
) -> Result<CrossHashAttestation, Sha384AttestationError<Infallible>>
where
    I: ObjectIdentity,
    V: CrossHashVerifier,
{
    let attestation_record = verified_record(identity, records, attestation)?;
    let decoded = decode_attestation(attestation_record)?;
    let statement = attestation_statement(
        decoded.descriptor,
        RefineryBatchContext::new(
            decoded.snapshot,
            crate::storage_model::PlacementEpoch::new(decoded.placement_epoch),
            super::super::RefineryResourceBudget::new(0, 0, 0, 0, 0, 0),
            None,
        ),
        &decoded.roots,
        decoded.object_count,
        decoded.tree_digest,
        decoded.public_key,
    );
    if !verifier.verify(
        decoded.descriptor,
        &decoded.public_key,
        &statement,
        &decoded.signature,
    ) {
        return Err(Sha384AttestationError::InvalidSignature);
    }
    let mut witnesses = Vec::new();
    decode_tree(
        identity,
        records,
        decoded.tree,
        &mut witnesses,
        MAX_TREE_LEVEL,
    )?;
    if witnesses
        .windows(2)
        .any(|pair| pair[0].object >= pair[1].object)
    {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    let object_count =
        u64::try_from(witnesses.len()).map_err(|_| Sha384AttestationError::ArithmeticOverflow)?;
    if object_count != decoded.object_count {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    validate_witness_closure(records, &decoded.roots, &witnesses)?;
    let mut rebuilt = TreeBuilder::new(identity);
    for witness in witnesses {
        rebuilt
            .push(witness)
            .map_err(Sha384AttestationError::InvalidEvidenceRecord)?;
        rebuilt.drain_emitted().for_each(drop);
    }
    let rebuilt = rebuilt.finish()?;
    if rebuilt.id != decoded.tree
        || rebuilt.digest != decoded.tree_digest
        || rebuilt.object_count != decoded.object_count
    {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    Ok(decoded)
}

fn validate_witness_closure(
    records: &BTreeMap<ObjectId, ObjectRecord>,
    roots: &[ObjectId],
    witnesses: &[ObjectWitness],
) -> Result<(), Sha384AttestationError<Infallible>> {
    validate_roots(roots)?;
    let sources = witnesses
        .iter()
        .map(|witness| witness.object)
        .collect::<BTreeSet<_>>();
    let source_records = records
        .iter()
        .filter(|(id, _)| sources.contains(id))
        .map(|(id, record)| (*id, record))
        .collect::<BTreeMap<_, _>>();
    let closure = owning_closure(&source_records, roots)?;
    if closure != sources {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    Ok(())
}

fn verified_record<'a, I>(
    identity: &I,
    records: &'a BTreeMap<ObjectId, ObjectRecord>,
    id: ObjectId,
) -> Result<&'a ObjectRecord, Sha384AttestationError<Infallible>>
where
    I: ObjectIdentity,
{
    let record = records
        .get(&id)
        .ok_or(Sha384AttestationError::MissingObject(id))?;
    if identity.identify(record) != id {
        return Err(Sha384AttestationError::ObjectIdentityMismatch(id));
    }
    Ok(record)
}

fn decode_tree<I>(
    identity: &I,
    records: &BTreeMap<ObjectId, ObjectRecord>,
    id: ObjectId,
    witnesses: &mut Vec<ObjectWitness>,
    remaining_level: u16,
) -> Result<TreeSummary, Sha384AttestationError<Infallible>>
where
    I: ObjectIdentity,
{
    let record = verified_record(identity, records, id)?;
    require_evidence_shape(record)?;
    if record.canonical_bytes().starts_with(LEAF_MAGIC) {
        let entries = decode_leaf(record)?;
        for entry in &entries {
            let source = verified_record(identity, records, entry.object)?;
            if object_digest(entry.object, source) != entry.digest {
                return Err(Sha384AttestationError::NonCanonicalEvidence);
            }
        }
        let digest = leaf_digest(&entries);
        witnesses.extend(entries.iter().copied());
        return Ok(TreeSummary {
            id,
            digest,
            object_count: u64::try_from(entries.len())
                .map_err(|_| Sha384AttestationError::ArithmeticOverflow)?,
            level: 0,
        });
    }
    if !record.canonical_bytes().starts_with(NODE_MAGIC) || remaining_level == 0 {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    let node = decode_node(record)?;
    if node.level > remaining_level || node.level == 0 {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    let child_level = node
        .level
        .checked_sub(1)
        .ok_or(Sha384AttestationError::NonCanonicalEvidence)?;
    let mut children = Vec::with_capacity(node.children.len());
    for child in node.children {
        let summary = decode_tree(identity, records, child, witnesses, child_level)?;
        if summary.level.checked_add(1) != Some(node.level) {
            return Err(Sha384AttestationError::NonCanonicalEvidence);
        }
        children.push(summary);
    }
    let object_count = children.iter().try_fold(0_u64, |total, child| {
        total
            .checked_add(child.object_count)
            .ok_or(Sha384AttestationError::ArithmeticOverflow)
    })?;
    let digest = node_digest(node.level, object_count, &children);
    if object_count != node.object_count || digest != node.digest {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    Ok(TreeSummary {
        id,
        digest,
        object_count,
        level: node.level,
    })
}

#[derive(Clone, Debug)]
struct DecodedNode {
    level: u16,
    object_count: u64,
    digest: Sha384Digest,
    children: Vec<ObjectId>,
}

fn decode_leaf(
    record: &ObjectRecord,
) -> Result<Vec<ObjectWitness>, Sha384AttestationError<Infallible>> {
    let mut cursor = Cursor::new(record.canonical_bytes());
    cursor.require(LEAF_MAGIC)?;
    let count = usize::from(cursor.u16()?);
    let declared_digest = cursor.array::<48>()?;
    if count == 0 || count > TREE_FANOUT || record.references().len() != count {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    let mut entries = Vec::with_capacity(count);
    for (index, reference) in record.references().iter().enumerate() {
        let object = cursor.current_identity()?;
        let digest = cursor.array::<48>()?;
        if reference.label() != &indexed_label(SOURCE_LABEL_PREFIX, index)
            || reference.target() != object
            || reference.kind() != ReferenceKind::Evidence
        {
            return Err(Sha384AttestationError::NonCanonicalEvidence);
        }
        entries.push(ObjectWitness { object, digest });
    }
    cursor.done()?;
    if entries
        .windows(2)
        .any(|pair| pair[0].object >= pair[1].object)
        || leaf_digest(&entries) != declared_digest
    {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    Ok(entries)
}

fn decode_node(record: &ObjectRecord) -> Result<DecodedNode, Sha384AttestationError<Infallible>> {
    let mut cursor = Cursor::new(record.canonical_bytes());
    cursor.require(NODE_MAGIC)?;
    let level = cursor.u16()?;
    let count = usize::from(cursor.u16()?);
    let object_count = cursor.u64()?;
    let digest = cursor.array::<48>()?;
    if level == 0
        || level > MAX_TREE_LEVEL
        || count == 0
        || count > TREE_FANOUT
        || record.references().len() != count
    {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    let child_level = level
        .checked_sub(1)
        .ok_or(Sha384AttestationError::NonCanonicalEvidence)?;
    let mut declared_children = Vec::with_capacity(count);
    let mut children = Vec::with_capacity(count);
    for (index, reference) in record.references().iter().enumerate() {
        let child_objects = cursor.u64()?;
        let child_digest = cursor.array::<48>()?;
        if child_objects == 0
            || reference.label() != &indexed_label(CHILD_LABEL_PREFIX, index)
            || reference.kind() != ReferenceKind::Owns
        {
            return Err(Sha384AttestationError::NonCanonicalEvidence);
        }
        declared_children.push((child_objects, child_digest));
        children.push(reference.target());
    }
    cursor.done()?;
    let summaries = declared_children
        .iter()
        .zip(&children)
        .map(|((count, digest), id)| TreeSummary {
            id: *id,
            digest: *digest,
            object_count: *count,
            level: child_level,
        })
        .collect::<Vec<_>>();
    if node_digest(level, object_count, &summaries) != digest {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    Ok(DecodedNode {
        level,
        object_count,
        digest,
        children,
    })
}

fn decode_attestation(
    record: &ObjectRecord,
) -> Result<CrossHashAttestation, Sha384AttestationError<Infallible>> {
    require_evidence_shape(record)?;
    let mut cursor = Cursor::new(record.canonical_bytes());
    cursor.require(ATTESTATION_MAGIC)?;
    if cursor.u16()? != ED25519_SIGNATURE_ALGORITHM {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    let root_count = usize::from(cursor.u16()?);
    let object_count = cursor.u64()?;
    let placement_epoch = cursor.u64()?;
    let tree_digest = cursor.array::<48>()?;
    let descriptor = RefineryPassDescriptorId::new(cursor.current_identity()?);
    let snapshot = super::super::RefinerySnapshotId::new(cursor.current_identity()?);
    let mut roots = Vec::with_capacity(root_count);
    for _ in 0..root_count {
        roots.push(cursor.current_identity()?);
    }
    let public_key = cursor.array::<32>()?;
    let signature = cursor.array::<64>()?;
    cursor.done()?;
    validate_roots(&roots)?;
    let expected_references = root_count
        .checked_add(3)
        .ok_or(Sha384AttestationError::ArithmeticOverflow)?;
    if object_count == 0 || root_count == 0 || record.references().len() != expected_references {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    let descriptor_ref = &record.references()[0];
    let snapshot_ref = &record.references()[1];
    if descriptor_ref.label().as_bytes() != PASS_DESCRIPTOR_LABEL
        || descriptor_ref.target() != descriptor.object_id()
        || descriptor_ref.kind() != ReferenceKind::Evidence
        || snapshot_ref.label().as_bytes() != SNAPSHOT_LABEL
        || snapshot_ref.target() != snapshot.object_id()
        || snapshot_ref.kind() != ReferenceKind::Evidence
    {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    for (index, root) in roots.iter().enumerate() {
        let reference_index = index
            .checked_add(2)
            .ok_or(Sha384AttestationError::ArithmeticOverflow)?;
        let reference = record
            .references()
            .get(reference_index)
            .ok_or(Sha384AttestationError::NonCanonicalEvidence)?;
        if reference.label() != &indexed_label(ROOT_LABEL_PREFIX, index)
            || reference.target() != *root
            || reference.kind() != ReferenceKind::Evidence
        {
            return Err(Sha384AttestationError::NonCanonicalEvidence);
        }
    }
    let tree_ref = record
        .references()
        .last()
        .ok_or(Sha384AttestationError::NonCanonicalEvidence)?;
    if tree_ref.label().as_bytes() != TREE_LABEL || tree_ref.kind() != ReferenceKind::Owns {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    Ok(CrossHashAttestation {
        descriptor,
        snapshot,
        placement_epoch,
        roots,
        object_count,
        tree_digest,
        tree: tree_ref.target(),
        public_key,
        signature,
    })
}

fn require_evidence_shape(record: &ObjectRecord) -> Result<(), Sha384AttestationError<Infallible>> {
    if record.kind() != ObjectKind::Evidence
        || record.format_version() != ObjectFormatVersion::V1
        || record.class() != ObjectClass::Metadata
        || record.logical_bytes() != 0
    {
        return Err(Sha384AttestationError::NonCanonicalEvidence);
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Sha384AttestationError<Infallible>> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Sha384AttestationError::NonCanonicalEvidence)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Sha384AttestationError::NonCanonicalEvidence)?;
        self.offset = end;
        Ok(value)
    }

    fn require(&mut self, expected: &[u8]) -> Result<(), Sha384AttestationError<Infallible>> {
        if self.take(expected.len())? != expected {
            return Err(Sha384AttestationError::NonCanonicalEvidence);
        }
        Ok(())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Sha384AttestationError<Infallible>> {
        self.take(N)?
            .try_into()
            .map_err(|_| Sha384AttestationError::NonCanonicalEvidence)
    }

    fn u16(&mut self) -> Result<u16, Sha384AttestationError<Infallible>> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, Sha384AttestationError<Infallible>> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, Sha384AttestationError<Infallible>> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn current_identity(&mut self) -> Result<ObjectId, Sha384AttestationError<Infallible>> {
        if self.u16()? != super::CURRENT_IDENTITY_ALGORITHM
            || self.u16()? != super::CURRENT_IDENTITY_CONSTRUCTION
            || self.u32()? != super::CURRENT_IDENTITY_LENGTH
        {
            return Err(Sha384AttestationError::NonCanonicalEvidence);
        }
        Ok(ObjectId::new(self.array()?))
    }

    fn done(self) -> Result<(), Sha384AttestationError<Infallible>> {
        if self.offset != self.bytes.len() {
            return Err(Sha384AttestationError::NonCanonicalEvidence);
        }
        Ok(())
    }
}
