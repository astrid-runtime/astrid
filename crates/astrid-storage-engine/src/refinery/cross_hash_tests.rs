use std::collections::BTreeMap;
use std::convert::Infallible;

use astrid_storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord,
    ObjectReference, PlacementEpoch, ReferenceKind, ReferenceLabel,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::{
    CrossHashSigner, CrossHashVerifier, RefineryBatchContext, RefineryPassDescriptorId,
    RefineryResourceBudget, RefinerySnapshotId, Sha384AttestationError, attest_sha384_closure,
    verify_sha384_attestation,
};

#[derive(Clone, Copy)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher =
            blake3::Hasher::new_derive_key("astrid principal store object identity v1");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hasher.update(
            &u128::try_from(record.canonical_bytes().len())
                .unwrap()
                .to_le_bytes(),
        );
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        hasher.update(&[record.class().code()]);
        hasher.update(
            &u128::try_from(record.references().len())
                .unwrap()
                .to_le_bytes(),
        );
        for reference in record.references() {
            hasher.update(
                &u128::try_from(reference.label().as_bytes().len())
                    .unwrap()
                    .to_le_bytes(),
            );
            hasher.update(reference.label().as_bytes());
            hasher.update(reference.target().as_bytes());
            hasher.update(&[reference.kind().code()]);
        }
        ObjectId::new(*hasher.finalize().as_bytes())
    }
}

struct TestAuthority(SigningKey);

impl TestAuthority {
    fn fixed() -> Self {
        Self(SigningKey::from_bytes(&[37; 32]))
    }
}

impl CrossHashSigner for TestAuthority {
    type Error = Infallible;

    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    fn sign(&self, statement: &[u8]) -> Result<[u8; 64], Self::Error> {
        Ok(self.0.sign(statement).to_bytes())
    }
}

struct TestVerifier;

impl CrossHashVerifier for TestVerifier {
    fn verify(
        &self,
        _descriptor: RefineryPassDescriptorId,
        public_key: &[u8; 32],
        statement: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        VerifyingKey::from_bytes(public_key)
            .and_then(|key| key.verify_strict(statement, &Signature::from_bytes(signature)))
            .is_ok()
    }
}

fn source_closure() -> (ObjectId, Vec<(ObjectId, ObjectRecord)>) {
    let identity = TestIdentity;
    let mut children = Vec::new();
    for value in 0_u16..130 {
        let record = ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            value.to_le_bytes().to_vec(),
            Vec::new(),
            2,
            ObjectClass::Data,
        )
        .unwrap();
        children.push((identity.identify(&record), record));
    }
    let references = children
        .iter()
        .enumerate()
        .map(|(index, (id, _))| {
            ObjectReference::new(
                ReferenceLabel::new(u16::try_from(index).unwrap().to_be_bytes().to_vec()),
                *id,
                ReferenceKind::Owns,
            )
        })
        .collect();
    let root_record = ObjectRecord::new(
        ObjectKind::Directory,
        ObjectFormatVersion::V1,
        b"test-root".to_vec(),
        references,
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let root = identity.identify(&root_record);
    children.push((root, root_record));
    children.sort_by_key(|(id, _)| *id);
    (root, children)
}

fn context() -> RefineryBatchContext {
    RefineryBatchContext::new(
        RefinerySnapshotId::new(ObjectId::new([11; 32])),
        PlacementEpoch::new(19),
        RefineryResourceBudget::new(u64::MAX, u128::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        None,
    )
}

fn records_with_attestation(
    source: &[(ObjectId, ObjectRecord)],
) -> (ObjectId, BTreeMap<ObjectId, ObjectRecord>) {
    let identity = TestIdentity;
    let root = source
        .iter()
        .find(|(_, record)| record.kind() == ObjectKind::Directory)
        .map(|(id, _)| *id)
        .unwrap();
    let outputs = attest_sha384_closure(
        &identity,
        &TestAuthority::fixed(),
        RefineryPassDescriptorId::new(ObjectId::new([10; 32])),
        context(),
        &[root],
        source,
    )
    .unwrap();
    let mut records = source.iter().cloned().collect::<BTreeMap<_, _>>();
    let mut attestation = None;
    for output in outputs {
        let record = output.record().clone();
        let id = identity.identify(&record);
        attestation = Some(id);
        records.insert(id, record);
    }
    (attestation.unwrap(), records)
}

#[test]
fn cross_hash_evidence_is_deterministic_and_independently_verifiable() {
    let (root, source) = source_closure();
    let first = attest_sha384_closure(
        &TestIdentity,
        &TestAuthority::fixed(),
        RefineryPassDescriptorId::new(ObjectId::new([10; 32])),
        context(),
        &[root],
        &source,
    )
    .unwrap();
    let second = attest_sha384_closure(
        &TestIdentity,
        &TestAuthority::fixed(),
        RefineryPassDescriptorId::new(ObjectId::new([10; 32])),
        context(),
        &[root],
        &source,
    )
    .unwrap();
    assert_eq!(first, second);

    let (attestation, records) = records_with_attestation(&source);
    let verified =
        verify_sha384_attestation(&TestIdentity, &TestVerifier, attestation, &records).unwrap();
    assert_eq!(verified.roots(), &[root]);
    assert_eq!(verified.object_count(), 131);
    assert_eq!(verified.placement_epoch(), 19);
}

#[test]
fn cross_hash_builder_rejects_reorder_omission_and_unrelated_objects() {
    let (root, mut source) = source_closure();
    source.swap(0, 1);
    assert_eq!(
        attest_sha384_closure(
            &TestIdentity,
            &TestAuthority::fixed(),
            RefineryPassDescriptorId::new(ObjectId::new([10; 32])),
            context(),
            &[root],
            &source,
        ),
        Err(Sha384AttestationError::NonCanonicalObjectOrder)
    );

    let (_, mut source) = source_closure();
    source.remove(0);
    assert!(matches!(
        attest_sha384_closure(
            &TestIdentity,
            &TestAuthority::fixed(),
            RefineryPassDescriptorId::new(ObjectId::new([10; 32])),
            context(),
            &[root],
            &source,
        ),
        Err(Sha384AttestationError::MissingObject(_))
    ));

    let (_, mut source) = source_closure();
    let unrelated = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"unrelated".to_vec(),
        Vec::new(),
        9,
        ObjectClass::Data,
    )
    .unwrap();
    source.push((TestIdentity.identify(&unrelated), unrelated));
    source.sort_by_key(|(id, _)| *id);
    assert!(matches!(
        attest_sha384_closure(
            &TestIdentity,
            &TestAuthority::fixed(),
            RefineryPassDescriptorId::new(ObjectId::new([10; 32])),
            context(),
            &[root],
            &source,
        ),
        Err(Sha384AttestationError::ExtraneousObject(_))
    ));
}

#[test]
fn verifier_rejects_source_substitution_omission_root_change_and_digest_tamper() {
    let (root, source) = source_closure();
    let (attestation, records) = records_with_attestation(&source);

    let source_id = source[0].0;
    let mut substituted = records.clone();
    substituted.insert(
        source_id,
        ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            b"substituted".to_vec(),
            Vec::new(),
            11,
            ObjectClass::Data,
        )
        .unwrap(),
    );
    assert!(matches!(
        verify_sha384_attestation(&TestIdentity, &TestVerifier, attestation, &substituted),
        Err(Sha384AttestationError::ObjectIdentityMismatch(id)) if id == source_id
    ));

    let mut omitted = records.clone();
    omitted.remove(&source_id);
    assert!(matches!(
        verify_sha384_attestation(&TestIdentity, &TestVerifier, attestation, &omitted),
        Err(Sha384AttestationError::MissingObject(id)) if id == source_id
    ));

    let original = records.get(&attestation).unwrap();
    let mut changed_references = original.references().to_vec();
    changed_references[2] = ObjectReference::new(
        changed_references[2].label().clone(),
        source_id,
        ReferenceKind::Evidence,
    );
    let changed_root = ObjectRecord::new(
        original.kind(),
        original.format_version(),
        original.canonical_bytes().to_vec(),
        changed_references,
        original.logical_bytes(),
        original.class(),
    )
    .unwrap();
    let changed_root_id = TestIdentity.identify(&changed_root);
    let mut changed_root_records = records.clone();
    changed_root_records.insert(changed_root_id, changed_root);
    assert!(matches!(
        verify_sha384_attestation(
            &TestIdentity,
            &TestVerifier,
            changed_root_id,
            &changed_root_records,
        ),
        Err(Sha384AttestationError::NonCanonicalEvidence)
    ));

    let mut canonical = original.canonical_bytes().to_vec();
    canonical[64] ^= 1;
    let tampered = ObjectRecord::new(
        original.kind(),
        original.format_version(),
        canonical,
        original.references().to_vec(),
        original.logical_bytes(),
        original.class(),
    )
    .unwrap();
    let tampered_id = TestIdentity.identify(&tampered);
    let mut tampered_records = records;
    tampered_records.insert(tampered_id, tampered);
    assert!(matches!(
        verify_sha384_attestation(&TestIdentity, &TestVerifier, tampered_id, &tampered_records,),
        Err(Sha384AttestationError::InvalidSignature | Sha384AttestationError::NonCanonicalEvidence)
    ));
    assert_ne!(root, source_id);
}
