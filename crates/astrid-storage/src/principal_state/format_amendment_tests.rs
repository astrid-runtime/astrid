//! Cross-implementation fixtures for the format-v1 derivation amendment.

#![cfg(not(target_os = "windows"))]

use std::path::{Path, PathBuf};

use astrid_storage_content::{ChunkingProfile, build_content};
use astrid_storage_engine::{
    BottomKSketchDescriptor, CrossHashSigner, RecoveryLimits, RefineryBatchContext,
    RefineryPassDescriptorId, RefineryResourceBudget, RefinerySnapshotId, attest_sha384_closure,
    build_bottom_k_sketch,
};
use astrid_storage_model::{
    AuthorityEpochId, CanonicalParametersId, ComputationSharingDomainId, DerivationContractId,
    DerivationEvidence, DerivationInvocation, DerivationOutput, DeterministicSeedId, EngineBuildId,
    ExecutionClass, ExecutionMeasurementsId, GcCommitEvidence, GcFactSnapshotId, GcPlanEvidence,
    HostFunctionSemanticBinding, InvocationInput, ObjectClass, ObjectFormatVersion, ObjectId,
    ObjectIdentity, ObjectKind, ObjectRecord, OutputContractId, PlacementSetId, RetentionPolicyId,
    RuntimeSemanticProfile, SemanticContractId, TensorLogicProofId, TransformId,
    VerifierEvidenceId,
};
use ed25519_dalek::{Signer, SigningKey};

use super::bootstrap;
use super::format_amendment::{STORE_METADATA_FILE, format_spec_record, store_metadata};
use super::{Blake3ObjectIdentityV1, RuntimeEngine, StateOwnerCodecV1};

fn id(value: u8) -> ObjectId {
    ObjectId::new([value; 32])
}

fn semantic(value: u8) -> SemanticContractId {
    SemanticContractId::new(id(value))
}

fn reader() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py")
}

fn open_fixture_store(path: &Path) -> RuntimeEngine {
    let engine = RuntimeEngine::open(
        path,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let specification = format_spec_record().unwrap();
    let specification_id = Blake3ObjectIdentityV1.identify(&specification);
    engine.persist_standalone_object(&specification).unwrap();
    let catalog_specification = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_specification_id = Blake3ObjectIdentityV1.identify(&catalog_specification);
    engine
        .persist_standalone_object(&catalog_specification)
        .unwrap();
    std::fs::write(
        path.join(STORE_METADATA_FILE),
        store_metadata(specification_id, catalog_specification_id),
    )
    .unwrap();
    engine
}

fn amendment_records() -> Vec<ObjectRecord> {
    let profile = RuntimeSemanticProfile::new(
        semantic(1),
        Some(semantic(2)),
        vec![semantic(3), semantic(4)],
        vec![
            HostFunctionSemanticBinding::new(b"astrid:content/read@1".to_vec(), semantic(5))
                .unwrap(),
            HostFunctionSemanticBinding::new(b"astrid:output/write@1".to_vec(), semantic(6))
                .unwrap(),
        ],
        semantic(7),
        semantic(8),
        semantic(9),
    )
    .unwrap();
    let profile_record = profile.to_object_record().unwrap();
    let profile_id = profile.identify(&Blake3ObjectIdentityV1).unwrap();

    let invocation = DerivationInvocation::new(
        ExecutionClass::Pure,
        TransformId::new(id(10)),
        DerivationContractId::new(id(11)),
        vec![InvocationInput::new(b"source".to_vec(), id(12)).unwrap()],
        CanonicalParametersId::new(id(13)),
        profile_id,
        OutputContractId::new(id(14)),
        None,
        Some(DeterministicSeedId::new(id(15))),
    )
    .unwrap();
    let invocation_record = invocation.to_object_record().unwrap();
    let invocation_id = invocation.identify(&Blake3ObjectIdentityV1).unwrap();

    let evidence = DerivationEvidence::new(
        invocation_id,
        &invocation,
        EngineBuildId::new(id(20)),
        vec![DerivationOutput::new(b"artifact".to_vec(), id(21)).unwrap()],
        ExecutionMeasurementsId::new(id(22)),
        Some(VerifierEvidenceId::new(id(23))),
        AuthorityEpochId::new(id(24)),
        ComputationSharingDomainId::new(id(25)),
    )
    .unwrap();

    let plan = GcPlanEvidence::new(
        GcFactSnapshotId::new(id(30)),
        RetentionPolicyId::new(id(31)),
        TensorLogicProofId::new(id(32)),
        vec![id(40), id(41)],
    )
    .unwrap();
    let receipt = GcCommitEvidence::new(
        &Blake3ObjectIdentityV1,
        &plan,
        plan.snapshot(),
        PlacementSetId::new(id(50)),
        PlacementSetId::new(id(51)),
        ExecutionMeasurementsId::new(id(52)),
    )
    .unwrap();

    vec![
        profile_record,
        invocation_record,
        evidence.to_object_record().unwrap(),
        plan.to_object_record().unwrap(),
        receipt.to_object_record().unwrap(),
    ]
}

struct FixedCrossHashAuthority(SigningKey);

impl CrossHashSigner for FixedCrossHashAuthority {
    type Error = std::convert::Infallible;

    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    fn sign(&self, statement: &[u8]) -> Result<[u8; 64], Self::Error> {
        Ok(self.0.sign(statement).to_bytes())
    }
}

fn cross_hash_records() -> Vec<ObjectRecord> {
    let source = ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        b"independent SHA-384 reader fixture".to_vec(),
        Vec::new(),
        37,
        ObjectClass::Data,
    )
    .unwrap();
    let source_id = Blake3ObjectIdentityV1.identify(&source);
    let authority = FixedCrossHashAuthority(SigningKey::from_bytes(&[37; 32]));
    let context = RefineryBatchContext::new(
        RefinerySnapshotId::new(id(80)),
        astrid_storage_model::PlacementEpoch::new(81),
        RefineryResourceBudget::new(u64::MAX, u128::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        None,
    );
    let mut records = vec![source.clone()];
    records.extend(
        attest_sha384_closure(
            &Blake3ObjectIdentityV1,
            &authority,
            RefineryPassDescriptorId::new(id(82)),
            context,
            &[source_id],
            &[(source_id, source)],
        )
        .unwrap()
        .into_iter()
        .map(|output| output.record().clone()),
    );
    records
}

fn bottom_k_records() -> Vec<ObjectRecord> {
    let built = build_content(
        &Blake3ObjectIdentityV1,
        ChunkingProfile::ASTRID_V1,
        &vec![0x41; 600 * 1024],
    )
    .unwrap();
    let descriptor = BottomKSketchDescriptor::ASTRID_V1;
    let output = build_bottom_k_sketch(
        &Blake3ObjectIdentityV1,
        descriptor,
        RefineryBatchContext::new(
            RefinerySnapshotId::new(id(90)),
            astrid_storage_model::PlacementEpoch::new(91),
            RefineryResourceBudget::new(
                u64::MAX,
                u128::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            ),
            None,
        ),
        built.descriptor().file(),
        built.records(),
    )
    .unwrap();
    let mut records = vec![descriptor.record().unwrap()];
    records.extend(built.into_records().into_iter().map(|(_, record)| record));
    records.extend(output.into_iter().map(|proposal| proposal.record().clone()));
    records
}

#[test]
fn independent_reader_decodes_all_derivation_amendment_schemas() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open_fixture_store(directory.path());
    let mut records = amendment_records();
    records.extend(cross_hash_records());
    records.extend(bottom_k_records());
    engine.stage_objects(records).unwrap();
    engine.close().unwrap();

    let output = std::process::Command::new("python3")
        .arg(reader())
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent reader rejected Rust fixtures: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let kinds: Vec<_> = decoded["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|object| object["kind"].as_str())
        .collect();
    for expected in [
        "RuntimeSemanticProfile",
        "DerivationInvocation",
        "DerivationEvidence",
        "GcPlanEvidence",
        "GcCommitEvidence",
        "Derived",
    ] {
        assert!(
            kinds.contains(&expected),
            "missing decoded {expected} fixture"
        );
    }
}

#[test]
fn independent_reader_rejects_recomputed_bottom_k_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open_fixture_store(directory.path());
    let mut records = bottom_k_records();
    let sketch = records
        .iter()
        .find(|record| {
            record.kind() == ObjectKind::Derived
                && record
                    .canonical_bytes()
                    .starts_with(b"astrid-bottom-k-sketch-v1\0")
        })
        .unwrap();
    let mut changed = sketch.canonical_bytes().to_vec();
    *changed.last_mut().unwrap() ^= 1;
    records.push(
        ObjectRecord::new(
            sketch.kind(),
            sketch.format_version(),
            changed,
            sketch.references().to_vec(),
            sketch.logical_bytes(),
            sketch.class(),
        )
        .unwrap(),
    );
    engine.stage_objects(records).unwrap();
    engine.close().unwrap();

    let output = std::process::Command::new("python3")
        .arg(reader())
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "independent reader accepted an identity-consistent sketch mismatch"
    );
}

#[test]
fn independent_reader_rejects_malformed_fixture_for_every_amendment_schema() {
    let malformed = [
        (ObjectKind::RuntimeSemanticProfile, vec![0]),
        (ObjectKind::DerivationInvocation, Vec::new()),
        (ObjectKind::DerivationEvidence, vec![0, 0]),
        (ObjectKind::GcPlanEvidence, Vec::new()),
        (ObjectKind::GcCommitEvidence, Vec::new()),
    ];
    for (kind, canonical) in malformed {
        let directory = tempfile::tempdir().unwrap();
        let engine = open_fixture_store(directory.path());
        let record = ObjectRecord::new(
            kind,
            ObjectFormatVersion::V1,
            canonical,
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        engine.persist_standalone_object(&record).unwrap();
        engine.close().unwrap();

        let output = std::process::Command::new("python3")
            .arg(reader())
            .arg(directory.path())
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "independent reader accepted identity-consistent malformed {kind:?}"
        );
    }
}
