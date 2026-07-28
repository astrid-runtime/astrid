//! Integration coverage for compacted stores and the independent reader.

#![cfg(not(target_os = "windows"))]

use std::path::Path;
use std::sync::Arc;

use astrid_storage_engine::{
    CompactionFacts, CompactionProofVerifier, CompactionRetainedRoot, CompactionRetention,
    CompactionRootKind, RecoveryLimits,
};
use astrid_storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, RetentionPolicyId,
};

use super::format_amendment::format_spec_record;
use super::{
    Blake3ObjectIdentityV1, KvQuotaResolver, RuntimeEngine, StateOwner, StateOwnerCodecV1,
    open_runtime_kv,
};
use astrid_core::dirs::AstridHome;

struct AcceptCompactionProof;

impl CompactionProofVerifier for AcceptCompactionProof {
    fn verify(
        &self,
        facts: &CompactionFacts,
        _policy: &ObjectRecord,
        _proof: &ObjectRecord,
    ) -> bool {
        !facts.condemned().is_empty()
    }
}

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) => Some(u64::MAX),
        })
    })
}

fn evidence(bytes: &[u8]) -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        bytes.to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

#[tokio::test]
async fn independent_reader_accepts_a_compacted_root_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    store
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    store.close().await.unwrap();
    drop(store);

    let engine = RuntimeEngine::open(
        home.principal_store_path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV1,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    engine
        .persist_standalone_object(&evidence(b"collect-me"))
        .unwrap();
    let format_spec_id = engine.identify(&format_spec_record().unwrap());
    let policy = evidence(b"test-retain-current-roots-and-rosetta");
    let retention = CompactionRetention::new(
        ObjectId::new([0xC0; 32]),
        RetentionPolicyId::new(engine.identify(&policy)),
        [CompactionRetainedRoot::new(
            CompactionRootKind::System,
            format_spec_id,
        )],
    );
    let facts = engine.capture_compaction_facts(&retention).unwrap();
    let plan = engine
        .verify_compaction_plan(
            retention,
            facts,
            policy,
            evidence(b"test-tensor-logic-proof"),
            &AcceptCompactionProof,
        )
        .unwrap();
    engine.compact(&plan).unwrap();
    engine.close().unwrap();

    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/principal_store_v1_reader.py");
    let compacted = std::process::Command::new("python3")
        .arg(script)
        .arg(home.principal_store_path())
        .output()
        .unwrap();
    assert!(
        compacted.status.success(),
        "independent reader rejected compacted root snapshot: {}",
        String::from_utf8_lossy(&compacted.stderr)
    );
    let decoded: serde_json::Value = serde_json::from_slice(&compacted.stdout).unwrap();
    assert_eq!(decoded["roots"]["alice"]["generation"], 0);
}
