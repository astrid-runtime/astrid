//! Integration coverage for production retention and independently decoded compaction.

#![cfg(not(target_os = "windows"))]

use std::path::Path;
use std::sync::Arc;

use crate::engine::{
    CompactionFacts, CompactionProofVerifier, CompactionRetention, CompactionRootKind,
};
use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, RetentionPolicyId,
};
use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;

use super::bootstrap::RuntimeBootstrapObject;
use super::format_amendment::object_id_hex;
use super::{
    IdentityStore, KvIdentityStore, KvQuotaResolver, RuntimePrincipalStore, ScopedKvStore,
    StateOwner, open_runtime_principal_store,
};

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

async fn create_alice(store: &RuntimePrincipalStore) -> PrincipalUid {
    let identities = KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(store.kv(), "system:identity").unwrap(),
        store.principal_directory(),
    );
    let user = identities
        .create_principal(PrincipalId::new("alice").unwrap(), [0xA1; 32])
        .await
        .unwrap();
    identities
        .get_principal_identity(user.id)
        .await
        .unwrap()
        .unwrap()
        .uid
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
async fn production_retention_preserves_bootstraps_during_compaction() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let alice_uid = create_alice(&store).await;
    store
        .kv()
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    let (orphan, _) = store
        .engine
        .persist_standalone_object(&evidence(b"collect-me"))
        .unwrap();
    let bootstraps = RuntimeBootstrapObject::registered()
        .iter()
        .map(|bootstrap| {
            let record = bootstrap.record().unwrap();
            (store.engine.identify(&record), record)
        })
        .collect::<Vec<_>>();
    let format_spec_id = store.engine.identify(
        &RuntimeBootstrapObject::RunatalFormatSpecification
            .record()
            .unwrap(),
    );
    let policy = evidence(b"test-runtime-retention");
    let retention = store
        .prepare_compaction_retention(
            ObjectId::new([0xC0; 32]),
            RetentionPolicyId::new(store.engine.identify(&policy)),
            Vec::new(),
        )
        .await
        .unwrap();

    for (object, _) in &bootstraps {
        assert!(
            retention.additional_roots().iter().any(|root| {
                root.kind() == CompactionRootKind::System && root.object() == *object
            })
        );
    }
    let facts = store.engine.capture_compaction_facts(&retention).unwrap();
    assert!(facts.condemned().contains(&orphan));
    assert!(
        bootstraps
            .iter()
            .all(|(object, _)| !facts.condemned().contains(object))
    );
    let plan = store
        .engine
        .verify_compaction_plan(
            retention,
            facts,
            policy,
            evidence(b"test-tensor-logic-proof"),
            &AcceptCompactionProof,
        )
        .unwrap();
    store.engine.compact(&plan).unwrap();
    assert_eq!(store.engine.object(orphan).unwrap(), None);
    store.engine.close().unwrap();
    drop(store);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    for (object, record) in &bootstraps {
        assert_eq!(
            reopened.engine.object(*object).unwrap().as_ref(),
            Some(record)
        );
    }
    reopened.engine.close().unwrap();
    drop(reopened);

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py");
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
    assert_eq!(decoded["roots"][alice_uid.to_string()]["generation"], 0);
    assert_eq!(
        decoded["format_spec_object"],
        format!("1:1:32:{}", object_id_hex(format_spec_id))
    );
}

#[tokio::test]
async fn physical_profiles_and_runtime_retention_both_pin_bootstrap_dependencies() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    create_alice(&store).await;
    store
        .kv()
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    let format_spec = RuntimeBootstrapObject::RunatalFormatSpecification
        .record()
        .unwrap();
    let format_spec_id = store.engine.identify(&format_spec);
    let policy = evidence(b"test-policy-neutral-engine-retention");
    let raw_retention = CompactionRetention::new(
        ObjectId::new([0xC0; 32]),
        RetentionPolicyId::new(store.engine.identify(&policy)),
        [],
    );
    let facts = store
        .engine
        .capture_compaction_facts(&raw_retention)
        .unwrap();
    assert!(!facts.condemned().contains(&format_spec_id));
    // Physical profiles pin their own logical specification dependencies.
    // Runtime composition additionally keeps the engine private and exposes
    // the constructor below, which adds and verifies every registered System
    // root, including bootstraps not named by physical authority.

    let policy = evidence(b"subsequent-runtime-retention");
    let retention = store
        .prepare_compaction_retention(
            ObjectId::new([0xC0; 32]),
            RetentionPolicyId::new(store.engine.identify(&policy)),
            Vec::new(),
        )
        .await
        .unwrap();
    assert!(retention.additional_roots().iter().any(|root| {
        root.kind() == CompactionRootKind::System && root.object() == format_spec_id
    }));
    store.engine.close().unwrap();
}
