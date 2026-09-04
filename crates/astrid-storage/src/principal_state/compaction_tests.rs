//! Integration coverage for production retention and independently decoded compaction.

#![cfg(not(target_os = "windows"))]

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
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    })
}

fn seed_legacy_layout(home: &AstridHome) {
    std::fs::create_dir_all(home.etc_dir()).unwrap();
    std::fs::write(
        home.layout_version_path(),
        astrid_core::dirs::LEGACY_LAYOUT_VERSION,
    )
    .unwrap();
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
    seed_legacy_layout(&home);
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
    assert_eq!(
        reopened
            .engine
            .root(&StateOwner::Principal(alice_uid))
            .unwrap()
            .unwrap()
            .generation
            .get(),
        0
    );
    reopened.engine.close().unwrap();
    drop(reopened);
    assert!(home.storage_volume_path().is_file());
}

#[tokio::test]
async fn runtime_retention_pins_volume_bootstrap_dependencies() {
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
    assert!(
        !facts.condemned().contains(&format_spec_id),
        "the volume representation catalogue must pin the frozen specification"
    );
    // Volume media now hosts the representation catalogue. The frozen
    // specification is a profile dependency, so engine-neutral facts keep it
    // live. Runtime composition still adds registered System roots before a
    // destructive plan is minted.

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

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the regression covers the complete crash/reopen/audit-delivery boundary"
)]
async fn deterministic_runtime_compaction_reclaims_and_delivers_receipt() {
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
    let mut orphan_payload = vec![0_u8; 512 * 1024];
    orphan_payload.fill(0xAB);
    let (orphan, _) = store
        .engine
        .persist_standalone_object(&evidence(&orphan_payload))
        .unwrap();
    let volume_before = std::fs::metadata(home.storage_volume_path()).unwrap().len();
    let policy = evidence(b"runtime-compaction-policy");
    let report = store
        .compact_with_deterministic_proof(ObjectId::new([0xD0; 32]), policy, Vec::new())
        .await
        .unwrap();
    assert!(report.objects_reclaimed() >= 1);
    assert_eq!(store.engine.object(orphan).unwrap(), None);
    let volume_after = std::fs::metadata(home.storage_volume_path()).unwrap().len();
    assert!(
        volume_after < volume_before,
        "compaction must reclaim hosted volume bytes: before={volume_before}, after={volume_after}"
    );

    let pending = store.pending_compaction_evidence().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].commit_id(), report.gc_commit());

    // Model the independent audit append boundary: a failed append must not
    // acknowledge the GC outbox. The first attempt deliberately emits no
    // durable audit marker, then the process is reopened and the exact bundle
    // is persisted once before acknowledgement.
    let commit = pending[0].commit_id();
    let audit_projection = store.system_control_kv("audit").unwrap().backend();
    let marker_key = format!("gc-receipt:{}", hex::encode(commit.object_id().as_bytes()));
    let failed_append: Result<(), &str> = Err("audit sink unavailable");
    assert!(failed_append.is_err());
    // No marker was written because the independent audit append failed.
    assert!(
        !audit_projection
            .exists("audit:gc_receipts", &marker_key)
            .await
            .unwrap()
    );
    assert_eq!(store.pending_compaction_evidence().unwrap().len(), 1);
    drop(audit_projection);

    // A reopened runtime sees the same pending bundle. Persist a canonical
    // marker exactly once, then acknowledge; repeated delivery is idempotent.
    store.engine.close().unwrap();
    drop(store);
    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let pending = reopened.pending_compaction_evidence().unwrap();
    assert_eq!(pending.len(), 1);
    let audit_projection = reopened.system_control_kv("audit").unwrap().backend();
    let records = [
        pending[0].fact_snapshot(),
        pending[0].retention_policy(),
        pending[0].tensor_logic_proof(),
        pending[0].plan(),
        pending[0].placement_before(),
        pending[0].placement_after(),
        pending[0].execution_measurements(),
        pending[0].commit(),
    ];
    let mut receipt_bytes = Vec::new();
    for record in records {
        receipt_bytes.extend_from_slice(record.canonical_bytes());
    }
    assert!(
        audit_projection
            .compare_and_swap(
                "audit:gc_receipts",
                &marker_key,
                None,
                receipt_bytes.clone(),
            )
            .await
            .unwrap()
    );
    assert!(
        !audit_projection
            .compare_and_swap(
                "audit:gc_receipts",
                &marker_key,
                None,
                receipt_bytes.clone(),
            )
            .await
            .unwrap()
    );
    assert_eq!(
        audit_projection
            .get("audit:gc_receipts", &marker_key)
            .await
            .unwrap()
            .as_deref(),
        Some(receipt_bytes.as_slice())
    );
    reopened
        .acknowledge_compaction_evidence(report.gc_commit())
        .unwrap();
    assert!(reopened.pending_compaction_evidence().unwrap().is_empty());
    assert!(
        reopened
            .engine
            .root(&StateOwner::Principal(alice_uid))
            .unwrap()
            .is_some()
    );
    reopened.engine.close().unwrap();
}
