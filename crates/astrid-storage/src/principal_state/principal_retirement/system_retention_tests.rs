//! System audit retention is independent of an executable UID's lifetime.
use std::sync::Arc;

use astrid_core::{PrincipalUid, dirs::AstridHome};

use crate::principal_state::{StateOwner, open_runtime_principal_store};
use crate::{ContentName, KvQuotaResolver};

#[tokio::test]
async fn principal_retirement_preserves_system_audit_bytes_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, Arc::clone(&quota))
        .await
        .unwrap();
    let uid = PrincipalUid::from_bytes([0x59; 32]);
    let audit = store.system_control_kv("audit").unwrap();
    let bytes = b"retained audit record referring to retired UID".to_vec();
    audit
        .set("principal-chain:entry", bytes.clone())
        .await
        .unwrap();
    store
        .content()
        .put(
            &StateOwner::Principal(uid),
            &ContentName::new("private").unwrap(),
            b"remove",
        )
        .unwrap();
    assert!(store.purge_principal_state(uid).unwrap());
    assert_eq!(
        audit.get("principal-chain:entry").await.unwrap(),
        Some(bytes.clone())
    );
    drop(audit);
    store.engine.close().unwrap();
    drop(store);
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    assert!(
        store
            .engine
            .root(&StateOwner::Principal(uid))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .system_control_kv("audit")
            .unwrap()
            .get("principal-chain:entry")
            .await
            .unwrap(),
        Some(bytes)
    );
    store.engine.close().unwrap();
}
