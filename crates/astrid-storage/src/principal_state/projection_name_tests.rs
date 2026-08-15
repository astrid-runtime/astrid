use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::ProjectionNamePolicyPreset;
use astrid_core::principal::PrincipalId;

use super::{RuntimePrincipalStore, StateOwner, open_runtime_principal_store};
use crate::content::ContentName;
use crate::identity::{IdentityStore, KvIdentityStore};
use crate::kv::{KvQuotaResolver, ScopedKvStore};

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    })
}

async fn create_principal(store: &RuntimePrincipalStore, alias: &str) -> StateOwner {
    let identities = KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(store.kv(), "system:identity").unwrap(),
        store.principal_directory(),
    );
    let principal = PrincipalId::new(alias).unwrap();
    let created = identities
        .create_principal(
            principal.clone(),
            *blake3::hash(alias.as_bytes()).as_bytes(),
        )
        .await
        .unwrap();
    let uid = identities
        .get_principal_identity(created.id)
        .await
        .unwrap()
        .unwrap()
        .uid;
    assert_eq!(
        store.principal_directory().uid_for(&principal).unwrap(),
        uid
    );
    StateOwner::Principal(uid)
}

#[tokio::test]
async fn projection_diagnostic_reads_only_the_selected_owner_catalog() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let alice = create_principal(&store, "alice").await;
    let bob = create_principal(&store, "bob").await;

    for source in ["Readme", "README"] {
        store
            .content()
            .put(
                &alice,
                &ContentName::new(source).unwrap(),
                source.as_bytes(),
            )
            .unwrap();
    }
    store
        .content()
        .put(
            &bob,
            &ContentName::new("private-to-bob").unwrap(),
            b"secret",
        )
        .unwrap();

    let report = store
        .projection_name_diagnostic(
            alice,
            ProjectionNamePolicyPreset::UnicodeCanonicalCaselessV1,
        )
        .await
        .unwrap();
    assert_eq!(report.catalog_entries, 2);
    assert_eq!(report.collisions.len(), 1);
    assert_eq!(
        report
            .collisions
            .iter()
            .flat_map(|collision| collision.sources.iter().map(String::as_str))
            .collect::<Vec<_>>(),
        ["README", "Readme"]
    );
    assert!(
        report
            .collisions
            .iter()
            .flat_map(|collision| &collision.sources)
            .all(|source| source != "private-to-bob")
    );
}
