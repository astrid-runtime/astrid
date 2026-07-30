//! Selection coverage for known in-place format-1 RÚNATAL amendments.

use std::sync::Arc;

use astrid_storage_model::{ObjectId, ObjectIdentity};

use super::bootstrap;
use super::format_amendment::{
    DestinationFormat, PRE_COMPACTION_FORMAT_SPEC_ID, PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID,
    PRE_GC_OUTBOX_FORMAT_SPEC_ID, PRE_RUNATAL_NAMING_FORMAT_SPEC_ID, STORE_METADATA_FILE,
    format_spec_record, legacy_store_metadata, prepare_destination, store_metadata,
};
use super::{Blake3ObjectIdentityV1, KvQuotaResolver, StateOwner, open_runtime_kv};
use astrid_core::dirs::AstridHome;

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) => Some(u64::MAX),
        })
    })
}

#[tokio::test]
async fn completed_prior_v1_stores_are_selected_for_runatal_amendment() {
    for prior in [
        PRE_COMPACTION_FORMAT_SPEC_ID,
        PRE_GC_OUTBOX_FORMAT_SPEC_ID,
        PRE_RUNATAL_NAMING_FORMAT_SPEC_ID,
        PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID,
    ] {
        assert_prior_format_is_selected(prior, false).await;
    }
    assert_prior_format_is_selected(PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID, true).await;
}

async fn assert_prior_format_is_selected(prior: ObjectId, catalog_aware: bool) {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    store.close().await.unwrap();
    drop(store);

    let store_path = home.principal_store_path();
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    std::fs::write(
        store_path.join(STORE_METADATA_FILE),
        if catalog_aware {
            store_metadata(prior, catalog_spec_id)
        } else {
            legacy_store_metadata(prior)
        },
    )
    .unwrap();
    let current_spec = format_spec_record().unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&current_spec);
    let current_metadata = store_metadata(current_spec_id, catalog_spec_id);
    assert_eq!(
        prepare_destination(
            &store_path,
            &current_metadata,
            current_spec_id,
            catalog_spec_id,
        )
        .unwrap(),
        DestinationFormat::PriorV1(prior)
    );
}
