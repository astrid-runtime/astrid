//! Selection coverage for known in-place format-1 RÚNATAL amendments.

use std::sync::Arc;

use astrid_storage_model::{ObjectId, ObjectIdentity};

use super::bootstrap;
use super::format_amendment::{
    DestinationFormat, PRE_BOTTOM_K_SKETCH_FORMAT_SPEC_ID, PRE_COMPACTION_FORMAT_SPEC_ID,
    PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID, PRE_GC_OUTBOX_FORMAT_SPEC_ID,
    PRE_KV_TRANSITION_FORMAT_SPEC_ID, PRE_RUNATAL_NAMING_FORMAT_SPEC_ID,
    PRE_SHA384_ATTESTATION_FORMAT_SPEC_ID, STORE_METADATA_FILE, format_spec_record,
    legacy_store_metadata, prepare_destination, previous_store_metadata, store_metadata,
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
        PRE_SHA384_ATTESTATION_FORMAT_SPEC_ID,
    ] {
        assert_prior_format_is_selected(prior, false).await;
    }
    assert_prior_format_is_selected(PRE_FASTCDC_FREEZE_FORMAT_SPEC_ID, true).await;
    assert_prior_format_is_selected(PRE_KV_TRANSITION_FORMAT_SPEC_ID, true).await;
    assert_prior_current_projection_is_selected(PRE_BOTTOM_K_SKETCH_FORMAT_SPEC_ID).await;
}

async fn assert_prior_current_projection_is_selected(prior: ObjectId) {
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
        store_metadata(prior, catalog_spec_id),
    )
    .unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&format_spec_record().unwrap());
    assert_eq!(
        prepare_destination(
            &store_path,
            &store_metadata(current_spec_id, catalog_spec_id),
            catalog_spec_id,
        )
        .unwrap(),
        DestinationFormat::PriorV1 {
            format_spec: prior,
            catalog_spec_was_declared: true,
        }
    );
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
            previous_store_metadata(prior, catalog_spec_id)
        } else {
            legacy_store_metadata(prior)
        },
    )
    .unwrap();
    let current_spec = format_spec_record().unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&current_spec);
    let current_metadata = store_metadata(current_spec_id, catalog_spec_id);
    assert_eq!(
        prepare_destination(&store_path, &current_metadata, catalog_spec_id,).unwrap(),
        DestinationFormat::PriorV1 {
            format_spec: prior,
            catalog_spec_was_declared: catalog_aware,
        }
    );
}

#[tokio::test]
async fn current_format_identity_without_catalog_metadata_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    store.close().await.unwrap();
    drop(store);

    let store_path = home.principal_store_path();
    let current_spec = format_spec_record().unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&current_spec);
    let catalog_spec_id = Blake3ObjectIdentityV1
        .identify(&bootstrap::content_catalog_format_specification().unwrap());
    std::fs::write(
        store_path.join(STORE_METADATA_FILE),
        legacy_store_metadata(current_spec_id),
    )
    .unwrap();

    let error = prepare_destination(
        &store_path,
        &store_metadata(current_spec_id, catalog_spec_id),
        catalog_spec_id,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("selects an unsupported format"),
        "{error}"
    );
}
