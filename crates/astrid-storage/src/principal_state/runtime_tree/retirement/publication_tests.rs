//! Exercise real preflight work and exact inventory publication checks.

use std::sync::Arc;

use super::*;
use crate::content::{ContentIngest, ContentName};
use crate::principal_state::runtime_tree::{operation_counts, write_projection_file};
use crate::{KvQuotaResolver, StateOwner, open_runtime_principal_store};

async fn fixture() -> (
    crate::test_directory::TestDirectory,
    AstridHome,
    RuntimePrincipalStore,
) {
    let directory = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    write_projection_file(home.root(), "config.toml", b"host generation").unwrap();
    crate::principal_state::lifecycle::staging::close_for_retirement(&store).unwrap();
    store.publish_runtime_projection(&home).unwrap();
    (directory, home, store)
}

fn name(value: &str) -> ContentName {
    ContentName::new(value).unwrap()
}

#[tokio::test]
async fn pack_uses_one_validating_walk_one_publication_and_two_receipt_reads() {
    let (_directory, home, store) = fixture().await;
    let before = operation_counts::snapshot();
    // Tracing callsite interest must never decide whether real work is counted.
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        store.pack_and_retire_runtime_projection(&home).unwrap();
    });
    let operations = operation_counts::snapshot().since(before);
    assert_eq!(operations.scans, 1);
    assert_eq!(operations.receipts, 2);
    assert_eq!(operations.publications, 1);
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
    assert!(active::read(&home, &store).unwrap().is_none());
}

#[tokio::test]
async fn small_retiring_retry_keeps_sparse_inventory_validation() {
    let (_directory, home, store) = fixture().await;
    transition_retiring_projection(&home, &store).unwrap();
    let lists_before = store.content().list_invocations();
    transition_retiring_projection(&home, &store).unwrap();
    assert_eq!(store.content().list_invocations(), lists_before);
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"host generation"
    );
}

#[tokio::test]
async fn payload_change_with_unchanged_receipt_revalidates_and_refuses_delete() {
    let (_directory, home, store) = fixture().await;
    transition_retiring_projection(&home, &store).unwrap();
    let receipt_name = active::active_projection_name().unwrap();
    let receipt_before = store
        .content()
        .describe(&StateOwner::System, &receipt_name)
        .unwrap();
    store
        .content()
        .put(
            &StateOwner::System,
            &name("config.toml"),
            b"new volume generation",
        )
        .unwrap();
    assert_eq!(
        store
            .content()
            .describe(&StateOwner::System, &receipt_name)
            .unwrap(),
        receipt_before
    );
    let before = operation_counts::snapshot();
    let error = retire_current_projection(&home, &store)
        .expect_err("receipt identity alone must never authorize stale payload deletion");
    let operations = operation_counts::snapshot().since(before);
    assert!(error.to_string().contains("does not match"), "{error}");
    assert_eq!(operations.receipts, 1);
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"host generation"
    );
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &name("config.toml"))
            .unwrap()
            .unwrap(),
        b"new volume generation"
    );
}

#[tokio::test]
async fn unrelated_catalogue_change_preserves_valid_retiring_inventory() {
    let (_directory, home, store) = fixture().await;
    transition_retiring_projection(&home, &store).unwrap();
    let volume_only = name("volume-only.wasm");
    store
        .content()
        .put(&StateOwner::System, &volume_only, b"new durable content")
        .unwrap();
    let before = operation_counts::snapshot();
    retire_current_projection(&home, &store).unwrap();
    let operations = operation_counts::snapshot().since(before);
    assert_eq!(operations.receipts, 1);
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &volume_only)
            .unwrap()
            .unwrap(),
        b"new durable content"
    );
}

#[tokio::test]
async fn concurrent_payload_change_prevents_stale_retiring_publication() {
    let (_directory, home, store) = fixture().await;
    let receipt_name = active::active_projection_name().unwrap();
    let receipt_before = store
        .content()
        .describe(&StateOwner::System, &receipt_name)
        .unwrap();
    let result = transition_retiring_with_hook(&home, &store, || {
        store
            .content()
            .put(&StateOwner::System, &name("config.toml"), b"concurrent")
            .map_err(|error| tree_error(home.root(), error))?;
        Ok(())
    });
    assert!(
        result.is_err(),
        "exact inventory expectations must bind the actual CAS"
    );
    assert_eq!(
        store
            .content()
            .describe(&StateOwner::System, &receipt_name)
            .unwrap(),
        receipt_before
    );
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"host generation"
    );
}

#[tokio::test]
async fn large_complete_inventory_is_revalidated_and_keeps_volume_only_files() {
    let (_directory, home, store) = fixture().await;
    let suffix = "a".repeat(80);
    let names = (0..24_000)
        .map(|index| name(&format!("volume-only/{index:05}-{suffix}")))
        .collect::<Vec<_>>();
    store
        .content()
        .put_streaming_batch(
            &StateOwner::System,
            names
                .iter()
                .cloned()
                .map(|name| ContentIngest::new(name, std::io::Cursor::new(b""))),
        )
        .unwrap();
    // Authenticate a large ACTIVE inventory before publication. The transition
    // needs the same catalog for retained entries, so it must list it once.
    let entries = super::super::active_projection_entries(&home, &store).unwrap();
    let bytes = active::encode(&home, super::super::ReceiptPhase::Active, &entries, None).unwrap();
    store
        .content()
        .put(
            &StateOwner::System,
            &active::active_projection_name().unwrap(),
            &bytes,
        )
        .unwrap();
    let lists_before = store.content().list_invocations();
    transition_retiring_projection(&home, &store).unwrap();
    assert_eq!(store.content().list_invocations(), lists_before + 1);
    let descriptor = store
        .content()
        .describe(
            &StateOwner::System,
            &active::active_projection_name().unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(
        descriptor.logical_bytes() > 4 * 1024 * 1024,
        "exercise the large inventory parser boundary"
    );
    let before = operation_counts::snapshot();
    retire_current_projection(&home, &store).unwrap();
    let operations = operation_counts::snapshot().since(before);
    assert_eq!(operations.receipts, 1);
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
    assert!(
        store
            .content()
            .describe(&StateOwner::System, &names[0])
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .content()
            .describe(&StateOwner::System, names.last().unwrap())
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn empty_source_active_publication_replaces_the_receipt_and_preserves_volume_only_content() {
    let (_directory, home, store) = fixture().await;
    let volume_only = name("volume-only.bin");
    store
        .content()
        .put(&StateOwner::System, &volume_only, b"durable")
        .unwrap();
    for entry in std::fs::read_dir(home.root()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() == "astrid.volume" {
            continue;
        }
        if entry.file_type().unwrap().is_dir() {
            std::fs::remove_dir_all(entry.path()).unwrap();
        } else {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    store.publish_runtime_projection(&home).unwrap();
    let receipt = active::read(&home, &store).unwrap().unwrap();
    assert_eq!(receipt.phase(), super::super::ReceiptPhase::Active);
    assert!(receipt.inventory_names().next().is_none());
    assert!(
        store
            .content()
            .describe(&StateOwner::System, &name("config.toml"))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &volume_only)
            .unwrap(),
        Some(b"durable".to_vec())
    );
    drop(store);
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let reopened = open_runtime_principal_store(&home, quota).await.unwrap();
    assert!(
        reopened
            .content()
            .describe(&StateOwner::System, &name("config.toml"))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened
            .content()
            .read(&StateOwner::System, &volume_only)
            .unwrap(),
        Some(b"durable".to_vec())
    );
}
