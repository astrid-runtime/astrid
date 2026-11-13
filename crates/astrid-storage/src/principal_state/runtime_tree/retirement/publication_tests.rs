//! Exercise real preflight work and exact inventory publication checks.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::content::{ContentIngest, ContentName};
use crate::principal_state::runtime_tree::write_projection_file;
use crate::{KvQuotaResolver, StateOwner, open_runtime_principal_store};

#[derive(Clone, Default)]
struct Operations {
    scans: Arc<AtomicUsize>,
    receipts: Arc<AtomicUsize>,
}

impl tracing::Subscriber for Operations {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        match event.metadata().target() {
            "astrid_storage::runtime_tree_scan" => {
                self.scans.fetch_add(1, Ordering::Relaxed);
            },
            "astrid_storage::projection_receipt_read" => {
                self.receipts.fetch_add(1, Ordering::Relaxed);
            },
            _ => {},
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

thread_local! {
    static COMPLETED_PUBLICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

// These synchronous API calls stay on the current test thread. Count their
// actual successful flush boundaries independently of global tracing filters.
pub(in crate::principal_state::runtime_tree) fn record_completed_publication() {
    COMPLETED_PUBLICATIONS.with(|count| count.set(count.get().strict_add(1)));
}

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
    let operations = Operations::default();
    let before = COMPLETED_PUBLICATIONS.with(std::cell::Cell::get);
    tracing::subscriber::with_default(operations.clone(), || {
        store.pack_and_retire_runtime_projection(&home).unwrap();
    });
    assert_eq!(operations.scans.load(Ordering::Relaxed), 1);
    assert_eq!(operations.receipts.load(Ordering::Relaxed), 2);
    assert_eq!(
        COMPLETED_PUBLICATIONS.with(std::cell::Cell::get) - before,
        1
    );
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
    assert!(active::read(&home, &store).unwrap().is_none());
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
    let operations = Operations::default();
    let error = tracing::subscriber::with_default(operations.clone(), || {
        retire_current_projection(&home, &store)
    })
    .expect_err("receipt identity alone must never authorize stale payload deletion");
    assert!(error.to_string().contains("does not match"), "{error}");
    assert_eq!(operations.receipts.load(Ordering::Relaxed), 1);
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
    let operations = Operations::default();
    tracing::subscriber::with_default(operations.clone(), || {
        retire_current_projection(&home, &store).unwrap();
    });
    assert_eq!(operations.receipts.load(Ordering::Relaxed), 1);
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
    transition_retiring_projection(&home, &store).unwrap();
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
    let operations = Operations::default();
    tracing::subscriber::with_default(operations.clone(), || {
        retire_current_projection(&home, &store).unwrap();
    });
    assert_eq!(operations.receipts.load(Ordering::Relaxed), 1);
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
