//! Exercise the fused publication through real durable batches and reopen.

use std::sync::Arc;

use super::*;
use crate::principal_state::runtime_tree::{scan, write_projection_file};
use crate::{KvQuotaResolver, open_runtime_principal_store};

async fn fixture() -> (
    crate::test_directory::TestDirectory,
    AstridHome,
    RuntimePrincipalStore,
) {
    let directory = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open(&home).await;
    write_projection_file(home.root(), "config.toml", b"host before").unwrap();
    crate::principal_state::lifecycle::staging::close_for_retirement(&store).unwrap();
    store.publish_runtime_projection(&home).unwrap();
    (directory, home, store)
}

async fn open(home: &AstridHome) -> RuntimePrincipalStore {
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    open_runtime_principal_store(home, quota).await.unwrap()
}

fn name(value: &str) -> ContentName {
    ContentName::new(value).unwrap()
}

fn assert_host(home: &AstridHome, bytes: &[u8]) {
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        bytes
    );
}

#[tokio::test]
async fn fused_payloads_removals_and_volume_only_inventory_survive_reopen() {
    let (_directory, home, store) = fixture().await;
    write_projection_file(home.root(), "removed.toml", b"old").unwrap();
    store.publish_runtime_projection(&home).unwrap();
    std::fs::remove_file(home.root().join("removed.toml")).unwrap();
    let retained = name("volume-only.wasm");
    let directory = name("volume-only/");
    store
        .content()
        .put(&StateOwner::System, &retained, b"opaque")
        .unwrap();
    crate::AstridFilesystem::new(store.content(), StateOwner::System)
        .create_dir(&crate::FilesystemPath::new("volume-only").unwrap())
        .unwrap();
    write_projection_file(home.root(), "config.toml", b"host after").unwrap();
    publish_retiring_projection(&home, &store, scan(home.root()).unwrap()).unwrap();
    let receipt = active::read(&home, &store).unwrap().unwrap();
    assert_eq!(receipt.phase(), ReceiptPhase::Retiring);
    assert!(receipt.contains_inventory_name(retained.as_str()));
    assert!(receipt.contains_inventory_name(directory.as_str()));
    assert!(!receipt.contains_inventory_name("removed.toml"));
    assert!(
        store
            .content()
            .describe(&StateOwner::System, &name("removed.toml"))
            .unwrap()
            .is_none()
    );
    assert_host(&home, b"host after");
    drop(store);

    let store = open(&home).await;
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &retained)
            .unwrap()
            .unwrap(),
        b"opaque"
    );
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &name("config.toml"))
            .unwrap()
            .unwrap(),
        b"host after"
    );
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);
    let store = open(&home).await;
    assert_host(&home, b"host after");
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &retained)
            .unwrap()
            .unwrap(),
        b"opaque"
    );
}

#[tokio::test]
async fn precommit_failure_preserves_active_payloads_and_retry_on_reopen() {
    let (_directory, home, store) = fixture().await;
    let receipt_before = store
        .content()
        .describe(
            &StateOwner::System,
            &active::active_projection_name().unwrap(),
        )
        .unwrap();
    write_projection_file(home.root(), "config.toml", b"host after").unwrap();
    let error = publish_with_hook(&home, &store, scan(home.root()).unwrap(), || {
        Err(tree_error(home.root(), "injected precommit failure"))
    })
    .unwrap_err();
    assert!(error.to_string().contains("injected precommit failure"));
    assert_eq!(
        store
            .content()
            .describe(
                &StateOwner::System,
                &active::active_projection_name().unwrap()
            )
            .unwrap(),
        receipt_before
    );
    assert_eq!(
        active::read(&home, &store).unwrap().unwrap().phase(),
        ReceiptPhase::Active
    );
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &name("config.toml"))
            .unwrap()
            .unwrap(),
        b"host before"
    );
    assert_host(&home, b"host after");
    drop(store);
    let store = open(&home).await;
    assert_host(&home, b"host after");
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);
    let _store = open(&home).await;
    assert_host(&home, b"host after");
}

#[tokio::test]
async fn concurrent_retained_or_receipt_replacement_refuses_publication() {
    for replace_receipt in [false, true] {
        let (_directory, home, store) = fixture().await;
        let retained = name("volume-only.wasm");
        store
            .content()
            .put(&StateOwner::System, &retained, b"before")
            .unwrap();
        let receipt_name = active::active_projection_name().unwrap();
        let result = publish_with_hook(&home, &store, scan(home.root()).unwrap(), || {
            if replace_receipt {
                // Same bytes would retain the same content identity: publish a
                // valid inventory with a newly materialized name instead.
                write_projection_file(home.root(), "new.toml", b"new")?;
                store.publish_runtime_projection(&home)?;
            } else {
                store
                    .content()
                    .put(&StateOwner::System, &retained, b"concurrent")
                    .map_err(|error| tree_error(home.root(), error))?;
            }
            Ok(())
        });
        assert!(
            result.is_err(),
            "captured inventory must bind the actual CAS"
        );
        let receipt = active::read(&home, &store).unwrap().unwrap();
        assert_eq!(receipt.phase(), ReceiptPhase::Active);
        assert_host(&home, b"host before");
        assert!(
            store
                .content()
                .describe(&StateOwner::System, &receipt_name)
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn source_read_failure_cannot_publish_retiring_or_delete_host() {
    let (_directory, home, store) = fixture().await;
    let receipt_before = store
        .content()
        .describe(
            &StateOwner::System,
            &active::active_projection_name().unwrap(),
        )
        .unwrap();
    let result = publish_with_hook(&home, &store, scan(home.root()).unwrap(), || {
        std::fs::write(home.root().join("config.toml"), b"changed source length")
            .map_err(|error| tree_error(home.root(), error))
    });
    assert!(result.is_err());
    assert_eq!(
        store
            .content()
            .describe(
                &StateOwner::System,
                &active::active_projection_name().unwrap()
            )
            .unwrap(),
        receipt_before
    );
    assert_eq!(
        active::read(&home, &store).unwrap().unwrap().phase(),
        ReceiptPhase::Active
    );
    assert_host(&home, b"changed source length");
}

#[tokio::test]
async fn empty_host_preserves_complete_durable_inventory() {
    let (_directory, home, store) = fixture().await;
    std::fs::remove_file(home.root().join("config.toml")).unwrap();
    // The open helper may also seed the layout sentinel. Remove every scanned
    // file to exercise the established entirely-absent-projection contract.
    for entry in scan(home.root()).unwrap() {
        std::fs::remove_file(entry.source_path).unwrap();
    }
    publish_retiring_projection(&home, &store, Vec::new()).unwrap();
    let receipt = active::read(&home, &store).unwrap().unwrap();
    assert_eq!(receipt.phase(), ReceiptPhase::Retiring);
    assert!(receipt.contains_inventory_name("config.toml"));
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &name("config.toml"))
            .unwrap()
            .unwrap(),
        b"host before"
    );
    drop(store);
    let store = open(&home).await;
    assert_host(&home, b"host before");
    store.pack_and_retire_runtime_projection(&home).unwrap();
}

#[tokio::test]
async fn interrupted_retiring_retry_preserves_volume_and_rejects_unreceipted_host() {
    let (_directory, home, store) = fixture().await;
    let retained = name("volume-only.wasm");
    store
        .content()
        .put(&StateOwner::System, &retained, b"opaque")
        .unwrap();
    publish_retiring_projection(&home, &store, scan(home.root()).unwrap()).unwrap();
    std::fs::remove_file(home.root().join("config.toml")).unwrap();
    let receipt_before = store
        .content()
        .describe(
            &StateOwner::System,
            &active::active_projection_name().unwrap(),
        )
        .unwrap();
    publish_retiring_projection(&home, &store, scan(home.root()).unwrap()).unwrap();
    assert_eq!(
        store
            .content()
            .describe(
                &StateOwner::System,
                &active::active_projection_name().unwrap()
            )
            .unwrap(),
        receipt_before
    );
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &retained)
            .unwrap()
            .unwrap(),
        b"opaque"
    );
    write_projection_file(home.root(), "unexpected.toml", b"not published").unwrap();
    assert!(store.pack_and_retire_runtime_projection(&home).is_err());
    assert_eq!(
        std::fs::read(home.root().join("unexpected.toml")).unwrap(),
        b"not published"
    );
}

thread_local! {
    static FAIL_FLUSH_FOR: std::cell::RefCell<Option<std::path::PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(super) fn before_flush(home: &AstridHome) -> StorageResult<()> {
    if FAIL_FLUSH_FOR.with(|slot| slot.borrow().as_deref() == Some(home.root())) {
        return Err(tree_error(
            home.root(),
            "injected retiring flush boundary failure",
        ));
    }
    Ok(())
}

struct FlushFailure;

impl Drop for FlushFailure {
    fn drop(&mut self) {
        FAIL_FLUSH_FOR.with(|slot| *slot.borrow_mut() = None);
    }
}

#[tokio::test]
async fn failed_flush_boundary_leaves_host_and_durable_retiring_intent_for_retry() {
    let (_directory, home, store) = fixture().await;
    write_projection_file(home.root(), "config.toml", b"host after").unwrap();
    {
        FAIL_FLUSH_FOR.with(|slot| *slot.borrow_mut() = Some(home.root().to_path_buf()));
        let _failure = FlushFailure;
        let error = store.pack_and_retire_runtime_projection(&home).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected retiring flush boundary failure")
        );
    }
    assert_host(&home, b"host after");
    assert_eq!(
        active::read(&home, &store).unwrap().unwrap().phase(),
        ReceiptPhase::Retiring
    );
    // The batch publication is independently durable; interruption before its
    // explicit flush barrier must retain recovery authority and all host data.
    drop(store);
    let store = open(&home).await;
    assert_host(&home, b"host after");
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);
    let _store = open(&home).await;
    assert_host(&home, b"host after");
}

#[tokio::test]
async fn failed_receipt_derivation_leaves_active_authority_untouched() {
    let (_directory, home, store) = fixture().await;
    let receipt_name = active::active_projection_name().unwrap();
    let receipt_before = store
        .content()
        .describe(&StateOwner::System, &receipt_name)
        .unwrap();
    let mut derived = RetiringReceiptDeriver {
        home: &home,
        entries: vec![(name("config.toml"), 0)],
        retained: &[],
    };
    // The real batch prepares a nonempty file. Its derived length must match
    // before any receipt or payload catalog entry can become authoritative.
    let source = scan(home.root())
        .unwrap()
        .into_iter()
        .find(|entry| entry.name == name("config.toml"))
        .unwrap();
    let result = store.replace_contiguous_files_with_expectation(
        StateOwner::System,
        [PackedProjectionIngest::File(ContiguousFileIngest::new(
            source.name,
            source.source_path,
            source.logical_bytes,
        ))],
        &[],
        Some(&mut derived),
        ContentBatchPreconditions::default(),
    );
    assert!(result.is_err());
    assert_eq!(
        store
            .content()
            .describe(&StateOwner::System, &receipt_name)
            .unwrap(),
        receipt_before
    );
    assert_eq!(
        active::read(&home, &store).unwrap().unwrap().phase(),
        ReceiptPhase::Active
    );
    assert_host(&home, b"host before");
}

thread_local! {
    static MUTATE_AFTER_PUBLICATION: std::cell::RefCell<Option<(std::path::PathBuf, std::time::SystemTime)>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(in crate::principal_state::runtime_tree::retirement) fn after_final_publication(
    home: &AstridHome,
) -> StorageResult<()> {
    let mutation = MUTATE_AFTER_PUBLICATION.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(root, _)| root == home.root()) {
            slot.take()
        } else {
            None
        }
    });
    if let Some((_, modified)) = mutation {
        use std::io::Write as _;
        let path = home.root().join("zz-source.toml");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|error| tree_error(&path, error))?;
        file.write_all(b"host newer!")
            .map_err(|error| tree_error(&path, error))?;
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .map_err(|error| tree_error(&path, error))?;
        file.sync_all().map_err(|error| tree_error(&path, error))?;
    }
    Ok(())
}

struct SourceMutation;

impl Drop for SourceMutation {
    fn drop(&mut self) {
        MUTATE_AFTER_PUBLICATION.with(|slot| *slot.borrow_mut() = None);
    }
}

#[tokio::test]
async fn same_length_postcommit_source_change_preserves_all_host_files_and_refuses_retry() {
    let (_directory, home, store) = fixture().await;
    write_projection_file(home.root(), "nested/other.toml", b"also preserve").unwrap();
    write_projection_file(home.root(), "zz-source.toml", b"host before").unwrap();
    let modified = std::fs::metadata(home.root().join("zz-source.toml"))
        .unwrap()
        .modified()
        .unwrap();
    {
        MUTATE_AFTER_PUBLICATION
            .with(|slot| *slot.borrow_mut() = Some((home.root().to_path_buf(), modified)));
        let _mutation = SourceMutation;
        let error = store.pack_and_retire_runtime_projection(&home).unwrap_err();
        assert!(error.to_string().contains("source bytes differ"), "{error}");
    }
    // The write occurs after the real durable payload/RETIRING CAS. Its size
    // and mtime are unchanged; only authenticated byte comparison detects it.
    assert_eq!(
        std::fs::read(home.root().join("zz-source.toml")).unwrap(),
        b"host newer!"
    );
    assert_host(&home, b"host before");
    assert_eq!(
        std::fs::metadata(home.root().join("zz-source.toml"))
            .unwrap()
            .modified()
            .unwrap(),
        modified
    );
    assert_eq!(
        std::fs::read(home.root().join("nested/other.toml")).unwrap(),
        b"also preserve"
    );
    assert_eq!(
        active::read(&home, &store).unwrap().unwrap().phase(),
        ReceiptPhase::Retiring
    );
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &name("zz-source.toml"))
            .unwrap()
            .unwrap(),
        b"host before"
    );
    let retry = store.pack_and_retire_runtime_projection(&home).unwrap_err();
    assert!(retry.to_string().contains("source bytes differ"), "{retry}");
    assert_eq!(
        std::fs::read(home.root().join("zz-source.toml")).unwrap(),
        b"host newer!"
    );
    assert_host(&home, b"host before");
    assert_eq!(
        std::fs::read(home.root().join("nested/other.toml")).unwrap(),
        b"also preserve"
    );
    // Restoring the receipted bytes permits the original bounded retry path.
    write_projection_file(home.root(), "zz-source.toml", b"host before").unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
}

#[tokio::test]
async fn fresh_catalogue_addition_refuses_incomplete_retiring_inventory() {
    for materialize in [false, true] {
        let (_directory, home, store) = fixture().await;
        let receipt_before = store
            .content()
            .describe(
                &StateOwner::System,
                &active::active_projection_name().unwrap(),
            )
            .unwrap();
        let added = name("fresh-generation.toml");
        let result = publish_with_hook(&home, &store, scan(home.root()).unwrap(), || {
            store
                .content()
                .put(&StateOwner::System, &added, b"fresh")
                .map_err(|error| tree_error(home.root(), error))?;
            if materialize {
                write_projection_file(home.root(), added.as_str(), b"fresh")?;
            }
            Ok(())
        });
        assert!(
            result.is_err(),
            "new names outside a captured inventory must fail its root precondition"
        );
        assert_eq!(
            store
                .content()
                .describe(
                    &StateOwner::System,
                    &active::active_projection_name().unwrap()
                )
                .unwrap(),
            receipt_before
        );
        assert_eq!(
            active::read(&home, &store).unwrap().unwrap().phase(),
            ReceiptPhase::Active
        );
        assert_host(&home, b"host before");
        assert_eq!(
            store
                .content()
                .read(&StateOwner::System, &added)
                .unwrap()
                .unwrap(),
            b"fresh"
        );
        if materialize {
            assert_eq!(
                std::fs::read(home.root().join(added.as_str())).unwrap(),
                b"fresh"
            );
        }
    }
}
