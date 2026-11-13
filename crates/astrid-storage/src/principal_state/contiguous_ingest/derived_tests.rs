//! Empty host snapshots still publish their derived receipt atomically.

use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_core::PrincipalUid;
use astrid_core::dirs::AstridHome;

use super::*;
use crate::content::{ContentDescriptor, PrincipalContentError};
use crate::engine::PrincipalProjectionEngine;
use crate::{KvQuotaResolver, open_runtime_principal_store};

struct Receipt {
    name: ContentName,
    fail: bool,
}

impl PrepareDerivedBatchContent for Receipt {
    fn prepare(
        &mut self,
        entries: &BTreeMap<ContentName, ContentDescriptor>,
    ) -> Result<(ContentName, Vec<u8>), PrincipalContentError> {
        assert!(
            entries.is_empty(),
            "this receipt describes an empty source snapshot"
        );
        if self.fail {
            return Err(PrincipalContentError::AccountingOverflow);
        }
        Ok((self.name.clone(), b"empty snapshot".to_vec()))
    }
}

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

fn owner() -> StateOwner {
    StateOwner::Principal(PrincipalUid::from_bytes([0x63; 32]))
}

fn name(value: &str) -> ContentName {
    ContentName::new(value).unwrap()
}

#[tokio::test]
async fn empty_source_publishes_derived_receipt_without_removals() {
    let directory = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    let receipt = name("receipt");
    let outcome = store
        .replace_contiguous_files_with_expectation(
            owner(),
            [],
            &[],
            Some(&mut Receipt {
                name: receipt.clone(),
                fail: false,
            }),
            None,
        )
        .unwrap()
        .expect("a derived-only publication has a root outcome");
    assert_eq!(outcome.entries().len(), 1);
    assert_eq!(
        store.content().read(&owner(), &receipt).unwrap(),
        Some(b"empty snapshot".to_vec())
    );
}

#[tokio::test]
async fn empty_source_removal_and_derived_receipt_survive_reopen() {
    let directory = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    let old = name("old-projection");
    let receipt = name("receipt");
    store.content().put(&owner(), &old, b"old").unwrap();
    let previous = store
        .content()
        .describe(&owner(), &old)
        .unwrap()
        .unwrap()
        .file();
    let expectation =
        ContentBatchExpectation::exact([(old.clone(), Some(previous)), (receipt.clone(), None)]);
    store
        .replace_contiguous_files_with_expectation(
            owner(),
            [],
            std::slice::from_ref(&old),
            Some(&mut Receipt {
                name: receipt.clone(),
                fail: false,
            }),
            Some(&expectation),
        )
        .unwrap()
        .expect("derived publication must not be silently dropped");
    store.engine.close().unwrap();
    drop(store);
    let reopened = open_runtime_principal_store(&home, quota()).await.unwrap();
    assert_eq!(reopened.content().read(&owner(), &old).unwrap(), None);
    assert_eq!(
        reopened.content().read(&owner(), &receipt).unwrap(),
        Some(b"empty snapshot".to_vec())
    );
}

#[tokio::test]
async fn empty_source_derivation_failure_keeps_removed_content_and_root() {
    let directory = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    let old = name("old-projection");
    let receipt = name("receipt");
    store.content().put(&owner(), &old, b"old").unwrap();
    let before = store.engine.current_root(&owner()).unwrap();
    let error = store
        .replace_contiguous_files_with_expectation(
            owner(),
            [],
            std::slice::from_ref(&old),
            Some(&mut Receipt {
                name: receipt.clone(),
                fail: true,
            }),
            None,
        )
        .expect_err("receipt derivation must run before any removal commits");
    assert!(error.to_string().contains("overflow"), "{error}");
    assert_eq!(store.engine.current_root(&owner()).unwrap(), before);
    assert_eq!(
        store.content().read(&owner(), &old).unwrap(),
        Some(b"old".to_vec())
    );
    assert_eq!(store.content().read(&owner(), &receipt).unwrap(), None);
}

#[tokio::test]
async fn empty_source_stale_expectation_keeps_payload_and_receipt() {
    let directory = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    let old = name("old-projection");
    let receipt = name("receipt");
    store.content().put(&owner(), &old, b"old").unwrap();
    let previous = store
        .content()
        .describe(&owner(), &old)
        .unwrap()
        .unwrap()
        .file();
    store.content().put(&owner(), &old, b"concurrent").unwrap();
    let expectation =
        ContentBatchExpectation::exact([(old.clone(), Some(previous)), (receipt.clone(), None)]);
    let before = store.engine.current_root(&owner()).unwrap();
    assert!(
        store
            .replace_contiguous_files_with_expectation(
                owner(),
                [],
                std::slice::from_ref(&old),
                Some(&mut Receipt {
                    name: receipt.clone(),
                    fail: false
                }),
                Some(&expectation),
            )
            .is_err()
    );
    assert_eq!(store.engine.current_root(&owner()).unwrap(), before);
    assert_eq!(
        store.content().read(&owner(), &old).unwrap(),
        Some(b"concurrent".to_vec())
    );
    assert_eq!(store.content().read(&owner(), &receipt).unwrap(), None);
}
