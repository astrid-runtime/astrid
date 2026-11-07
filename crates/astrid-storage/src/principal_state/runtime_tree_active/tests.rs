use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;

use super::*;
use crate::content::CONTENT_COMPONENT_LABEL;
use crate::engine::RootTransaction;
use crate::storage_model::{ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel};
use crate::{ContentIngest, KvQuotaResolver, open_runtime_principal_store};

fn decode_listed_receipt(
    path: &Path,
    bytes: &[u8],
    catalog: &[ContentEntry],
) -> StorageResult<Option<ActiveProjectionReceipt>> {
    decode_receipt(path, bytes, &ReceiptInventory::Listed(catalog))
}

fn inventory(count: usize) -> Vec<ContentEntry> {
    (0..count)
        .map(|index| {
            ContentEntry::new(
                ContentName::new(format!(
                    "etc/agent-{index:05}/{}/{}",
                    "name".repeat(50),
                    "name".repeat(50)
                ))
                .unwrap(),
                ObjectId::new([0x47; 32]),
                7,
            )
        })
        .collect()
}

#[test]
fn ten_thousand_entry_receipt_exceeds_old_cap_and_authenticates_every_identity() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let catalog = inventory(10_000);
    let entries = catalog
        .iter()
        .rev()
        .map(|entry| ActiveProjectionEntry {
            name: entry.name().clone(),
            file: entry.file(),
            logical_bytes: entry.logical_bytes(),
        })
        .collect::<Vec<_>>();
    let bytes = encode(&home, ReceiptPhase::Active, &entries).unwrap();
    assert!(bytes.len() as u64 > RECEIPT_FRAMING_BYTES);
    assert!(
        bytes.len() as u64 <= receipt_size_bound(catalog.iter().map(ContentEntry::name)).unwrap()
    );
    let receipt = decode_listed_receipt(home.root(), &bytes, &catalog)
        .unwrap()
        .unwrap();
    for entry in &catalog {
        assert!(receipt.contains_inventory_name(entry.name().as_str()));
    }
    assert!(!receipt.contains_inventory_name("etc/missing"));
    // Surviving input is deliberately unordered, and a genuine absence must
    // still produce exactly one removal from the authenticated inventory.
    let surviving = catalog
        .iter()
        .rev()
        .skip(1)
        .map(|entry| entry.name().clone())
        .collect::<Vec<_>>();
    assert_eq!(
        removals(&receipt, &surviving).unwrap(),
        vec![catalog.last().unwrap().name().clone()]
    );
    let mut corrupt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    corrupt["entries"][4]["file"] = serde_json::Value::String("00".repeat(32));
    assert!(
        decode_listed_receipt(
            home.root(),
            &serde_json::to_vec(&corrupt).unwrap(),
            &catalog
        )
        .is_err()
    );
}

#[test]
fn receipt_cannot_amplify_inventory_with_duplicate_names() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let catalog = inventory(2);
    let entry = ActiveProjectionEntry {
        name: catalog[0].name().clone(),
        file: catalog[0].file(),
        logical_bytes: 7,
    };
    let bytes = encode(&home, ReceiptPhase::Active, &[entry.clone(), entry]).unwrap();
    assert!(
        decode_listed_receipt(home.root(), &bytes, &catalog)
            .unwrap_err()
            .to_string()
            .contains("repeats")
    );
}

#[test]
fn receipt_allowance_scales_only_with_authenticated_catalog_names() {
    let catalog = inventory(10_000);
    let bound = receipt_size_bound(catalog.iter().map(ContentEntry::name)).unwrap();
    assert!(bound > RECEIPT_FRAMING_BYTES);
    assert_eq!(
        receipt_size_bound(std::iter::empty()).unwrap(),
        RECEIPT_FRAMING_BYTES
    );
    assert_eq!(
        bound,
        RECEIPT_FRAMING_BYTES
            + catalog
                .iter()
                .map(|entry| 128 + 6 * entry.name().as_str().len() as u64)
                .sum::<u64>()
    );
}

#[test]
fn oversized_receipt_is_rejected_before_json_decoding() {
    let bytes = vec![
        b' ';
        usize::try_from(RECEIPT_FRAMING_BYTES)
            .unwrap()
            .checked_add(1)
            .unwrap()
    ];
    let error = decode_listed_receipt(Path::new("receipt"), &bytes, &[]).unwrap_err();
    assert!(error.to_string().contains("exceeds catalog-derived"));
}

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    })
}

fn long_inventory_name(index: usize) -> ContentName {
    // Same shape as the synthetic 10k unit fixture: long authenticated names
    // force the encoded receipt above the historical fixed 4 MiB ceiling.
    ContentName::new(format!(
        "etc/agent-{index:05}/{}/{}",
        "name".repeat(50),
        "name".repeat(50)
    ))
    .unwrap()
}

#[tokio::test]
async fn sparse_receipt_reads_do_not_list_growing_unrelated_catalogs() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let mut previous_count = 0;
    for count in [1, 100, 1_000, 10_000] {
        let ingests = (previous_count..count)
            .map(|index| {
                ContentIngest::new(
                    ContentName::new(format!("etc/sparse-{index:05}")).unwrap(),
                    Cursor::new(b"x"),
                )
            })
            .collect::<Vec<_>>();
        store
            .content()
            .put_streaming_batch(&StateOwner::System, ingests)
            .unwrap();
        previous_count = count;
        let name = ContentName::new("etc/sparse-00000").unwrap();
        let descriptor = store
            .content()
            .describe(&StateOwner::System, &name)
            .unwrap()
            .unwrap();
        let entries = [ActiveProjectionEntry {
            name: name.clone(),
            file: descriptor.file(),
            logical_bytes: descriptor.logical_bytes(),
        }];
        let bytes = encode(&home, ReceiptPhase::Active, &entries).unwrap();
        assert!((bytes.len() as u64) < RECEIPT_FRAMING_BYTES);
        store
            .content()
            .put(
                &StateOwner::System,
                &active_projection_name().unwrap(),
                &bytes,
            )
            .unwrap();
        read(&home, &store).unwrap().unwrap();
        let lists_before = store.content().list_invocations();
        let receipt = read(&home, &store).unwrap().unwrap();
        assert_eq!(
            store.content().list_invocations(),
            lists_before,
            "catalog size {count}"
        );
        assert_eq!(receipt.phase(), ReceiptPhase::Active);
        assert!(receipt.root_matches(&home).unwrap());
        assert_eq!(receipt.entries.len(), 1);
        assert_eq!(receipt.entries[0].name, name.as_str());
        assert_eq!(receipt.entries[0].logical_bytes, descriptor.logical_bytes());
        assert_eq!(
            receipt.inventory_identity(name.as_str()).unwrap(),
            Some(descriptor.file())
        );
    }
}

#[tokio::test]
async fn receipt_allocation_boundary_selects_authenticated_inventory_source() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let name = ContentName::new("etc/boundary").unwrap();
    store
        .content()
        .put(&StateOwner::System, &name, b"x")
        .unwrap();
    let descriptor = store
        .content()
        .describe(&StateOwner::System, &name)
        .unwrap()
        .unwrap();
    let entries = [ActiveProjectionEntry {
        name: name.clone(),
        file: descriptor.file(),
        logical_bytes: descriptor.logical_bytes(),
    }];
    for (length, expected_lists) in [(RECEIPT_FRAMING_BYTES, 0), (RECEIPT_FRAMING_BYTES + 1, 1)] {
        let mut bytes = encode(&home, ReceiptPhase::Active, &entries).unwrap();
        bytes.resize(usize::try_from(length).unwrap(), b' ');
        store
            .content()
            .put(
                &StateOwner::System,
                &active_projection_name().unwrap(),
                &bytes,
            )
            .unwrap();
        let lists_before = store.content().list_invocations();
        let receipt = read(&home, &store).unwrap().unwrap();
        assert_eq!(
            store.content().list_invocations(),
            lists_before + expected_lists
        );
        assert_eq!(receipt.phase(), ReceiptPhase::Active);
        assert!(receipt.root_matches(&home).unwrap());
        assert_eq!(receipt.entries.len(), 1);
        assert_eq!(receipt.entries[0].name, name.as_str());
        assert_eq!(receipt.entries[0].logical_bytes, descriptor.logical_bytes());
        assert_eq!(
            receipt.inventory_identity(name.as_str()).unwrap(),
            Some(descriptor.file())
        );
    }
}

#[tokio::test]
async fn public_receipt_read_scales_past_four_mib_with_one_catalog_list() {
    const COUNT: usize = 10_000;

    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();

    let ingests = (0..COUNT)
        .map(|index| ContentIngest::new(long_inventory_name(index), Cursor::new(b"x")))
        .collect::<Vec<_>>();
    let published = store
        .content()
        .put_streaming_batch(&StateOwner::System, ingests)
        .unwrap();
    assert_eq!(published.entries().len(), COUNT);

    let entries = published
        .entries()
        .iter()
        .map(|entry| ActiveProjectionEntry {
            name: entry.name().clone(),
            file: entry.descriptor().file(),
            logical_bytes: entry.descriptor().logical_bytes(),
        })
        .collect::<Vec<_>>();
    let bytes = encode(&home, ReceiptPhase::Active, &entries).unwrap();
    assert!(
        bytes.len() > 4 * 1024 * 1024,
        "fixture must exceed the historical fixed receipt ceiling of 4194304 bytes; got {}",
        bytes.len()
    );

    store
        .content()
        .put(
            &StateOwner::System,
            &active_projection_name().unwrap(),
            &bytes,
        )
        .unwrap();

    let lists_before = store.content().list_invocations();
    let receipt = read(&home, &store)
        .unwrap()
        .expect("authenticated oversize receipt must load through the public path");
    assert_eq!(
        store.content().list_invocations(),
        lists_before + 1,
        "inventory authentication must take exactly one content.list snapshot"
    );
    assert_eq!(receipt.phase(), ReceiptPhase::Active);
    for entry in &entries {
        assert!(
            receipt.contains_inventory_name(entry.name.as_str()),
            "missing authenticated inventory name {}",
            entry.name.as_str()
        );
    }
}

#[test]
fn receipt_rejects_noncanonical_authenticated_catalog_inventory() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let catalog = inventory(2);
    let entries = catalog
        .iter()
        .map(|entry| ActiveProjectionEntry {
            name: entry.name().clone(),
            file: entry.file(),
            logical_bytes: entry.logical_bytes(),
        })
        .collect::<Vec<_>>();
    let bytes = encode(&home, ReceiptPhase::Active, &entries).unwrap();
    let mut unordered = catalog.clone();
    unordered.reverse();
    for invalid in [unordered, vec![catalog[0].clone(), catalog[0].clone()]] {
        let error = decode_listed_receipt(home.root(), &bytes, &invalid).unwrap_err();
        assert!(
            error.to_string().contains("unique canonical order"),
            "{error}"
        );
    }
}

fn replace_fixture_reference(record: &ObjectRecord, replacement: ObjectReference) -> ObjectRecord {
    let mut references = record
        .references()
        .iter()
        .filter(|reference| reference.label() != replacement.label())
        .cloned()
        .collect::<Vec<_>>();
    references.push(replacement);
    references.sort();
    ObjectRecord::new(
        record.kind(),
        record.format_version(),
        record.canonical_bytes().to_vec(),
        references,
        record.logical_bytes(),
        record.class(),
    )
    .unwrap()
}

fn forge_catalog_leaf_length(leaf: &ObjectRecord, honest_logical_bytes: u64) -> ObjectRecord {
    // Catalog format v2 encodes its leaf tag before the little-endian length.
    const LOGICAL_BYTES_OFFSET: usize = 1;

    assert_eq!(leaf.logical_bytes(), honest_logical_bytes);
    assert_eq!(leaf.canonical_bytes()[0], 0, "fixture requires a leaf");
    let dishonest_logical_bytes = honest_logical_bytes.checked_add(1).unwrap();
    let mut bytes = leaf.canonical_bytes().to_vec();
    let length_bytes = dishonest_logical_bytes.to_le_bytes();
    bytes[LOGICAL_BYTES_OFFSET..][..length_bytes.len()].copy_from_slice(&length_bytes);
    ObjectRecord::new(
        leaf.kind(),
        leaf.format_version(),
        bytes,
        leaf.references().to_vec(),
        dishonest_logical_bytes,
        leaf.class(),
    )
    .unwrap()
}

fn publish_forged_system_catalog_leaf_length(
    store: &RuntimePrincipalStore,
    honest_logical_bytes: u64,
) {
    // Like content::tests::publish_forged_kv_quota, preserve content-addressed
    // identity, Owns edges and lineage while forging a component claim. Engine
    // commit checks the graph; catalog/file agreement is a content-read check.
    let previous = store.engine.root(&StateOwner::System).unwrap().unwrap();
    let commit = store.engine.object(previous.commit).unwrap().unwrap();
    let state_id = commit
        .reference(&ReferenceLabel::new(b"state".to_vec()))
        .unwrap()
        .target();
    let state = store.engine.object(state_id).unwrap().unwrap();
    let catalog_id = state
        .reference(&ReferenceLabel::new(CONTENT_COMPONENT_LABEL.to_vec()))
        .unwrap()
        .target();
    let leaf = store.engine.object(catalog_id).unwrap().unwrap();
    let forged_leaf = forge_catalog_leaf_length(&leaf, honest_logical_bytes);
    let forged_leaf_id = store.engine.identify(&forged_leaf);
    let forged_state = replace_fixture_reference(
        &state,
        ObjectReference::owns(
            ReferenceLabel::new(CONTENT_COMPONENT_LABEL.to_vec()),
            forged_leaf_id,
        ),
    );
    let forged_state_id = store.engine.identify(&forged_state);
    let with_state = replace_fixture_reference(
        &commit,
        ObjectReference::owns(ReferenceLabel::new(b"state".to_vec()), forged_state_id),
    );
    let forged_commit = replace_fixture_reference(
        &with_state,
        ObjectReference::new(
            ReferenceLabel::new(b"parent".to_vec()),
            previous.commit,
            ReferenceKind::Lineage,
        ),
    );
    let forged_commit_id = store.engine.identify(&forged_commit);
    store
        .engine
        .commit(RootTransaction::new(
            StateOwner::System,
            Some(previous),
            forged_commit_id,
            vec![
                (forged_leaf_id, forged_leaf),
                (forged_state_id, forged_state),
                (forged_commit_id, forged_commit),
            ],
        ))
        .unwrap();
}

#[tokio::test]
async fn public_receipt_read_rejects_catalog_file_logical_length_disagreement() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let receipt_name = active_projection_name().unwrap();
    // Open seeds bootstrap content. Remove it through ordinary store APIs so
    // the forged component below is genuinely a single-entry catalog leaf.
    for entry in store.content().list(&StateOwner::System).unwrap() {
        if entry.name() != &receipt_name {
            assert!(
                store
                    .content()
                    .delete(&StateOwner::System, entry.name())
                    .unwrap()
            );
        }
    }
    let bytes = encode(&home, ReceiptPhase::Active, &[]).unwrap();
    let outcome = store
        .content()
        .put(&StateOwner::System, &receipt_name, &bytes)
        .unwrap();
    let catalog = store.content().list(&StateOwner::System).unwrap();
    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog[0].name(), &receipt_name);
    let honest_logical_bytes = outcome.descriptor().logical_bytes();
    assert_eq!(honest_logical_bytes, u64::try_from(bytes.len()).unwrap());

    // Warm the honest caches. Replacing the catalog changes its ObjectId, so
    // public read must validate the new root before parsing receipt JSON.
    assert!(read(&home, &store).unwrap().is_some());
    publish_forged_system_catalog_leaf_length(&store, honest_logical_bytes);
    let error = read(&home, &store)
        .expect_err("public receipt read must reject catalog/file logical length disagreement");
    let text = error.to_string();
    assert!(
        text.contains("inspect active projection receipt"),
        "rejection must occur during describe/header validation before receipt JSON parsing: {text}"
    );
    assert!(
        text.contains("content catalog and file logical lengths disagree"),
        "{text}"
    );
}
