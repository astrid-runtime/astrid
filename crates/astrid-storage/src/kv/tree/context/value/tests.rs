use super::*;
use crate::engine::InMemoryEngine;
use crate::kv::tree_tests::TestIdentity;

fn bytes() -> Vec<u8> {
    let mut state = 0x12ab_56cd_90ef_3412_u64;
    (0..512 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn applying_new_chunked_value_does_not_read_it_back_for_the_overlay() {
    use crate::kv::tree::delta::{Head, decode_head};
    use crate::kv::tree::header::TreeHeader;

    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    let bytes = bytes();
    let expected = blake3::hash(&bytes);
    let key = b"alice:capsule:ownership\0graph".to_vec();
    let projection = context
        .apply_mutations(
            &TreeHeader::empty(principal.clone()),
            vec![(key.clone(), Some(bytes))],
        )
        .unwrap();
    assert_eq!(
        context.content_loads.get(),
        0,
        "encoding a replacement must not reopen its just-built content DAG"
    );
    let visible = projection.overlay.get(&key).unwrap().as_ref().unwrap();
    assert_eq!(blake3::hash(visible), expected);
    let head = projection.head.unwrap();
    let Head::Delta { mutations, .. } = decode_head(head, &context.record(head).unwrap()).unwrap()
    else {
        panic!("mutation must produce a delta")
    };
    let reconstructed = context
        .value_bytes(mutations[0].value.as_ref().unwrap())
        .unwrap();
    assert_eq!(blake3::hash(&reconstructed), expected);
    assert!(
        context.content_loads.get() > 0,
        "read counter must observe the real decoder"
    );
    assert_eq!(
        engine.object_count(),
        0,
        "encoding must remain transaction-local"
    );
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn cached_content_source_reuses_principal_accounted_allocations() {
    use crate::engine::{DurableEngine, ObjectCacheConfig, RecoveryLimits};
    use crate::kv::tree::header::TreeHeader;
    use crate::kv::tree_tests::Utf8Codec;
    use std::sync::Arc;

    let directory = tempfile::tempdir().unwrap();
    let engine = DurableEngine::open_with_object_cache(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        RecoveryLimits::process_addressable(),
        ObjectCacheConfig::bounded(std::num::NonZeroU64::new(8 * 1024 * 1024).unwrap()),
    )
    .unwrap();
    let alice = "alice".to_owned();
    let bob = "bob".to_owned();
    let mut pending = TreeContext::new(&engine, &alice);
    let root = pending
        .build_sorted(vec![(b"alice:capsule:ownership\0graph".to_vec(), bytes())])
        .unwrap();
    let ids: Vec<_> = pending
        .records
        .iter()
        .filter_map(|(id, record)| (record.kind() == ObjectKind::Chunk).then_some(*id))
        .collect();
    assert!(
        ids.len() > 1,
        "fixture must exercise the batch content path"
    );
    engine
        .commit(
            pending
                .finish(TreeHeader::empty(alice.clone()), root)
                .unwrap(),
        )
        .unwrap();
    engine.flush().unwrap();
    let cached = engine.shared_objects_for(&alice, &ids).unwrap();
    let source = TreeContext::new(&engine, &alice);
    let single = source.load_shared_content_object(ids[0]).unwrap().unwrap();
    assert!(Arc::ptr_eq(&single, cached[0].as_ref().unwrap()));
    let batch = source.load_shared_content_objects(&ids).unwrap();
    assert_eq!(batch.len(), ids.len());
    for (actual, expected) in batch.iter().zip(&cached) {
        assert!(Arc::ptr_eq(
            actual.as_ref().unwrap(),
            expected.as_ref().unwrap()
        ));
    }
    let resident_before_bob = engine.object_cache_stats().resident_record_bytes;
    let bob_cached = engine.shared_objects_for(&bob, &ids).unwrap();
    let bob_source = TreeContext::new(&engine, &bob);
    let bob_batch = bob_source.load_shared_content_objects(&ids).unwrap();
    for ((actual, expected), alice_record) in bob_batch.iter().zip(&bob_cached).zip(&cached) {
        assert!(Arc::ptr_eq(
            actual.as_ref().unwrap(),
            expected.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            actual.as_ref().unwrap(),
            alice_record.as_ref().unwrap()
        ));
    }
    assert!(engine.object_cache_principal_charge(&alice) > 0);
    assert_eq!(
        engine.object_cache_principal_charge(&alice),
        engine.object_cache_principal_charge(&bob)
    );
    assert_eq!(
        engine.object_cache_stats().resident_record_bytes,
        resident_before_bob
    );
    let mut mixed = TreeContext::new(&engine, &alice);
    assert_mixed_content_batch(&mut mixed, ids[0], cached[0].as_ref().unwrap());
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn shared_content_reads_committed_wal_before_and_after_fold() {
    use crate::engine::{
        DurableEngine, DurableEnginePolicy, GroupCommitPolicy, ObjectCacheConfig, RecoveryLimits,
        RecoveryRetryPolicy, TransactionWalPolicy,
    };
    use crate::kv::tree::header::TreeHeader;
    use crate::kv::tree_tests::Utf8Codec;
    use std::num::NonZeroU64;

    let directory = tempfile::tempdir().unwrap();
    let policy = DurableEnginePolicy::new(
        GroupCommitPolicy::immediate(),
        RecoveryRetryPolicy::immediate(),
        ObjectCacheConfig::disabled(),
    )
    .with_transaction_wal(TransactionWalPolicy::enabled(
        NonZeroU64::new(u64::MAX).unwrap(),
    ));
    let engine = DurableEngine::open_with_policy(
        directory.path(),
        TestIdentity,
        Utf8Codec,
        RecoveryLimits::process_addressable(),
        policy,
    )
    .unwrap();
    let principal = "alice".to_owned();
    let mut pending = TreeContext::new(&engine, &principal);
    let value = pending.make_value(bytes().into()).unwrap();
    let ids: Vec<_> = pending
        .records
        .iter()
        .filter_map(|(id, record)| (record.kind() == ObjectKind::Chunk).then_some(*id))
        .collect();
    let root = pending
        .build_sorted(vec![(
            b"alice:capsule:ownership\0wal-content".to_vec(),
            bytes(),
        )])
        .unwrap();
    engine
        .commit(
            pending
                .finish(TreeHeader::empty(principal.clone()), root)
                .unwrap(),
        )
        .unwrap();
    assert!(ids.len() > 1);
    for folded in [false, true] {
        if folded {
            engine.flush().unwrap();
        }
        let context = TreeContext::new(&engine, &principal);
        // Single ContentSource loads precede any batch and cache is disabled.
        for id in &ids {
            let expected = engine.object(*id).unwrap().unwrap();
            assert_eq!(
                context.load_shared_content_object(*id).unwrap().as_deref(),
                Some(&expected)
            );
        }
        assert_eq!(context.value_bytes(&value).unwrap(), bytes());
        let batch = context.load_shared_content_objects(&ids).unwrap();
        assert_eq!(batch.len(), ids.len());
        assert!(batch.iter().all(Option::is_some));
    }
}

fn assert_mixed_content_batch<P: Ord, E: KvProjectionEngine<P>>(
    context: &mut TreeContext<'_, P, E>,
    committed: ObjectId,
    cached: &std::sync::Arc<ObjectRecord>,
) {
    let (local, record) = build_content(context, PROFILE, b"transaction-local content")
        .unwrap()
        .into_records()
        .into_iter()
        .find(|(_, record)| record.kind() == ObjectKind::Chunk)
        .unwrap();
    assert_ne!(local, committed);
    context.insert(record.clone()).unwrap();
    let batch = context
        .load_shared_content_objects(&[local, committed, committed, local])
        .unwrap();
    assert_eq!(batch.len(), 4);
    assert_eq!(batch[0].as_deref(), Some(&record));
    assert_eq!(batch[3].as_deref(), Some(&record));
    assert!(
        std::sync::Arc::ptr_eq(batch[0].as_ref().unwrap(), batch[3].as_ref().unwrap(),),
        "duplicate transaction-local content shares one allocation"
    );
    assert!(std::sync::Arc::ptr_eq(batch[1].as_ref().unwrap(), cached));
    assert!(std::sync::Arc::ptr_eq(batch[2].as_ref().unwrap(), cached));
    let missing = context
        .engine
        .identify_kv_object(&value_record(b"not inserted".to_vec()).unwrap());
    assert!(context.load_shared_content_object(missing).is_err());
    assert!(
        context
            .load_shared_content_objects(&[local, missing, committed])
            .is_err()
    );
}

#[test]
fn chunked_value_round_trip_stays_transaction_local() {
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    let bytes = bytes();
    let value = context.make_value(bytes.clone().into()).unwrap();
    assert_eq!(context.value_bytes(&value).unwrap(), bytes);
    assert_eq!(
        engine.object_count(),
        0,
        "building content must not publish it"
    );
}

#[test]
fn old_large_opaque_value_remains_readable() {
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    let bytes = bytes();
    let object = context
        .insert(value_record(bytes.clone()).unwrap())
        .unwrap();
    let value = ValueSlot::Spilled {
        object,
        length: bytes.len() as u64,
    };
    assert_eq!(context.value_bytes(&value).unwrap(), bytes);
}

#[test]
fn chunked_value_rejects_malformed_wrapper_and_descriptor() {
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    let value = context.make_value(bytes().into()).unwrap();
    let ValueSlot::Spilled { object, length } = value else {
        panic!("large value must spill")
    };
    let record = context.record(object).unwrap();
    let variants = malformed_wrappers(&record, length);
    for (bad, declared) in variants {
        let id = context.insert(bad).unwrap();
        assert!(
            context
                .value_bytes(&ValueSlot::Spilled {
                    object: id,
                    length: declared
                })
                .is_err()
        );
    }
    context.records.remove(&record.references()[0].target());
    assert!(
        context.value_bytes(&value).is_err(),
        "missing file must fail closed"
    );
}

fn malformed_wrappers(record: &ObjectRecord, length: u64) -> [(ObjectRecord, u64); 8] {
    let reference = record.references()[0].clone();
    let wrong_reference =
        ObjectReference::owns(ReferenceLabel::new(b"wrong".to_vec()), reference.target());
    let evidence = ObjectReference::new(
        reference.label().clone(),
        reference.target(),
        ReferenceKind::Evidence,
    );
    [
        (
            ObjectKind::File,
            ObjectClass::Data,
            0,
            length.to_le_bytes().to_vec(),
            vec![reference.clone()],
            length,
        ),
        (
            ObjectKind::KvLeaf,
            ObjectClass::Metadata,
            0,
            length.to_le_bytes().to_vec(),
            vec![reference.clone()],
            length,
        ),
        (
            ObjectKind::KvLeaf,
            ObjectClass::Data,
            1,
            length.to_le_bytes().to_vec(),
            vec![reference.clone()],
            length,
        ),
        (
            ObjectKind::KvLeaf,
            ObjectClass::Data,
            0,
            vec![0; 7],
            vec![reference.clone()],
            length,
        ),
        (
            ObjectKind::KvLeaf,
            ObjectClass::Data,
            0,
            length.to_le_bytes().to_vec(),
            vec![],
            length,
        ),
        (
            ObjectKind::KvLeaf,
            ObjectClass::Data,
            0,
            length.to_le_bytes().to_vec(),
            vec![wrong_reference],
            length,
        ),
        (
            ObjectKind::KvLeaf,
            ObjectClass::Data,
            0,
            length.to_le_bytes().to_vec(),
            vec![evidence],
            length,
        ),
        (
            ObjectKind::KvLeaf,
            ObjectClass::Data,
            0,
            (length.strict_add(1)).to_le_bytes().to_vec(),
            vec![reference],
            length.strict_add(1),
        ),
    ]
    .map(|(kind, class, logical, canonical, references, length)| {
        (
            ObjectRecord::new(
                kind,
                CHUNKED_VALUE_VERSION,
                canonical,
                references,
                logical,
                class,
            )
            .unwrap(),
            length,
        )
    })
}

#[test]
fn chunked_value_verifies_content_boundaries() {
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    // These chunks have consistent lengths and tree summaries, but the first
    // ignores an earlier FastCDC boundary. Opening the descriptor alone is
    // insufficient: the full canonical-boundary verifier must reject them.
    let bytes = bytes();
    let length = bytes.len() as u64;
    let file = noncanonical_file(&mut context, &bytes);
    assert!(open_content(&context, file).is_ok());
    let object = context
        .insert(
            ObjectRecord::new(
                ObjectKind::KvLeaf,
                CHUNKED_VALUE_VERSION,
                length.to_le_bytes().to_vec(),
                vec![ObjectReference::owns(
                    ReferenceLabel::new(CONTENT_LABEL.to_vec()),
                    file,
                )],
                0,
                ObjectClass::Data,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        context
            .value_bytes(&ValueSlot::Spilled { object, length })
            .is_err()
    );
}

fn noncanonical_file(
    context: &mut TreeContext<'_, String, InMemoryEngine<String, TestIdentity>>,
    bytes: &[u8],
) -> ObjectId {
    let mut canonical = 2_u16.to_le_bytes().to_vec();
    canonical.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    canonical.extend_from_slice(&2_u64.to_le_bytes());
    let mut references = Vec::new();
    for (index, chunk) in bytes.chunks(256 * 1024).enumerate() {
        let object = context
            .insert(
                ObjectRecord::new(
                    ObjectKind::Chunk,
                    crate::content_dag::FORMAT_VERSION,
                    chunk.to_vec(),
                    vec![],
                    0,
                    ObjectClass::Data,
                )
                .unwrap(),
            )
            .unwrap();
        canonical.extend_from_slice(&(chunk.len() as u64).to_le_bytes());
        canonical.extend_from_slice(&1_u64.to_le_bytes());
        references.push(ObjectReference::owns(
            ReferenceLabel::new(u16::try_from(index).unwrap().to_be_bytes().to_vec()),
            object,
        ));
    }
    let tree = context
        .insert(
            ObjectRecord::new(
                ObjectKind::ChunkTree,
                crate::content_dag::FORMAT_VERSION,
                canonical,
                references,
                0,
                ObjectClass::Metadata,
            )
            .unwrap(),
        )
        .unwrap();
    context
        .insert(
            ObjectRecord::new(
                ObjectKind::File,
                crate::content_dag::FORMAT_VERSION,
                crate::content_dag::encode_file_header(PROFILE, bytes.len() as u64, 2),
                vec![ObjectReference::owns(
                    ReferenceLabel::new(CONTENT_LABEL.to_vec()),
                    tree,
                )],
                0,
                ObjectClass::Metadata,
            )
            .unwrap(),
        )
        .unwrap()
}

#[test]
fn root_conflict_after_chunk_build_admits_no_content() {
    use crate::kv::tree::header::TreeHeader;
    use crate::storage_model::ModelError;
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    let root = context
        .build_sorted(vec![(b"alice:capsule:ownership\0graph".to_vec(), bytes())])
        .unwrap();
    let pending = context
        .finish(TreeHeader::empty(principal.clone()), root)
        .unwrap();
    assert_eq!(engine.object_count(), 0);
    let mut context = TreeContext::new(&engine, &principal);
    let root = context
        .build_sorted(vec![(
            b"alice:capsule:ownership\0other".to_vec(),
            b"competing".to_vec(),
        )])
        .unwrap();
    let competing = context
        .finish(TreeHeader::empty(principal.clone()), root)
        .unwrap();
    let committed = engine.commit(competing).unwrap().root();
    let count = engine.object_count();
    assert!(matches!(
        engine.commit(pending),
        Err(ModelError::RootConflict { .. })
    ));
    assert_eq!(engine.object_count(), count);
    assert_eq!(engine.root(&principal), Some(committed));
}

#[test]
fn spilled_value_encoding_thresholds_are_pinned() {
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    for (length, version) in [
        (1024, None),
        (1025, Some(4)),
        (262_144, Some(4)),
        (262_145, Some(5)),
    ] {
        let mut context = TreeContext::new(&engine, &principal);
        let bytes = vec![0x55; length];
        let value = context.make_value(bytes.clone().into()).unwrap();
        let actual = match value {
            ValueSlot::Inline(_) => None,
            ValueSlot::Spilled { object, .. } => {
                Some(context.record(object).unwrap().format_version().get())
            },
        };
        assert_eq!(actual, version, "encoding for {length} visible bytes");
        assert_eq!(context.value_bytes(&value).unwrap(), bytes);
    }
}
