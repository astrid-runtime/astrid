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
fn chunked_value_round_trip_stays_transaction_local() {
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    let bytes = bytes();
    let value = context.make_value(bytes.clone()).unwrap();
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
    let value = context.make_value(bytes()).unwrap();
    let ValueSlot::Spilled { object, length } = value else {
        panic!("large value must spill")
    };
    let record = context.record(object).unwrap();
    let variants = malformed_wrappers(&record, length);
    for (bad, declared) in variants {
        let id = context.insert(bad).unwrap();
        let value = ValueSlot::Spilled {
            object: id,
            length: declared,
        };
        let read = context.value_bytes(&value).unwrap_err().to_string();
        let (validation, output) =
            crate::content_dag::output_measurement::measure(|| context.validate_value(&value));
        assert_eq!(validation.unwrap_err().to_string(), read);
        assert_eq!(output.reserved, 0);
        assert_eq!(output.written, 0, "wrapper errors precede traversal");
    }
    context.records.remove(&record.references()[0].target());
    assert_eq!(
        context.validate_value(&value).unwrap_err().to_string(),
        context.value_bytes(&value).unwrap_err().to_string(),
        "missing file must fail closed with the same error"
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
    let value = ValueSlot::Spilled { object, length };
    let error = context.value_bytes(&value).unwrap_err().to_string();
    assert_eq!(
        context.validate_value(&value).unwrap_err().to_string(),
        error
    );
    let root = context
        .make_leaf_page(&[crate::kv::tree::node::LeafEntry {
            key: b"alice:capsule:ownership\0graph".to_vec(),
            value,
        }])
        .unwrap()
        .object;
    assert_eq!(
        context.validate_tree(Some(root)).unwrap_err().to_string(),
        error
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
        let value = context.make_value(bytes.clone()).unwrap();
        let actual = match value {
            ValueSlot::Inline(_) => None,
            ValueSlot::Spilled { object, .. } => {
                Some(context.record(object).unwrap().format_version().get())
            },
        };
        assert_eq!(actual, version, "encoding for {length} visible bytes");
        context.validate_value(&value).unwrap();
        assert_eq!(context.value_bytes(&value).unwrap(), bytes);
        let root = context
            .build_sorted(vec![(b"alice:capsule:ownership\0graph".to_vec(), bytes)])
            .unwrap();
        assert_eq!(context.validate_tree(root).unwrap().entries, 1);
    }
}

#[test]
fn tree_validation_does_not_reserve_discarded_value_output() {
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    let bytes = bytes();
    let key = b"alice:capsule:ownership\0graph".to_vec();
    let root = context
        .build_sorted(vec![(key.clone(), bytes.clone())])
        .unwrap();
    let (result, output) =
        crate::content_dag::output_measurement::measure(|| context.validate_tree(root));
    assert_eq!(result.unwrap().entries, 1);
    assert_eq!(output.written, bytes.len());
    assert_eq!(
        output.reserved, 0,
        "validation must not reconstruct and discard a whole value"
    );
    let (read, output) =
        crate::content_dag::output_measurement::measure(|| context.get(root, &key));
    assert_eq!(read.unwrap(), Some(bytes.clone()));
    assert_eq!(output.reserved, bytes.len());
    assert_eq!(output.written, bytes.len());
}

#[test]
fn opaque_validation_preserves_the_materializing_decoder_predicate() {
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    let record = value_record(vec![42; 2048]).unwrap();
    let valid = context.insert(record.clone()).unwrap();
    context
        .validate_value(&ValueSlot::Spilled {
            object: valid,
            length: 2048,
        })
        .unwrap();
    for (kind, version, class, logical, refs, length) in [
        (ObjectKind::File, 4, ObjectClass::Data, 0, vec![], 2048),
        (ObjectKind::KvLeaf, 3, ObjectClass::Data, 0, vec![], 2048),
        (
            ObjectKind::KvLeaf,
            4,
            ObjectClass::Metadata,
            0,
            vec![],
            2048,
        ),
        (ObjectKind::KvLeaf, 4, ObjectClass::Data, 1, vec![], 2048),
        (
            ObjectKind::KvLeaf,
            4,
            ObjectClass::Data,
            0,
            vec![ObjectReference::owns(
                ReferenceLabel::new(b"unexpected".to_vec()),
                valid,
            )],
            2048,
        ),
        (ObjectKind::KvLeaf, 4, ObjectClass::Data, 0, vec![], 2049),
        (ObjectKind::KvLeaf, 4, ObjectClass::Data, 0, vec![], 1024),
    ] {
        let object = context
            .insert(
                ObjectRecord::new(
                    kind,
                    ObjectFormatVersion::new(version).unwrap(),
                    if length == 1024 {
                        vec![42; 1024]
                    } else {
                        record.canonical_bytes().to_vec()
                    },
                    refs,
                    logical,
                    class,
                )
                .unwrap(),
            )
            .unwrap();
        let value = ValueSlot::Spilled { object, length };
        assert_eq!(
            context.validate_value(&value).unwrap_err().to_string(),
            context.value_bytes(&value).unwrap_err().to_string()
        );
    }
}

#[test]
fn chunked_validation_rejects_descriptor_profile_before_reading_content() {
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    let ValueSlot::Spilled { object, length } = context.make_value(bytes()).unwrap() else {
        panic!("large value must spill");
    };
    let wrapper = context.record(object).unwrap();
    let file = context.record(wrapper.references()[0].target()).unwrap();
    let profile = ChunkingProfile::fastcdc_v2020(16 * 1024, 64 * 1024, 256 * 1024, 1).unwrap();
    let (_, _, chunks) = crate::content_dag::decode_file_header(
        wrapper.references()[0].target(),
        file.canonical_bytes(),
    )
    .unwrap();
    let wrong_file = context
        .insert(
            ObjectRecord::new(
                file.kind(),
                file.format_version(),
                crate::content_dag::encode_file_header(profile, length, chunks),
                file.references().to_vec(),
                file.logical_bytes(),
                file.class(),
            )
            .unwrap(),
        )
        .unwrap();
    let object = context
        .insert(
            ObjectRecord::new(
                wrapper.kind(),
                wrapper.format_version(),
                wrapper.canonical_bytes().to_vec(),
                vec![ObjectReference::owns(
                    ReferenceLabel::new(CONTENT_LABEL.to_vec()),
                    wrong_file,
                )],
                wrapper.logical_bytes(),
                wrapper.class(),
            )
            .unwrap(),
        )
        .unwrap();
    let value = ValueSlot::Spilled { object, length };
    let (result, output) =
        crate::content_dag::output_measurement::measure(|| context.validate_value(&value));
    let error = result.unwrap_err().to_string();
    assert!(error.contains("descriptor disagrees with wrapper"));
    assert_eq!(error, context.value_bytes(&value).unwrap_err().to_string());
    assert_eq!(output.written, 0);
    assert_eq!(output.reserved, 0);
}
