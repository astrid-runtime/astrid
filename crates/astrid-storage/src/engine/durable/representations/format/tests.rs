use super::*;

#[test]
fn map_node_metadata_encodes_the_identified_payload_once() {
    use crate::storage_model::{CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapKey};

    let identity = Blake3PhysicalIdentity;
    let mut variants = [false; 4];
    for domain in [
        PhysicalMapDomain::Profile,
        PhysicalMapDomain::Representation,
        PhysicalMapDomain::Placement,
    ] {
        let entries: Vec<_> = (0_u8..16)
            .map(|index| (PhysicalMapKey::new([index; 32]), vec![index; 4096]))
            .collect();
        for map in [
            CanonicalPhysicalMap::build(&identity, domain, entries.clone()).unwrap(),
            CanonicalPhysicalMap::build_dense(&identity, domain, entries).unwrap(),
        ] {
            for (expected_id, node) in map.nodes() {
                let expected_bytes = node.encode().unwrap();
                let (variant, context) = match node {
                    PhysicalMapNode::Leaf { .. } => (0, "astrid-physical-map-node-v1\0"),
                    PhysicalMapNode::Branch { .. } => (1, "astrid-physical-map-node-v1\0"),
                    PhysicalMapNode::Page { .. } => (2, "astrid-physical-radix-map-node-v1\0"),
                    PhysicalMapNode::Radix { .. } => (3, "astrid-physical-radix-map-node-v1\0"),
                };
                let (frame, encodings) = PhysicalMapNode::count_encodings_during(|| {
                    MetadataFrame::map_node(&identity, node).unwrap()
                });
                assert_eq!(encodings, 1, "metadata must retain the identified bytes");
                assert_eq!(frame.kind, MetadataKind::MapNode);
                assert_eq!(frame.identity, *expected_id.as_bytes());
                assert_eq!(frame.identity, blake3::derive_key(context, &expected_bytes));
                assert_eq!(frame.value, expected_bytes);
                frame.verify(&identity).unwrap();
                let encoded = frame.encode().unwrap();
                assert_eq!(MetadataFrame::decode(&encoded).unwrap().value, frame.value);
                variants[variant] = true;
            }
        }
    }
    assert_eq!(variants, [true; 4]);
}

// Frozen pre-borrowing decoder: re-encoding is the canonicality oracle, not a
// second production parser. Compare acceptance and bytes under malformed input.
fn owned_reference(bytes: &[u8]) -> Result<MetadataFrame, DurableError> {
    let mut reader = Reader::new(bytes);
    let kind = MetadataKind::decode(reader.u8()?)?;
    let identity = reader.physical_identity()?;
    let value = reader.length_prefixed()?.to_vec();
    reader.finish()?;
    let frame = MetadataFrame::new(kind, identity, value);
    if frame.encode()?.as_slice() != bytes {
        return Err(DurableError::InvalidRepresentationState(
            "metadata frame is not canonical",
        ));
    }
    Ok(frame)
}

fn compare_decoders(bytes: &[u8]) {
    let old = owned_reference(bytes);
    let borrowed = MetadataFrame::decode(bytes);
    assert_eq!(
        old.is_ok(),
        borrowed.is_ok(),
        "acceptance differs: {bytes:?}"
    );
    if let (Ok(old), Ok(borrowed)) = (old, borrowed) {
        assert_eq!(old.kind, borrowed.kind);
        assert_eq!(old.identity, borrowed.identity);
        assert_eq!(old.value, borrowed.value);
        assert_eq!(borrowed.encode().unwrap(), bytes);
    }
}

#[test]
fn metadata_decode_borrows_original_payload() {
    let frame = MetadataFrame::new(MetadataKind::MapNode, [7; 32], vec![42; 4096]);
    let bytes = frame.encode().unwrap();
    let decoded = MetadataFrame::decode(&bytes).unwrap();
    assert_eq!(decoded.kind, frame.kind);
    assert_eq!(decoded.identity, frame.identity);
    assert_eq!(decoded.value, frame.value.as_slice());
    assert_eq!(
        decoded.value.as_ptr(),
        bytes[bytes.len() - frame.value.len()..].as_ptr(),
        "recovery must borrow the original outer-frame payload"
    );
}

#[test]
fn metadata_decode_preserves_canonical_frame_language() {
    for kind in [
        MetadataKind::Profile,
        MetadataKind::Representation,
        MetadataKind::MapNode,
        MetadataKind::Catalogue,
        MetadataKind::Placement,
        MetadataKind::State,
    ] {
        let original = MetadataFrame::new(kind, [7; 32], vec![42; 3])
            .encode()
            .unwrap();
        compare_decoders(&original);
        for end in 0..original.len() {
            compare_decoders(&original[..end]);
            assert!(MetadataFrame::decode(&original[..end]).is_err());
        }
        let mut trailing = original.clone();
        trailing.push(0);
        compare_decoders(&trailing);
        assert!(MetadataFrame::decode(&trailing).is_err());
        // Exhaust every possible byte in the kind, tagged identity and length,
        // including unknown tags, wrong digest width and unrepresentable size.
        for offset in 0..original.len() - 3 {
            for byte in u8::MIN..=u8::MAX {
                let mut mutated = original.clone();
                mutated[offset] = byte;
                compare_decoders(&mutated);
            }
        }
        let mut overflow = original.clone();
        overflow[41..49].fill(u8::MAX);
        compare_decoders(&overflow);
        assert!(MetadataFrame::decode(&overflow).is_err());
    }
    for length in [0, 1, 127, 4096] {
        let bytes = MetadataFrame::new(MetadataKind::Profile, [0; 32], vec![0; length])
            .encode()
            .unwrap();
        compare_decoders(&bytes);
    }
}
