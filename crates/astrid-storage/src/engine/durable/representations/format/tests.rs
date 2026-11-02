use super::*;

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

const PHYSICAL_CONTEXTS: &[&str] = &[
    LEGACY_MAP_CONTEXT,
    RADIX_MAP_CONTEXT,
    "astrid-representation-admission-subject-v1\0",
    "astrid-representation-admission-transcript-v1\0",
    "astrid-placement-set-v1\0",
    "astrid-representation-state-v1\0",
    "astrid-representation-catalogue-root-v1\0",
    "astrid-blob-identity-v1\0",
    "astrid-representation-record-v1\0",
    "astrid-representation-profile-v1\0",
    "astrid-representation-journal-bytes-v1\0",
    "unknown-successor-physical-context\0",
    "astrid-physical-map-node-v1",
    "astrid-physical-radix-map-node-v1",
];

#[test]
fn physical_identity_preserves_derive_key_bytes_and_segment_boundaries() {
    for &context in PHYSICAL_CONTEXTS {
        for length in [0, 1, 63, 64, 65, 1023, 1024, 1025, 65_537] {
            let material: Vec<_> = (0..length)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();
            let expected = blake3::derive_key(context, &material);
            assert_eq!(
                Blake3PhysicalIdentity.identify(context, &material),
                expected
            );
            for split in [0, length / 2, length.min(64), length.min(1024), length] {
                let parts = [
                    &[][..],
                    &material[..split],
                    &[][..],
                    &material[split..],
                    &[][..],
                ];
                assert_eq!(
                    Blake3PhysicalIdentity.identify_parts(context, &parts),
                    expected
                );
            }
        }
        assert_eq!(
            Blake3PhysicalIdentity.identify_parts(context, &[]),
            blake3::derive_key(context, &[])
        );
    }
}

#[test]
fn map_identity_reuses_actual_derive_key_initialization() {
    for context in [LEGACY_MAP_CONTEXT, RADIX_MAP_CONTEXT] {
        PHYSICAL_HASHER_INITIALIZATIONS.with(|count| count.set(0));
        for material in [b"first".as_slice(), b"", b"different material"] {
            Blake3PhysicalIdentity.identify(context, material);
            Blake3PhysicalIdentity.identify_parts(context, &[material]);
        }
        // Another test may already have initialized the process-wide template.
        // Thread-local counting excludes unrelated concurrent fallback calls.
        assert!(PHYSICAL_HASHER_INITIALIZATIONS.with(std::cell::Cell::get) <= 1);
    }
    PHYSICAL_HASHER_INITIALIZATIONS.with(|count| count.set(0));
    for _ in 0..6 {
        Blake3PhysicalIdentity.identify("uncached-context-control\0", b"control");
    }
    assert_eq!(
        PHYSICAL_HASHER_INITIALIZATIONS.with(std::cell::Cell::get),
        6
    );
}

struct UncachedPhysicalIdentity;

impl PhysicalIdentity for UncachedPhysicalIdentity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, material)
    }
}

#[test]
fn cached_physical_identity_preserves_actual_canonical_map_roots_and_nodes() {
    use crate::storage_model::{CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapKey};

    for domain in [
        PhysicalMapDomain::Profile,
        PhysicalMapDomain::Representation,
        PhysicalMapDomain::Placement,
    ] {
        PHYSICAL_HASHER_INITIALIZATIONS.with(|count| count.set(0));
        let entries: Vec<_> = (0_u8..32)
            .map(|index| (PhysicalMapKey::new([index; 32]), vec![index; 129]))
            .collect();
        let legacy =
            CanonicalPhysicalMap::build(&Blake3PhysicalIdentity, domain, entries.clone()).unwrap();
        let expected_legacy =
            CanonicalPhysicalMap::build(&UncachedPhysicalIdentity, domain, entries.clone())
                .unwrap();
        let radix =
            CanonicalPhysicalMap::build_dense(&Blake3PhysicalIdentity, domain, entries.clone())
                .unwrap();
        let expected_radix =
            CanonicalPhysicalMap::build_dense(&UncachedPhysicalIdentity, domain, entries).unwrap();
        assert!(
            PHYSICAL_HASHER_INITIALIZATIONS.with(std::cell::Cell::get) <= 2,
            "actual map contexts must select the two reusable templates"
        );
        for (actual, expected) in [(legacy, expected_legacy), (radix, expected_radix)] {
            assert_eq!(actual.root(), expected.root());
            assert_eq!(actual.nodes(), expected.nodes());
            for (id, node) in actual.nodes() {
                assert_eq!(*id, node.identify(&UncachedPhysicalIdentity).unwrap());
            }
        }
    }
}
