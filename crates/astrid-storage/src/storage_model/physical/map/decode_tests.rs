use super::decode::MapNodeView;
use super::*;
use core::cell::Cell;

struct Identity(Cell<usize>);

impl PhysicalIdentity for Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        self.0.set(self.0.get().strict_add(1));
        blake3::derive_key(context, material)
    }
}

fn assert_borrowed(bytes: &[u8], borrowed: &[u8]) {
    let start = bytes.as_ptr() as usize;
    let pointer = borrowed.as_ptr() as usize;
    assert!(pointer >= start);
    assert!(pointer.strict_add(borrowed.len()) <= start.strict_add(bytes.len()));
}

#[test]
fn borrowed_map_decode_keeps_values_and_prefixes_in_the_original_payload() {
    let identity = Identity(Cell::new(0));
    let mut seen = [false; 4];
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
            for (expected, owned) in map.nodes() {
                let bytes = owned.encode().unwrap();
                super::super::codec::reset_encoder_finishes();
                let mut expected_children = Vec::new();
                decode::with_decoded(&bytes, |view| {
                    match &view {
                        MapNodeView::Leaf { value, .. } => {
                            seen[0] = true;
                            assert_borrowed(&bytes, value);
                        },
                        MapNodeView::Branch {
                            prefix, zero, one, ..
                        } => {
                            seen[1] = true;
                            assert_borrowed(&bytes, prefix);
                            expected_children.extend([*zero, *one]);
                        },
                        MapNodeView::Page { entries, .. } => {
                            seen[2] = true;
                            assert_eq!(entries.len(), 1);
                            assert_borrowed(&bytes, entries[0].1);
                        },
                        MapNodeView::Radix {
                            prefix, children, ..
                        } => {
                            seen[3] = true;
                            assert_borrowed(&bytes, prefix);
                            expected_children.extend_from_slice(children);
                        },
                    }
                    assert_eq!(&decode::into_owned(view).unwrap(), owned);
                })
                .unwrap();
                let calls = identity.0.get();
                let (children, computed) = PhysicalMapNode::with_child_ids_and_identify(
                    &bytes,
                    &identity,
                    |id, children| (children.to_vec(), id),
                )
                .unwrap();
                assert_eq!(identity.0.get(), calls.strict_add(1));
                assert_eq!(&computed, expected);
                assert_eq!(&*children, expected_children);
                assert_eq!(PhysicalMapNode::decode(&bytes).unwrap(), *owned);
                assert_eq!(
                    super::super::codec::encoder_finishes(),
                    0,
                    "canonical decoding and identity must not materialize another encoded value"
                );
                for end in 0..bytes.len() {
                    let truncated = &bytes[..end];
                    assert!(decode::with_decoded(truncated, |_| ()).is_err());
                }
            }
        }
    }
    assert_eq!(seen, [true; 4]);
}

fn assert_rejected(bytes: &[u8]) {
    let identity = Identity(Cell::new(0));
    let owned = PhysicalMapNode::decode(bytes).unwrap_err();
    let borrowed = decode::with_decoded(bytes, |_| ()).unwrap_err();
    assert_eq!(format!("{owned:?}"), format!("{borrowed:?}"));
    assert!(PhysicalMapNode::with_child_ids_and_identify(bytes, &identity, |_, _| ()).is_err());
    assert_eq!(
        identity.0.get(),
        0,
        "malformed input must never reach identity authentication"
    );
}

#[test]
fn borrowed_decode_preserves_version_domain_tags_and_canonical_prefix_rejections() {
    let zero = PhysicalMapNodeId::new([1; 32]);
    let one = PhysicalMapNodeId::new([2; 32]);
    let domain = PhysicalMapDomain::Placement;
    let branch = PhysicalMapNode::branch(domain, 1, vec![0x80], zero, one, 2).unwrap();
    let page = PhysicalMapNode::page(domain, vec![(PhysicalMapKey::new([3; 32]), vec![])]).unwrap();
    let radix = PhysicalMapNode::radix(domain, 1, vec![0x80], 3, vec![zero, one], 2).unwrap();
    for node in [branch, page, radix] {
        let bytes = node.encode().unwrap();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_rejected(&trailing);
        for (offset, replacement) in [(0, 255), (2, 255), (3, 255)] {
            let mut invalid = bytes.clone();
            invalid[offset] = replacement;
            assert_rejected(&invalid);
        }
    }
    for prefix_bits in [0, 1, SEARCH_KEY_BITS - 1] {
        let prefix = vec![0; legacy::prefix_byte_len(prefix_bits).unwrap()];
        let node = PhysicalMapNode::branch(domain, prefix_bits, prefix, zero, one, 2).unwrap();
        assert!(PhysicalMapNode::decode(&node.encode().unwrap()).is_ok());
    }
    for prefix_nibbles in [0, 1, 62, 63] {
        for count in [2_u32, 16] {
            let children = (0..count)
                .map(|i| PhysicalMapNodeId::new([u8::try_from(i).unwrap(); 32]))
                .collect();
            let bitmap = if count == 16 { u16::MAX } else { 3 };
            let node = PhysicalMapNode::radix(
                domain,
                prefix_nibbles,
                vec![0; nibble_prefix_byte_len(prefix_nibbles)],
                bitmap,
                children,
                u64::from(count),
            )
            .unwrap();
            let bytes = node.encode().unwrap();
            assert!(
                PhysicalMapNode::with_child_ids_and_identify(
                    &bytes,
                    &Identity(Cell::new(0)),
                    |_, _| ()
                )
                .is_ok()
            );
        }
    }
}

#[test]
fn borrowed_decode_rejects_aliases_impossible_counts_and_unused_prefix_bits() {
    let domain = PhysicalMapDomain::Representation;
    let id = PhysicalMapNodeId::new([1; 32]);
    let other = PhysicalMapNodeId::new([2; 32]);
    let invalid = [
        PhysicalMapNode::Branch {
            domain,
            prefix_bits: 1,
            prefix: vec![0x81],
            zero: id,
            one: other,
            subtree_entries: 2,
        },
        PhysicalMapNode::Branch {
            domain,
            prefix_bits: 0,
            prefix: vec![],
            zero: id,
            one: id,
            subtree_entries: 2,
        },
        PhysicalMapNode::Branch {
            domain,
            prefix_bits: 0,
            prefix: vec![],
            zero: id,
            one: other,
            subtree_entries: 1,
        },
        PhysicalMapNode::Page {
            domain,
            entries: vec![],
        },
        PhysicalMapNode::Page {
            domain,
            entries: vec![(PhysicalMapKey::new([0; 32]), vec![]); 2],
        },
        PhysicalMapNode::Radix {
            domain,
            prefix_nibbles: 1,
            prefix: vec![1],
            child_bitmap: 3,
            children: vec![id, other],
            subtree_entries: 2,
        },
        PhysicalMapNode::Radix {
            domain,
            prefix_nibbles: 64,
            prefix: vec![0; 32],
            child_bitmap: 3,
            children: vec![id, other],
            subtree_entries: 2,
        },
        PhysicalMapNode::Radix {
            domain,
            prefix_nibbles: 0,
            prefix: vec![],
            child_bitmap: 3,
            children: vec![id, id],
            subtree_entries: 2,
        },
        PhysicalMapNode::Radix {
            domain,
            prefix_nibbles: 0,
            prefix: vec![],
            child_bitmap: 1,
            children: vec![id],
            subtree_entries: 2,
        },
        PhysicalMapNode::Radix {
            domain,
            prefix_nibbles: 0,
            prefix: vec![],
            child_bitmap: 3,
            children: vec![id, other],
            subtree_entries: 1,
        },
    ];
    for node in invalid {
        assert_rejected(&node.encode().unwrap());
    }
}

#[test]
fn canonical_node_wire_vectors_cover_owned_and_borrowed_encoders() {
    let domain = PhysicalMapDomain::Representation;
    let key = PhysicalMapKey::new([0x11; 32]);
    let zero = PhysicalMapNodeId::new([0x22; 32]);
    let one = PhysicalMapNodeId::new([0x33; 32]);
    let nodes = [
        PhysicalMapNode::leaf(domain, key, b"abc".to_vec()),
        PhysicalMapNode::branch(domain, 1, vec![0x80], zero, one, 2).unwrap(),
        PhysicalMapNode::page(domain, vec![(key, b"abc".to_vec())]).unwrap(),
        PhysicalMapNode::radix(domain, 1, vec![0x80], 3, vec![zero, one], 2).unwrap(),
    ];
    // Frozen format-one and format-two bytes, independent of either encoder.
    let vectors = [
        "01000100010002002000000011111111111111111111111111111111111111111111111111111111111111110300000000000000616263",
        "01000101010000008001000200200000002222222222222222222222222222222222222222222222222222222222222222010002002000000033333333333333333333333333333333333333333333333333333333333333330200000000000000",
        "0200010001010002002000000011111111111111111111111111111111111111111111111111111111111111110300000000000000616263",
        "020001010180030001000200200000002222222222222222222222222222222222222222222222222222222222222222010002002000000033333333333333333333333333333333333333333333333333333333333333330200000000000000",
    ];
    for (node, vector) in nodes.into_iter().zip(vectors) {
        let expected = hex::decode(vector).unwrap();
        assert_eq!(node.encode().unwrap(), expected);
        let actual = decode::with_decoded(&expected, |view| {
            let mut encoder = Encoder::new();
            view.encode_into(&mut encoder).unwrap();
            encoder.finish()
        })
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(PhysicalMapNode::decode(&expected).unwrap(), node);
    }
}
