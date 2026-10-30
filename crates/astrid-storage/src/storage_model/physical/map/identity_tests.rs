use super::*;
use core::cell::Cell;

struct Identity;

impl PhysicalIdentity for Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, material)
    }
}

struct BorrowedIdentity<'a> {
    bytes: &'a [u8],
    context: &'static str,
    calls: Cell<usize>,
}

impl PhysicalIdentity for BorrowedIdentity<'_> {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        assert_eq!(context, self.context);
        assert_eq!(material, self.bytes);
        assert_eq!(material.as_ptr(), self.bytes.as_ptr());
        self.calls.set(self.calls.get().strict_add(1));
        Identity.identify(context, material)
    }
}

#[test]
fn canonical_node_identity_borrows_validated_bytes_for_every_construction_and_domain() {
    let mut variants = [false; 4];
    for domain in [
        PhysicalMapDomain::Profile,
        PhysicalMapDomain::Representation,
        PhysicalMapDomain::Placement,
    ] {
        let entries: Vec<_> = (0_u8..16)
            .map(|ordinal| (PhysicalMapKey::new([ordinal; 32]), vec![ordinal; 128]))
            .collect();
        let maps = [
            CanonicalPhysicalMap::build(&Identity, domain, entries.clone()).unwrap(),
            CanonicalPhysicalMap::build_dense(&Identity, domain, entries).unwrap(),
        ];
        for map in maps {
            for (expected_id, node) in map.nodes() {
                let (variant, context) = match node {
                    PhysicalMapNode::Leaf { .. } => (0, "astrid-physical-map-node-v1\0"),
                    PhysicalMapNode::Branch { .. } => (1, "astrid-physical-map-node-v1\0"),
                    PhysicalMapNode::Page { .. } => (2, "astrid-physical-radix-map-node-v1\0"),
                    PhysicalMapNode::Radix { .. } => (3, "astrid-physical-radix-map-node-v1\0"),
                };
                variants[variant] = true;
                let bytes = node.encode().unwrap();
                let identity = BorrowedIdentity {
                    bytes: &bytes,
                    context,
                    calls: Cell::new(0),
                };
                super::super::codec::reset_encoder_finishes();
                let (decoded, id) =
                    PhysicalMapNode::decode_and_identify(&bytes, &identity).unwrap();
                assert_eq!(
                    super::super::codec::encoder_finishes(),
                    0,
                    "decode allocated a roundtrip encoding"
                );
                assert_eq!(&decoded, node);
                assert_eq!(&id, expected_id);
                assert_eq!(id, node.identify(&Identity).unwrap());
                assert_eq!(
                    super::super::codec::encoder_finishes(),
                    1,
                    "identify must still encode its owned node"
                );
                assert_eq!(identity.calls.get(), 1);
            }
        }
    }
    assert_eq!(variants, [true; 4]);
}

#[test]
fn canonical_node_identity_rejects_invalid_bytes_before_hashing() {
    let node = PhysicalMapNode::branch(
        PhysicalMapDomain::Representation,
        1,
        vec![0x80],
        PhysicalMapNodeId::new([1; 32]),
        PhysicalMapNodeId::new([2; 32]),
        2,
    )
    .unwrap();
    let canonical = node.encode().unwrap();
    let mut trailing = canonical.clone();
    trailing.push(0);
    let mut noncanonical = canonical.clone();
    // Version (2), domain (1), branch tag (1), prefix bit count (4).
    // The seven unused prefix bits must be zero.
    noncanonical[8] |= 1;
    let mut wrong_version = canonical.clone();
    wrong_version[..2].copy_from_slice(&u16::MAX.to_le_bytes());
    for bytes in [
        canonical[..canonical.len().strict_sub(1)].to_vec(),
        trailing,
        noncanonical,
        wrong_version,
    ] {
        assert!(PhysicalMapNode::decode(&bytes).is_err());
        let identity = BorrowedIdentity {
            bytes: &bytes,
            context: "astrid-physical-map-node-v1\0",
            calls: Cell::new(0),
        };
        assert!(PhysicalMapNode::decode_and_identify(&bytes, &identity).is_err());
        assert_eq!(identity.calls.get(), 0);
    }
}
