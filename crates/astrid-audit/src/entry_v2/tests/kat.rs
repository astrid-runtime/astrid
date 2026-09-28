//! Known-answer test for the v2 byte format.
//!
//! These values are the contract with verifiers outside this crate. They
//! were also reproduced by an implementation written from the module docs
//! alone. Changing any of them is a format change.

use super::*;
use crate::entry_v2::{
    DecodedField, EntryV2Header, SECTION_ACTION, SECTION_AUTHORIZATION, SECTION_OUTCOME,
    signing_input, verify_entry_v2_body, verify_field_disclosure,
};

const KAT_AUDIT_PUBLIC: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const KAT_RUNTIME_PUBLIC: &str = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";
const KAT_GENESIS_BODY: &[&str] = &[
    "87781c6173747269642e61756469742e6b65792d72656769737472792e763200",
    "5820000000000000000000000000000000000000000000000000000000000000",
    "00001b18d953032f4c00000084820158208a88e3dd7409f195fd52db2d3cba5d",
    "72ca6709bf1d94121bf3748801b40f6f5c820258208139770ea87d175f56a354",
    "66c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394820358208139770ea87d17",
    "5f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39482045820813977",
    "0ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39480",
];
const KAT_REGISTRY_ID: &str = "6861a01ac38bbf60ef4f8dea9d663a64b6d522a742b6bc8b0f738469d505e82a";
/// Genesis signatures, sorted by key: the runtime key, then the audit key.
const KAT_GENESIS_SIGNATURES: [&str; 2] = [
    "2901ebc640af3015e4a0824e93e8645b00fb602fc689e6cb5a3708c7aa93c966\
     e11125eeddb7e51adb7e8ae39927712c2945582695f190e6d5d5014dbc999f05",
    "31bcc560a55222cdd2c2ff3f417733f5c689701e90333a2105df0c2c5f69d69d\
     29bda7cfff7b6381f775a7417d082f734367d563d51f900e5612c1725e9d990d",
];
const KAT_CHAIN_ID: &str = "748b16dd8b05e5237500376103842e628936b7858f8faa1557770519f26d0914";
const KAT_BODY: &[&str] = &[
    "8d756173747269642e61756469742e656e7472792e76325820748b16dd8b05e5",
    "237500376103842e628936b7858f8faa1557770519f26d091401582000000000",
    "000000000000000000000000000000000000000000000000000000001b18d97c",
    "3582a52d155000112233445566778899aabbccddeeff50010203040506070809",
    "0a0b0c0d0e0f1082582007070707070707070707070707070707070707070707",
    "0707070707070707070765616c6963658266616f732d66735820080808080808",
    "08080808080808080808080808080808080808080808080808088209a2018200",
    "5820875e7f9306a5ae92cac15bc6a90967cc178deb57aeec9feecb350f72453e",
    "9e4a0282005820ceb2db5d2f6834ebded8c4b74dff91195f308f758ae2a40417",
    "0c93360d12e5288205a101820058200fc322752b8a1a72247922571253aa74b4",
    "2645248742cf0915cb496a2a0ddf2d8201a10182005820944d87f5b22ebd49a5",
    "809e224ee25e0463217ef4ba1cf3013f2808e9c538628c820058208a88e3dd74",
    "09f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
];
const KAT_ENTRY_HASH: &str = "d2d1781063370a7b0d95098f98a8f9ec82f2083448bbc23a55d677942d40e35b";
const KAT_SIGNATURE: &str = "fb9e2166af75320997a583c63950451cc244d32cf623ed51e660fa20337035e2\
                             0c11c13ac3a87253f67fe92a9e32f1198ceabb35dc0f837a042b2ccc42d9f002";
/// `(section, key, salt, value, commitment)` of each committed field.
const KAT_DISCLOSURES: [(u64, u64, &str, &str, &str); 4] = [
    (
        9,
        1,
        "505f4fe84229b4ece2fd174bea25c0c4",
        "752f686f6d652f616c6963652f6e6f7465732e747874",
        "875e7f9306a5ae92cac15bc6a90967cc178deb57aeec9feecb350f72453e9e4a",
    ),
    (
        9,
        2,
        "403e57796b153c9a66bb36df0ce6db25",
        "58200a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        "ceb2db5d2f6834ebded8c4b74dff91195f308f758ae2a404170c93360d12e528",
    ),
    (
        10,
        1,
        "cebf2148dcb80c652b45a4acecd13abd",
        "78186d616e69666573742d676174656420686f73742063616c6c",
        "0fc322752b8a1a72247922571253aa74b42645248742cf0915cb496a2a0ddf2d",
    ),
    (
        11,
        1,
        "89222369d907ce33b72cf6a4ed6a24d9",
        "696469736b2066756c6c",
        "944d87f5b22ebd49a5809e224ee25e0463217ef4ba1cf3013f2808e9c538628c",
    ),
];

#[test]
fn registry_genesis_matches_known_answer() {
    assert_eq!(key(1).export_public_key().to_hex(), KAT_AUDIT_PUBLIC);
    assert_eq!(key(2).export_public_key().to_hex(), KAT_RUNTIME_PUBLIC);
    let registry = kat_registry();
    let genesis = &registry.records()[0];
    assert_eq!(hex::encode(genesis.body()), KAT_GENESIS_BODY.concat());
    assert_eq!(hex::encode(registry.registry_id()), KAT_REGISTRY_ID);
    let signatures: Vec<String> = genesis
        .signatures
        .iter()
        .map(|signature| signature.signature.to_hex())
        .collect();
    assert_eq!(signatures, KAT_GENESIS_SIGNATURES);
}

#[test]
fn entry_matches_known_answer() {
    let registry = kat_registry();
    let entry = kat_entry(&registry);
    let seal = entry.v2.as_ref().unwrap();
    assert_eq!(hex::encode(seal.chain_id), KAT_CHAIN_ID);
    assert_eq!(hex::encode(entry.v2_body().unwrap()), KAT_BODY.concat());
    assert_eq!(entry.content_hash().to_hex(), KAT_ENTRY_HASH);
    assert_eq!(entry.signature.to_hex(), KAT_SIGNATURE);
    assert_eq!(
        entry.signing_data(),
        signing_input(entry.content_hash().as_bytes())
    );
    assert!(entry.verify_signature().is_ok());
}

#[test]
fn entry_survives_a_json_round_trip_unchanged() {
    let registry = kat_registry();
    let entry = kat_entry(&registry);
    let stored = serde_json::to_vec(&entry).unwrap();
    let reloaded: AuditEntry = serde_json::from_slice(&stored).unwrap();
    assert_eq!(reloaded.content_hash().to_hex(), KAT_ENTRY_HASH);
    assert_eq!(hex::encode(reloaded.v2_body().unwrap()), KAT_BODY.concat());
    let result = crate::ChainVerifier::new(Some(&registry))
        .verify(std::slice::from_ref(&reloaded), crate::ChainStart::Genesis);
    assert!(result.valid, "{:?}", result.issues);
}

#[test]
fn disclosures_match_known_answer_and_open_their_commitments() {
    let registry = kat_registry();
    let entry = kat_entry(&registry);
    let seal = entry.v2.as_ref().unwrap();
    let disclosures = entry.v2_field_disclosures();
    assert_eq!(disclosures.len(), KAT_DISCLOSURES.len());
    for (disclosure, (section, key, salt, value, commitment)) in
        disclosures.iter().zip(KAT_DISCLOSURES)
    {
        assert_eq!(disclosure.section, section);
        assert_eq!(disclosure.key, key);
        assert_eq!(hex::encode(disclosure.salt), salt);
        assert_eq!(hex::encode(&disclosure.value), value);
        assert_eq!(hex::encode(disclosure.commitment), commitment);
        assert!(verify_field_disclosure(
            &seal.chain_id,
            seal.seq,
            disclosure
        ));
        let mut wrong = disclosure.clone();
        wrong.value = crate::entry_v2::cbor::Cbor::text("something else").encode();
        assert!(!verify_field_disclosure(&seal.chain_id, seal.seq, &wrong));
    }
}

#[test]
fn redacted_body_decodes_and_verifies_against_the_registry() {
    let registry = kat_registry();
    let entry = kat_entry(&registry);
    let body = hex::decode(KAT_BODY.concat()).unwrap();
    let header = verify_entry_v2_body(&body, &entry.signature, &registry).unwrap();
    assert_eq!(hex::encode(header.entry_hash), KAT_ENTRY_HASH);
    assert_eq!(hex::encode(header.chain_id), KAT_CHAIN_ID);
    assert_eq!(header.seq, 1);
    assert_eq!(header.prev, [0; 32]);
    assert_eq!(header.time_ns, 1_790_598_896_123_456_789);
    assert_eq!(header.entry_id, *kat_entry_id().0.as_bytes());
    assert_eq!(header.session, *kat_session().0.as_bytes());
    assert_eq!(header.principal_uid, Some([7; 32]));
    assert_eq!(header.principal_alias.as_deref(), Some("alice"));
    assert_eq!(header.actor, Some(("aos-fs".to_owned(), Some([8; 32]))));
    assert_eq!(header.key_epoch, 0);
    assert_eq!(header.signer, key(1).export_public_key());
    assert_eq!(header.action.kind, 9);
    assert_eq!(header.authorization.kind, 5);
    assert_eq!(header.outcome.kind, 1);
    let commitments: Vec<(u64, u64, String)> = [
        (SECTION_ACTION, &header.action),
        (SECTION_AUTHORIZATION, &header.authorization),
        (SECTION_OUTCOME, &header.outcome),
    ]
    .into_iter()
    .flat_map(|(section, decoded)| {
        decoded.fields.iter().map(move |(key, field)| match field {
            DecodedField::Committed(commitment) => (section, *key, hex::encode(commitment)),
            DecodedField::Public(_) => panic!("the KAT entry has no public fields"),
        })
    })
    .collect();
    let expected: Vec<(u64, u64, String)> = KAT_DISCLOSURES
        .iter()
        .map(|(section, key, _, _, commitment)| (*section, *key, (*commitment).to_owned()))
        .collect();
    assert_eq!(commitments, expected);
}

#[test]
fn redacted_body_is_rejected_when_tampered_or_signed_by_an_unregistered_key() {
    let registry = kat_registry();
    let entry = kat_entry(&registry);
    let body = hex::decode(KAT_BODY.concat()).unwrap();

    // Any change to the body changes its hash, so the signature fails.
    let mut tampered = body.clone();
    let last = tampered.len() - 40;
    tampered[last] ^= 1;
    assert!(verify_entry_v2_body(&tampered, &entry.signature, &registry).is_err());

    // The same entry re-signed by a key the registry does not list.
    let rogue = key(0x55);
    let mut forged = entry.clone();
    forged.runtime_key = rogue.export_public_key();
    forged.signature = rogue.sign(&forged.signing_data());
    let forged_body = forged.v2_body().unwrap();
    assert!(matches!(
        verify_entry_v2_body(&forged_body, &forged.signature, &registry),
        Err(crate::AuditError::KeyNotRegistered { .. })
    ));

    // A trailing byte makes the encoding non-canonical.
    let mut trailing = body;
    trailing.push(0);
    assert!(EntryV2Header::decode(&trailing).is_err());
}
