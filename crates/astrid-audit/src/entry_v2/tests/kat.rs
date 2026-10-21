//! Known-answer test for the v2 byte format.
//!
//! These values are the contract with verifiers outside this crate. They
//! were also reproduced by an implementation written from the module docs
//! alone. Changing any of them is a format change.

use super::*;
use crate::entry_v2::{
    EntryV2Header, SECTION_ACTION, SECTION_AUTHORIZATION, SECTION_OUTCOME, signing_input,
    verify_entry_v2_body, verify_field_disclosure,
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
    "0808080808080808080808080808080808080808080808080808826a66696c65",
    "5f7772697465a264706174685820667206c8f1d0a10df01f886c473418cd3397",
    "4f3d67b19d7ca2a242273665e4016c636f6e74656e745f686173685820715d8d",
    "185919a9d9d1861cea95d501fd45d91378de6937e3a6b96f777a4753cb826673",
    "797374656da166726561736f6e58203e9f1d3bf578a2c001fa91701bf583711b",
    "2737d300649d498bb753586951a87e82676661696c757265a1656572726f7258",
    "2043a56020b3f9bdc2e31434da239a723c7c0dc19c284586e23b66c2d5ac50e2",
    "90820058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf37488",
    "01b40f6f5c",
];
const KAT_ENTRY_HASH: &str = "c1b3fc3e9b0ac43f52d8f9cbc8156c9c3dafbc1a2b5354d901d63b1d8e6a7d1d";
const KAT_SIGNATURE: &str = "3d4003e5bb035238faa0a9fe73569af19569b9e33e8dcb16a230422e69928fff\
                             81aae511da20372b3c11b1eb03955599323ad88b6ca1e426debf40dda966190e";
/// `(section, name, salt, value, commitment)` of each committed field, in
/// body order.
const KAT_DISCLOSURES: [(u64, &str, &str, &str, &str); 4] = [
    (
        9,
        "path",
        "afa77b89ac10bcf6c2fdbe913b2d4112",
        "752f686f6d652f616c6963652f6e6f7465732e747874",
        "667206c8f1d0a10df01f886c473418cd33974f3d67b19d7ca2a242273665e401",
    ),
    (
        9,
        "content_hash",
        "165eb4b4eb1d90dc5cf685aff63ab6eb",
        concat!(
            "7840",
            "30613061306130613061306130613061306130613061306130613061306130613061",
            "306130613061306130613061306130613061306130613061306130613061",
        ),
        "715d8d185919a9d9d1861cea95d501fd45d91378de6937e3a6b96f777a4753cb",
    ),
    (
        10,
        "reason",
        "4c0c9735dee25688858940a554006641",
        "78186d616e69666573742d676174656420686f73742063616c6c",
        "3e9f1d3bf578a2c001fa91701bf583711b2737d300649d498bb753586951a87e",
    ),
    (
        11,
        "error",
        "b75d5c8e07b9ca6bc6e11c98f848c871",
        "696469736b2066756c6c",
        "43a56020b3f9bdc2e31434da239a723c7c0dc19c284586e23b66c2d5ac50e290",
    ),
];

fn kat_body(entry: &AuditEntry) -> Vec<u8> {
    entry.v2_body().unwrap().unwrap()
}

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
    assert_eq!(hex::encode(kat_body(&entry)), KAT_BODY.concat());
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
    assert_eq!(hex::encode(kat_body(&reloaded)), KAT_BODY.concat());
    let result = crate::ChainVerifier::new(Some(&registry))
        .verify(std::slice::from_ref(&reloaded), crate::ChainStart::Genesis);
    assert!(result.valid, "{:?}", result.issues);
}

#[test]
fn disclosures_match_known_answer_and_open_their_commitments() {
    let registry = kat_registry();
    let entry = kat_entry(&registry);
    let seal = entry.v2.as_ref().unwrap();
    let disclosures = entry.v2_field_disclosures().unwrap();
    assert_eq!(disclosures.len(), KAT_DISCLOSURES.len());
    for (disclosure, (section, name, salt, value, commitment)) in
        disclosures.iter().zip(KAT_DISCLOSURES)
    {
        assert_eq!(disclosure.section, section);
        assert_eq!(disclosure.name, name);
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
        let mut renamed = disclosure.clone();
        renamed.name.push('x');
        assert!(!verify_field_disclosure(&seal.chain_id, seal.seq, &renamed));
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
    assert_eq!(header.action.kind, "file_write");
    assert_eq!(header.authorization.kind, "system");
    assert_eq!(header.outcome.kind, "failure");
    let commitments: Vec<(u64, String, String)> = [
        (SECTION_ACTION, &header.action),
        (SECTION_AUTHORIZATION, &header.authorization),
        (SECTION_OUTCOME, &header.outcome),
    ]
    .into_iter()
    .flat_map(|(section, decoded)| {
        decoded
            .fields
            .iter()
            .map(move |(name, commitment)| (section, name.clone(), hex::encode(commitment)))
    })
    .collect();
    let expected: Vec<(u64, String, String)> = KAT_DISCLOSURES
        .iter()
        .map(|(section, name, _, _, commitment)| {
            (*section, (*name).to_owned(), (*commitment).to_owned())
        })
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
    let forged_body = kat_body(&forged);
    assert!(matches!(
        verify_entry_v2_body(&forged_body, &forged.signature, &registry),
        Err(crate::AuditError::KeyNotRegistered { .. })
    ));

    // A trailing byte makes the encoding non-canonical.
    let mut trailing = body;
    trailing.push(0);
    assert!(EntryV2Header::decode(&trailing).is_err());
}

#[test]
fn a_body_with_sequence_zero_is_rejected() {
    let registry = kat_registry();
    let mut entry = kat_entry(&registry);
    entry.v2.as_mut().unwrap().seq = 0;
    entry.signature = key(1).sign(&entry.signing_data());
    let body = kat_body(&entry);
    assert!(EntryV2Header::decode(&body).is_err());
    assert!(verify_entry_v2_body(&body, &entry.signature, &registry).is_err());
}
