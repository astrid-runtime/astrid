//! Audit entry format v2: canonical, fully signed entries verified against a
//! key registry.
//!
//! This module is the normative definition of the format. A verifier in any
//! language can implement it from this text and check itself against the
//! known-answer test below. Format v1 ([`AuditEntry`](crate::AuditEntry)
//! without [`EntryV2Seal`]) is unchanged; see [Migration](#migration).
//!
//! # Conventions
//!
//! - **dCBOR** is RFC 8949 §4.2.1 core deterministic encoding, restricted to
//!   unsigned integers (major 0), negative integers (major 1), byte strings
//!   (2), UTF-8 text strings (3), definite-length arrays (4) and maps (5),
//!   and the simple values `false` (`0xf4`), `true` (`0xf5`) and `null`
//!   (`0xf6`). Every head uses its shortest form; map entries are ordered by
//!   the bytewise order of their encoded keys; keys are unique. No floats,
//!   tags or indefinite lengths. Decoders reject anything else, including
//!   trailing bytes.
//! - **`H(x)`** is SHA-256 of `dCBOR(x)`. Every hashed or signed structure is
//!   a positional array whose element 0 is a text domain tag carrying the
//!   format version, so no two structures can share an encoding.
//! - **Signatures** are Ed25519 (RFC 8032, pure) and are verified with
//!   strict verification (small-order keys and `R` values and non-canonical
//!   encodings rejected).
//! - The key that signs is never trusted because it appears in the object.
//!   It is looked up in the [key registry](#key-registry).
//!
//! # Entry body
//!
//! ```cddl
//! EntryV2 = [
//!   0  "astrid.audit.entry.v2",
//!   1  chain:     bstr .size 32,          ; chain id, see below
//!   2  seq:       uint,                   ; 1, 2, 3, ... within the chain
//!   3  prev:      bstr .size 32,          ; entry hash of the storage predecessor
//!   4  time_ns:   uint,                   ; wall clock, ns since the Unix epoch (UTC)
//!   5  id:        bstr .size 16,          ; entry id (UUID bytes)
//!   6  session:   bstr .size 16,          ; session id (UUID bytes)
//!   7  principal: [uid: bstr .size 32 / null, alias: tstr / null],
//!   8  actor:     [capsule_id: tstr, wasm_sha256: bstr .size 32 / null] / null,
//!   9  action:    Section,
//!   10 authz:     Section,
//!   11 outcome:   Section,
//!   12 signer:    [key_epoch: uint, key: bstr .size 32],
//! ]
//! Section  = [kind: tstr, { * tstr => bstr .size 32 }]   ; field name => commitment
//!
//! entry_hash = SHA-256(dCBOR(EntryV2))
//! signature  = Ed25519(audit_key, dCBOR(["astrid.audit.sig.v2", "entry", entry_hash]))
//! ```
//!
//! - `prev` is the entry hash of the entry stored directly before this one in
//!   the same storage chain (`session`, `principal alias`), of either format
//!   (a v1 predecessor contributes its v1 content hash), or 32 zero bytes when
//!   there is none. A chain opens with `seq = 1`; `seq` then increases by one
//!   per entry. A new chain opens in the same storage chain when the chain id
//!   changes (for example when the store first writes v2 after v1, or the
//!   principal's UID resolves differently); its first entry again has
//!   `seq = 1` and links to the last entry before it.
//! - `principal` is `[null, null]` on the system chain. `uid` is the
//!   principal's durable [`PrincipalUid`](astrid_core::identity::PrincipalUid)
//!   when the kernel resolved it, else `null`; `alias` is the principal name
//!   under which the chain is stored.
//! - `actor` names the capsule that performed the action, when the caller
//!   knew it.
//! - `key_epoch` is the sequence number of the latest key-registry record
//!   when the entry was signed.
//!
//! ## Chain id
//!
//! ```text
//! chain_id = H(["astrid.audit.chain-id.v2", registry_id: bstr .size 32,
//!               session: bstr .size 16, principal])
//! ```
//!
//! `principal` is element 7 of the entry. The chain id therefore binds the
//! node's key registry, the session, the principal's durable UID and the
//! alias under which the chain is stored: a renamed principal, or a new
//! principal that reuses an alias, starts a different chain.
//!
//! ## Sections
//!
//! Sections 9, 10 and 11 are taken from the stored JSON form of the action
//! ([`AuditAction`](crate::AuditAction)), the authorization
//! ([`AuthorizationProof`](crate::AuthorizationProof)) and the outcome
//! ([`AuditOutcome`](crate::AuditOutcome)). Each is an internally tagged
//! object: one tag member names the variant (`type` for the action and the
//! authorization, `status` for the outcome) and every other member is a
//! field. The section is `[tag value, map]`, where the map holds one salted
//! commitment per field, keyed by the member name. Every field is committed:
//! the body shows which variant and which fields an entry has, never their
//! values.
//!
//! The rule is generic: a new variant, or a new optional field that is
//! skipped when absent (`#[serde(default, skip_serializing_if = ...)]`),
//! needs no change to this format and does not change the encoding of
//! existing entries. Changing how an existing field serializes would change
//! the bodies of entries already signed, so the serde form of these enums is
//! part of the format.
//!
//! A field's committed value is its JSON value mapped to CBOR:
//!
//! - `null`, `true` and `false` map to the CBOR simple values;
//! - an integer in `0..=2^64-1` maps to an unsigned integer, and a negative
//!   integer in `i64` range to a negative integer;
//! - any other number maps to a byte string holding its literal JSON text
//!   (JSON has no byte strings, so this is unambiguous);
//! - a string maps to a text string (hashes, ids and keys appear as the text
//!   they have in JSON);
//! - an array maps to an array, and an object to a map with text keys.
//!
//! For example, `FileWrite { path, content_hash }` stores as
//! `{"type": "file_write", "path": ..., "content_hash": "<64 hex>"}` and
//! becomes the section `["file_write", {"path": c1, "content_hash": c2}]`;
//! `Failure { error }` becomes `["failure", {"error": c}]`; `Success` without
//! details becomes `["success", {}]`.
//!
//! ## Field commitments and salts
//!
//! ```text
//! salt       = HMAC-SHA256(salt_key, dCBOR(["astrid.audit.salt.v2", section, name]))[0..16]
//! commitment = H(["astrid.audit.field.v2", chain, seq, section, name, salt: bstr .size 16, value])
//! ```
//!
//! `section` is the body element (9, 10 or 11), `name` the field name (text)
//! and `value` the committed CBOR value. `salt_key` is 32 random bytes drawn per entry and stored with the
//! entry in the node's private store ([`EntryV2Seal::salt_key`]); it is not
//! part of the body. Revealing one field means handing out `(salt, value)`
//! ([`FieldDisclosure`]); that opens its commitment and no other, and it does
//! not reveal `salt_key`.
//!
//! # Key registry
//!
//! ```cddl
//! KeyRegistryRecord = [
//!   0 "astrid.audit.key-registry.v2",
//!   1 seq: uint,                          ; 0 = genesis
//!   2 prev: bstr .size 32,                ; record hash of seq - 1; zero at genesis
//!   3 time_ns: uint,
//!   4 op: uint,                           ; 0 genesis, 1 rotate
//!   5 add:    [* [role: uint, key: bstr .size 32]],
//!   6 retire: [* [role: uint, key: bstr .size 32]],
//! ]
//! record_hash = SHA-256(dCBOR(KeyRegistryRecord))
//! registry_id = record_hash of the genesis record
//! signature   = Ed25519(key, dCBOR(["astrid.audit.sig.v2", "key-registry", record_hash]))
//! ```
//!
//! Roles: 1 audit (signs v2 entries and their archive receipts), 2
//! capability tokens, 3 local capsule builds, 4 audit-v1 (the key that signed
//! v1 entries; never valid for v2). `add` and `retire` are sorted by role
//! code, then key bytes, without duplicates. Every distinct key in `add` and
//! `retire` signs the record (one signature each, sorted by key bytes).
//!
//! - **Genesis** (`seq` 0) binds one key to each listed role, exactly one of
//!   them the audit key, which holds no other role.
//! - **Rotate** retires the active key of one role and adds a key that was
//!   never registered before, for the same role. The old and the new key both
//!   sign it: the old key authorizes the change, the new key proves
//!   possession.
//!
//! A key holds a role in registry states `from..until`: from the record that
//! adds it up to, excluding, the record that retires it. A v2 entry is valid
//! only if its signer holds the audit role in state `key_epoch`, `key_epoch`
//! does not exceed the latest record, and `key_epoch` never decreases along
//! the storage chain, including where a new v2 chain opens. An entry signed by
//! a retired key therefore fails unless it names an epoch in which that key
//! was current and its storage chain has not moved past it.
//! Astrid itself never writes such an entry: an append commits only if its
//! `key_epoch` is still the latest registry record, checked under the same
//! lock that registry writes take. Bounding what a leaked retired key can
//! sign outside Astrid needs an external anchor of the chain heads at
//! rotation.
//!
//! # Verification
//!
//! For each storage chain, in storage order ([`ChainVerifier`]):
//!
//! 1. Recompute the body and `entry_hash`; verify the signature strictly
//!    under the signer key, and require that key to hold the audit role at
//!    `key_epoch`.
//! 2. Recompute the chain id from the registry id, session and principal.
//! 3. Require `prev` to be the storage predecessor's hash, `seq` to be one
//!    more than the predecessor's when both are in the same chain (without
//!    overflow) and 1 otherwise, `seq` never to be 0, and `key_epoch` not to
//!    decrease from a v2 predecessor, whichever chain it belongs to.
//! 4. Reject a v1 entry that follows a v2 entry.
//! 5. Require each v1 entry's embedded key to hold the audit-v1 role, so a v1
//!    chain re-signed under another key no longer passes (a verifier may turn
//!    this off to check v1 entries the way format v1 did).
//!
//! The first retained entry of a pruned chain links to a signed archive
//! receipt. Under v2 the audit key signs receipts and the receipt carries the
//! signer's `key_epoch`: its key must hold the audit role in that state, and
//! for a v2 first entry the epoch must be no earlier than the entry's. A
//! receipt written before v2 (no epoch) anchors only a v1 first entry and must
//! be signed by the registered audit-v1 key. A verifier that holds only the canonical bodies and
//! signatures uses [`EntryV2Header::decode`] and [`verify_entry_v2_body`]
//! instead of recomputing from stored fields.
//!
//! # Migration
//!
//! Format v2 is off by default
//! ([`AuditEntryFormat::V1`](crate::AuditEntryFormat::V1)). Enabling it
//! ([`AuditLog::enable_entry_v2`](crate::AuditLog::enable_entry_v2)) creates
//! the key registry on first use. From then on:
//!
//! - existing v1 entries stay exactly as they are; their signatures and links
//!   verify as before, and their signing key must now be the registered v1
//!   key, which the kernel records as the runtime key at enablement (v1
//!   entries signed by an earlier runtime key are reported as unregistered);
//! - the next entry of each storage chain opens a v2 chain with `seq = 1`
//!   whose `prev` is the content hash of the chain's last v1 entry, so the
//!   v1 history stays hash-linked into the v2 chain and is never re-signed;
//! - v1 is closed: the log refuses to append a v1 entry to a chain whose head
//!   is v2, or to any chain once the store holds a key registry, and a
//!   verifier reports a v1 entry after a v2 entry.
//!
//! # Known-answer test
//!
//! See `KAT_*` in this module's tests (`entry_v2/tests/kat.rs`). Inputs:
//!
//! ```text
//! audit key seed    = 32 bytes 0x01    runtime key seed = 32 bytes 0x02
//! registry genesis  = time 2026-09-28T00:00:00Z, add
//!                     [[1, audit_pub], [2, runtime_pub], [3, runtime_pub], [4, runtime_pub]]
//! entry             = id 00112233-4455-6677-8899-aabbccddeeff,
//!                     session 01020304-0506-0708-090a-0b0c0d0e0f10,
//!                     time 2026-09-28T12:34:56.123456789Z, seq 1, prev zero,
//!                     principal [uid 32 bytes 0x07, "alice"],
//!                     actor ["aos-fs", 32 bytes 0x08], key_epoch 0,
//!                     salt_key 32 bytes 0x09,
//!                     action FileWrite { path "/home/alice/notes.txt",
//!                                        content_hash 32 bytes 0x0a },
//!                     authorization System { reason "manifest-gated host call" },
//!                     outcome Failure { error "disk full" }
//! ```
//!
//! Expected outputs:
//!
//! ```text
//! audit_pub     8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
//! runtime_pub   8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
//! registry_id   6861a01ac38bbf60ef4f8dea9d663a64b6d522a742b6bc8b0f738469d505e82a
//! chain_id      748b16dd8b05e5237500376103842e628936b7858f8faa1557770519f26d0914
//! body          8d756173747269642e61756469742e656e7472792e76325820748b16dd8b05e5
//!               237500376103842e628936b7858f8faa1557770519f26d091401582000000000
//!               000000000000000000000000000000000000000000000000000000001b18d97c
//!               3582a52d155000112233445566778899aabbccddeeff50010203040506070809
//!               0a0b0c0d0e0f1082582007070707070707070707070707070707070707070707
//!               0707070707070707070765616c6963658266616f732d66735820080808080808
//!               0808080808080808080808080808080808080808080808080808826a66696c65
//!               5f7772697465a264706174685820667206c8f1d0a10df01f886c473418cd3397
//!               4f3d67b19d7ca2a242273665e4016c636f6e74656e745f686173685820715d8d
//!               185919a9d9d1861cea95d501fd45d91378de6937e3a6b96f777a4753cb826673
//!               797374656da166726561736f6e58203e9f1d3bf578a2c001fa91701bf583711b
//!               2737d300649d498bb753586951a87e82676661696c757265a1656572726f7258
//!               2043a56020b3f9bdc2e31434da239a723c7c0dc19c284586e23b66c2d5ac50e2
//!               90820058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf37488
//!               01b40f6f5c
//! entry_hash    c1b3fc3e9b0ac43f52d8f9cbc8156c9c3dafbc1a2b5354d901d63b1d8e6a7d1d
//! signature     3d4003e5bb035238faa0a9fe73569af19569b9e33e8dcb16a230422e69928fff
//!               81aae511da20372b3c11b1eb03955599323ad88b6ca1e426debf40dda966190e
//! salt (9, "path")   afa77b89ac10bcf6c2fdbe913b2d4112
//! salt (11, "error") b75d5c8e07b9ca6bc6e11c98f848c871
//! ```
//!
//! The stored JSON form of the entry, the genesis record body and
//! signatures, and every field disclosure are pinned in the same test.

mod body;
mod cbor;
mod decode;
mod fields;
mod json;
mod registry;
mod serde_hex;
mod verify;

pub use body::{
    AuditActor, CHAIN_ID_TAG, ENTRY_TAG, EntryV2Seal, FIELD_TAG, FieldDisclosure, SALT_TAG,
    SECTION_ACTION, SECTION_AUTHORIZATION, SECTION_OUTCOME, SIGNATURE_TAG, derive_chain_id,
    field_salt, signing_input, verify_field_disclosure,
};
pub use decode::{DecodedSection, EntryV2Header, verify_entry_v2_body};
pub use registry::{
    KeyBinding, KeyRegistry, KeyRegistryRecord, KeyRole, REGISTRY_TAG, RegistryOp,
    RegistrySignature,
};
pub use verify::{ChainStart, ChainVerifier};

pub(crate) use body::EntryV2Draft;

#[cfg(test)]
mod tests;
