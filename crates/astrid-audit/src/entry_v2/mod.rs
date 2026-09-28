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
//! Section  = [kind: uint, FieldMap]
//! FieldMap = { * uint => Field }
//! Field    = [0, commitment: bstr .size 32]   ; salted commitment
//!          / [1, Public]                       ; value in the clear
//! Public   = uint / bstr / [* Public]
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
//! A section is `[kind, FieldMap]`. Kind codes and field keys are fixed;
//! they are never renumbered or reused. A key is absent when the Rust field
//! is `None`. `C` marks a committed field, `P` a public one; `uint`, `bstr`
//! and `tstr` give the committed or public value's CBOR type.
//!
//! Every text value, and every hash of caller-supplied content, is committed.
//! Enum codes, counts, ports, durations, kernel-issued ids and hashes of
//! signed objects are public.
//!
//! Section 9, action (kind: variant):
//!
//! | kind | variant | fields |
//! |---|---|---|
//! | 1 | `McpToolCall` | 1 `server` C tstr, 2 `tool` C tstr, 3 `args_hash` C bstr32 |
//! | 2 | `CapsuleToolCall` | 1 `capsule_id` C tstr, 2 `tool` C tstr, 3 `args_hash` C bstr32 |
//! | 3 | `McpResourceRead` | 1 `server` C tstr, 2 `uri` C tstr |
//! | 4 | `McpPromptGet` | 1 `server` C tstr, 2 `name` C tstr |
//! | 5 | `McpElicitation` | 1 `request_id` C tstr, 2 `schema` C tstr |
//! | 6 | `McpUrlElicitation` | 1 `url` C tstr, 2 `interaction_type` C tstr |
//! | 7 | `McpSampling` | 1 `model` C tstr, 2 `prompt_tokens` P uint |
//! | 8 | `FileRead` | 1 `path` C tstr |
//! | 9 | `FileWrite` | 1 `path` C tstr, 2 `content_hash` C bstr32 |
//! | 10 | `FileDelete` | 1 `path` C tstr |
//! | 11 | `NetConnect` | 1 `host` C tstr, 2 `port` P uint |
//! | 12 | `NetBind` | 1 `addr` C tstr |
//! | 13 | `ProcessSpawn` | 1 `command` C tstr |
//! | 14 | `CapabilityCreated` | 1 `token_id` P bstr16, 2 `resource` C tstr, 3 `permissions` P \[uint\], 4 `scope` P uint |
//! | 15 | `CapabilityRevoked` | 1 `token_id` P bstr16, 2 `reason` C tstr |
//! | 16 | `ApprovalRequested` | 1 `action_type` C tstr, 2 `resource` C tstr |
//! | 17 | `ApprovalGranted` | 1 `action` C tstr, 2 `resource?` C tstr, 3 `scope` P uint |
//! | 18 | `ApprovalDenied` | 1 `action` C tstr, 2 `reason?` C tstr |
//! | 19 | `SessionStarted` | 1 `user_id` P bstr8, 2 `platform` C tstr |
//! | 20 | `SessionEnded` | 1 `reason` C tstr, 2 `duration_secs` P uint |
//! | 21 | `ContextSummarized` | 1 `evicted_count` P uint, 2 `tokens_freed` P uint |
//! | 22 | `LlmRequest` | 1 `model` C tstr, 2 `input_tokens` P uint, 3 `output_tokens` P uint |
//! | 23 | `ServerStarted` | 1 `name` C tstr, 2 `transport` C tstr, 3 `binary_hash?` P bstr32 |
//! | 24 | `ServerStopped` | 1 `name` C tstr, 2 `reason` C tstr |
//! | 25 | `ElicitationSent` | 1 `request_id` C tstr, 2 `server` C tstr, 3 `elicitation_type` C tstr |
//! | 26 | `ElicitationReceived` | 1 `request_id` C tstr, 2 `action` C tstr |
//! | 27 | `SecurityViolation` | 1 `violation_type` C tstr, 2 `details` C tstr |
//! | 28 | `SubAgentSpawned` | 1 `parent_session_id` C tstr, 2 `child_session_id` C tstr, 3 `description` C tstr |
//! | 29 | `ConfigReloaded` | (none) |
//! | 30 | `AdminRequest` | 1 `method` C tstr, 2 `required_capability` C tstr, 3 `target_principal?` C tstr, 4 `params?` C json, 5 `device_key_id?` C tstr |
//! | 31 | `NetAccept` | 1 `local_addr` C tstr, 2 `peer_addr` C tstr |
//!
//! Scope codes: once 0, session 1, workspace 2, always 3. Permission codes:
//! read 1, write 2, execute 3, delete 4, invoke 5, list 6, create 7. Token
//! and entry ids are their 16 UUID bytes.
//!
//! `json` maps a JSON value to CBOR: `null`/`true`/`false` to the simple
//! values, an integer in `0..=2^64-1` to an unsigned integer, a negative
//! integer in `i64` range to a negative integer, any other number to a byte
//! string holding its literal JSON text (JSON has no byte strings, so this is
//! unambiguous), a string to a text string, an array to an array and an
//! object to a map with text keys.
//!
//! Section 10, authorization:
//!
//! | kind | variant | fields |
//! |---|---|---|
//! | 1 | `User` | 1 `user_id` P bstr8, 2 `message_id` C tstr |
//! | 2 | `Capability` | 1 `token_id` P bstr16, 2 `token_hash` P bstr32 |
//! | 3 | `UserApproval` | 1 `user_id` P bstr8, 2 `approval_entry_id?` P bstr16 |
//! | 4 | `NotRequired` | 1 `reason` C tstr |
//! | 5 | `System` | 1 `reason` C tstr |
//! | 6 | `Denied` | 1 `reason` C tstr |
//!
//! Section 11, outcome: kind 0 `Success` with 1 details? C tstr; kind 1
//! `Failure` with 1 error C tstr. The full outcome text is signed through its
//! commitment.
//!
//! ## Field commitments and salts
//!
//! ```text
//! salt       = HMAC-SHA256(salt_key, dCBOR(["astrid.audit.salt.v2", section, key]))[0..16]
//! commitment = H(["astrid.audit.field.v2", chain, seq, section, key, salt: bstr .size 16, value])
//! ```
//!
//! `section` is the body element (9, 10 or 11) and `value` the committed CBOR
//! value. `salt_key` is 32 random bytes drawn per entry and stored with the
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
//! does not exceed the latest record, and `key_epoch` never decreases along a
//! chain. An entry signed by a retired key therefore fails unless it names an
//! epoch in which that key was current and its chain has not moved past it.
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
//!    more than the predecessor's when both are in the same chain and 1
//!    otherwise, and `key_epoch` not to decrease.
//! 4. Reject a v1 entry that follows a v2 entry.
//!
//! The first retained entry of a pruned chain links to a signed archive
//! receipt. Under v2 the audit key signs receipts and the receipt carries the
//! signer's `key_epoch`; for a v2 first entry the receipt's `key_epoch` must be
//! no earlier than the entry's, and its key must hold the audit role in that
//! state. A verifier that holds only the canonical bodies and
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
//! - existing v1 entries stay exactly as they are and verify as before;
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
//!               08080808080808080808080808080808080808080808080808088209a2018200
//!               5820875e7f9306a5ae92cac15bc6a90967cc178deb57aeec9feecb350f72453e
//!               9e4a0282005820ceb2db5d2f6834ebded8c4b74dff91195f308f758ae2a40417
//!               0c93360d12e5288205a101820058200fc322752b8a1a72247922571253aa74b4
//!               2645248742cf0915cb496a2a0ddf2d8201a10182005820944d87f5b22ebd49a5
//!               809e224ee25e0463217ef4ba1cf3013f2808e9c538628c820058208a88e3dd74
//!               09f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
//! entry_hash    d2d1781063370a7b0d95098f98a8f9ec82f2083448bbc23a55d677942d40e35b
//! signature     fb9e2166af75320997a583c63950451cc244d32cf623ed51e660fa20337035e2
//!               0c11c13ac3a87253f67fe92a9e32f1198ceabb35dc0f837a042b2ccc42d9f002
//! salt (9, 1)   505f4fe84229b4ece2fd174bea25c0c4
//! salt (11, 1)  89222369d907ce33b72cf6a4ed6a24d9
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
pub use decode::{DecodedField, DecodedSection, EntryV2Header, verify_entry_v2_body};
pub use registry::{
    KeyBinding, KeyRegistry, KeyRegistryRecord, KeyRole, REGISTRY_TAG, RegistryOp,
    RegistrySignature,
};
pub use verify::{ChainStart, ChainVerifier};

pub(crate) use body::EntryV2Draft;

#[cfg(test)]
mod tests;
