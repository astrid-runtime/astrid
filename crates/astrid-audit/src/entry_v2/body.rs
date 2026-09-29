//! The signed body of a v2 entry: construction, hashing, signing and field
//! commitments. The byte-level definition is in the [module docs](super).

use astrid_core::identity::PrincipalUid;
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_crypto::{ContentHash, KeyPair, Signature};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::cbor::Cbor;
use super::fields::{Section, action_section, authorization_section, outcome_section};
use super::serde_hex;
use crate::entry::{AuditAction, AuditEntry, AuditOutcome, AuthorizationProof};
use crate::error::{AuditError, AuditResult};
use astrid_capabilities::AuditEntryId;

/// Domain tag, element 0 of every v2 entry body.
pub const ENTRY_TAG: &str = "astrid.audit.entry.v2";
/// Domain tag of every v2 signature input.
pub const SIGNATURE_TAG: &str = "astrid.audit.sig.v2";
/// Domain tag of a field commitment.
pub const FIELD_TAG: &str = "astrid.audit.field.v2";
/// Domain tag of a field salt derivation.
pub const SALT_TAG: &str = "astrid.audit.salt.v2";
/// Domain tag of a chain-id derivation.
pub const CHAIN_ID_TAG: &str = "astrid.audit.chain-id.v2";

/// Body element (and commitment section) holding the action.
pub const SECTION_ACTION: u64 = 9;
/// Body element (and commitment section) holding the authorization.
pub const SECTION_AUTHORIZATION: u64 = 10;
/// Body element (and commitment section) holding the outcome.
pub const SECTION_OUTCOME: u64 = 11;

/// Hash reported for a v2 entry whose body cannot be encoded. Such an entry
/// is never signed ([`AuditEntry::create_v2`] refuses it), so no signature or
/// link can match this value.
const UNENCODABLE_TAG: &[u8] = b"astrid.audit.entry.v2: body cannot be encoded";

/// The code that performed an audited action, when the kernel knows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditActor {
    /// Capsule identifier.
    pub capsule_id: String,
    /// SHA-256 of the capsule's WebAssembly module, when known.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_hex::option_array"
    )]
    pub wasm_sha256: Option<[u8; 32]>,
}

/// Format-v2 data stored with an [`AuditEntry`].
///
/// Together with the entry's common fields this is everything the signed
/// body is computed from. `salt_key` is the per-entry secret the field salts
/// are derived from; it is kept in the node's private store and is never part
/// of the signed body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryV2Seal {
    /// Chain identity (element 1).
    #[serde(with = "serde_hex::array")]
    pub chain_id: [u8; 32],
    /// 1-based position in the chain (element 2).
    pub seq: u64,
    /// Key-registry state the signer was taken from (element 12).
    pub key_epoch: u64,
    /// Durable identity of the principal, when it resolved (element 7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_uid: Option<PrincipalUid>,
    /// The acting capsule, when known (element 8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<AuditActor>,
    /// Per-entry secret from which the field salts are derived.
    #[serde(with = "serde_hex::array")]
    pub salt_key: [u8; 32],
}

/// Everything needed to open one field commitment of a v2 entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDisclosure {
    /// Body element holding the field: 9, 10 or 11.
    pub section: u64,
    /// Field name inside that section.
    pub name: String,
    /// The field salt.
    pub salt: [u8; 16],
    /// Deterministic CBOR encoding of the committed value.
    pub value: Vec<u8>,
    /// The commitment carried in the signed body.
    pub commitment: [u8; 32],
}

/// Inputs for a new v2 entry, apart from its signer.
pub(crate) struct EntryV2Draft {
    pub(crate) session_id: SessionId,
    pub(crate) principal: Option<PrincipalId>,
    pub(crate) principal_uid: Option<PrincipalUid>,
    pub(crate) actor: Option<AuditActor>,
    pub(crate) action: AuditAction,
    pub(crate) authorization: AuthorizationProof,
    pub(crate) outcome: AuditOutcome,
    pub(crate) previous_hash: ContentHash,
    pub(crate) chain_id: [u8; 32],
    pub(crate) seq: u64,
    pub(crate) key_epoch: u64,
}

/// SHA-256 of `bytes`.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // HMAC accepts keys of any length, so construction cannot fail.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts every key length"));
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Nanoseconds since the Unix epoch, when `timestamp` is representable.
pub(crate) fn timestamp_nanos(timestamp: &Timestamp) -> Option<u64> {
    timestamp
        .0
        .timestamp_nanos_opt()
        .and_then(|nanos| u64::try_from(nanos).ok())
}

/// Element 7: `[uid / null, alias / null]`.
fn principal_item(alias: Option<&str>, uid: Option<&[u8; 32]>) -> Cbor {
    Cbor::Array(vec![
        uid.map_or(Cbor::Null, |uid| Cbor::bytes(uid.to_vec())),
        alias.map_or(Cbor::Null, Cbor::text),
    ])
}

/// Chain id from raw parts; see [`derive_chain_id`].
pub(crate) fn chain_id_from_parts(
    registry_id: &[u8; 32],
    session: &[u8; 16],
    principal_uid: Option<&[u8; 32]>,
    principal_alias: Option<&str>,
) -> [u8; 32] {
    sha256(
        &Cbor::Array(vec![
            Cbor::text(CHAIN_ID_TAG),
            Cbor::bytes(registry_id.to_vec()),
            Cbor::bytes(session.to_vec()),
            principal_item(principal_alias, principal_uid),
        ])
        .encode(),
    )
}

/// Derive the chain id of the chain a principal's entries in `session` join
/// under the key registry `registry_id`.
#[must_use]
pub fn derive_chain_id(
    registry_id: &[u8; 32],
    session: &SessionId,
    principal: Option<&PrincipalId>,
    principal_uid: Option<&PrincipalUid>,
) -> [u8; 32] {
    chain_id_from_parts(
        registry_id,
        session.0.as_bytes(),
        principal_uid.map(PrincipalUid::as_bytes),
        principal.map(PrincipalId::as_str),
    )
}

/// Derive the salt of field `name` in `section` from an entry's salt key.
#[must_use]
pub fn field_salt(salt_key: &[u8; 32], section: u64, name: &str) -> [u8; 16] {
    let message = Cbor::Array(vec![
        Cbor::text(SALT_TAG),
        Cbor::Uint(section),
        Cbor::text(name),
    ])
    .encode();
    let mac = hmac_sha256(salt_key, &message);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(mac.get(..16).unwrap_or(&[0u8; 16]));
    salt
}

fn commitment(
    chain_id: &[u8; 32],
    seq: u64,
    section: u64,
    name: &str,
    salt: &[u8; 16],
    value: Cbor,
) -> [u8; 32] {
    sha256(
        &Cbor::Array(vec![
            Cbor::text(FIELD_TAG),
            Cbor::bytes(chain_id.to_vec()),
            Cbor::Uint(seq),
            Cbor::Uint(section),
            Cbor::text(name),
            Cbor::bytes(salt.to_vec()),
            value,
        ])
        .encode(),
    )
}

/// Check that `disclosure` opens a commitment of the entry at (`chain_id`,
/// `seq`). The caller must also check that the commitment is the one carried
/// at `[section][1][name]` of the signed body.
#[must_use]
pub fn verify_field_disclosure(
    chain_id: &[u8; 32],
    seq: u64,
    disclosure: &FieldDisclosure,
) -> bool {
    let Ok(value) = Cbor::decode(&disclosure.value) else {
        return false;
    };
    commitment(
        chain_id,
        seq,
        disclosure.section,
        &disclosure.name,
        &disclosure.salt,
        value,
    ) == disclosure.commitment
}

/// Sections 9, 10 and 11 of `entry`, before commitments.
fn sections(entry: &AuditEntry) -> AuditResult<[(u64, Section); 3]> {
    Ok([
        (SECTION_ACTION, action_section(&entry.action)?),
        (
            SECTION_AUTHORIZATION,
            authorization_section(&entry.authorization)?,
        ),
        (SECTION_OUTCOME, outcome_section(&entry.outcome)?),
    ])
}

fn section_item(index: u64, section: Section, seal: &EntryV2Seal) -> Cbor {
    let fields = section
        .fields
        .into_iter()
        .map(|(name, value)| {
            let salt = field_salt(&seal.salt_key, index, &name);
            let commitment = commitment(&seal.chain_id, seal.seq, index, &name, &salt, value);
            (Cbor::Text(name), Cbor::bytes(commitment.to_vec()))
        })
        .collect();
    Cbor::Array(vec![Cbor::Text(section.kind), Cbor::Map(fields)])
}

/// The body array of `entry`.
fn body_item(entry: &AuditEntry, seal: &EntryV2Seal) -> AuditResult<Cbor> {
    let [action, authorization, outcome] =
        sections(entry)?.map(|(index, section)| section_item(index, section, seal));
    Ok(Cbor::Array(vec![
        Cbor::text(ENTRY_TAG),
        Cbor::bytes(seal.chain_id.to_vec()),
        Cbor::Uint(seal.seq),
        Cbor::bytes(entry.previous_hash.as_bytes().to_vec()),
        // An unrepresentable time is never signed (creation rejects it); the
        // verifier reports it, so the placeholder cannot verify.
        Cbor::Uint(timestamp_nanos(&entry.timestamp).unwrap_or(0)),
        Cbor::bytes(entry.id.0.as_bytes().to_vec()),
        Cbor::bytes(entry.session_id.0.as_bytes().to_vec()),
        principal_item(
            entry.principal.as_ref().map(PrincipalId::as_str),
            seal.principal_uid.as_ref().map(PrincipalUid::as_bytes),
        ),
        seal.actor.as_ref().map_or(Cbor::Null, |actor| {
            Cbor::Array(vec![
                Cbor::text(actor.capsule_id.as_str()),
                actor
                    .wasm_sha256
                    .map_or(Cbor::Null, |hash| Cbor::bytes(hash.to_vec())),
            ])
        }),
        action,
        authorization,
        outcome,
        Cbor::Array(vec![
            Cbor::Uint(seal.key_epoch),
            Cbor::bytes(entry.runtime_key.as_bytes().to_vec()),
        ]),
    ]))
}

/// Deterministic CBOR bytes of the signed body.
pub(crate) fn body_bytes(entry: &AuditEntry, seal: &EntryV2Seal) -> AuditResult<Vec<u8>> {
    body_item(entry, seal).map(|item| item.encode())
}

/// The bytes Ed25519 signs for an entry with hash `entry_hash`.
#[must_use]
pub fn signing_input(entry_hash: &[u8; 32]) -> Vec<u8> {
    Cbor::Array(vec![
        Cbor::text(SIGNATURE_TAG),
        Cbor::text("entry"),
        Cbor::bytes(entry_hash.to_vec()),
    ])
    .encode()
}

fn disclosures(entry: &AuditEntry, seal: &EntryV2Seal) -> AuditResult<Vec<FieldDisclosure>> {
    let mut disclosures = Vec::new();
    for (index, section) in sections(entry)? {
        for (name, value) in section.fields {
            let salt = field_salt(&seal.salt_key, index, &name);
            let encoded = value.encode();
            let commitment = commitment(&seal.chain_id, seal.seq, index, &name, &salt, value);
            disclosures.push(FieldDisclosure {
                section: index,
                name,
                salt,
                value: encoded,
                commitment,
            });
        }
    }
    // The body's key order: section, then the dCBOR order of the name.
    disclosures.sort_by_cached_key(|disclosure| {
        (
            disclosure.section,
            Cbor::text(disclosure.name.as_str()).encode(),
        )
    });
    Ok(disclosures)
}

impl AuditEntry {
    /// The deterministic CBOR body of a format-v2 entry; `None` for v1.
    ///
    /// SHA-256 of these bytes is the entry's
    /// [`content_hash`](Self::content_hash).
    ///
    /// # Errors
    ///
    /// Returns an error when a section cannot be taken from its serde form;
    /// such an entry is never signed.
    pub fn v2_body(&self) -> AuditResult<Option<Vec<u8>>> {
        self.v2
            .as_ref()
            .map(|seal| body_bytes(self, seal))
            .transpose()
    }

    /// Openings of every committed field of a format-v2 entry.
    ///
    /// Hand a single disclosure to a third party to reveal one field; the
    /// others stay hidden. Empty for v1 entries.
    ///
    /// # Errors
    ///
    /// Returns an error when a section cannot be taken from its serde form.
    pub fn v2_field_disclosures(&self) -> AuditResult<Vec<FieldDisclosure>> {
        self.v2
            .as_ref()
            .map_or_else(|| Ok(Vec::new()), |seal| disclosures(self, seal))
    }

    /// SHA-256 of the v2 body.
    pub(crate) fn v2_entry_hash(&self, seal: &EntryV2Seal) -> AuditResult<[u8; 32]> {
        body_bytes(self, seal).map(|body| sha256(&body))
    }

    /// SHA-256 of the v2 body, or a value no signature or link can match
    /// when the body cannot be encoded.
    pub(crate) fn v2_hash_or_unencodable(&self, seal: &EntryV2Seal) -> [u8; 32] {
        self.v2_entry_hash(seal)
            .unwrap_or_else(|_| sha256(UNENCODABLE_TAG))
    }

    /// Create and sign a new v2 entry at the current time.
    pub(crate) fn create_v2(draft: EntryV2Draft, signer: &KeyPair) -> AuditResult<Self> {
        Self::assemble_v2(
            draft,
            signer,
            AuditEntryId::new(),
            Timestamp::now(),
            astrid_crypto::random_bytes(),
        )
    }

    /// Build and sign a v2 entry from fixed identity, time and salt key.
    pub(crate) fn assemble_v2(
        draft: EntryV2Draft,
        signer: &KeyPair,
        id: AuditEntryId,
        timestamp: Timestamp,
        salt_key: [u8; 32],
    ) -> AuditResult<Self> {
        if timestamp_nanos(&timestamp).is_none() {
            return Err(AuditError::IntegrityViolation {
                entry_id: id.to_string(),
                reason: "entry time is not representable as u64 nanoseconds".to_owned(),
            });
        }
        if draft.seq == 0 {
            return Err(AuditError::IntegrityViolation {
                entry_id: id.to_string(),
                reason: "v2 sequence numbers start at 1".to_owned(),
            });
        }
        let mut entry = Self {
            id,
            timestamp,
            session_id: draft.session_id,
            principal: draft.principal,
            action: draft.action,
            authorization: draft.authorization,
            outcome: draft.outcome,
            previous_hash: draft.previous_hash,
            runtime_key: signer.export_public_key(),
            signature: Signature::from_bytes([0u8; 64]),
            v2: Some(EntryV2Seal {
                chain_id: draft.chain_id,
                seq: draft.seq,
                key_epoch: draft.key_epoch,
                principal_uid: draft.principal_uid,
                actor: draft.actor,
                salt_key,
            }),
        };
        let seal = entry
            .v2
            .as_ref()
            .ok_or_else(|| AuditError::SerializationError("a v2 entry lost its seal".to_owned()))?;
        let hash = entry.v2_entry_hash(seal)?;
        entry.signature = signer.sign(&signing_input(&hash));
        Ok(entry)
    }
}
