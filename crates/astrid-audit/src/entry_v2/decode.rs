//! Strict decoding of a v2 entry body, for verifiers that hold only the
//! canonical bytes and the signature (the redacted form).

use astrid_crypto::{PublicKey, Signature};

use super::body::{ENTRY_TAG, chain_id_from_parts, sha256, signing_input};
use super::cbor::Cbor;
use super::registry::{KeyRegistry, KeyRole};
use crate::error::{AuditError, AuditResult};

/// A decoded `[kind, FieldMap]` section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedSection {
    /// The variant tag.
    pub kind: String,
    /// Each field's name and salted commitment, in encoded order.
    pub fields: Vec<(String, [u8; 32])>,
}

/// Every element of a v2 entry body, decoded from its canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryV2Header {
    /// SHA-256 of the body: the entry hash.
    pub entry_hash: [u8; 32],
    /// Element 1: chain id.
    pub chain_id: [u8; 32],
    /// Element 2: sequence number.
    pub seq: u64,
    /// Element 3: previous hash.
    pub prev: [u8; 32],
    /// Element 4: nanoseconds since the Unix epoch.
    pub time_ns: u64,
    /// Element 5: entry id (UUID bytes).
    pub entry_id: [u8; 16],
    /// Element 6: session id (UUID bytes).
    pub session: [u8; 16],
    /// Element 7: principal UID, when bound.
    pub principal_uid: Option<[u8; 32]>,
    /// Element 7: principal alias; `None` on a system chain.
    pub principal_alias: Option<String>,
    /// Element 8: acting capsule id and module SHA-256, when known.
    pub actor: Option<(String, Option<[u8; 32]>)>,
    /// Element 9: the action.
    pub action: DecodedSection,
    /// Element 10: the authorization.
    pub authorization: DecodedSection,
    /// Element 11: the outcome.
    pub outcome: DecodedSection,
    /// Element 12: key epoch.
    pub key_epoch: u64,
    /// Element 12: signing key.
    pub signer: PublicKey,
}

fn malformed(reason: &str) -> AuditError {
    AuditError::SerializationError(format!("malformed v2 entry body: {reason}"))
}

fn uint(item: &Cbor, what: &str) -> AuditResult<u64> {
    match item {
        Cbor::Uint(value) => Ok(*value),
        _ => Err(malformed(what)),
    }
}

fn fixed<const N: usize>(item: &Cbor, what: &str) -> AuditResult<[u8; N]> {
    match item {
        Cbor::Bytes(bytes) => <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| malformed(what)),
        _ => Err(malformed(what)),
    }
}

fn optional<T>(item: &Cbor, parse: impl FnOnce(&Cbor) -> AuditResult<T>) -> AuditResult<Option<T>> {
    match item {
        Cbor::Null => Ok(None),
        other => parse(other).map(Some),
    }
}

fn text(item: &Cbor, what: &str) -> AuditResult<String> {
    match item {
        Cbor::Text(text) => Ok(text.clone()),
        _ => Err(malformed(what)),
    }
}

fn section(item: &Cbor, what: &str) -> AuditResult<DecodedSection> {
    let Cbor::Array(parts) = item else {
        return Err(malformed(what));
    };
    let [kind, Cbor::Map(entries)] = parts.as_slice() else {
        return Err(malformed(what));
    };
    let fields = entries
        .iter()
        .map(|(name, commitment)| Ok((text(name, what)?, fixed(commitment, what)?)))
        .collect::<AuditResult<Vec<_>>>()?;
    Ok(DecodedSection {
        kind: text(kind, what)?,
        fields,
    })
}

fn actor(item: &Cbor) -> AuditResult<(String, Option<[u8; 32]>)> {
    let Cbor::Array(parts) = item else {
        return Err(malformed("actor"));
    };
    let [capsule, wasm] = parts.as_slice() else {
        return Err(malformed("actor"));
    };
    Ok((
        text(capsule, "actor capsule id")?,
        optional(wasm, |item| fixed(item, "actor wasm hash"))?,
    ))
}

impl EntryV2Header {
    /// Strictly decode a v2 entry body.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::SerializationError`] when `body` is not the
    /// deterministic encoding of a well-formed v2 entry body.
    pub fn decode(body: &[u8]) -> AuditResult<Self> {
        let item = Cbor::decode(body).map_err(|error| malformed(&error.to_string()))?;
        let Cbor::Array(elements) = item else {
            return Err(malformed("not an array"));
        };
        let [
            tag,
            chain,
            seq,
            prev,
            time,
            id,
            session,
            principal,
            actor_item,
            action,
            authorization,
            outcome,
            signer,
        ] = elements.as_slice()
        else {
            return Err(malformed("expected 13 elements"));
        };
        if *tag != Cbor::text(ENTRY_TAG) {
            return Err(malformed("unknown domain tag"));
        }
        if *seq == Cbor::Uint(0) {
            return Err(malformed("sequence numbers start at 1"));
        }
        let Cbor::Array(principal) = principal else {
            return Err(malformed("principal"));
        };
        let [uid, alias] = principal.as_slice() else {
            return Err(malformed("principal"));
        };
        let Cbor::Array(signer) = signer else {
            return Err(malformed("signer"));
        };
        let [epoch, key] = signer.as_slice() else {
            return Err(malformed("signer"));
        };
        Ok(Self {
            entry_hash: sha256(body),
            chain_id: fixed(chain, "chain id")?,
            seq: uint(seq, "sequence")?,
            prev: fixed(prev, "previous hash")?,
            time_ns: uint(time, "time")?,
            entry_id: fixed(id, "entry id")?,
            session: fixed(session, "session")?,
            principal_uid: optional(uid, |item| fixed(item, "principal uid"))?,
            principal_alias: optional(alias, |item| text(item, "principal alias"))?,
            actor: optional(actor_item, actor)?,
            action: section(action, "action")?,
            authorization: section(authorization, "authorization")?,
            outcome: section(outcome, "outcome")?,
            key_epoch: uint(epoch, "key epoch")?,
            signer: PublicKey::from_bytes(fixed(key, "signer key")?),
        })
    }
}

/// Verify a v2 entry held only as its canonical body and signature.
///
/// Decodes the body strictly, checks the chain id against the registry,
/// requires the signer to hold [`KeyRole::Audit`] in the registry state the
/// body names, and checks the
/// signature with strict Ed25519 verification. Chain continuity (sequence and
/// previous hash across entries) is left to the caller, using the returned
/// header.
///
/// # Errors
///
/// Returns an error when the body is malformed, the signer is not registered
/// for the audit role at the body's key epoch, or the signature is invalid.
pub fn verify_entry_v2_body(
    body: &[u8],
    signature: &Signature,
    registry: &KeyRegistry,
) -> AuditResult<EntryV2Header> {
    let header = EntryV2Header::decode(body)?;
    let chain_id = chain_id_from_parts(
        &registry.registry_id(),
        &header.session,
        header.principal_uid.as_ref(),
        header.principal_alias.as_deref(),
    );
    if chain_id != header.chain_id {
        return Err(AuditError::IntegrityViolation {
            entry_id: hex::encode(header.entry_id),
            reason: "chain id does not match the registry, session and principal".to_owned(),
        });
    }
    if !registry.is_active(KeyRole::Audit, &header.signer, header.key_epoch) {
        return Err(AuditError::KeyNotRegistered {
            key: header.signer.to_hex(),
        });
    }
    header
        .signer
        .verify_strict(&signing_input(&header.entry_hash), signature)
        .map_err(|_| AuditError::InvalidSignature {
            entry_id: hex::encode(header.entry_id),
        })?;
    Ok(header)
}
