//! The key registry: a cross-signed chain of records that says which Ed25519
//! key holds which signing role, and from which registry state on.
//!
//! The byte-level definition is in the [module docs](super).

use astrid_core::Timestamp;
use astrid_crypto::{KeyPair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use super::body::{SIGNATURE_TAG, sha256, timestamp_nanos};
use super::cbor::Cbor;
use super::serde_hex;
use crate::error::{AuditError, AuditResult};

/// Domain tag, element 0 of every key-registry record body.
pub const REGISTRY_TAG: &str = "astrid.audit.key-registry.v2";

/// A signing role a key can be registered for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// Signs format-v2 audit entries and their archive receipts.
    Audit,
    /// Signs capability tokens.
    Capability,
    /// Signs local capsule builds.
    Build,
    /// Signed format-v1 audit entries. Never accepted for a v2 entry.
    AuditV1,
}

impl KeyRole {
    /// Stable wire code of the role.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Audit => 1,
            Self::Capability => 2,
            Self::Build => 3,
            Self::AuditV1 => 4,
        }
    }

    /// The role with wire code `code`.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Audit),
            2 => Some(Self::Capability),
            3 => Some(Self::Build),
            4 => Some(Self::AuditV1),
            _ => None,
        }
    }
}

/// One `[role, key]` pair of a registry record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBinding {
    /// The role.
    pub role: KeyRole,
    /// The Ed25519 public key.
    pub key: PublicKey,
}

impl KeyBinding {
    fn sort_key(&self) -> (u64, [u8; 32]) {
        (self.role.code(), *self.key.as_bytes())
    }

    fn item(&self) -> Cbor {
        Cbor::Array(vec![
            Cbor::Uint(self.role.code()),
            Cbor::bytes(self.key.as_bytes().to_vec()),
        ])
    }
}

/// What a registry record does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryOp {
    /// The first record: registers the initial key of each role.
    Genesis,
    /// Replaces the key of one role.
    Rotate,
}

impl RegistryOp {
    /// Stable wire code of the operation.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Genesis => 0,
            Self::Rotate => 1,
        }
    }
}

/// A signature by one key over a registry record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySignature {
    /// The signing key; must be one of the record's bound keys.
    pub key: PublicKey,
    /// Ed25519 over the record's signing input.
    pub signature: Signature,
}

/// One record of the key registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRegistryRecord {
    /// Position in the registry; 0 is the genesis.
    pub seq: u64,
    /// Hash of the previous record; zero at genesis.
    #[serde(with = "serde_hex::array")]
    pub prev: [u8; 32],
    /// When the record was made (self-asserted).
    pub timestamp: Timestamp,
    /// What the record does.
    pub op: RegistryOp,
    /// Keys the record registers, sorted by role code then key bytes.
    pub add: Vec<KeyBinding>,
    /// Keys the record retires, sorted like `add`.
    pub retire: Vec<KeyBinding>,
    /// One signature per distinct key in `add` and `retire`, sorted by key.
    pub signatures: Vec<RegistrySignature>,
}

impl KeyRegistryRecord {
    /// Deterministic CBOR body of the record (signatures excluded).
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        Cbor::Array(vec![
            Cbor::text(REGISTRY_TAG),
            Cbor::Uint(self.seq),
            Cbor::bytes(self.prev.to_vec()),
            Cbor::Uint(timestamp_nanos(&self.timestamp).unwrap_or(0)),
            Cbor::Uint(self.op.code()),
            Cbor::Array(self.add.iter().map(KeyBinding::item).collect()),
            Cbor::Array(self.retire.iter().map(KeyBinding::item).collect()),
        ])
        .encode()
    }

    /// SHA-256 of [`body`](Self::body).
    #[must_use]
    pub fn record_hash(&self) -> [u8; 32] {
        sha256(&self.body())
    }

    /// The bytes each bound key signs.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        Cbor::Array(vec![
            Cbor::text(SIGNATURE_TAG),
            Cbor::text("key-registry"),
            Cbor::bytes(self.record_hash().to_vec()),
        ])
        .encode()
    }

    /// Distinct keys that must sign this record, sorted by key bytes.
    fn required_signers(&self) -> Vec<PublicKey> {
        let mut keys: Vec<PublicKey> = self
            .add
            .iter()
            .chain(&self.retire)
            .map(|binding| binding.key)
            .collect();
        keys.sort_by_key(|key| *key.as_bytes());
        keys.dedup();
        keys
    }

    fn signed_by(mut self, keys: &[&KeyPair]) -> AuditResult<Self> {
        let input = self.signing_input();
        let mut signatures = Vec::new();
        for key in self.required_signers() {
            let pair = keys
                .iter()
                .find(|pair| pair.export_public_key() == key)
                .ok_or_else(|| registry_error("a bound key's private half was not supplied"))?;
            signatures.push(RegistrySignature {
                key,
                signature: pair.sign(&input),
            });
        }
        self.signatures = signatures;
        Ok(self)
    }
}

fn registry_error(reason: impl Into<String>) -> AuditError {
    AuditError::KeyRegistry(reason.into())
}

/// Validity of one registered key for one role, in registry states
/// `from..until`.
#[derive(Clone, Debug)]
struct Grant {
    binding: KeyBinding,
    from: u64,
    until: Option<u64>,
}

/// A verified key registry.
#[derive(Clone, Debug)]
pub struct KeyRegistry {
    records: Vec<KeyRegistryRecord>,
    hashes: Vec<[u8; 32]>,
    grants: Vec<Grant>,
}

impl KeyRegistry {
    /// Build and sign a genesis record binding each key to its role.
    ///
    /// Every key signs the record, which proves possession. There must be
    /// exactly one [`KeyRole::Audit`] key, it must not hold any other role,
    /// and no role may appear twice.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::KeyRegistry`] when the key set breaks those rules.
    pub fn genesis_record(
        timestamp: Timestamp,
        keys: &[(KeyRole, &KeyPair)],
    ) -> AuditResult<KeyRegistryRecord> {
        let mut add: Vec<KeyBinding> = keys
            .iter()
            .map(|(role, pair)| KeyBinding {
                role: *role,
                key: pair.export_public_key(),
            })
            .collect();
        add.sort_by_key(KeyBinding::sort_key);
        let pairs: Vec<&KeyPair> = keys.iter().map(|(_, pair)| *pair).collect();
        let record = KeyRegistryRecord {
            seq: 0,
            prev: [0u8; 32],
            timestamp,
            op: RegistryOp::Genesis,
            add,
            retire: Vec::new(),
            signatures: Vec::new(),
        }
        .signed_by(&pairs)?;
        // Validate through the same rules a verifier applies.
        Self::from_records(vec![record.clone()])?;
        Ok(record)
    }

    /// Verify a complete registry, genesis first.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::KeyRegistry`] for an empty list or any record
    /// that breaks the linkage, ordering, role or signature rules.
    pub fn from_records(records: Vec<KeyRegistryRecord>) -> AuditResult<Self> {
        if records.is_empty() {
            return Err(registry_error("a key registry needs a genesis record"));
        }
        let mut registry = Self {
            records: Vec::with_capacity(records.len()),
            hashes: Vec::with_capacity(records.len()),
            grants: Vec::new(),
        };
        for record in records {
            registry.push(record)?;
        }
        Ok(registry)
    }

    /// Build and sign a record that replaces `old` with `new` for `role`.
    ///
    /// Both keys sign it. `new` must never have been registered before.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::KeyRegistry`] when `old` is not the active key of
    /// `role` or the rotation is otherwise invalid.
    pub fn rotation_record(
        &self,
        role: KeyRole,
        old: &KeyPair,
        new: &KeyPair,
        timestamp: Timestamp,
    ) -> AuditResult<KeyRegistryRecord> {
        let record = KeyRegistryRecord {
            seq: self
                .head_seq()
                .checked_add(1)
                .ok_or_else(|| registry_error("key registry sequence exhausted"))?,
            prev: self.head_hash(),
            timestamp,
            op: RegistryOp::Rotate,
            add: vec![KeyBinding {
                role,
                key: new.export_public_key(),
            }],
            retire: vec![KeyBinding {
                role,
                key: old.export_public_key(),
            }],
            signatures: Vec::new(),
        }
        .signed_by(&[old, new])?;
        self.clone().push(record.clone())?;
        Ok(record)
    }

    /// Verify `record` as the next record and apply it.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::KeyRegistry`] when the record does not validly
    /// extend this registry; the registry is left unchanged.
    pub fn push(&mut self, record: KeyRegistryRecord) -> AuditResult<()> {
        let expected_seq = u64::try_from(self.records.len())
            .map_err(|_| registry_error("key registry too long"))?;
        if record.seq != expected_seq {
            return Err(registry_error(format!(
                "record {} is out of sequence; expected {expected_seq}",
                record.seq
            )));
        }
        if record.prev != self.head_hash_or_zero() {
            return Err(registry_error(format!(
                "record {} does not link to the previous record",
                record.seq
            )));
        }
        if timestamp_nanos(&record.timestamp).is_none() {
            return Err(registry_error("record time is not representable"));
        }
        check_sorted(&record.add)?;
        check_sorted(&record.retire)?;
        match record.op {
            RegistryOp::Genesis => self.check_genesis(&record)?,
            RegistryOp::Rotate => self.check_rotation(&record)?,
        }
        check_signatures(&record)?;
        self.apply(&record);
        self.hashes.push(record.record_hash());
        self.records.push(record);
        Ok(())
    }

    fn check_genesis(&self, record: &KeyRegistryRecord) -> AuditResult<()> {
        if record.seq != 0 || !self.records.is_empty() {
            return Err(registry_error("genesis must be the first record"));
        }
        if !record.retire.is_empty() || record.add.is_empty() {
            return Err(registry_error("genesis registers keys and retires none"));
        }
        let mut roles: Vec<KeyRole> = record.add.iter().map(|binding| binding.role).collect();
        roles.dedup();
        if roles.len() != record.add.len() {
            return Err(registry_error("genesis binds a role more than once"));
        }
        let audit: Vec<&KeyBinding> = record
            .add
            .iter()
            .filter(|binding| binding.role == KeyRole::Audit)
            .collect();
        let [audit] = audit.as_slice() else {
            return Err(registry_error("genesis must bind exactly one audit key"));
        };
        if record
            .add
            .iter()
            .any(|binding| binding.role != KeyRole::Audit && binding.key == audit.key)
        {
            return Err(registry_error("the audit key must not hold another role"));
        }
        Ok(())
    }

    fn check_rotation(&self, record: &KeyRegistryRecord) -> AuditResult<()> {
        if self.records.is_empty() {
            return Err(registry_error("a rotation needs a genesis"));
        }
        let ([added], [retired]) = (record.add.as_slice(), record.retire.as_slice()) else {
            return Err(registry_error("a rotation replaces exactly one key"));
        };
        if added.role != retired.role {
            return Err(registry_error("a rotation must keep the role"));
        }
        if self.active_key(retired.role, self.head_seq()) != Some(retired.key) {
            return Err(registry_error(
                "a rotation must retire the role's active key",
            ));
        }
        if self
            .grants
            .iter()
            .any(|grant| grant.binding.key == added.key)
        {
            return Err(registry_error(
                "a rotation must introduce a never-registered key",
            ));
        }
        Ok(())
    }

    fn apply(&mut self, record: &KeyRegistryRecord) {
        for retired in &record.retire {
            for grant in &mut self.grants {
                if grant.binding == *retired && grant.until.is_none() {
                    grant.until = Some(record.seq);
                }
            }
        }
        for added in &record.add {
            self.grants.push(Grant {
                binding: *added,
                from: record.seq,
                until: None,
            });
        }
    }

    fn head_hash_or_zero(&self) -> [u8; 32] {
        self.hashes.last().copied().unwrap_or([0u8; 32])
    }

    /// Hash of the latest record.
    #[must_use]
    pub fn head_hash(&self) -> [u8; 32] {
        self.head_hash_or_zero()
    }

    /// The registry id: the hash of the genesis record.
    #[must_use]
    pub fn registry_id(&self) -> [u8; 32] {
        self.hashes.first().copied().unwrap_or([0u8; 32])
    }

    /// Sequence number of the latest record: the current key epoch.
    #[must_use]
    pub fn head_seq(&self) -> u64 {
        self.records.last().map_or(0, |record| record.seq)
    }

    /// All records, genesis first.
    #[must_use]
    pub fn records(&self) -> &[KeyRegistryRecord] {
        &self.records
    }

    /// The key that holds `role` in registry state `epoch`.
    #[must_use]
    pub fn active_key(&self, role: KeyRole, epoch: u64) -> Option<PublicKey> {
        self.grants
            .iter()
            .find(|grant| grant.binding.role == role && grant.covers(epoch))
            .map(|grant| grant.binding.key)
    }

    /// Whether `key` holds `role` in registry state `epoch`. States beyond
    /// the latest record are unknown and never match.
    #[must_use]
    pub fn is_active(&self, role: KeyRole, key: &PublicKey, epoch: u64) -> bool {
        epoch <= self.head_seq()
            && self.grants.iter().any(|grant| {
                grant.binding.role == role && grant.binding.key == *key && grant.covers(epoch)
            })
    }

    /// Whether `key` was ever registered for `role`.
    #[must_use]
    pub fn was_registered(&self, role: KeyRole, key: &PublicKey) -> bool {
        self.grants
            .iter()
            .any(|grant| grant.binding.role == role && grant.binding.key == *key)
    }
}

impl Grant {
    fn covers(&self, epoch: u64) -> bool {
        self.from <= epoch && self.until.is_none_or(|until| epoch < until)
    }
}

fn check_sorted(bindings: &[KeyBinding]) -> AuditResult<()> {
    if bindings
        .windows(2)
        .all(|pair| matches!(pair, [left, right] if left.sort_key() < right.sort_key()))
    {
        Ok(())
    } else {
        Err(registry_error("key bindings must be sorted and distinct"))
    }
}

fn check_signatures(record: &KeyRegistryRecord) -> AuditResult<()> {
    let required = record.required_signers();
    if record.signatures.len() != required.len()
        || record
            .signatures
            .iter()
            .zip(&required)
            .any(|(signature, key)| signature.key != *key)
    {
        return Err(registry_error(format!(
            "record {} must carry exactly one signature per bound key, sorted by key",
            record.seq
        )));
    }
    let input = record.signing_input();
    for signature in &record.signatures {
        if signature
            .key
            .verify_strict(&input, &signature.signature)
            .is_err()
        {
            return Err(registry_error(format!(
                "record {} has an invalid signature by {}",
                record.seq, signature.key
            )));
        }
    }
    Ok(())
}
