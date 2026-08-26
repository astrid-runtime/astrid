//! One-shot first-owner provisioning facts.
//!
//! The claim in this module is deliberately only a signed, portable fact. It
//! does not assign an owner by itself. A storage authority must verify the
//! authenticated boot context and atomically commit the claim with the
//! ownership graph before any principal authority exists.

use core::num::NonZeroU64;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use astrid_resource_types::AuthorityEpoch;

use super::{FleetUid, PrincipalUid, UserUid};

/// Exact number of bytes in the first-owner signing statement.
pub const FIRST_OWNER_MESSAGE_LEN: usize = 349;

const MESSAGE_HEADER: [u8; 5] = *b"AFOv1";
const DOMAIN_SEPARATOR: [u8; 32] = *b"ASTRID-FIRST-OWNER-PROVISION-V1!";

/// Failure while validating a first-owner claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FirstOwnerClaimError {
    /// Authority epochs are one-based and cannot be zero.
    #[error("first-owner authority epoch must be non-zero")]
    ZeroAuthorityEpoch,
    /// Authority generations are one-based and cannot be zero.
    #[error("first-owner authority generation must be non-zero")]
    ZeroAuthorityGeneration,
    /// A pending first-owner claim must carry a non-zero expiry timestamp.
    #[error("first-owner claim expiry must be non-zero")]
    ZeroExpiry,
    /// The immutable user key is not a valid Ed25519 public key.
    #[error("first-owner public key is not a valid Ed25519 key")]
    InvalidPublicKey,
    /// The claim signature does not authenticate the canonical statement.
    #[error("first-owner claim signature verification failed")]
    InvalidSignature,
}

/// A signed one-shot request to bind the first human owner to a principal.
///
/// The signature is over [`Self::canonical_message`], not over a serialized
/// Rust/Serde representation. The exact statement is:
///
/// ```text
/// 0..5     fixed format marker (AFOv1)
/// 5..37    fixed domain separator
/// 37..69   authenticated machine context
/// 69..101  authenticated boot context
/// 101..133 kernel identity
/// 133..165 System Generation identity
/// 165..197 UserUid
/// 197..229 FleetUid
/// 229..261 initial PrincipalUid
/// 261..293 immutable initial user public key
/// 293..325 request nonce
/// 325..333 non-zero authority generation, little endian
/// 333..341 non-zero expiry timestamp, little endian
/// 341..349 non-zero AuthorityEpoch, little endian
/// ```
///
/// A claim is not a bearer handle. In particular, the bytes do not grant
/// authority until the storage CAS revalidates every identity and publishes
/// the enrolled graph edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstOwnerClaim {
    machine_context: [u8; 32],
    boot_context: [u8; 32],
    kernel_identity: [u8; 32],
    system_generation: [u8; 32],
    user_uid: UserUid,
    fleet_uid: FleetUid,
    principal_uid: PrincipalUid,
    initial_user_public_key: [u8; 32],
    nonce: [u8; 32],
    authority_generation: FirstOwnerGeneration,
    expires_at: u64,
    authority_epoch: AuthorityEpoch,
    #[serde(
        serialize_with = "serialize_signature",
        deserialize_with = "deserialize_signature"
    )]
    signature: [u8; 64],
}

/// Durable generation of the first-owner authority domain.
///
/// This is deliberately distinct from [`AuthorityEpoch`]: the epoch names
/// the live authorization decision while the generation names the enrollment
/// state incarnation. Both values are signed into a claim and persisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FirstOwnerGeneration(NonZeroU64);

impl FirstOwnerGeneration {
    /// First valid generation.
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    /// Construct from a non-zero raw value.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the raw non-zero value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Advance without wrapping.
    #[must_use]
    pub fn checked_next(self) -> Option<Self> {
        self.get().checked_add(1).and_then(Self::from_raw)
    }
}

fn serialize_signature<S>(signature: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(signature))
}

fn deserialize_signature<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(serde::de::Error::custom(
            "first-owner signature must be exactly 128 lowercase hexadecimal characters",
        ));
    }
    let decoded = hex::decode(value).map_err(serde::de::Error::custom)?;
    <[u8; 64]>::try_from(decoded)
        .map_err(|_| serde::de::Error::custom("first-owner signature must contain 64 bytes"))
}

impl FirstOwnerClaim {
    /// Construct a claim from its fixed fields and detached Ed25519 signature.
    ///
    /// The caller must obtain the signature over [`Self::canonical_message`]
    /// using the immutable user key. Storage performs the authoritative
    /// verification again before persisting a pending claim.
    ///
    /// # Errors
    ///
    /// Returns [`FirstOwnerClaimError::ZeroAuthorityEpoch`] when the bound
    /// authority epoch is zero.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors the fixed canonical statement fields"
    )]
    pub fn from_parts(
        machine_context: [u8; 32],
        boot_context: [u8; 32],
        kernel_identity: [u8; 32],
        system_generation: [u8; 32],
        user_uid: UserUid,
        fleet_uid: FleetUid,
        principal_uid: PrincipalUid,
        initial_user_public_key: [u8; 32],
        nonce: [u8; 32],
        authority_epoch: u64,
        signature: [u8; 64],
    ) -> Result<Self, FirstOwnerClaimError> {
        Self::from_parts_with_authority(
            machine_context,
            boot_context,
            kernel_identity,
            system_generation,
            user_uid,
            fleet_uid,
            principal_uid,
            initial_user_public_key,
            nonce,
            FirstOwnerGeneration::INITIAL.get(),
            u64::MAX,
            authority_epoch,
            signature,
        )
    }

    /// Construct a claim with explicit authority generation and expiry.
    ///
    /// # Errors
    ///
    /// Returns an error when the generation or authority epoch is zero, or
    /// when the expiry timestamp is zero.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors the fixed canonical statement fields"
    )]
    pub fn from_parts_with_authority(
        machine_context: [u8; 32],
        boot_context: [u8; 32],
        kernel_identity: [u8; 32],
        system_generation: [u8; 32],
        user_uid: UserUid,
        fleet_uid: FleetUid,
        principal_uid: PrincipalUid,
        initial_user_public_key: [u8; 32],
        nonce: [u8; 32],
        authority_generation: u64,
        expires_at: u64,
        authority_epoch: u64,
        signature: [u8; 64],
    ) -> Result<Self, FirstOwnerClaimError> {
        let authority_generation = FirstOwnerGeneration::from_raw(authority_generation)
            .ok_or(FirstOwnerClaimError::ZeroAuthorityGeneration)?;
        if expires_at == 0 {
            return Err(FirstOwnerClaimError::ZeroExpiry);
        }
        let authority_epoch = AuthorityEpoch::from_raw(authority_epoch)
            .ok_or(FirstOwnerClaimError::ZeroAuthorityEpoch)?;
        Ok(Self {
            machine_context,
            boot_context,
            kernel_identity,
            system_generation,
            user_uid,
            fleet_uid,
            principal_uid,
            initial_user_public_key,
            nonce,
            authority_generation,
            expires_at,
            authority_epoch,
            signature,
        })
    }

    /// Return the authenticated machine context bound by the statement.
    #[must_use]
    pub const fn machine_context(&self) -> &[u8; 32] {
        &self.machine_context
    }

    /// Return the authenticated boot context bound by the statement.
    #[must_use]
    pub const fn boot_context(&self) -> &[u8; 32] {
        &self.boot_context
    }

    /// Return the kernel identity bound by the statement.
    #[must_use]
    pub const fn kernel_identity(&self) -> &[u8; 32] {
        &self.kernel_identity
    }

    /// Return the System Generation identity bound by the statement.
    #[must_use]
    pub const fn system_generation(&self) -> &[u8; 32] {
        &self.system_generation
    }

    /// Return the human authority UID.
    #[must_use]
    pub const fn user_uid(&self) -> UserUid {
        self.user_uid
    }

    /// Return the fleet ownership UID.
    #[must_use]
    pub const fn fleet_uid(&self) -> FleetUid {
        self.fleet_uid
    }

    /// Return the initial executable principal UID.
    #[must_use]
    pub const fn principal_uid(&self) -> PrincipalUid {
        self.principal_uid
    }

    /// Return the immutable initial user public key.
    #[must_use]
    pub const fn initial_user_public_key(&self) -> &[u8; 32] {
        &self.initial_user_public_key
    }

    /// Return the one-shot request nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Return the non-zero authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Return the signed authority generation.
    #[must_use]
    pub const fn authority_generation(&self) -> FirstOwnerGeneration {
        self.authority_generation
    }

    /// Return the signed expiry timestamp in Unix seconds.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Return whether this claim has expired at the supplied Unix timestamp.
    #[must_use]
    pub const fn is_expired_at(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Return the detached Ed25519 signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Encode the exact fixed-width statement authenticated by the signature.
    #[must_use]
    pub fn canonical_message(&self) -> [u8; FIRST_OWNER_MESSAGE_LEN] {
        let mut message = [0_u8; FIRST_OWNER_MESSAGE_LEN];
        message[0..5].copy_from_slice(&MESSAGE_HEADER);
        message[5..37].copy_from_slice(&DOMAIN_SEPARATOR);
        message[37..69].copy_from_slice(&self.machine_context);
        message[69..101].copy_from_slice(&self.boot_context);
        message[101..133].copy_from_slice(&self.kernel_identity);
        message[133..165].copy_from_slice(&self.system_generation);
        message[165..197].copy_from_slice(self.user_uid.as_bytes());
        message[197..229].copy_from_slice(self.fleet_uid.as_bytes());
        message[229..261].copy_from_slice(self.principal_uid.as_bytes());
        message[261..293].copy_from_slice(&self.initial_user_public_key);
        message[293..325].copy_from_slice(&self.nonce);
        message[325..333].copy_from_slice(&self.authority_generation.get().to_le_bytes());
        message[333..341].copy_from_slice(&self.expires_at.to_le_bytes());
        message[341..349].copy_from_slice(&self.authority_epoch.get().to_le_bytes());
        message
    }

    /// Return the BLAKE3 digest of the canonical statement.
    #[must_use]
    pub fn canonical_digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_message()).as_bytes()
    }

    /// Verify the claim using its immutable initial user public key.
    ///
    /// # Errors
    ///
    /// Returns [`FirstOwnerClaimError::InvalidPublicKey`] or
    /// [`FirstOwnerClaimError::InvalidSignature`] when authentication fails.
    pub fn verify_signature(&self) -> Result<(), FirstOwnerClaimError> {
        let key = VerifyingKey::from_bytes(&self.initial_user_public_key)
            .map_err(|_| FirstOwnerClaimError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.canonical_message(), &signature)
            .map_err(|_| FirstOwnerClaimError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};
    use uuid::Uuid;

    use super::*;
    use crate::{FleetGenesis, PrincipalGenesis, PrincipalIdentity, UserGenesis, UserIdentity};

    fn fixture_nonce() -> [u8; 32] {
        let mut nonce: [u8; 32] = std::array::from_fn(|_| 0_u8);
        getrandom::fill(&mut nonce).expect("fixture nonce");
        nonce
    }

    fn claim() -> FirstOwnerClaim {
        let key = SigningKey::from_bytes(&[7; 32]);
        let user = UserIdentity::from_genesis(UserGenesis::from_parts(
            Uuid::from_u128(1),
            chrono::Utc
                .timestamp_opt(1_700_000_000, 0)
                .single()
                .unwrap(),
            key.verifying_key().to_bytes(),
        ))
        .unwrap();
        let fleet = crate::FleetIdentity::from_genesis(FleetGenesis::from_parts(
            Uuid::from_u128(2),
            chrono::Utc
                .timestamp_opt(1_700_001_000, 0)
                .single()
                .unwrap(),
            user.uid,
        ))
        .unwrap();
        let principal = PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
            Uuid::from_u128(3),
            chrono::Utc
                .timestamp_opt(1_700_002_000, 0)
                .single()
                .unwrap(),
            [9; 32],
        ))
        .unwrap();
        let nonce = fixture_nonce();
        let unsigned = FirstOwnerClaim::from_parts_with_authority(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            user.uid,
            fleet.uid,
            principal.uid,
            key.verifying_key().to_bytes(),
            nonce,
            1,
            1_800_000_000,
            1,
            [0; 64],
        )
        .unwrap();
        let claim = FirstOwnerClaim::from_parts_with_authority(
            *unsigned.machine_context(),
            *unsigned.boot_context(),
            *unsigned.kernel_identity(),
            *unsigned.system_generation(),
            unsigned.user_uid(),
            unsigned.fleet_uid(),
            unsigned.principal_uid(),
            *unsigned.initial_user_public_key(),
            *unsigned.nonce(),
            unsigned.authority_generation().get(),
            unsigned.expires_at(),
            unsigned.authority_epoch().get(),
            key.sign(&unsigned.canonical_message()).to_bytes(),
        )
        .unwrap();
        assert_eq!(*claim.nonce(), nonce);
        claim
    }

    #[test]
    fn canonical_message_has_golden_shape_and_digest() {
        let claim = claim();
        let message = claim.canonical_message();
        assert_eq!(message.len(), FIRST_OWNER_MESSAGE_LEN);
        assert_eq!(&message[..5], b"AFOv1");
        assert_eq!(&message[5..37], b"ASTRID-FIRST-OWNER-PROVISION-V1!");
        assert_eq!(message[325..333], [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(message[333..341], 1_800_000_000_u64.to_le_bytes());
        assert_eq!(message[341..349], [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(claim.canonical_digest(), *blake3::hash(&message).as_bytes());
    }

    #[test]
    fn every_bound_field_changes_the_statement() {
        let claim = claim();
        let original = claim.canonical_digest();
        let mut altered = claim;
        altered.machine_context[0] ^= 1;
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.boot_context[0] ^= 1;
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.kernel_identity[0] ^= 1;
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.system_generation[0] ^= 1;
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.user_uid = UserUid::from_bytes([8; 32]);
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.fleet_uid = FleetUid::from_bytes([8; 32]);
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.principal_uid = PrincipalUid::from_bytes([8; 32]);
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.initial_user_public_key[0] ^= 1;
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.nonce[0] ^= 1;
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.authority_generation = FirstOwnerGeneration::from_raw(2).unwrap();
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.expires_at += 1;
        assert_ne!(altered.canonical_digest(), original);
        altered = claim;
        altered.authority_epoch = AuthorityEpoch::from_raw(2).unwrap();
        assert_ne!(altered.canonical_digest(), original);
    }

    #[test]
    fn signature_is_verified_over_canonical_message() {
        let claim = claim();
        claim.verify_signature().unwrap();
        let mut altered = claim;
        altered.nonce[0] ^= 1;
        assert_eq!(
            altered.verify_signature(),
            Err(FirstOwnerClaimError::InvalidSignature)
        );
    }

    #[test]
    fn zero_epoch_is_rejected() {
        assert_eq!(
            FirstOwnerClaim::from_parts_with_authority(
                [0; 32],
                [0; 32],
                [0; 32],
                [0; 32],
                UserUid::from_bytes([0; 32]),
                FleetUid::from_bytes([0; 32]),
                PrincipalUid::from_bytes([0; 32]),
                [0; 32],
                [0; 32],
                1,
                1_800_000_000,
                0,
                [0; 64],
            ),
            Err(FirstOwnerClaimError::ZeroAuthorityEpoch)
        );
    }

    #[test]
    fn maximum_epoch_is_encoded_without_wrapping() {
        let nonce = fixture_nonce();
        let claim = FirstOwnerClaim::from_parts_with_authority(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            UserUid::from_bytes([5; 32]),
            FleetUid::from_bytes([6; 32]),
            PrincipalUid::from_bytes([7; 32]),
            [8; 32],
            nonce,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            [0; 64],
        )
        .unwrap();
        assert_eq!(*claim.nonce(), nonce);
        assert_eq!(claim.authority_epoch().get(), u64::MAX);
        assert_eq!(&claim.canonical_message()[325..333], &[0xff; 8]);
    }
}
