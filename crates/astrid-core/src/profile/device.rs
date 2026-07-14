//! Per-device capability scope: [`DeviceKey`] and [`DeviceScope`].
//!
//! A principal's `AuthConfig.public_keys` is a list of [`DeviceKey`]s — each a
//! registered ed25519 public key plus the capability [`DeviceScope`] the
//! pairing was granted. The scope is a *floor* applied on top of the
//! principal's effective capabilities at the cap-gate: a request
//! authenticated with a `Scoped` device is permitted only if the principal
//! holds the capability AND the scope admits it. `Full` devices apply no
//! attenuation, which is the behaviour every registered key had before
//! per-device scoping and the form every migrated legacy bare key loads as.
//!
//! On disk a `DeviceKey` may be EITHER a legacy bare `"ed25519:<hex>"` string
//! (migrated to a Full-scope device on load) OR the full struct form;
//! serialization always re-emits the struct form.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Capability attenuation scope bound to a single registered device key.
///
/// A device's scope is a *floor* applied on top of the acting principal's
/// effective capabilities: a request authenticated with a `Scoped` device is
/// permitted only if the principal holds it AND the scope admits it. `Full`
/// devices apply no attenuation — they act with the principal's full effective
/// capability set, which is the behaviour every key had before per-device
/// scoping and the form every migrated legacy bare key loads as.
///
/// Wire form is internally tagged on `type` so it round-trips cleanly through
/// TOML and JSON: `Full` is `{ type = "full" }`, `Scoped` is
/// `{ type = "scoped", allow = [..], deny = [..] }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceScope {
    /// No attenuation. The device acts with the principal's full effective
    /// capability set.
    Full,
    /// The device may exercise a capability only if it matches an `allow`
    /// pattern AND matches no `deny` pattern. Deny wins, mirroring the
    /// grant/revoke precedence on a principal profile. Patterns may be
    /// wildcards (same grammar as grants/revokes). This is purely
    /// restrictive — it can never grant a capability the principal lacks.
    Scoped {
        /// Capability patterns the device is permitted to exercise.
        #[serde(default)]
        allow: Vec<String>,
        /// Capability patterns the device is forbidden to exercise. A match
        /// here denies even if an `allow` pattern also matches.
        #[serde(default)]
        deny: Vec<String>,
    },
}

impl DeviceScope {
    /// Resolve a named scope preset, or `None` for an unknown name.
    ///
    /// - `"full"` → [`DeviceScope::Full`] (no attenuation; minting one
    ///   requires the `self:auth:pair:admin` capability).
    /// - `"use-only"` → a `Scoped` device that may use the principal's own
    ///   self-scoped capabilities but cannot mint further pair-device tokens
    ///   (neither scoped nor full) and cannot delegate self capabilities. This
    ///   is the safe default for a device that should be able to act but never
    ///   widen the principal's device fleet.
    #[must_use]
    pub fn preset(name: &str) -> Option<Self> {
        match name {
            "full" => Some(Self::Full),
            "use-only" => Some(Self::Scoped {
                allow: vec!["self:*".to_string()],
                deny: vec![
                    "self:auth:pair".to_string(),
                    "self:auth:pair:admin".to_string(),
                    "delegate:self:*".to_string(),
                ],
            }),
            _ => None,
        }
    }
}

/// A public key registered to a principal, with the capability scope the
/// device pairing was granted.
///
/// `pubkey` is the canonical lowercase hex form of the ed25519 public key
/// *without* the `ed25519:` prefix; [`DeviceKey::ed25519_entry`] reconstructs
/// the prefixed form the signature-verification loops expect. `key_id` is a
/// deterministic short fingerprint of the pubkey (see
/// [`device_key_id_fingerprint`]) — stable across re-pairing of the same key,
/// so a re-redeem is idempotent and a revoke can target one device by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceKey {
    /// Deterministic short fingerprint of `pubkey`. Non-secret (the pubkey it
    /// derives from is itself public). Used as the stable per-device handle
    /// for scope attenuation, listing, and revocation.
    pub key_id: String,
    /// Canonical lowercase hex of the ed25519 public key, no `ed25519:`
    /// prefix.
    pub pubkey: String,
    /// Capability attenuation scope for requests authenticated with this key.
    pub scope: DeviceScope,
    /// Optional operator/user-facing label (e.g. "Josh's laptop").
    pub label: Option<String>,
    /// Unix epoch seconds when the device was paired. `0` for migrated legacy
    /// keys that predate pairing-time recording.
    pub created_at: i64,
}

/// Length, in hex characters, of a [`DeviceKey::key_id`] fingerprint
/// (8 bytes of BLAKE3 -> 16 hex chars). Collision-resistant enough for the
/// per-principal device set while staying short enough to paste.
pub const DEVICE_KEY_ID_HEX_LEN: usize = 16;

/// Number of hex characters in a canonical ed25519 public key (32 bytes).
const ED25519_PUBKEY_HEX_LEN: usize = 64;

/// Validated deterministic handle for a paired device key.
///
/// The public profile and management API remain string-shaped for
/// compatibility. This wrapper lets internal code distinguish a revocation /
/// bearer handle from the raw ed25519 public key it was derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceKeyId<S = String>(S);

impl<S: AsRef<str>> DeviceKeyId<S> {
    /// Create a validated device key handle.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason when `id` is not the canonical
    /// lowercase hex fingerprint shape produced by
    /// [`device_key_id_fingerprint`].
    pub fn new(id: S) -> Result<Self, String> {
        validate_device_key_id(id.as_ref())?;
        Ok(Self(id))
    }

    /// Borrow the validated key id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl DeviceKeyId<String> {
    /// Derive the deterministic device key id for a canonical public key.
    #[must_use]
    pub fn for_pubkey(pubkey: &DevicePubkey<impl AsRef<str>>) -> Self {
        Self(device_key_id_fingerprint(pubkey.as_str()))
    }

    /// Consume the wrapper and return the owned string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Validated canonical lowercase hex ed25519 public key, without prefix.
///
/// This is the profile storage form. Incoming operator/API values may include
/// an `ed25519:` prefix and mixed case; use [`DevicePubkey::normalize`] at
/// those edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DevicePubkey<S = String>(S);

impl<S: AsRef<str>> DevicePubkey<S> {
    /// Create a typed view over a canonical stored public key.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason when `pubkey` is not 64 lowercase hex
    /// characters without the `ed25519:` prefix.
    pub fn from_canonical(pubkey: S) -> Result<Self, String> {
        validate_pubkey_hex(pubkey.as_ref(), "device public key")?;
        Ok(Self(pubkey))
    }

    /// Borrow the canonical public key hex.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl DevicePubkey<String> {
    /// Normalize an incoming public key to the profile storage form.
    ///
    /// Accepts either bare 64-character hex or `ed25519:<hex>`, trims
    /// surrounding whitespace, and lowercases the result.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason when the normalized key is not a
    /// 32-byte ed25519 public key encoded as hex.
    pub fn normalize(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let candidate = trimmed
            .strip_prefix("ed25519:")
            .unwrap_or(trimmed)
            .to_ascii_lowercase();
        validate_pubkey_hex(&candidate, "device public key")?;
        Ok(Self(candidate))
    }

    /// Consume the wrapper and return the owned canonical public key hex.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

macro_rules! impl_string_newtype {
    ($ty:ident) => {
        impl<S: AsRef<str>> AsRef<str> for $ty<S> {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl<S: AsRef<str>> fmt::Display for $ty<S> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl From<$ty<String>> for String {
            fn from(value: $ty<String>) -> Self {
                value.into_inner()
            }
        }

        impl TryFrom<String> for $ty<String> {
            type Error = String;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl FromStr for $ty<String> {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s.to_string())
            }
        }

        impl<S: AsRef<str>> PartialEq<str> for $ty<S> {
            fn eq(&self, other: &str) -> bool {
                self.as_str() == other
            }
        }

        impl<S: AsRef<str>> PartialEq<&str> for $ty<S> {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }

        impl<S: AsRef<str>> PartialEq<String> for $ty<S> {
            fn eq(&self, other: &String) -> bool {
                self.as_str() == other
            }
        }

        impl<S: AsRef<str>> PartialEq<&String> for $ty<S> {
            fn eq(&self, other: &&String) -> bool {
                self.as_str() == other.as_str()
            }
        }

        impl<S: AsRef<str>> Serialize for $ty<S> {
            fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
            where
                Ser: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $ty<String> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

impl_string_newtype!(DeviceKeyId);

impl<S: AsRef<str>> AsRef<str> for DevicePubkey<S> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<S: AsRef<str>> fmt::Display for DevicePubkey<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<DevicePubkey<String>> for String {
    fn from(value: DevicePubkey<String>) -> Self {
        value.into_inner()
    }
}

impl TryFrom<String> for DevicePubkey<String> {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_canonical(value)
    }
}

impl FromStr for DevicePubkey<String> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate_pubkey_hex(s, "device public key")?;
        Ok(Self(s.to_string()))
    }
}

impl<S: AsRef<str>> PartialEq<str> for DevicePubkey<S> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<S: AsRef<str>> PartialEq<&str> for DevicePubkey<S> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl<S: AsRef<str>> PartialEq<String> for DevicePubkey<S> {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl<S: AsRef<str>> PartialEq<&String> for DevicePubkey<S> {
    fn eq(&self, other: &&String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<S: AsRef<str>> Serialize for DevicePubkey<S> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DevicePubkey<String> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_canonical(value).map_err(serde::de::Error::custom)
    }
}

/// Derive a deterministic, non-secret fingerprint for a device key from its
/// canonical lowercase-hex pubkey: the first [`DEVICE_KEY_ID_HEX_LEN`] hex
/// chars of `BLAKE3(pubkey_hex_bytes)`.
///
/// The fingerprint is **not** a secret — it is derived purely from the
/// already-public ed25519 public key, so surfacing it in listings, audit
/// rows, and on the bus leaks nothing. Determinism is the point: re-pairing
/// the same key yields the same `key_id`, which makes redemption idempotent
/// (dedup by pubkey) and lets revocation target a single device by id.
#[must_use]
pub fn device_key_id_fingerprint(pubkey_hex: &str) -> String {
    device_key_id_for_pubkey_hex(pubkey_hex).into_inner()
}

fn device_key_id_for_pubkey_hex(pubkey_hex: &str) -> DeviceKeyId<String> {
    let digest = blake3::hash(pubkey_hex.as_bytes());
    DeviceKeyId(hex::encode(&digest.as_bytes()[..DEVICE_KEY_ID_HEX_LEN / 2]))
}

/// Normalise a candidate ed25519 public key string to canonical lowercase hex
/// without the `ed25519:` prefix, validating shape. Returns the bare hex on
/// success or a human-readable reason on failure (fail-closed).
fn normalise_pubkey_hex(raw: &str) -> Result<String, String> {
    DevicePubkey::normalize(raw).map(DevicePubkey::into_inner)
}

fn validate_pubkey_hex(candidate: &str, field: &str) -> Result<(), String> {
    if candidate.len() != ED25519_PUBKEY_HEX_LEN {
        return Err(format!(
            "{field} must be 32 bytes hex-encoded ({ED25519_PUBKEY_HEX_LEN} hex chars); got {} chars",
            candidate.len()
        ));
    }
    if !candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{field} contains non-hex characters"));
    }
    if candidate.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(format!("{field} must be lowercase hex"));
    }
    Ok(())
}

fn validate_device_key_id(id: &str) -> Result<(), String> {
    if id.len() != DEVICE_KEY_ID_HEX_LEN {
        return Err(format!(
            "device key_id must be {DEVICE_KEY_ID_HEX_LEN} lowercase hex chars; got {} chars",
            id.len()
        ));
    }
    if !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("device key_id contains non-hex characters".into());
    }
    if id.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("device key_id must be lowercase hex".into());
    }
    Ok(())
}

impl DeviceKey {
    /// Build a [`DeviceKey`] from a canonical lowercase-hex pubkey and a
    /// scope, deriving the deterministic `key_id` and defaulting label/time.
    ///
    /// The caller is responsible for having already validated `pubkey_hex`
    /// (e.g. via the redeem/issue paths); the fingerprint is computed over
    /// whatever bytes are passed.
    #[must_use]
    pub fn new(
        pubkey_hex: String,
        scope: DeviceScope,
        label: Option<String>,
        created_at: i64,
    ) -> Self {
        let pubkey = DevicePubkey(pubkey_hex);
        let key_id = DeviceKeyId::for_pubkey(&pubkey).into_inner();
        Self {
            key_id,
            pubkey: pubkey.into_inner(),
            scope,
            label,
            created_at,
        }
    }

    /// The `ed25519:<hex>` self-describing form expected by the signature
    /// verification loops and the audit fingerprinter.
    #[must_use]
    pub fn ed25519_entry(&self) -> String {
        format!("ed25519:{}", self.pubkey)
    }

    /// Whether this key's canonical pubkey equals `hex_lower` (already
    /// lowercase hex, no prefix).
    #[must_use]
    pub fn matches_pubkey(&self, hex_lower: &str) -> bool {
        self.pubkey == hex_lower
    }

    /// Typed view of this device's stable key id.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason if the public `key_id` field has been
    /// mutated into a non-canonical value.
    pub fn typed_key_id(&self) -> Result<DeviceKeyId<&str>, String> {
        DeviceKeyId::new(self.key_id.as_str())
    }

    /// Typed view of this device's canonical public key.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason if the public `pubkey` field has been
    /// mutated into a non-canonical value.
    pub fn typed_pubkey(&self) -> Result<DevicePubkey<&str>, String> {
        DevicePubkey::from_canonical(self.pubkey.as_str())
    }
}

/// Plain deserialization mirror of [`DeviceKey`]'s full struct form, used by
/// the migration-aware [`DeviceKey`] `Deserialize` impl. `deny_unknown_fields`
/// keeps an operator typo (or an attacker-crafted profile) from silently
/// dropping a field. Defaults let the full form omit `scope`/`label`/
/// `created_at`/`key_id`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceKeyData {
    /// Accepted on the wire so a serialized `DeviceKey` (which always writes
    /// `key_id`) round-trips under `deny_unknown_fields`, but intentionally
    /// NOT read: the `Deserialize` impl re-derives `key_id` from the pubkey
    /// unconditionally, since it is a deterministic fingerprint by contract.
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "accepted for round-trip; key_id is re-derived from pubkey"
    )]
    key_id: String,
    pubkey: String,
    #[serde(default = "device_scope_full")]
    scope: DeviceScope,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    created_at: i64,
}

/// serde default helper: a missing `scope` on a full `DeviceKey` struct means
/// no attenuation (Full), matching the migrated-bare-key behaviour.
fn device_scope_full() -> DeviceScope {
    DeviceScope::Full
}

/// Untagged migration helper: a `DeviceKey` on disk may be EITHER a bare
/// string (legacy `ed25519:<hex>` or bare hex) OR the full struct form. serde
/// tries each variant in order; the bare-string path migrates legacy
/// `public_keys` entries to Full-scope devices, the struct path carries the
/// new scoped form.
#[derive(Deserialize)]
#[serde(untagged)]
enum DeviceKeyRepr {
    Bare(String),
    Full(DeviceKeyData),
}

impl<'de> Deserialize<'de> for DeviceKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        match DeviceKeyRepr::deserialize(deserializer)? {
            DeviceKeyRepr::Bare(s) => {
                // Legacy bare-key migration: strip an optional `ed25519:`
                // prefix, lowercase, and validate hex/len. A malformed bare
                // string is a hard error — never a silently-dropped or
                // partially-trusted key.
                let hex = normalise_pubkey_hex(&s).map_err(D::Error::custom)?;
                Ok(DeviceKey::new(hex, DeviceScope::Full, None, 0))
            },
            DeviceKeyRepr::Full(d) => {
                // Full struct form. The canonical source of `key_id` is ALWAYS
                // the pubkey — it is a deterministic fingerprint by contract, and
                // stable-handle / idempotent-redeem / revocation-targeting logic
                // relies on that. So normalise the pubkey exactly like the bare
                // form and re-derive `key_id` unconditionally, ignoring whatever
                // `key_id` is on disk: a hand-edited or stale value can never
                // diverge from its pubkey (which would desync the handshake-
                // returned id from the gate/revocation fingerprint). The on-disk
                // `key_id` field is accepted (so a serialized struct round-trips)
                // but treated as informational only.
                let hex = normalise_pubkey_hex(&d.pubkey).map_err(D::Error::custom)?;
                Ok(DeviceKey {
                    key_id: device_key_id_fingerprint(&hex),
                    pubkey: hex,
                    scope: d.scope,
                    label: d.label,
                    created_at: d.created_at,
                })
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_scope_full_roundtrips() {
        let scope = DeviceScope::Full;
        let json = serde_json::to_string(&scope).unwrap();
        assert_eq!(json, r#"{"type":"full"}"#);
        let back: DeviceScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }

    #[test]
    fn device_scope_scoped_roundtrips() {
        let scope = DeviceScope::Scoped {
            allow: vec!["self:*".into()],
            deny: vec!["self:auth:pair".into()],
        };
        let json = serde_json::to_string(&scope).unwrap();
        let back: DeviceScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
        // Tagged on `type` with snake_case variant names.
        assert!(json.contains(r#""type":"scoped""#), "json: {json}");
    }

    #[test]
    fn device_scope_preset_full_and_use_only() {
        assert_eq!(DeviceScope::preset("full"), Some(DeviceScope::Full));
        let use_only = DeviceScope::preset("use-only").expect("use-only preset");
        match use_only {
            DeviceScope::Scoped { allow, deny } => {
                assert_eq!(allow, vec!["self:*".to_string()]);
                assert!(deny.contains(&"self:auth:pair".to_string()));
                assert!(deny.contains(&"self:auth:pair:admin".to_string()));
                assert!(deny.contains(&"delegate:self:*".to_string()));
            },
            DeviceScope::Full => panic!("use-only must be Scoped, got DeviceScope::Full"),
        }
        assert_eq!(DeviceScope::preset("nonexistent"), None);
    }

    #[test]
    fn device_key_id_is_deterministic_blake3_and_short() {
        let hex = "a".repeat(64);
        let a = device_key_id_fingerprint(&hex);
        let b = device_key_id_fingerprint(&hex);
        assert_eq!(a, b, "fingerprint must be deterministic");
        assert_eq!(a, "472c51290d607f10");
        assert_eq!(a.len(), DEVICE_KEY_ID_HEX_LEN);
        assert_ne!(a, device_key_id_fingerprint(&"b".repeat(64)));
    }

    #[test]
    fn device_key_id_newtype_validates_shape() {
        let id = DeviceKeyId::new("0123456789abcdef").unwrap();
        assert_eq!(id.as_str(), "0123456789abcdef");
        assert!(DeviceKeyId::new("0123456789abcde").is_err());
        assert!(DeviceKeyId::new("0123456789abcdeg").is_err());
        assert!(DeviceKeyId::new("0123456789ABCDEF").is_err());
    }

    #[test]
    fn device_pubkey_newtype_normalizes_and_validates() {
        let pubkey = DevicePubkey::normalize(&format!(" ed25519:{} ", "A".repeat(64))).unwrap();
        assert_eq!(pubkey.as_str(), "a".repeat(64));
        assert_eq!(
            DeviceKeyId::for_pubkey(&pubkey).into_inner(),
            device_key_id_fingerprint(pubkey.as_str())
        );
        assert!(DevicePubkey::normalize("deadbeef").is_err());
        assert!(DevicePubkey::from_canonical("A".repeat(64)).is_err());
    }

    #[test]
    fn device_pubkey_newtype_has_generic_string_traits() {
        let hex = "b".repeat(64);
        let pubkey = DevicePubkey::from_canonical(hex.clone()).unwrap();
        assert_eq!(pubkey.as_str(), hex);
        assert_eq!(pubkey, hex);
        assert_eq!(pubkey, hex.as_str());
        assert_eq!(pubkey.to_string(), hex);
        assert_eq!(String::from(pubkey.clone()), hex);

        let parsed: DevicePubkey<String> = hex.parse().unwrap();
        assert_eq!(parsed, hex);
        assert_eq!(DevicePubkey::try_from(hex.clone()).unwrap(), parsed);

        let json = serde_json::to_string(&pubkey).unwrap();
        assert_eq!(json, format!(r#""{hex}""#));
        let decoded: DevicePubkey<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, hex);
    }

    #[test]
    fn device_pubkey_deserialize_rejects_noncanonical_storage_form() {
        let prefixed = format!(r#""ed25519:{}""#, "c".repeat(64));
        assert!(serde_json::from_str::<DevicePubkey<String>>(&prefixed).is_err());

        let uppercase = format!(r#""{}""#, "C".repeat(64));
        assert!(serde_json::from_str::<DevicePubkey<String>>(&uppercase).is_err());
    }

    #[test]
    fn device_key_new_derives_key_id_and_ed25519_entry() {
        let hex = "f".repeat(64);
        let key = DeviceKey::new(hex.clone(), DeviceScope::Full, None, 0);
        assert_eq!(key.key_id, device_key_id_fingerprint(&hex));
        assert_eq!(key.ed25519_entry(), format!("ed25519:{hex}"));
        assert!(key.matches_pubkey(&hex));
        assert!(!key.matches_pubkey(&"e".repeat(64)));
        assert_eq!(key.typed_key_id().unwrap(), key.key_id);
        assert_eq!(key.typed_pubkey().unwrap().as_str(), key.pubkey);
    }

    #[test]
    fn device_key_serializes_as_struct() {
        let key = DeviceKey::new("a".repeat(64), DeviceScope::Full, Some("laptop".into()), 42);
        let json = serde_json::to_value(&key).unwrap();
        assert!(json.get("key_id").is_some());
        assert_eq!(json["pubkey"], "a".repeat(64));
        assert_eq!(json["scope"]["type"], "full");
        assert_eq!(json["label"], "laptop");
        assert_eq!(json["created_at"], 42);
    }

    #[test]
    fn device_key_migrates_legacy_bare_prefixed_key() {
        // A legacy `"ed25519:<hex>"` string loads as a Full-scope device.
        let hex = "a".repeat(64);
        let json = format!(r#""ed25519:{hex}""#);
        let key: DeviceKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.pubkey, hex);
        assert_eq!(key.scope, DeviceScope::Full);
        assert_eq!(key.label, None);
        assert_eq!(key.created_at, 0);
        assert_eq!(key.key_id, device_key_id_fingerprint(&hex));
    }

    #[test]
    fn device_key_migrates_legacy_bare_unprefixed_uppercase_key() {
        // Bare hex with no prefix, uppercased — normalised to lowercase Full.
        let hex_upper = "A".repeat(64);
        let json = format!(r#""{hex_upper}""#);
        let key: DeviceKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.pubkey, "a".repeat(64));
        assert_eq!(key.scope, DeviceScope::Full);
    }

    #[test]
    fn device_key_bare_invalid_hex_is_error() {
        // A bare string that is not 64 hex chars is a hard deserialization
        // error — fail-closed, never a partially-trusted key.
        let bad_len = r#""deadbeef""#;
        assert!(serde_json::from_str::<DeviceKey>(bad_len).is_err());
        let non_hex = format!(r#""{}""#, "g".repeat(64));
        assert!(serde_json::from_str::<DeviceKey>(&non_hex).is_err());
        let prefixed_bad = format!(r#""ed25519:{}""#, "z".repeat(64));
        assert!(serde_json::from_str::<DeviceKey>(&prefixed_bad).is_err());
    }

    #[test]
    fn device_key_full_struct_derives_missing_key_id() {
        let hex = "c".repeat(64);
        let json = format!(
            r#"{{"pubkey":"{hex}","scope":{{"type":"scoped","allow":["self:*"],"deny":[]}},"label":"phone","created_at":123}}"#
        );
        let key: DeviceKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.key_id, device_key_id_fingerprint(&hex));
        assert_eq!(key.label.as_deref(), Some("phone"));
        assert_eq!(key.created_at, 123);
        assert!(matches!(key.scope, DeviceScope::Scoped { .. }));
    }

    #[test]
    fn device_key_full_struct_self_heals_legacy_sha256_key_id() {
        let hex = "a".repeat(64);
        let json = format!(
            r#"{{"key_id":"ffe054fe7ae0cb6d","pubkey":"{hex}","scope":{{"type":"full"}}}}"#
        );
        let key: DeviceKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.key_id, "472c51290d607f10");
        assert_eq!(key.key_id, device_key_id_fingerprint(&hex));
    }

    #[test]
    fn device_key_full_struct_normalizes_pubkey() {
        // The struct form normalises its pubkey (strip `ed25519:`, lowercase)
        // exactly like the bare form, so the derived key_id and `matches_pubkey`
        // stay consistent regardless of how the pubkey was written on disk.
        let json = format!(r#"{{"pubkey":"ed25519:{}"}}"#, "A".repeat(64));
        let key: DeviceKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.pubkey, "a".repeat(64));
        assert_eq!(key.key_id, device_key_id_fingerprint(&"a".repeat(64)));
    }

    #[test]
    fn device_key_full_struct_defaults_scope_to_full() {
        let hex = "d".repeat(64);
        let json = format!(r#"{{"pubkey":"{hex}"}}"#);
        let key: DeviceKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.scope, DeviceScope::Full);
        assert_eq!(key.label, None);
        assert_eq!(key.created_at, 0);
    }

    #[test]
    fn device_key_full_struct_rejects_unknown_field() {
        let hex = "e".repeat(64);
        let json = format!(r#"{{"pubkey":"{hex}","bogus":true}}"#);
        // `deny_unknown_fields` on the struct mirror means a stray field is
        // not silently dropped. The untagged enum then falls through to the
        // Bare(String) arm, which rejects a non-string map — so the whole
        // parse is an error rather than an under-validated key.
        assert!(serde_json::from_str::<DeviceKey>(&json).is_err());
    }
}
