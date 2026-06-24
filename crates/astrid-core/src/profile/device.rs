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
/// (8 bytes of SHA-256 → 16 hex chars). Collision-resistant enough for the
/// per-principal device set while staying short enough to paste.
pub const DEVICE_KEY_ID_HEX_LEN: usize = 16;

/// Number of hex characters in a canonical ed25519 public key (32 bytes).
const ED25519_PUBKEY_HEX_LEN: usize = 64;

/// Derive a deterministic, non-secret fingerprint for a device key from its
/// canonical lowercase-hex pubkey: the first [`DEVICE_KEY_ID_HEX_LEN`] hex
/// chars of `SHA-256(pubkey_hex_bytes)`.
///
/// The fingerprint is **not** a secret — it is derived purely from the
/// already-public ed25519 public key, so surfacing it in listings, audit
/// rows, and on the bus leaks nothing. Determinism is the point: re-pairing
/// the same key yields the same `key_id`, which makes redemption idempotent
/// (dedup by pubkey) and lets revocation target a single device by id.
#[must_use]
pub fn device_key_id_fingerprint(pubkey_hex: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey_hex.as_bytes());
    let digest = hex::encode(hasher.finalize());
    // SHA-256 hex is always 64 chars, so this slice never panics; guard with
    // a min anyway so a future hash swap can't introduce an out-of-bounds.
    digest[..DEVICE_KEY_ID_HEX_LEN.min(digest.len())].to_string()
}

/// Normalise a candidate ed25519 public key string to canonical lowercase hex
/// without the `ed25519:` prefix, validating shape. Returns the bare hex on
/// success or a human-readable reason on failure (fail-closed).
fn normalise_pubkey_hex(raw: &str) -> Result<String, String> {
    let candidate = raw
        .strip_prefix("ed25519:")
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    if candidate.len() != ED25519_PUBKEY_HEX_LEN {
        return Err(format!(
            "device public key must be 32 bytes hex-encoded ({ED25519_PUBKEY_HEX_LEN} hex chars); got {} chars",
            candidate.len()
        ));
    }
    if !candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("device public key contains non-hex characters".into());
    }
    Ok(candidate)
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
        let key_id = device_key_id_fingerprint(&pubkey_hex);
        Self {
            key_id,
            pubkey: pubkey_hex,
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
    fn device_key_id_is_deterministic_and_short() {
        let hex = "a".repeat(64);
        let a = device_key_id_fingerprint(&hex);
        let b = device_key_id_fingerprint(&hex);
        assert_eq!(a, b, "fingerprint must be deterministic");
        assert_eq!(a.len(), DEVICE_KEY_ID_HEX_LEN);
        assert_ne!(a, device_key_id_fingerprint(&"b".repeat(64)));
    }

    #[test]
    fn device_key_new_derives_key_id_and_ed25519_entry() {
        let hex = "f".repeat(64);
        let key = DeviceKey::new(hex.clone(), DeviceScope::Full, None, 0);
        assert_eq!(key.key_id, device_key_id_fingerprint(&hex));
        assert_eq!(key.ed25519_entry(), format!("ed25519:{hex}"));
        assert!(key.matches_pubkey(&hex));
        assert!(!key.matches_pubkey(&"e".repeat(64)));
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
    fn device_key_full_struct_rederives_key_id_ignoring_on_disk_value() {
        // A hand-edited / stale `key_id` that does NOT match the pubkey is
        // ignored: `key_id` is always re-derived as the deterministic
        // fingerprint of the pubkey, so the handshake-returned id can never
        // diverge from the gate/revocation fingerprint.
        let hex = "a".repeat(64);
        let json = format!(
            r#"{{"key_id":"deadbeefdeadbeef","pubkey":"{hex}","scope":{{"type":"full"}}}}"#
        );
        let key: DeviceKey = serde_json::from_str(&json).unwrap();
        assert_eq!(
            key.key_id,
            device_key_id_fingerprint(&hex),
            "key_id must be re-derived from the pubkey, not taken from disk"
        );
        assert_ne!(key.key_id, "deadbeefdeadbeef");
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
