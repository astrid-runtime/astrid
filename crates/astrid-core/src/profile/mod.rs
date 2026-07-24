//! Per-principal profile: enablement, auth, resource quotas, egress policy.
//!
//! A [`PrincipalProfile`] is loaded from
//! `~/.astrid/home/{principal}/.config/profile.toml` and describes the static
//! policy for a single principal: whether it is enabled, which authentication
//! methods it supports, its group memberships, its resource quotas, and its
//! egress / process-spawn policy.
//!
//! This module is **Layer 2** of the multi-tenancy work (see parent issue
//! #653). It is pure data plumbing — the kernel does not yet consume these
//! values in `invoke_interceptor`. Layer 3 will wire quota enforcement;
//! Layer 6 will expose management IPC; the CLI surface lives in #657.
//!
//! # Behavior
//!
//! - Missing file → [`PrincipalProfile::default`]. Fresh principals without a
//!   profile on disk get the permissive-ish defaults below (egress and
//!   process spawn default to empty → fail-closed).
//! - Malformed TOML, unknown fields, failed validation, or a future
//!   `profile_version` → hard error. The operator must correct the file.
//! - Save is atomic on Unix (write to `.tmp` with `0o600`, then `rename`).
//!
//! # Defaults
//!
//! - `max_memory_bytes`         = 4 `GiB`
//! - `max_timeout_secs`         = 300  (5 min)
//! - `max_ipc_throughput_bytes` = 10 `MiB`/s
//! - `max_background_processes` = 8
//! - `max_compute_workers`      = 0  (delegate to host pool)
//! - `max_storage_bytes`        = 1 `GiB`
//! - `max_cpu_fuel_per_sec`     = 0  (unlimited; operator-tunable)
//! - `network.egress`           = `[]`  (no outbound)
//! - `process.allow`            = `[]`  (no spawn)

use std::io;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod device;
mod field;
mod io_impl;
mod validation;

pub use device::{
    DEVICE_KEY_ID_HEX_LEN, DeviceKey, DeviceKeyId, DevicePubkey, DeviceScope,
    device_key_id_fingerprint,
};
pub use field::{
    CapabilityPattern, CapsuleGrant, GroupName, ProfileFieldError, ValidatedProfileFields,
};

/// Current profile schema version. Bumped on breaking field changes.
///
/// Profiles on disk with a version greater than this constant are rejected
/// by [`PrincipalProfile::validate`] — a forward-dated profile would otherwise
/// be silently truncated to whatever fields this binary understands.
pub const CURRENT_PROFILE_VERSION: u32 = 1;

/// Default per-principal memory ceiling in bytes (4 `GiB`).
///
/// This is an admission ceiling, not an eager allocation. Runtime-wide host
/// pools and actual module declarations remain tighter bounds, while operators
/// can lower it for managed principals with `astrid quota set --memory`.
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Default per-invocation wall-clock timeout in seconds (5 minutes).
pub const DEFAULT_MAX_TIMEOUT_SECS: u64 = 300;
/// Default per-principal IPC throughput ceiling in bytes/sec (10 `MiB`/s).
pub const DEFAULT_MAX_IPC_THROUGHPUT_BYTES: u64 = 10 * 1024 * 1024;
/// Default max concurrent background processes per principal.
pub const DEFAULT_MAX_BACKGROUND_PROCESSES: u32 = 8;
/// Default aggregate generic-compute workers for one principal.
///
/// Zero delegates to the runtime's host-derived pool. A nonzero operator value
/// is an additional per-principal ceiling; it cannot widen the host pool.
pub const DEFAULT_MAX_COMPUTE_WORKERS: u32 = 0;
/// Default per-principal storage ceiling in bytes (1 `GiB`).
pub const DEFAULT_MAX_STORAGE_BYTES: u64 = 1024 * 1024 * 1024;

/// Default per-principal CPU rate ceiling in wasmtime fuel units per second.
///
/// Fuel meters **executed guest instructions** independently of host-call
/// yields. This per-principal rate is the quota surface for CPU attribution
/// and future per-invocation budgeting; the capsule engine records the exact
/// fuel each interceptor call consumes (per-principal ledger) against it. Zero
/// is the explicit unlimited default for an owner-operated machine; managed
/// deployments can set a nonzero rate per principal. The
/// run-loop CPU **bound** itself is enforced by the capsule engine's epoch
/// interrupt (a no-recv spinner is trapped after a few windows, a recv loop
/// never is), not by this rate directly. Capability-based resource exemption
/// remains an independent authority path.
pub const DEFAULT_MAX_CPU_FUEL_PER_SEC: u64 = 0;

/// Absolute upper bound on [`Quotas::max_timeout_secs`] (24 hours).
///
/// A sanity guard against runaway invocations — the enforcement layer may
/// impose a tighter ceiling.
pub const TIMEOUT_SECS_UPPER_BOUND: u64 = 86_400;
/// Absolute upper bound on [`Quotas::max_background_processes`].
pub const BACKGROUND_PROCESSES_UPPER_BOUND: u32 = 256;

/// Maximum length of a single entry in [`PrincipalProfile::groups`].
pub const MAX_GROUP_NAME_LEN: usize = 64;

/// Maximum length of a single entry in [`PrincipalProfile::capsules`].
///
/// A defensive sanity bound on operator-supplied grant entries — `CapsuleId`
/// itself caps only the charset, not the length, so this is the profile's own
/// limit rather than a kernel-enforced capsule-id cap. An entry longer than
/// this is well beyond any realistic capsule id, so reject it on load.
pub const MAX_CAPSULE_GRANT_LEN: usize = 128;

/// Result alias for profile operations.
pub type ProfileResult<T> = Result<T, ProfileError>;

/// Errors raised by [`PrincipalProfile`] load, save, and validation.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// Filesystem IO failed (read, write, rename, `create_dir_all`).
    #[error("profile io error: {0}")]
    Io(#[from] io::Error),
    /// Profile TOML failed to deserialize (syntax or `deny_unknown_fields`).
    #[error("profile parse error: {0}")]
    Parse(#[from] toml::de::Error),
    /// Profile failed to serialize back to TOML.
    #[error("profile serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// Profile value failed semantic validation.
    #[error("profile validation error: {0}")]
    Invalid(String),
}

/// Per-principal profile: enablement, auth, resource quotas, egress policy.
///
/// Loaded from `~/.astrid/home/{principal}/.config/profile.toml`. A missing
/// file yields [`PrincipalProfile::default`]. A malformed, invalid, or
/// future-versioned file is a hard error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalProfile {
    /// Schema version. Bumped on breaking field changes.
    ///
    /// Values above [`CURRENT_PROFILE_VERSION`] are rejected at load time.
    #[serde(default = "current_profile_version")]
    pub profile_version: u32,

    /// Master enable switch. When `false`, the kernel will refuse every
    /// invocation for this principal regardless of capabilities.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Group memberships. Resolved to capability sets via
    /// [`GroupConfig`](crate::GroupConfig).
    #[serde(default)]
    pub groups: Vec<String>,

    /// Capability patterns granted directly to this principal, beyond the
    /// capabilities inherited from the groups listed in
    /// [`PrincipalProfile::groups`]. Each entry is validated against the
    /// capability grammar (see
    /// [`crate::capability_grammar::validate_capability`]) at load time.
    #[serde(default)]
    pub grants: Vec<String>,

    /// Capability patterns explicitly denied to this principal. Revokes
    /// have the highest precedence — a matching revoke overrides any
    /// grant or group-inherited capability, including an `admin` group
    /// membership. Entries are validated against the same grammar as
    /// [`PrincipalProfile::grants`].
    #[serde(default)]
    pub revokes: Vec<String>,

    /// Capsule ids this principal is granted access to invoke.
    ///
    /// The kernel gates the **user-invocable tool surface**
    /// (`tool.v1.execute.*`, `cli.v1.command.execute`) at dispatch: a
    /// principal may have a capsule's tool dispatched to it only if the
    /// capsule's [`CapsuleId`](../../astrid_capsule/capsule/struct.CapsuleId.html)
    /// appears here. The internal orchestration mesh is **not** gated by
    /// this field — only the tool/CLI execute surface. New principals get
    /// **no** capsule access by default (empty), consistent with the
    /// inherit-nothing model (#924); admins (`*`) bypass the filter
    /// entirely, so single-tenant `default` is unaffected.
    ///
    /// Each entry is validated against the same grammar as a
    /// [`CapsuleId`](../../astrid_capsule/capsule/struct.CapsuleId.html):
    /// non-empty, lowercase alphanumeric and hyphens only.
    #[serde(default)]
    pub capsules: Vec<String>,

    /// Authentication configuration.
    #[serde(default)]
    pub auth: AuthConfig,

    /// Network egress policy.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Process-spawn policy.
    #[serde(default)]
    pub process: ProcessConfig,

    /// Resource quotas.
    #[serde(default)]
    pub quotas: Quotas,
}

/// Authentication methods a principal may use.
///
/// Closed enum so serde rejects typos (`passky`, `keyparr`) at load time
/// rather than silently granting access via a method the authenticator
/// does not understand. TOML / JSON wire form is the lowercase variant name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// Ed25519 public-key authentication.
    Keypair,
    /// `WebAuthn` / FIDO2 passkey.
    Passkey,
    /// System-level authentication (e.g. peer UID over the kernel socket).
    System,
}

/// Authentication configuration for a principal.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Accepted authentication methods. Serde rejects unknown variants.
    #[serde(default)]
    pub methods: Vec<AuthMethod>,

    /// Device keys bound to this principal.
    ///
    /// Each entry is a [`DeviceKey`] carrying the registered ed25519 public
    /// key plus the capability [`DeviceScope`] that pairing was granted. On
    /// disk an entry may be a legacy bare `"ed25519:<hex>"` string (migrated
    /// to a Full-scope device on load) or the full struct form; serialization
    /// always re-emits the struct form.
    #[serde(default)]
    pub public_keys: Vec<DeviceKey>,
}

impl AuthConfig {
    /// Look up a registered device by its deterministic `key_id`.
    #[must_use]
    pub fn device_by_key_id(&self, key_id: &str) -> Option<&DeviceKey> {
        self.device_by_typed_key_id(&DeviceKeyId::new(key_id).ok()?)
    }

    /// Look up a registered device by a typed deterministic `key_id`.
    #[must_use]
    pub fn device_by_typed_key_id<S: AsRef<str>>(
        &self,
        key_id: &DeviceKeyId<S>,
    ) -> Option<&DeviceKey> {
        self.public_keys
            .iter()
            .find(|k| k.key_id == key_id.as_str())
    }

    /// Look up a registered device by its canonical lowercase-hex pubkey.
    #[must_use]
    pub fn device_by_pubkey(&self, hex_lower: &str) -> Option<&DeviceKey> {
        self.device_by_typed_pubkey(&DevicePubkey::from_canonical(hex_lower).ok()?)
    }

    /// Look up a registered device by a typed canonical lowercase-hex pubkey.
    #[must_use]
    pub fn device_by_typed_pubkey<S: AsRef<str>>(
        &self,
        pubkey: &DevicePubkey<S>,
    ) -> Option<&DeviceKey> {
        self.public_keys
            .iter()
            .find(|k| k.matches_pubkey(pubkey.as_str()))
    }
}

/// Network egress configuration for a principal.
///
/// Empty `egress` means no outbound traffic is permitted (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Egress allow-list patterns.
    ///
    /// Exact pattern grammar is settled by Layer 5 (it will reuse the
    /// capsule manifest net-pattern parser). This layer validates only
    /// that entries are non-empty strings.
    #[serde(default)]
    pub egress: Vec<String>,

    /// Operator-consented local-egress endpoints, **keyed by capsule id**.
    ///
    /// Persistence target of the runtime `approve_always` local-egress consent:
    /// a `host:port` the local operator chose to remember for a *specific*
    /// capsule across daemon restarts. Mirrors the operator
    /// `[security.capsule_local_egress]` shape so a grant is per-(principal,
    /// capsule, endpoint) and never widens across capsules — a persisted grant
    /// for capsule A reaching `127.0.0.1:1234` must not exempt capsule B.
    ///
    /// `#[serde(default)]` so profiles written before this field existed (flat
    /// `egress` only) still load unchanged; absent/empty = no consented
    /// endpoints (fail-closed).
    #[serde(default)]
    pub capsule_egress: std::collections::HashMap<String, Vec<String>>,
}

/// Process-spawn configuration for a principal.
///
/// Empty `allow` means the principal cannot spawn external processes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessConfig {
    /// Executables permitted for process spawn.
    ///
    /// Entries may be absolute paths or short names drawn from a sandbox
    /// profile allowlist; the final grammar is pinned by Layer 5. This
    /// layer validates only that entries are non-empty strings.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Per-principal resource quotas.
///
/// Enforcement happens in Layer 3. This struct only carries the values and
/// rejects nonsense on load/save.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quotas {
    /// Maximum resident memory in bytes. Must be > 0.
    #[serde(default = "default_max_memory_bytes")]
    pub max_memory_bytes: u64,

    /// Maximum wall-clock time for a single invocation, in seconds.
    ///
    /// Must be in `1..=`[`TIMEOUT_SECS_UPPER_BOUND`].
    #[serde(default = "default_max_timeout_secs")]
    pub max_timeout_secs: u64,

    /// Maximum IPC throughput in bytes/sec. Must be > 0.
    #[serde(default = "default_max_ipc_throughput_bytes")]
    pub max_ipc_throughput_bytes: u64,

    /// Maximum concurrent background processes. Must be
    /// `<=` [`BACKGROUND_PROCESSES_UPPER_BOUND`].
    #[serde(default = "default_max_background_processes")]
    pub max_background_processes: u32,

    /// Aggregate generic-compute workers reserved by this principal.
    /// Zero delegates to the runtime's host-derived pool.
    #[serde(default = "default_max_compute_workers")]
    pub max_compute_workers: u32,

    /// Maximum persistent storage in bytes. Must be > 0.
    #[serde(default = "default_max_storage_bytes")]
    pub max_storage_bytes: u64,

    /// Maximum CPU rate in wasmtime fuel units per second. Zero is unlimited.
    ///
    /// Per-principal CPU attribution surface: the capsule engine meters the
    /// exact fuel each interceptor invocation consumes and accumulates it per
    /// principal against this rate (telemetry today, per-invocation budgeting
    /// later). The run-loop CPU **bound** is enforced separately by the capsule
    /// engine's epoch interrupt (a no-recv spinner traps after a few windows; a
    /// recv loop never does), not by this value. A principal holding
    /// [`CAP_RESOURCES_UNBOUNDED`](crate::CAP_RESOURCES_UNBOUNDED) (e.g. any
    /// `admin`) is exempt from the run-loop bound regardless of this value.
    #[serde(default = "default_max_cpu_fuel_per_sec")]
    pub max_cpu_fuel_per_sec: u64,
}

// ── serde default helpers ────────────────────────────────────────────────

fn current_profile_version() -> u32 {
    CURRENT_PROFILE_VERSION
}

fn default_true() -> bool {
    true
}

fn default_max_memory_bytes() -> u64 {
    DEFAULT_MAX_MEMORY_BYTES
}

fn default_max_timeout_secs() -> u64 {
    DEFAULT_MAX_TIMEOUT_SECS
}

fn default_max_ipc_throughput_bytes() -> u64 {
    DEFAULT_MAX_IPC_THROUGHPUT_BYTES
}

fn default_max_background_processes() -> u32 {
    DEFAULT_MAX_BACKGROUND_PROCESSES
}

fn default_max_compute_workers() -> u32 {
    DEFAULT_MAX_COMPUTE_WORKERS
}

fn default_max_storage_bytes() -> u64 {
    DEFAULT_MAX_STORAGE_BYTES
}

fn default_max_cpu_fuel_per_sec() -> u64 {
    DEFAULT_MAX_CPU_FUEL_PER_SEC
}

// ── Default impls ────────────────────────────────────────────────────────

impl Default for PrincipalProfile {
    fn default() -> Self {
        Self {
            profile_version: CURRENT_PROFILE_VERSION,
            enabled: true,
            groups: Vec::new(),
            grants: Vec::new(),
            revokes: Vec::new(),
            capsules: Vec::new(),
            auth: AuthConfig::default(),
            network: NetworkConfig::default(),
            process: ProcessConfig::default(),
            quotas: Quotas::default(),
        }
    }
}

impl PrincipalProfile {
    /// Borrow the process-global default profile.
    ///
    /// Layer 3's `effective_profile()` accessor returns `&PrincipalProfile`,
    /// so it needs a stable reference to hand back when no per-invocation
    /// profile has been set. Allocating a fresh [`Self::default`] per call
    /// would cost an allocation on every hot-path accessor read; a static
    /// reference is cheaper and safe because the default is immutable.
    #[must_use]
    pub fn default_ref() -> &'static Self {
        static DEFAULT: OnceLock<PrincipalProfile> = OnceLock::new();
        DEFAULT.get_or_init(Self::default)
    }
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_timeout_secs: DEFAULT_MAX_TIMEOUT_SECS,
            max_ipc_throughput_bytes: DEFAULT_MAX_IPC_THROUGHPUT_BYTES,
            max_background_processes: DEFAULT_MAX_BACKGROUND_PROCESSES,
            max_compute_workers: DEFAULT_MAX_COMPUTE_WORKERS,
            max_storage_bytes: DEFAULT_MAX_STORAGE_BYTES,
            max_cpu_fuel_per_sec: DEFAULT_MAX_CPU_FUEL_PER_SEC,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_permissive_but_fail_closed_egress() {
        let p = PrincipalProfile::default();
        assert_eq!(p.profile_version, CURRENT_PROFILE_VERSION);
        assert!(p.enabled);
        assert!(p.groups.is_empty());
        assert!(p.grants.is_empty());
        assert!(p.revokes.is_empty());
        assert!(p.capsules.is_empty(), "capsule grants must default empty");
        assert!(p.auth.methods.is_empty());
        assert!(p.auth.public_keys.is_empty());
        assert!(p.network.egress.is_empty(), "egress must fail-closed");
        assert!(p.process.allow.is_empty(), "process spawn must fail-closed");
        assert_eq!(p.quotas.max_memory_bytes, DEFAULT_MAX_MEMORY_BYTES);
        assert_eq!(p.quotas.max_timeout_secs, DEFAULT_MAX_TIMEOUT_SECS);
        assert_eq!(
            p.quotas.max_ipc_throughput_bytes,
            DEFAULT_MAX_IPC_THROUGHPUT_BYTES
        );
        assert_eq!(
            p.quotas.max_background_processes,
            DEFAULT_MAX_BACKGROUND_PROCESSES
        );
        assert_eq!(p.quotas.max_compute_workers, DEFAULT_MAX_COMPUTE_WORKERS);
        assert_eq!(p.quotas.max_storage_bytes, DEFAULT_MAX_STORAGE_BYTES);
        assert_eq!(p.quotas.max_cpu_fuel_per_sec, DEFAULT_MAX_CPU_FUEL_PER_SEC);
        p.validate().expect("defaults validate");
    }

    #[test]
    fn default_ref_matches_default_and_is_stable() {
        let a = PrincipalProfile::default_ref();
        let b = PrincipalProfile::default_ref();
        // Same `OnceLock` value across calls — stable pointer.
        assert!(std::ptr::eq(a, b));
        // And it observably equals a freshly-constructed `Default`.
        assert_eq!(*a, PrincipalProfile::default());
    }

    #[test]
    fn roundtrip_default() {
        let p = PrincipalProfile::default();
        let s = toml::to_string_pretty(&p).unwrap();
        let back: PrincipalProfile = toml::from_str(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn roundtrip_populated() {
        let p = PrincipalProfile {
            profile_version: 1,
            enabled: false,
            groups: vec!["admins".into(), "ops_team".into()],
            grants: vec!["capsule:install".into()],
            revokes: vec!["system:shutdown".into()],
            capsules: vec!["identity".into(), "registry".into()],
            auth: AuthConfig {
                methods: vec![AuthMethod::Keypair, AuthMethod::Passkey],
                public_keys: vec![DeviceKey::new("a".repeat(64), DeviceScope::Full, None, 0)],
            },
            network: NetworkConfig {
                egress: vec!["api.example.com:443".into()],
                capsule_egress: std::collections::HashMap::new(),
            },
            process: ProcessConfig {
                allow: vec!["/usr/bin/env".into()],
            },
            quotas: Quotas {
                max_memory_bytes: 128 * 1024 * 1024,
                max_timeout_secs: 600,
                max_ipc_throughput_bytes: 5 * 1024 * 1024,
                max_background_processes: 16,
                max_compute_workers: 6,
                max_storage_bytes: 2 * 1024 * 1024 * 1024,
                max_cpu_fuel_per_sec: 4_000_000_000,
            },
        };
        let s = toml::to_string_pretty(&p).unwrap();
        let back: PrincipalProfile = toml::from_str(&s).unwrap();
        assert_eq!(p, back);
    }

    // ── AuthConfig device-key list (migration + lookups) ──────────────────

    #[test]
    fn auth_config_legacy_bare_list_loads_as_full_devices() {
        // The historical `public_keys = ["ed25519:<hex>"]` TOML form round-
        // trips into Full-scope DeviceKeys.
        let hex = "a".repeat(64);
        let toml_src = format!("methods = [\"keypair\"]\npublic_keys = [\"ed25519:{hex}\"]\n");
        let auth: AuthConfig = toml::from_str(&toml_src).unwrap();
        assert_eq!(auth.public_keys.len(), 1);
        assert_eq!(auth.public_keys[0].pubkey, hex);
        assert_eq!(auth.public_keys[0].scope, DeviceScope::Full);
    }

    #[test]
    fn auth_config_mixed_bare_and_struct_list() {
        // One legacy bare string + one full struct entry deserialize together.
        let bare = "a".repeat(64);
        let full = "b".repeat(64);
        let json = format!(
            r#"{{"methods":["keypair"],"public_keys":["ed25519:{bare}",{{"pubkey":"{full}","scope":{{"type":"scoped","allow":["self:agent:prompt"],"deny":[]}},"label":"tablet","created_at":99}}]}}"#
        );
        let auth: AuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(auth.public_keys.len(), 2);
        assert_eq!(auth.public_keys[0].scope, DeviceScope::Full);
        assert_eq!(auth.public_keys[0].pubkey, bare);
        assert!(matches!(
            auth.public_keys[1].scope,
            DeviceScope::Scoped { .. }
        ));
        assert_eq!(auth.public_keys[1].label.as_deref(), Some("tablet"));

        // Lookups resolve by key_id and pubkey.
        let id0 = auth.public_keys[0].key_id.clone();
        assert!(auth.device_by_key_id(&id0).is_some());
        assert!(auth.device_by_pubkey(&full).is_some());
        assert!(auth.device_by_pubkey(&"c".repeat(64)).is_none());
    }

    #[test]
    fn auth_config_reemits_struct_form() {
        // Serialization always writes the struct form, never the bare string.
        let hex = "a".repeat(64);
        let toml_src = format!("public_keys = [\"ed25519:{hex}\"]\n");
        let auth: AuthConfig = toml::from_str(&toml_src).unwrap();
        let out = toml::to_string(&auth).unwrap();
        assert!(
            out.contains("pubkey"),
            "serialized form must be a struct: {out}"
        );
        assert!(
            out.contains("key_id"),
            "serialized form carries key_id: {out}"
        );
        // And it round-trips back to the same value.
        let back: AuthConfig = toml::from_str(&out).unwrap();
        assert_eq!(auth, back);
    }
}
