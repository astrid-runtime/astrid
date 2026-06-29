//! Shared gateway state.
//!
//! Constructed once at daemon boot and shared across every HTTP
//! handler via `Arc<GatewayState>`. Owns the boot-time signing
//! keypair, a hot-cached copy of the deployment's `Distro.toml`, the
//! redeem rate-limiter, and the configuration.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use astrid_core::PrincipalId;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{TryRng, rngs::SysRng};
use tokio::sync::Mutex;
use uuid::Uuid;

use metrics_exporter_prometheus::PrometheusHandle;

use crate::config::GatewayConfig;
use crate::routes::distribution::{DistributionInfo, OnboardingFields};

/// Signing material for session bearer tokens.
///
/// Persisted at `$ASTRID_HOME/keys/gateway.ed25519` so outstanding
/// session tokens survive daemon restarts. Same file-system posture
/// as the kernel's `runtime.ed25519` runtime key: 0600 perms, atomic
/// write-then-rename, raw 32-byte secret. The file is generated on
/// first gateway boot and reused on every subsequent boot.
///
/// Rotation: delete the file → restart the daemon → fresh keypair is
/// generated, all existing bearers invalidated. (No in-place rotation
/// route; that needs a multi-key verifier and is deferred.)
pub struct SigningMaterial {
    /// Signs new bearer tokens.
    pub signer: SigningKey,
    /// Verifies incoming bearer tokens. Same key — kept separately
    /// so middleware can hold a cheap `Copy` of the public half.
    pub verifier: VerifyingKey,
}

impl SigningMaterial {
    /// Generate a fresh signing keypair from the OS CSPRNG. Used by
    /// tests and by the load path when the on-disk key is missing.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG is unavailable.
    #[must_use]
    pub fn fresh() -> Self {
        let mut secret = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut secret)
            .expect("OS CSPRNG unavailable while generating gateway signing key");
        let signer = SigningKey::from_bytes(&secret);
        let verifier = signer.verifying_key();
        Self { signer, verifier }
    }

    /// Load the persisted gateway signing key, generating it on
    /// first boot. Matches the kernel's `runtime.ed25519` load
    /// pattern: 0600 perms, atomic write-then-rename. Same path
    /// layout convention (`keys/` under `$ASTRID_HOME`).
    ///
    /// # Errors
    /// Returns an error if the keys directory can't be created,
    /// the on-disk key is corrupt (wrong length), or the file
    /// write fails.
    pub fn load_or_generate() -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let home = astrid_core::dirs::AstridHome::resolve()
            .context("resolve $ASTRID_HOME for gateway signing key")?;
        let keys_dir = home.keys_dir();
        let key_path = keys_dir.join("gateway.ed25519");

        if key_path.exists() {
            let bytes = std::fs::read(&key_path)
                .with_context(|| format!("read gateway key at {}", key_path.display()))?;
            if bytes.len() != 32 {
                anyhow::bail!(
                    "gateway key at {} has wrong length ({} bytes, expected 32) — remove the file to regenerate",
                    key_path.display(),
                    bytes.len()
                );
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let signer = SigningKey::from_bytes(&arr);
            let verifier = signer.verifying_key();
            return Ok(Self { signer, verifier });
        }

        // Generate fresh and persist atomically (write-then-rename
        // with 0600 perms, matching the kernel's runtime key flow).
        std::fs::create_dir_all(&keys_dir)
            .with_context(|| format!("create keys dir {}", keys_dir.display()))?;
        let fresh = Self::fresh();

        let tmp = key_path.with_extension(format!("{}.tmp", std::process::id()));
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("create {}", tmp.display()))?;
            f.write_all(fresh.signer.as_bytes())
                .with_context(|| format!("write {}", tmp.display()))?;
            f.sync_all()
                .with_context(|| format!("fsync {}", tmp.display()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, fresh.signer.as_bytes())
                .with_context(|| format!("write {}", tmp.display()))?;
        }
        std::fs::rename(&tmp, &key_path)
            .with_context(|| format!("rename {} → {}", tmp.display(), key_path.display()))?;
        Ok(fresh)
    }
}

impl std::fmt::Debug for SigningMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningMaterial").finish_non_exhaustive()
    }
}

/// Rate-limit ledger keyed by source IP. Drops entries lazily on
/// every probe to bound memory.
#[derive(Debug, Default)]
pub struct RedeemRateLimiter {
    last_seen: HashMap<IpAddr, Instant>,
}

impl RedeemRateLimiter {
    /// Record an attempt from `ip` and return the wait duration if
    /// the caller must back off, or `None` if it's free to proceed.
    pub fn check(&mut self, ip: IpAddr, interval: Duration) -> Option<Duration> {
        let now = Instant::now();
        // Lazy GC: drop entries whose interval has elapsed.
        self.last_seen
            .retain(|_, last| now.saturating_duration_since(*last) < interval.saturating_mul(8));
        if let Some(last) = self.last_seen.get(&ip) {
            let elapsed = now.saturating_duration_since(*last);
            if elapsed < interval {
                return Some(interval.saturating_sub(elapsed));
            }
        }
        self.last_seen.insert(ip, now);
        None
    }
}

/// State shared across every HTTP handler.
#[derive(Debug)]
pub struct GatewayState {
    /// Configuration loaded at boot.
    pub config: GatewayConfig,
    /// Per-boot signing material.
    pub signing: SigningMaterial,
    /// Live event bus handle for the audit SSE stream. `Some` when
    /// the gateway is spawned by `astrid-daemon` co-located with the
    /// kernel; `None` for the standalone-builder constructor used by
    /// route-level unit tests (those tests never exercise SSE so
    /// the `Option` is safe).
    pub event_bus: Option<Arc<astrid_events::EventBus>>,
    /// Pre-parsed distribution discovery payload. Computed once at
    /// boot from `Distro.toml` so the public `/api/distribution`
    /// route doesn't reparse TOML on every request — that would be a
    /// trivial CPU-exhaustion `DoS` vector against an unauthenticated
    /// endpoint. `Arc` so route handlers can clone cheaply.
    pub distribution: Arc<DistributionInfo>,
    /// Pre-parsed onboarding fields drawn from `[variables]`. Same
    /// rationale as [`Self::distribution`].
    pub onboarding: Arc<OnboardingFields>,
    /// Redeem rate-limiter. Wrapped in async `Mutex` because the
    /// limiter is a write-mostly workload and handlers are async.
    pub redeem_limiter: Mutex<RedeemRateLimiter>,
    /// Handle into the process-wide Prometheus recorder. The
    /// gateway's `/metrics` route renders this; kernel-side or
    /// capsule-side code that calls `metrics::counter!()` flows
    /// into the same recorder so a single scrape covers the whole
    /// daemon. Installed once at gateway boot via
    /// [`crate::metrics::install_recorder`].
    pub metrics_handle: PrometheusHandle,
    /// Bearer revocation map: `principal → epoch when the principal
    /// was deleted`. Populated by a background task that watches the
    /// kernel's audit-event stream for successful `AgentDelete` ops,
    /// persisted to `$ASTRID_HOME/etc/gateway-revocations.json`. The
    /// auth middleware rejects any bearer whose `iat` is at or before
    /// the recorded epoch — see [`crate::auth::verify_bearer`].
    /// `std::sync::RwLock` because the read path (every authenticated
    /// request) outweighs the write path (admin-only delete events)
    /// by orders of magnitude, and the critical sections are
    /// non-`await`-blocking.
    pub revoked_at: Arc<RwLock<HashMap<PrincipalId, u64>>>,
    /// Per-device bearer revocation map: `key_id` → the epoch the device was
    /// revoked via `PairDeviceRevoke`. Populated by a background task watching
    /// the audit stream for successful `admin.auth.pair.revoke` ops. The auth
    /// middleware rejects a device-scoped bearer whose `key_id` is present and
    /// whose `iat` is at-or-before the recorded epoch — see
    /// [`crate::auth::verify_bearer`].
    ///
    /// This is defense-in-depth on the HTTP path so a live bearer stops
    /// immediately; the kernel cap-gate is the primary mechanism (a revoked
    /// key is gone from `public_keys`, so every kernel request fails closed).
    /// Keying on the revoke epoch (mirroring principal-level `revoked_at`)
    /// rather than a bare membership set matters because a `key_id` is a
    /// deterministic fingerprint of its pubkey: re-pairing the same key yields
    /// the same id, so a bearer minted *after* a re-pair (`iat` > the recorded
    /// epoch) authenticates again instead of being dead forever — and the map
    /// is not a permanent, unbounded deny-list.
    /// Deliberately in-memory only: a restart re-derives correctness from the
    /// (now key-less) profile, and the bearer's own expiry bounds the window.
    pub revoked_key_ids: Arc<RwLock<HashMap<String, u64>>>,
    /// Live audit-log handle backing `GET /api/sys/audit`. `Some`
    /// when the gateway is spawned by `astrid-daemon` (which holds
    /// the kernel's `Arc<AuditLog>`); `None` for the standalone-
    /// builder constructor used by route-level unit tests, in which
    /// case the audit-history route returns 502 honestly rather
    /// than hanging.
    pub audit_log: Option<Arc<astrid_audit::AuditLog>>,
    /// Kernel session id, paired with [`Self::audit_log`] because the
    /// audit log indexes entries by session. Single-session daemons
    /// today; if a future kernel ever runs multiple sessions
    /// concurrently this becomes the slice the gateway is scoped to.
    pub session_id: Option<astrid_core::SessionId>,
    /// Stable per-gateway-instance UUID supplied as the `capsule_uuid`
    /// argument to [`astrid_events::EventBus::subscribe_topic_routed`]
    /// for every gateway SSE subscription. Each subscribe call still
    /// receives a unique `RouteKey` via the bus's internal
    /// `subscription_rep` allocator, so a fixed UUID here is fine —
    /// it pairs the metric labels (`capsule="gateway"`) across every
    /// route this gateway opens. Re-generated on each boot
    /// (`Uuid::new_v4`); harmless because no persisted state is keyed
    /// on it. Layer 4 of the #813 fix swaps the gateway's broadcast
    /// receivers for the routed surface so the per-(topic, principal)
    /// DRR fairness machinery applies to the SSE streams.
    pub gateway_route_uuid: Uuid,
    /// In-process agent-loop readiness probe. `Some` when the gateway is
    /// spawned by `astrid-daemon` (co-located with the kernel); `None` for the
    /// route-level / standalone test constructors, in which case the prompt
    /// fail-fast proceeds (fails open) exactly as if the loop were ready.
    ///
    /// The prompt fail-fast calls this to learn whether the loaded capsule set
    /// can serve a chat turn — global daemon health, so it needs no
    /// per-principal capability and no socket round-trip. The detailed,
    /// ops-facing view stays behind the capability-gated `GET /api/sys/readiness`.
    pub readiness_probe: Option<astrid_core::kernel_api::AgentReadinessProbe>,
    /// In-process probe for whether a loaded capsule subscribes to a given
    /// topic — the cap-free counterpart to the capability-gated
    /// `GetCapsuleMetadata`. `Some` when co-located with the kernel
    /// (daemon-spawned); `None` for standalone / test constructors, in which
    /// case routes that use it skip the degradation gate and fall through to
    /// the bus. The session thread-management routes (`list` / `get_meta` /
    /// `update` / `delete` / `search`) use it to answer `501` when no loaded
    /// session capsule implements the 1.1 verbs, instead of waiting out the
    /// bus timeout.
    pub topic_probe: Option<astrid_core::kernel_api::CapsuleTopicProbe>,
    /// Optional override for the registry round-trip wait budget. `None`
    /// in production, where the model routes fall back to their built-in
    /// default of 10 seconds. Tests that assert a *negative* round-trip
    /// outcome (no reply arrives) set a short duration here so the assertion
    /// doesn't block for the full production budget.
    pub registry_timeout: Option<Duration>,
}

impl GatewayState {
    /// Build the gateway state at daemon boot.
    ///
    /// # Errors
    /// Returns an error if `distro_path` points at a file that can't
    /// be read or whose contents fail to parse, or if the persisted
    /// revocation file is present but corrupt.
    pub fn new(
        config: GatewayConfig,
        event_bus: Option<Arc<astrid_events::EventBus>>,
        audit_log: Option<Arc<astrid_audit::AuditLog>>,
        session_id: Option<astrid_core::SessionId>,
        readiness_probe: Option<astrid_core::kernel_api::AgentReadinessProbe>,
        topic_probe: Option<astrid_core::kernel_api::CapsuleTopicProbe>,
    ) -> anyhow::Result<Arc<Self>> {
        let (distribution, onboarding) = match &config.distro_path {
            Some(p) => {
                let text = std::fs::read_to_string(p).with_context(|| {
                    format!("failed to read distro manifest at {}", p.display())
                })?;
                let dist =
                    crate::routes::distribution::parse_distribution(&text).with_context(|| {
                        format!("failed to parse distro manifest at {}", p.display())
                    })?;
                let onb =
                    crate::routes::distribution::parse_onboarding(&text).with_context(|| {
                        format!("failed to parse onboarding fields at {}", p.display())
                    })?;
                (dist, onb)
            },
            None => (
                DistributionInfo::single_tenant(),
                OnboardingFields::default(),
            ),
        };
        let signing =
            SigningMaterial::load_or_generate().context("load or generate gateway signing key")?;
        let revoked_at = Arc::new(RwLock::new(
            crate::revocations::load_from_disk().context("load gateway revocations")?,
        ));
        let metrics_handle =
            crate::metrics::install_recorder().context("install Prometheus recorder")?;
        Ok(Arc::new(Self {
            config,
            signing,
            distribution: Arc::new(distribution),
            onboarding: Arc::new(onboarding),
            redeem_limiter: Mutex::new(RedeemRateLimiter::default()),
            metrics_handle,
            event_bus,
            revoked_at,
            revoked_key_ids: Arc::new(RwLock::new(HashMap::new())),
            audit_log,
            session_id,
            gateway_route_uuid: Uuid::new_v4(),
            readiness_probe,
            topic_probe,
            registry_timeout: None,
        }))
    }

    /// Build a bus-direct admin client bound to `caller`. Routes
    /// hosted in this same process talk to the kernel over the
    /// shared event bus rather than the Unix socket — bypasses the
    /// `astrid-capsule-cli` proxy entirely and removes the 19 RPS
    /// admin-throughput ceiling the socket path imposes.
    ///
    /// # Errors
    /// Returns an internal error if the state was built without a
    /// live event bus (the standalone tests-only constructor). In
    /// production the daemon always wires it up.
    pub fn admin_client(
        &self,
        caller: astrid_core::PrincipalId,
    ) -> Result<crate::bus_admin::BusAdminClient, crate::error::GatewayError> {
        let bus = self.event_bus.clone().ok_or_else(|| {
            crate::error::GatewayError::Internal(anyhow::anyhow!(
                "gateway is not wired to a live event bus; admin operations unavailable"
            ))
        })?;
        Ok(crate::bus_admin::BusAdminClient::new(bus, caller))
    }

    /// Build a bus-direct admin client for an authenticated caller, carrying
    /// the caller's device scope through to the kernel cap-gate.
    ///
    /// Use this for every admin op behind the auth middleware: it stamps the
    /// caller's `device_key_id` (when the bearer was device-scoped) onto each
    /// outbound request so a paired device's scope is enforced kernel-side.
    /// The two unauthenticated redeem routes (which act as the bootstrap
    /// `default` principal) keep [`admin_client`](Self::admin_client) — their
    /// caller has no device scope.
    ///
    /// # Errors
    /// Returns an internal error if the state was built without a live event
    /// bus (the standalone tests-only constructor).
    pub fn admin_client_for(
        &self,
        caller: &crate::auth::CallerContext,
    ) -> Result<crate::bus_admin::BusAdminClient, crate::error::GatewayError> {
        Ok(self
            .admin_client(caller.principal.clone())?
            .with_device_key_id(caller.device_key_id.clone()))
    }

    /// Build a bus-direct kernel client bound to an authenticated caller.
    ///
    /// HTTP routes have already verified the bearer token and resolved the
    /// caller/device scope. They should not re-enter the external socket
    /// handshake, because the gateway intentionally does not possess arbitrary
    /// agent private keys and would be downgraded to `anonymous`.
    ///
    /// # Errors
    /// Returns an internal error if the state was built without a live event
    /// bus (the standalone tests-only constructor).
    pub fn kernel_client_for(
        &self,
        caller: &crate::auth::CallerContext,
    ) -> Result<crate::bus_kernel::BusKernelClient, crate::error::GatewayError> {
        let bus = self.event_bus.clone().ok_or_else(|| {
            crate::error::GatewayError::Internal(anyhow::anyhow!(
                "gateway is not wired to a live event bus; kernel requests unavailable"
            ))
        })?;
        let session_id = self.session_id.as_ref().ok_or_else(|| {
            crate::error::GatewayError::Internal(anyhow::anyhow!(
                "gateway is not wired to a live kernel session; kernel requests unavailable"
            ))
        })?;
        Ok(
            crate::bus_kernel::BusKernelClient::new(bus, caller.principal.clone(), session_id.0)
                .with_device_key_id(caller.device_key_id.clone()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_blocks_within_window() {
        let mut limiter = RedeemRateLimiter::default();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let interval = Duration::from_mins(1);

        assert!(limiter.check(ip, interval).is_none());
        let wait = limiter.check(ip, interval).expect("second probe blocks");
        assert!(wait > Duration::from_secs(0));
    }

    #[test]
    fn rate_limiter_zero_interval_never_blocks() {
        let mut limiter = RedeemRateLimiter::default();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let interval = Duration::from_secs(0);
        // Zero interval: every probe should be free regardless.
        assert!(limiter.check(ip, interval).is_none());
        assert!(limiter.check(ip, interval).is_none());
    }

    #[test]
    fn signing_material_round_trips() {
        use ed25519_dalek::{Signer, Verifier};
        let s = SigningMaterial::fresh();
        let msg = b"hello world";
        let sig = s.signer.sign(msg);
        assert!(s.verifier.verify(msg, &sig).is_ok());
    }
}
