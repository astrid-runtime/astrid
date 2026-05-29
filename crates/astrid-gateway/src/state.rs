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
use rand::RngCore;
use tokio::sync::Mutex;

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
    #[must_use]
    pub fn fresh() -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
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
            audit_log,
            session_id,
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
