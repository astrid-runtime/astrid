//! Shared gateway state.
//!
//! Constructed once at daemon boot and shared across every HTTP
//! handler via `Arc<GatewayState>`. Owns the boot-time signing
//! keypair, a hot-cached copy of the deployment's `Distro.toml`, the
//! redeem rate-limiter, and the configuration.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use tokio::sync::Mutex;

use crate::config::GatewayConfig;

/// Signing material for session bearer tokens.
///
/// A fresh keypair is generated on every daemon boot. This means
/// outstanding session tokens become invalid across restarts —
/// acceptable for v1, and keeps the gateway from needing
/// persistent-key management. Long-running deployments that want
/// session continuity can switch to a persisted key in a follow-up.
pub struct SigningMaterial {
    /// Signs new bearer tokens.
    pub signer: SigningKey,
    /// Verifies incoming bearer tokens. Same key — kept separately
    /// so middleware can hold a cheap `Copy` of the public half.
    pub verifier: VerifyingKey,
}

impl SigningMaterial {
    /// Generate a fresh signing keypair from the OS CSPRNG.
    #[must_use]
    pub fn fresh() -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let signer = SigningKey::from_bytes(&secret);
        let verifier = signer.verifying_key();
        Self { signer, verifier }
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
    /// Raw `Distro.toml` text, cached at boot. The gateway reflects
    /// this through `/api/distribution` and `/api/distribution/onboarding`.
    /// `None` for single-tenant deployments with no manifest.
    pub distro_toml: Option<String>,
    /// Redeem rate-limiter. Wrapped in async `Mutex` because the
    /// limiter is a write-mostly workload and handlers are async.
    pub redeem_limiter: Mutex<RedeemRateLimiter>,
}

impl GatewayState {
    /// Build the gateway state at daemon boot.
    ///
    /// # Errors
    /// Returns an error if `distro_path` points at a file that can't
    /// be read.
    pub fn new(config: GatewayConfig) -> anyhow::Result<Arc<Self>> {
        let distro_toml =
            match &config.distro_path {
                Some(p) => Some(std::fs::read_to_string(p).with_context(|| {
                    format!("failed to read distro manifest at {}", p.display())
                })?),
                None => None,
            };
        Ok(Arc::new(Self {
            config,
            signing: SigningMaterial::fresh(),
            distro_toml,
            redeem_limiter: Mutex::new(RedeemRateLimiter::default()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_blocks_within_window() {
        let mut limiter = RedeemRateLimiter::default();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let interval = Duration::from_secs(60);

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
