//! Per-request rate-limit metadata for the kernel management API.
//!
//! Split out of `kernel_router/mod.rs` to keep that file under the 1000-line CI
//! threshold. Pure functions mapping a [`KernelRequest`] to its rate-limit label
//! and per-minute cap; the dispatcher in `mod.rs` applies the limit after
//! capability authorization and before executing a management request.

use astrid_config::types::RateLimitsConfig;
use astrid_core::principal::PrincipalId;
use astrid_events::kernel_api::KernelRequest;
use astrid_runtime::time::Instant;
use std::collections::{HashMap, VecDeque};

use super::kernel_request_method;

const MANAGEMENT_RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_mins(1);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RateLimitKey {
    principal: PrincipalId,
    method: &'static str,
}

/// Per-principal sliding-window rate limiter for authorized management API
/// requests. Each queue is bounded by its method's configured limit. Periodic
/// global pruning removes inactive principal/method keys so the map cannot
/// retain stale principals indefinitely.
///
/// Cardinality consists only of recently active, fully authorized
/// principal/method pairs: the router calls [`Self::check`] only after profile,
/// capability, enabled-state, and device-scope authorization succeeds. Missing
/// or denied identities therefore cannot allocate keys. Each principal ID is
/// validated and bounded, the method set is closed, and each timestamp queue is
/// bounded by its configured limit.
///
/// The management router is its sole consumer, so this type needs no internal
/// synchronization.
pub(crate) struct ManagementRateLimiter {
    buckets: HashMap<RateLimitKey, VecDeque<Instant>>,
    last_global_prune: Instant,
    // Read by from_kernel/limit_for. spawn_kernel_router still uses new()
    // plus the 1-arg rate_limit_for_request default until that wiring lands.
    limits: RateLimitsConfig,
}

impl ManagementRateLimiter {
    pub(crate) fn new() -> Self {
        Self::with_limits(RateLimitsConfig::default())
    }

    pub(crate) fn with_limits(limits: RateLimitsConfig) -> Self {
        Self {
            buckets: HashMap::new(),
            last_global_prune: Instant::now(),
            limits,
        }
    }

    /// Load operator rate-limit knobs from the kernel home. Invalid or
    /// missing config falls back to the derived core-set default, not a
    /// silent `5/min` cap.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "operator-knob handle for spawn_kernel_router")
    )]
    pub(crate) fn from_kernel(kernel: &crate::Kernel) -> Self {
        let limits = astrid_config::Config::load_with_home_and_layout(
            Some(&kernel.workspace_root),
            kernel.astrid_home.root(),
            kernel.workspace_layout(),
        )
        .map(|resolved| resolved.config.rate_limits)
        .unwrap_or_default();
        Self::with_limits(limits)
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "operator-knob handle for spawn_kernel_router")
    )]
    pub(crate) fn limits(&self) -> &RateLimitsConfig {
        &self.limits
    }

    /// Look up the per-method cap using this limiter's operator knobs.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "operator-knob handle for spawn_kernel_router")
    )]
    pub(crate) fn limit_for(&self, req: &KernelRequest) -> (&'static str, Option<u32>) {
        rate_limit_for_request_with_limits(req, &self.limits)
    }

    /// Check if a principal's request of the given type is within the rate
    /// limit.
    ///
    /// Returns `true` if allowed, `false` if rate-limited.
    pub(crate) fn check(
        &mut self,
        principal: &PrincipalId,
        method: &'static str,
        max_per_minute: u32,
    ) -> bool {
        self.check_at(principal, method, max_per_minute, Instant::now())
    }

    fn check_at(
        &mut self,
        principal: &PrincipalId,
        method: &'static str,
        max_per_minute: u32,
        now: Instant,
    ) -> bool {
        if now.saturating_duration_since(self.last_global_prune) >= MANAGEMENT_RATE_LIMIT_WINDOW {
            self.prune_expired(now);
            self.last_global_prune = now;
        }
        let key = RateLimitKey {
            principal: principal.clone(),
            method,
        };
        let timestamps = self.buckets.entry(key).or_default();
        Self::prune_timestamps(timestamps, now);

        if timestamps.len() >= max_per_minute as usize {
            return false;
        }
        timestamps.push_back(now);
        true
    }

    fn prune_expired(&mut self, now: Instant) {
        self.buckets.retain(|_, timestamps| {
            Self::prune_timestamps(timestamps, now);
            !timestamps.is_empty()
        });
    }

    fn prune_timestamps(timestamps: &mut VecDeque<Instant>, now: Instant) {
        while let Some(&oldest) = timestamps.front() {
            if now.saturating_duration_since(oldest) >= MANAGEMENT_RATE_LIMIT_WINDOW {
                timestamps.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Return the rate limit label and max-per-minute for a request type.
/// Returns `None` for the limit if the request type is not rate-limited.
///
/// Uses the derived core-set default. The router still calls this 1-arg
/// form; wire [`ManagementRateLimiter::from_kernel`] plus [`ManagementRateLimiter::limit_for`]
/// so a non-default `[rate_limits].capsule_reload_per_min` is honored.
pub(crate) fn rate_limit_for_request(req: &KernelRequest) -> (&'static str, Option<u32>) {
    rate_limit_for_request_with_limits(req, &RateLimitsConfig::default())
}

pub(crate) fn rate_limit_for_request_with_limits(
    req: &KernelRequest,
    limits: &RateLimitsConfig,
) -> (&'static str, Option<u32>) {
    (kernel_request_method(req), rate_limit_max(req, limits))
}

/// Return the max-per-minute rate limit for a request type, if any.
fn rate_limit_max(req: &KernelRequest, limits: &RateLimitsConfig) -> Option<u32> {
    match req {
        KernelRequest::ReloadCapsules
        | KernelRequest::ReloadCapsule { .. }
        | KernelRequest::UnloadCapsule { .. }
        | KernelRequest::RemoveCapsule { .. }
        | KernelRequest::PromoteWorkspace { .. }
        | KernelRequest::RollbackWorkspace { .. } => Some(limits.capsule_reload_per_min),
        KernelRequest::InstallCapsule { .. } | KernelRequest::ApproveCapability { .. } => Some(10),
        KernelRequest::Shutdown { .. } => Some(1),
        KernelRequest::ListCapsules
        | KernelRequest::GetCommands
        | KernelRequest::GetCapsuleMetadata
        | KernelRequest::GetAgentReadiness
        | KernelRequest::GetStatus => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(id: &str) -> PrincipalId {
        PrincipalId::new(id).expect("valid principal")
    }

    #[test]
    fn allows_exactly_the_configured_limit() {
        let mut limiter = ManagementRateLimiter::new();
        let alice = principal("alice");

        for _ in 0..5 {
            assert!(limiter.check(&alice, "ReloadCapsules", 5));
        }
        assert!(!limiter.check(&alice, "ReloadCapsules", 5));
    }

    #[test]
    fn separates_methods_for_one_principal() {
        let mut limiter = ManagementRateLimiter::new();
        let alice = principal("alice");

        for _ in 0..5 {
            assert!(limiter.check(&alice, "ReloadCapsules", 5));
        }
        assert!(!limiter.check(&alice, "ReloadCapsules", 5));
        assert!(limiter.check(&alice, "InstallCapsule", 10));
    }

    #[test]
    fn separates_principals_for_one_method() {
        let mut limiter = ManagementRateLimiter::new();
        let alice = principal("alice");
        let bob = principal("bob");

        assert!(limiter.check(&alice, "Shutdown", 1));
        assert!(!limiter.check(&alice, "Shutdown", 1));
        assert!(limiter.check(&bob, "Shutdown", 1));
    }

    #[test]
    fn sliding_window_expires_at_the_exact_boundary() {
        let mut limiter = ManagementRateLimiter::new();
        let alice = principal("alice");
        let start = Instant::now();
        let just_before_expiry =
            start + MANAGEMENT_RATE_LIMIT_WINDOW - std::time::Duration::from_nanos(1);
        let exact_expiry = start + MANAGEMENT_RATE_LIMIT_WINDOW;

        assert!(limiter.check_at(&alice, "Shutdown", 1, start));
        assert!(!limiter.check_at(&alice, "Shutdown", 1, just_before_expiry));
        assert!(limiter.check_at(&alice, "Shutdown", 1, exact_expiry));
    }

    #[test]
    fn sliding_window_frees_only_expired_slots() {
        let mut limiter = ManagementRateLimiter::new();
        let alice = principal("alice");
        let start = Instant::now();
        let later = start + std::time::Duration::from_secs(1);

        for _ in 0..3 {
            assert!(limiter.check_at(&alice, "ReloadCapsules", 5, start));
        }
        for _ in 0..2 {
            assert!(limiter.check_at(&alice, "ReloadCapsules", 5, later));
        }

        let partial_expiry = start + MANAGEMENT_RATE_LIMIT_WINDOW;
        for _ in 0..3 {
            assert!(limiter.check_at(&alice, "ReloadCapsules", 5, partial_expiry));
        }
        assert!(!limiter.check_at(&alice, "ReloadCapsules", 5, partial_expiry));
    }

    #[test]
    fn prunes_stale_principal_buckets_globally() {
        let mut limiter = ManagementRateLimiter::new();
        let alice = principal("alice");
        let bob = principal("bob");
        let start = Instant::now();

        assert!(limiter.check_at(&alice, "Shutdown", 1, start));
        assert!(limiter.check_at(
            &bob,
            "ReloadCapsules",
            5,
            start + MANAGEMENT_RATE_LIMIT_WINDOW
        ));

        assert_eq!(limiter.buckets.len(), 1);
        assert!(limiter.buckets.contains_key(&RateLimitKey {
            principal: bob,
            method: "ReloadCapsules",
        }));
    }

    #[test]
    fn staggered_bucket_is_retired_by_the_following_global_sweep() {
        let mut limiter = ManagementRateLimiter::new();
        let first = principal("first");
        let staggered = principal("staggered");
        let trigger = principal("trigger");
        let start = Instant::now();
        let first_sweep = start + MANAGEMENT_RATE_LIMIT_WINDOW;

        assert!(limiter.check_at(&first, "Shutdown", 1, first_sweep));
        assert!(limiter.check_at(
            &staggered,
            "Shutdown",
            1,
            first_sweep + std::time::Duration::from_secs(1)
        ));

        let second_sweep = first_sweep + MANAGEMENT_RATE_LIMIT_WINDOW;
        assert!(limiter.check_at(&trigger, "ReloadCapsules", 5, second_sweep));
        assert!(
            limiter.buckets.contains_key(&RateLimitKey {
                principal: staggered.clone(),
                method: "Shutdown",
            }),
            "a not-yet-expired staggered bucket must survive the sweep"
        );

        let third_sweep = second_sweep + MANAGEMENT_RATE_LIMIT_WINDOW;
        assert!(limiter.check_at(&trigger, "InstallCapsule", 10, third_sweep));
        assert!(
            !limiter.buckets.contains_key(&RateLimitKey {
                principal: staggered,
                method: "Shutdown",
            }),
            "the next periodic sweep must retire the expired staggered bucket"
        );
    }

    #[test]
    fn rejections_do_not_grow_a_full_bucket() {
        let mut limiter = ManagementRateLimiter::new();
        let alice = principal("alice");
        let now = Instant::now();

        assert!(limiter.check_at(&alice, "Shutdown", 1, now));
        for _ in 0..100 {
            assert!(!limiter.check_at(&alice, "Shutdown", 1, now));
        }

        let key = RateLimitKey {
            principal: alice,
            method: "Shutdown",
        };
        assert_eq!(limiter.buckets.get(&key).map(VecDeque::len), Some(1));
    }

    #[test]
    fn derived_default_covers_a_core_set_reload_burst() {
        let limits = RateLimitsConfig::default();
        let max = limits.capsule_reload_per_min;
        assert!(
            max >= RateLimitsConfig::CORE_SET_CAPSULE_COUNT,
            "default {max} cannot cover a {n}-capsule core-set burst",
            n = RateLimitsConfig::CORE_SET_CAPSULE_COUNT
        );

        let (_, reload) = rate_limit_for_request(&KernelRequest::ReloadCapsule {
            id: "astrid-capsule-openai-compat".into(),
        });
        let (_, reloads) = rate_limit_for_request(&KernelRequest::ReloadCapsules);
        assert_eq!(reload, Some(max));
        assert_eq!(reloads, Some(max));
        assert_ne!(
            reload,
            Some(5),
            "silent Some(5) cannot cover a core-set burst"
        );

        let mut limiter = ManagementRateLimiter::with_limits(limits);
        let alice = principal("alice");
        for i in 0..RateLimitsConfig::CORE_SET_CAPSULE_COUNT {
            assert!(
                limiter.check(&alice, "ReloadCapsule", max),
                "core-set reload {i} of {n} must succeed",
                n = RateLimitsConfig::CORE_SET_CAPSULE_COUNT
            );
        }
        for i in RateLimitsConfig::CORE_SET_CAPSULE_COUNT..max {
            assert!(
                limiter.check(&alice, "ReloadCapsule", max),
                "retry-window reload {i} of {max} must succeed"
            );
        }
        assert!(
            !limiter.check(&alice, "ReloadCapsule", max),
            "the derived default is still a finite per-minute cap"
        );
    }

    #[test]
    fn reload_limit_follows_operator_config_not_a_silent_five() {
        let limits = RateLimitsConfig {
            capsule_reload_per_min: RateLimitsConfig::CORE_SET_CAPSULE_COUNT,
            ..RateLimitsConfig::default()
        };
        let limiter = ManagementRateLimiter::with_limits(limits);
        let (name, limit) = limiter.limit_for(&KernelRequest::ReloadCapsule {
            id: "astrid-capsule-react".into(),
        });
        assert_eq!(name, "ReloadCapsule");
        assert_eq!(limit, Some(7));
        assert_ne!(limit, Some(5));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn from_kernel_honors_home_capsule_reload_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = astrid_core::dirs::AstridHome::from_path(dir.path());
        let kernel = crate::test_kernel_with_home(home).await;
        std::fs::write(
            kernel.astrid_home.root().join("config.toml"),
            "[rate_limits]\ncapsule_reload_per_min = 7\n",
        )
        .expect("write home rate-limit config");
        let limiter = ManagementRateLimiter::from_kernel(&kernel);
        assert_eq!(
            limiter.limits().capsule_reload_per_min,
            RateLimitsConfig::CORE_SET_CAPSULE_COUNT
        );
        let (_, cap) = limiter.limit_for(&KernelRequest::ReloadCapsule {
            id: "astrid-capsule-openai-compat".into(),
        });
        assert_eq!(cap, Some(7));
        assert_ne!(cap, Some(5));
    }
}
