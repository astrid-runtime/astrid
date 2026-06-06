//! Tunables and request-normalisation helpers for the persistent tier.
//!
//! Guest-supplied sizes / TTLs are clamped DOWN to host ceilings here so a
//! capsule can never request an unbounded ring, lifetime, or label.

use std::time::Duration;

use crate::engine::wasm::bindings::astrid::process::host::OverflowPolicy;

use super::ring::Overflow;

/// Default per-stream output ring capacity (stdout and stderr each).
const DEFAULT_LOG_RING_BYTES: usize = 1024 * 1024;
/// Hard ceiling on a guest-requested per-stream ring.
const MAX_LOG_RING_BYTES: usize = 8 * 1024 * 1024;
/// Floor on a guest-requested per-stream ring (a 0-byte ring is useless).
const MIN_LOG_RING_BYTES: usize = 4096;
/// Per-`write-stdin` call byte cap (matches the WIT contract).
pub(super) const MAX_STDIN_WRITE: usize = 1024 * 1024;
/// Per-principal RETAINED-id cap (live + exited-but-unreleased). Distinct
/// from the CONCURRENT cap (the profile's `max_background_processes`).
pub(super) const MAX_RETAINED_PER_PRINCIPAL: usize = 32;
/// Global registry-entry ceiling across all principals of one capsule.
pub(super) const MAX_REGISTRY_ENTRIES: usize = 256;
/// Default wall-clock lifetime ceiling, and the hard cap a guest request is
/// clamped DOWN to — a guest cannot request an unbounded lifetime.
const MAX_LIFETIME: Duration = Duration::from_secs(60 * 60 * 6);
/// Default idle reap interval (no read / wait / signal / write).
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 30);
/// Default post-exit retention of the id + log tail.
const DEFAULT_EXIT_RETENTION: Duration = Duration::from_secs(60 * 5);
/// Hard cap on post-exit retention.
const MAX_EXIT_RETENTION: Duration = Duration::from_secs(60 * 60);
/// SIGTERM→SIGKILL grace when `stop` is called with `grace-ms: none`.
pub(super) const DEFAULT_STOP_GRACE: Duration = Duration::from_secs(5);
/// Upper bound the `stop` grace is clamped to so a guest cannot pin a slot.
pub(super) const MAX_STOP_GRACE: Duration = Duration::from_secs(30);
/// Max bytes a single `read-since` chunk returns (host hard cap).
pub(super) const MAX_READ_SINCE_BYTES: usize = 4 * 1024 * 1024;
/// Operator label length clamp.
const MAX_LABEL_BYTES: usize = 128;

/// Map the WIT `overflow-policy` (and its `none` default) to the internal
/// enum.
pub(super) fn overflow_from_wit(o: Option<OverflowPolicy>) -> Overflow {
    match o {
        Some(OverflowPolicy::Backpressure) => Overflow::Backpressure,
        _ => Overflow::DropOldest,
    }
}

/// Clamp a guest-requested per-stream ring size to `[MIN, MAX]`, or the
/// default when unset.
pub(super) fn clamp_log_ring(bytes: Option<u32>) -> usize {
    bytes
        .map(|b| (b as usize).clamp(MIN_LOG_RING_BYTES, MAX_LOG_RING_BYTES))
        .unwrap_or(DEFAULT_LOG_RING_BYTES)
}

/// Clamp a guest label (strip control chars, length-cap), or derive from
/// `cmd`. The label is NOT an identity — only the `process-id` is.
pub(super) fn clamp_label(label: Option<String>, cmd: &str) -> String {
    let raw = label.unwrap_or_else(|| cmd.to_string());
    raw.chars()
        .filter(|c| !c.is_control())
        .take(MAX_LABEL_BYTES)
        .collect()
}

/// Resolve the effective `(lifetime, idle, retention)` durations from the
/// guest request, applying defaults and DOWN-clamping to host ceilings.
pub(super) fn resolve_ttls(
    max_lifetime_ms: Option<u64>,
    idle_timeout_ms: Option<u64>,
    exit_retention_ms: Option<u64>,
) -> (Duration, Duration, Duration) {
    let lifetime = max_lifetime_ms
        .map(Duration::from_millis)
        .unwrap_or(MAX_LIFETIME)
        .min(MAX_LIFETIME);
    let idle = idle_timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_IDLE_TIMEOUT)
        .min(MAX_LIFETIME);
    let retention = exit_retention_ms
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_EXIT_RETENTION)
        .min(MAX_EXIT_RETENTION);
    (lifetime, idle, retention)
}
