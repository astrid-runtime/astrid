//! Hand-rolled Prometheus counters.
//!
//! Lives in the gateway crate (not the daemon or kernel) because
//! the gateway is the natural ops-monitoring boundary — every HTTP
//! request flows through it, and the metrics we want
//! (requests-per-route, auth failures, redeem attempts) are
//! gateway-scoped.
//!
//! A full `metrics` / `prometheus` crate dep would be overkill for
//! the four counters we emit. The Prometheus text-exposition
//! format is well-specified (one line per series, type + help
//! optional), so hand-emitting it from atomic counters reads
//! clearly and adds no compile-time surface to the workspace.
//!
//! Counters are namespaced under `astrid_gateway_*` so a single
//! Prometheus instance can scrape multiple Astrid daemons without
//! collision.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;

/// Shared metrics handle. One per `GatewayState`. Counters are
/// `AtomicU64` so route handlers don't take a lock to increment.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Per-route request counts. Keyed by `<METHOD> <route-pattern>`
    /// (e.g. `GET /api/sys/principals`). Wrapped in `RwLock<HashMap>`
    /// because the key set grows lazily on first request and shrinks
    /// never — read-mostly after warm-up, so the lock cost is
    /// negligible.
    pub requests_total: RwLock<HashMap<&'static str, AtomicU64>>,
    /// Bearer-verification failures (tampered sig, expired, malformed).
    pub auth_failures_total: AtomicU64,
    /// Invite-redemption attempts (successful + rejected combined).
    /// Subtract rate-limited from this to estimate token-brute-force
    /// pressure if it ever shows up in dashboards.
    pub redeem_attempts_total: AtomicU64,
    /// Invite redemptions rejected for rate-limiting.
    pub redeem_rate_limited_total: AtomicU64,
}

impl Metrics {
    /// Bump the per-route counter for `(method, route_pattern)`.
    /// The key is `&'static str` so we don't allocate on the hot
    /// path — pass route-template strings directly from the route
    /// handler.
    pub async fn observe_request(&self, key: &'static str) {
        // Fast path: read lock, increment if entry exists.
        {
            let map = self.requests_total.read().await;
            if let Some(counter) = map.get(key) {
                counter.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Slow path: write lock, double-check, insert.
        let mut map = self.requests_total.write().await;
        let counter = map.entry(key).or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Render the current snapshot as Prometheus text-exposition
    /// format. One pass over each counter family; no allocation per
    /// counter beyond the output `String`.
    pub async fn render(&self) -> String {
        let mut out = String::with_capacity(1024);

        // Per-route counter family.
        out.push_str("# HELP astrid_gateway_requests_total Total HTTP requests by method+route.\n");
        out.push_str("# TYPE astrid_gateway_requests_total counter\n");
        {
            let map = self.requests_total.read().await;
            // Sort keys for stable output — easier to diff in
            // dashboards and tests.
            let mut entries: Vec<(&&'static str, &AtomicU64)> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            for (key, counter) in entries {
                let v = counter.load(Ordering::Relaxed);
                // Split on the first space to get method + route.
                let (method, route) = key.split_once(' ').unwrap_or(("UNKNOWN", *key));
                let _ = writeln!(
                    out,
                    "astrid_gateway_requests_total{{method=\"{method}\",route=\"{}\"}} {v}",
                    escape_label(route),
                );
            }
        }

        // Auth failures.
        out.push_str("\n# HELP astrid_gateway_auth_failures_total Failed bearer verifications.\n");
        out.push_str("# TYPE astrid_gateway_auth_failures_total counter\n");
        let _ = writeln!(
            out,
            "astrid_gateway_auth_failures_total {}",
            self.auth_failures_total.load(Ordering::Relaxed)
        );

        // Redeem attempts.
        out.push_str("\n# HELP astrid_gateway_redeem_attempts_total Invite-redemption attempts.\n");
        out.push_str("# TYPE astrid_gateway_redeem_attempts_total counter\n");
        let _ = writeln!(
            out,
            "astrid_gateway_redeem_attempts_total {}",
            self.redeem_attempts_total.load(Ordering::Relaxed)
        );

        // Redeem rate-limit rejections.
        out.push_str(
            "\n# HELP astrid_gateway_redeem_rate_limited_total Redeem requests rejected by the rate limiter.\n",
        );
        out.push_str("# TYPE astrid_gateway_redeem_rate_limited_total counter\n");
        let _ = writeln!(
            out,
            "astrid_gateway_redeem_rate_limited_total {}",
            self.redeem_rate_limited_total.load(Ordering::Relaxed)
        );

        out
    }
}

/// Escape characters that have meaning in Prometheus label values
/// (`\`, `"`, `\n`). Route patterns won't normally need this but
/// route registration helpers might let weirder strings through.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn observe_increments_counter() {
        let m = Metrics::default();
        m.observe_request("GET /api/sys/status").await;
        m.observe_request("GET /api/sys/status").await;
        m.observe_request("GET /api/sys/principals").await;
        let rendered = m.render().await;
        assert!(
            rendered.contains(
                "astrid_gateway_requests_total{method=\"GET\",route=\"/api/sys/status\"} 2"
            )
        );
        assert!(rendered.contains(
            "astrid_gateway_requests_total{method=\"GET\",route=\"/api/sys/principals\"} 1"
        ));
    }

    #[tokio::test]
    async fn renders_help_and_type_for_every_family() {
        let m = Metrics::default();
        let rendered = m.render().await;
        for family in [
            "astrid_gateway_requests_total",
            "astrid_gateway_auth_failures_total",
            "astrid_gateway_redeem_attempts_total",
            "astrid_gateway_redeem_rate_limited_total",
        ] {
            assert!(
                rendered.contains(&format!("# HELP {family}")),
                "missing HELP for {family} in:\n{rendered}"
            );
            assert!(
                rendered.contains(&format!("# TYPE {family} counter")),
                "missing TYPE for {family} in:\n{rendered}"
            );
        }
    }

    #[test]
    fn label_escape_handles_quote_and_backslash() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label(r#"with"quote"#), r#"with\"quote"#);
        assert_eq!(escape_label(r"with\backslash"), r"with\\backslash");
        assert_eq!(escape_label("with\nnewline"), "with\\nnewline");
    }
}
