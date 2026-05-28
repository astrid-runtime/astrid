//! Hand-rolled Prometheus counters + histograms.
//!
//! Lives in the gateway crate (not the daemon or kernel) because
//! the gateway is the natural ops-monitoring boundary — every HTTP
//! request flows through it, and the metrics we want
//! (requests-per-route, latency, auth failures, redeem attempts)
//! are gateway-scoped.
//!
//! A full `metrics` / `prometheus` crate dep would be overkill for
//! the handful of series we emit. The Prometheus text-exposition
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
use std::time::Duration;

use tokio::sync::RwLock;

/// Prometheus default histogram buckets for HTTP request duration in
/// seconds: 5 ms, 10 ms, 25 ms, 50 ms, 100 ms, 250 ms, 500 ms, 1 s,
/// 2.5 s, 5 s, 10 s, +Inf. Spans the range from "p50 of a hot admin
/// call" (<5 ms) to "definitely something has wedged" (>10 s).
const DURATION_BUCKETS_SECONDS: [f64; 11] = [
    0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 2.500, 5.000, 10.000,
];

/// One Prometheus histogram. Hand-rolled to avoid the `prometheus`
/// crate dep; matches the same posture as the counters in this
/// module.
///
/// `sum_micros` accumulates the total observed duration in *micro*-
/// seconds so a `u64` can hold the running sum without ever
/// overflowing (584,554 years at one observation per microsecond),
/// and there's no need for an `AtomicF64` (which isn't a thing in
/// std).
#[derive(Debug)]
pub struct Histogram {
    /// Cumulative bucket counters — `buckets[i]` counts observations
    /// `<= DURATION_BUCKETS_SECONDS[i]`. The total observation count
    /// (== `+Inf` bucket) lives in `count`.
    buckets: Vec<AtomicU64>,
    /// Total observed value in microseconds. Rendered as seconds in
    /// the exposition format.
    sum_micros: AtomicU64,
    /// Total observation count (== `+Inf` bucket).
    count: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: (0..DURATION_BUCKETS_SECONDS.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl Histogram {
    /// Record one observation. `duration` is converted to seconds for
    /// bucketing and to microseconds for the running sum.
    pub fn observe(&self, duration: Duration) {
        let secs = duration.as_secs_f64();
        for (i, &le) in DURATION_BUCKETS_SECONDS.iter().enumerate() {
            if secs <= le {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // saturate at u64::MAX rather than wrap — a wrap would emit
        // a nonsensical sum/count ratio to dashboards.
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

/// One bucket of per-request observability: total count + latency
/// histogram. Keyed in `Metrics::requests` by `"METHOD ROUTE STATUS"`
/// so a 500-rate spike against `/api/auth/redeem` decomposes
/// separately from the 200 traffic on the same route.
#[derive(Debug, Default)]
pub struct PerRequestMetrics {
    pub count: AtomicU64,
    pub duration: Histogram,
}

/// Shared metrics handle. One per `GatewayState`. Counters are
/// `AtomicU64` so route handlers don't take a lock to increment.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Per-request observability. Keyed by
    /// `"<METHOD> <route-pattern> <status>"` (e.g.
    /// `GET /api/sys/principals 200`). Wrapped in
    /// `RwLock<HashMap>` because the key set grows lazily on first
    /// request and shrinks never — read-mostly after warm-up, so
    /// the lock cost is negligible. Cardinality is bounded by
    /// `routes × ~6 typical statuses` (~210 series at the current
    /// router shape).
    pub requests: RwLock<HashMap<&'static str, PerRequestMetrics>>,
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
    /// Record one request observation: bump the count and feed the
    /// duration into the histogram. The key is `&'static str` so we
    /// don't allocate on the hot path — the router middleware interns
    /// the `"METHOD ROUTE STATUS"` string once per unique combination
    /// and passes the interned pointer.
    pub async fn observe_request(&self, key: &'static str, duration: Duration) {
        // Fast path: read lock, increment if entry exists.
        {
            let map = self.requests.read().await;
            if let Some(entry) = map.get(key) {
                entry.count.fetch_add(1, Ordering::Relaxed);
                entry.duration.observe(duration);
                return;
            }
        }
        // Slow path: write lock, double-check, insert.
        let mut map = self.requests.write().await;
        let entry = map.entry(key).or_default();
        entry.count.fetch_add(1, Ordering::Relaxed);
        entry.duration.observe(duration);
    }

    /// Render the current snapshot as Prometheus text-exposition
    /// format. One pass over each counter family; no allocation per
    /// counter beyond the output `String`.
    pub async fn render(&self) -> String {
        let mut out = String::with_capacity(4096);

        // Per-request counter family + histogram emitted together so
        // a scraper reading the body sees `_total` and `_bucket`
        // lines for the same `{method,route,status}` combination
        // next to each other.
        out.push_str(
            "# HELP astrid_gateway_requests_total Total HTTP requests by method+route+status.\n",
        );
        out.push_str("# TYPE astrid_gateway_requests_total counter\n");
        out.push_str(
            "# HELP astrid_gateway_request_duration_seconds Per-request handler latency by method+route+status.\n",
        );
        out.push_str("# TYPE astrid_gateway_request_duration_seconds histogram\n");
        {
            let map = self.requests.read().await;
            // Sort keys for stable output — easier to diff in
            // dashboards and tests.
            let mut entries: Vec<(&&'static str, &PerRequestMetrics)> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            for (key, entry) in entries {
                let (method, route, status) = split_key(key);
                let labels = format!(
                    "method=\"{method}\",route=\"{}\",status=\"{status}\"",
                    escape_label(route)
                );
                let count = entry.count.load(Ordering::Relaxed);
                let _ = writeln!(out, "astrid_gateway_requests_total{{{labels}}} {count}");

                // Histogram render: one line per bucket (including
                // `+Inf`), then `_sum` and `_count` aggregates.
                for (i, &le) in DURATION_BUCKETS_SECONDS.iter().enumerate() {
                    let bucket = entry.duration.buckets[i].load(Ordering::Relaxed);
                    let _ = writeln!(
                        out,
                        "astrid_gateway_request_duration_seconds_bucket{{{labels},le=\"{le}\"}} {bucket}"
                    );
                }
                let total = entry.duration.count.load(Ordering::Relaxed);
                let _ = writeln!(
                    out,
                    "astrid_gateway_request_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {total}"
                );
                let sum_secs = micros_to_seconds(entry.duration.sum_micros.load(Ordering::Relaxed));
                let _ = writeln!(
                    out,
                    "astrid_gateway_request_duration_seconds_sum{{{labels}}} {sum_secs}"
                );
                let _ = writeln!(
                    out,
                    "astrid_gateway_request_duration_seconds_count{{{labels}}} {total}"
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

/// Convert microseconds to seconds without losing precision below
/// nanosecond granularity. `as f64 / 1_000_000.0` would round-trip
/// fine for our histogram range; extracted as a named function so
/// future refactors don't drift from the unit invariant.
#[allow(clippy::cast_precision_loss)] // sum_micros never exceeds the f64 mantissa range for sane uptimes
fn micros_to_seconds(micros: u64) -> f64 {
    micros as f64 / 1_000_000.0
}

/// Split a `"METHOD ROUTE STATUS"` key back into its three parts.
/// Defaults are paranoia — the router middleware interns the key in
/// exactly this shape, so the empty cases should be unreachable in
/// production.
fn split_key(key: &str) -> (&str, &str, &str) {
    let (method, rest) = key.split_once(' ').unwrap_or(("UNKNOWN", key));
    let (route, status) = rest.rsplit_once(' ').unwrap_or((rest, "0"));
    (method, route, status)
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
    async fn observe_records_count_and_duration() {
        let m = Metrics::default();
        m.observe_request("GET /api/sys/status 200", Duration::from_millis(12))
            .await;
        m.observe_request("GET /api/sys/status 200", Duration::from_millis(25))
            .await;
        m.observe_request("GET /api/sys/principals 200", Duration::from_millis(8))
            .await;
        let rendered = m.render().await;
        assert!(rendered.contains(
            "astrid_gateway_requests_total{method=\"GET\",route=\"/api/sys/status\",status=\"200\"} 2"
        ));
        assert!(rendered.contains(
            "astrid_gateway_requests_total{method=\"GET\",route=\"/api/sys/principals\",status=\"200\"} 1"
        ));
        // Histogram presence: each entry emits a `_count` line equal
        // to its total observations.
        assert!(rendered.contains(
            "astrid_gateway_request_duration_seconds_count{method=\"GET\",route=\"/api/sys/status\",status=\"200\"} 2"
        ));
    }

    #[tokio::test]
    async fn status_label_decomposes_2xx_from_5xx() {
        let m = Metrics::default();
        m.observe_request("POST /api/auth/redeem 200", Duration::from_millis(5))
            .await;
        m.observe_request("POST /api/auth/redeem 200", Duration::from_millis(7))
            .await;
        m.observe_request("POST /api/auth/redeem 500", Duration::from_millis(80))
            .await;
        let rendered = m.render().await;
        assert!(rendered.contains(
            "astrid_gateway_requests_total{method=\"POST\",route=\"/api/auth/redeem\",status=\"200\"} 2"
        ));
        assert!(rendered.contains(
            "astrid_gateway_requests_total{method=\"POST\",route=\"/api/auth/redeem\",status=\"500\"} 1"
        ));
    }

    #[tokio::test]
    async fn histogram_buckets_are_cumulative() {
        let m = Metrics::default();
        // Three observations: 7 ms, 20 ms, 200 ms. Buckets above are
        // cumulative — every bucket whose `le >= obs` increments.
        m.observe_request("GET /x 200", Duration::from_millis(7))
            .await;
        m.observe_request("GET /x 200", Duration::from_millis(20))
            .await;
        m.observe_request("GET /x 200", Duration::from_millis(200))
            .await;
        let rendered = m.render().await;
        // `<= 0.005` is below all three: 0
        assert!(rendered.contains(
            "astrid_gateway_request_duration_seconds_bucket{method=\"GET\",route=\"/x\",status=\"200\",le=\"0.005\"} 0"
        ));
        // `<= 0.025` catches 7 ms + 20 ms = 2
        assert!(rendered.contains(
            "astrid_gateway_request_duration_seconds_bucket{method=\"GET\",route=\"/x\",status=\"200\",le=\"0.025\"} 2"
        ));
        // `<= 0.25` catches all three: 3
        assert!(rendered.contains(
            "astrid_gateway_request_duration_seconds_bucket{method=\"GET\",route=\"/x\",status=\"200\",le=\"0.25\"} 3"
        ));
        // `+Inf` always matches `_count`.
        assert!(rendered.contains(
            "astrid_gateway_request_duration_seconds_bucket{method=\"GET\",route=\"/x\",status=\"200\",le=\"+Inf\"} 3"
        ));
    }

    #[tokio::test]
    async fn renders_help_and_type_for_every_family() {
        let m = Metrics::default();
        let rendered = m.render().await;
        for (family, kind) in [
            ("astrid_gateway_requests_total", "counter"),
            ("astrid_gateway_request_duration_seconds", "histogram"),
            ("astrid_gateway_auth_failures_total", "counter"),
            ("astrid_gateway_redeem_attempts_total", "counter"),
            ("astrid_gateway_redeem_rate_limited_total", "counter"),
        ] {
            assert!(
                rendered.contains(&format!("# HELP {family}")),
                "missing HELP for {family} in:\n{rendered}"
            );
            assert!(
                rendered.contains(&format!("# TYPE {family} {kind}")),
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

    #[test]
    fn split_key_extracts_three_parts() {
        assert_eq!(split_key("GET /a 200"), ("GET", "/a", "200"));
        assert_eq!(
            split_key("POST /api/sys/principals/:id 404"),
            ("POST", "/api/sys/principals/:id", "404")
        );
    }
}
