//! Metric recording for the gateway.
//!
//! Uses the `metrics` facade + `metrics-exporter-prometheus` instead
//! of a hand-rolled counter/histogram pair. The facade decouples
//! recording from export format, so kernel-side or capsule-side code
//! that wants to participate in observability later can do so via
//! the same `counter!()` / `histogram!()` macros without each
//! subsystem reinventing a metrics layer.
//!
//! ## Layout
//!
//! * [`install_recorder`] installs a process-wide `PrometheusRecorder`
//!   (idempotent — re-invocation returns the existing handle) and
//!   pre-registers every series the gateway is expected to emit so
//!   even uninstrumented counters show up at `0` in the scrape body.
//! * Handler / middleware sites record via the facade
//!   macros: `counter!("astrid_gateway_requests_total", "method" => …,
//!   "route" => …, "status" => …).increment(1)` etc.
//! * `/metrics` renders the recorder handle.
//!
//! ## Metric inventory
//!
//! | Name | Type | Labels | What it tracks |
//! |---|---|---|---|
//! | `astrid_gateway_requests_total` | counter | method, route, status | Per-request count |
//! | `astrid_gateway_request_duration_seconds` | histogram | method, route, status | Per-request latency |
//! | `astrid_gateway_auth_failures_total` | counter | — | Bearer verification failures |
//! | `astrid_gateway_redeem_attempts_total` | counter | — | Invite redemptions attempted |
//! | `astrid_gateway_redeem_rate_limited_total` | counter | — | Redeem rejections by the rate limiter |
//!
//! Cardinality on the labelled series is bounded by
//! `routes × ~6 typical statuses` (~210 series at the current router
//! shape). The histogram inherits the same labels.

use std::sync::Mutex;
use std::time::Duration;

use metrics::{Unit, describe_counter, describe_histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// Prometheus default histogram buckets for HTTP request duration in
/// seconds: 5 ms → 10 s. Spans the range from "p50 of a hot admin
/// call" (< 5 ms) to "definitely something has wedged" (> 10 s).
/// Identical to what `prometheus_client::default_buckets` ships, so
/// dashboards built against the convention "just work".
const DURATION_BUCKETS_SECONDS: &[f64] = &[
    0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 2.500, 5.000, 10.000,
];

/// Metric name for the per-request count. Kept as a `const` so the
/// middleware call site and the inventory above stay in lock-step.
pub const METRIC_REQUESTS_TOTAL: &str = "astrid_gateway_requests_total";

/// Metric name for the per-request latency histogram.
pub const METRIC_REQUEST_DURATION_SECONDS: &str = "astrid_gateway_request_duration_seconds";

/// Bearer-verification failure counter.
pub const METRIC_AUTH_FAILURES_TOTAL: &str = "astrid_gateway_auth_failures_total";

/// Invite-redemption attempt counter.
pub const METRIC_REDEEM_ATTEMPTS_TOTAL: &str = "astrid_gateway_redeem_attempts_total";

/// Invite-redemption rate-limited counter.
pub const METRIC_REDEEM_RATE_LIMITED_TOTAL: &str = "astrid_gateway_redeem_rate_limited_total";

/// Install the process-wide Prometheus recorder. Idempotent: every
/// call after the first returns the same handle (the `metrics` crate
/// allows only one recorder per process, so we serialise the install
/// behind a [`Mutex`] and memoise the handle inside it).
///
/// The Mutex (rather than `OnceLock::get_or_try_init`, which is
/// nightly) is what makes the function safe under concurrent
/// callers: two test binaries that both call `install_recorder` at
/// boot would race the underlying `metrics::set_global_recorder`,
/// the loser would `Err`, and we'd have no way to recover the
/// already-installed handle. Serialising the check + install + store
/// inside one critical section avoids that.
///
/// # Errors
/// Returns an error if `PrometheusBuilder::install_recorder` fails
/// on first call. Subsequent calls cannot fail.
pub fn install_recorder() -> anyhow::Result<PrometheusHandle> {
    static HANDLE: Mutex<Option<PrometheusHandle>> = Mutex::new(None);
    let mut guard = HANDLE
        .lock()
        .map_err(|e| anyhow::anyhow!("recorder lock poisoned: {e}"))?;
    if let Some(existing) = guard.as_ref() {
        return Ok(existing.clone());
    }
    let handle = PrometheusBuilder::new()
        // Set the per-route latency histogram's buckets explicitly.
        // The `Suffix` matcher applies to every series whose name
        // matches the metric base — same buckets for every
        // (method, route, status) combo.
        .set_buckets_for_metric(
            Matcher::Suffix(METRIC_REQUEST_DURATION_SECONDS.to_string()),
            DURATION_BUCKETS_SECONDS,
        )
        .map_err(|e| anyhow::anyhow!("configure histogram buckets: {e}"))?
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("install Prometheus recorder: {e}"))?;

    // Describe every metric the gateway emits so `/metrics` carries
    // `# HELP` + `# TYPE` lines even before the series sees its
    // first observation. Touch each counter once at zero so it
    // appears in the scrape body — `metrics-exporter-prometheus`
    // only renders series after they've been recorded against.
    describe_counter!(
        METRIC_REQUESTS_TOTAL,
        Unit::Count,
        "Total HTTP requests by method+route+status."
    );
    describe_histogram!(
        METRIC_REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "Per-request handler latency by method+route+status."
    );
    describe_counter!(
        METRIC_AUTH_FAILURES_TOTAL,
        Unit::Count,
        "Failed bearer verifications."
    );
    describe_counter!(
        METRIC_REDEEM_ATTEMPTS_TOTAL,
        Unit::Count,
        "Invite-redemption attempts."
    );
    describe_counter!(
        METRIC_REDEEM_RATE_LIMITED_TOTAL,
        Unit::Count,
        "Redeem requests rejected by the rate limiter."
    );
    // Force registration of the unlabelled counters so they render
    // at zero even before instrumentation lands. The labelled
    // request counter and histogram materialise lazily on first
    // observation — that's fine because the router middleware hits
    // them every request.
    metrics::counter!(METRIC_AUTH_FAILURES_TOTAL).absolute(0);
    metrics::counter!(METRIC_REDEEM_ATTEMPTS_TOTAL).absolute(0);
    metrics::counter!(METRIC_REDEEM_RATE_LIMITED_TOTAL).absolute(0);

    *guard = Some(handle.clone());
    Ok(handle)
}

/// Map an axum `Method` to a `&'static str` for use as a metric
/// label. Custom methods (`Method::from_bytes(b"WEIRD")`) collapse to
/// `"OTHER"` so a malicious client can't inflate metric cardinality
/// by spraying random verbs.
#[must_use]
pub fn http_method_static(method: &axum::http::Method) -> &'static str {
    match *method {
        axum::http::Method::GET => "GET",
        axum::http::Method::POST => "POST",
        axum::http::Method::PUT => "PUT",
        axum::http::Method::DELETE => "DELETE",
        axum::http::Method::PATCH => "PATCH",
        axum::http::Method::HEAD => "HEAD",
        axum::http::Method::OPTIONS => "OPTIONS",
        axum::http::Method::CONNECT => "CONNECT",
        axum::http::Method::TRACE => "TRACE",
        _ => "OTHER",
    }
}

/// Convenience for the router middleware: record one observation
/// (count + duration) on the per-request metrics in a single call,
/// keyed by `(method, route, status)`.
pub fn observe_request(method: &'static str, route: &'static str, status: u16, duration: Duration) {
    let status_str = status_to_static(status);
    metrics::counter!(
        METRIC_REQUESTS_TOTAL,
        "method" => method,
        "route" => route,
        "status" => status_str,
    )
    .increment(1);
    metrics::histogram!(
        METRIC_REQUEST_DURATION_SECONDS,
        "method" => method,
        "route" => route,
        "status" => status_str,
    )
    .record(duration.as_secs_f64());
}

/// Map common HTTP status codes to `&'static str` to dodge the
/// `String` allocation the `metrics` macros would otherwise force
/// on the hot path. Anything outside the standard range falls back
/// to `"other"` so cardinality stays bounded under a hostile client.
fn status_to_static(status: u16) -> &'static str {
    match status {
        100 => "100",
        101 => "101",
        102 => "102",
        103 => "103",
        200 => "200",
        201 => "201",
        202 => "202",
        203 => "203",
        204 => "204",
        205 => "205",
        206 => "206",
        207 => "207",
        208 => "208",
        226 => "226",
        300 => "300",
        301 => "301",
        302 => "302",
        303 => "303",
        304 => "304",
        305 => "305",
        307 => "307",
        308 => "308",
        400 => "400",
        401 => "401",
        402 => "402",
        403 => "403",
        404 => "404",
        405 => "405",
        406 => "406",
        407 => "407",
        408 => "408",
        409 => "409",
        410 => "410",
        411 => "411",
        412 => "412",
        413 => "413",
        414 => "414",
        415 => "415",
        416 => "416",
        417 => "417",
        418 => "418",
        421 => "421",
        422 => "422",
        423 => "423",
        424 => "424",
        425 => "425",
        426 => "426",
        428 => "428",
        429 => "429",
        431 => "431",
        451 => "451",
        500 => "500",
        501 => "501",
        502 => "502",
        503 => "503",
        504 => "504",
        505 => "505",
        506 => "506",
        507 => "507",
        508 => "508",
        510 => "510",
        511 => "511",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The metrics crate's global recorder is process-wide. Every
    // test in this module shares the same recorder via
    // `install_recorder`'s OnceLock, so observations accumulate
    // across tests. That's fine — assertions use `.contains()` and
    // the test names are not the metric labels.

    #[test]
    fn install_recorder_is_idempotent() {
        let h1 = install_recorder().expect("install");
        let h2 = install_recorder().expect("second install");
        // Calling `render()` shouldn't panic on either handle.
        let _ = h1.render();
        let _ = h2.render();
    }

    #[test]
    fn http_method_static_covers_standard_set() {
        use axum::http::Method;
        assert_eq!(http_method_static(&Method::GET), "GET");
        assert_eq!(http_method_static(&Method::POST), "POST");
        assert_eq!(http_method_static(&Method::PUT), "PUT");
        assert_eq!(http_method_static(&Method::DELETE), "DELETE");
        assert_eq!(http_method_static(&Method::PATCH), "PATCH");
        assert_eq!(http_method_static(&Method::HEAD), "HEAD");
        assert_eq!(http_method_static(&Method::OPTIONS), "OPTIONS");
        let custom = Method::from_bytes(b"WEIRD").unwrap();
        assert_eq!(http_method_static(&custom), "OTHER");
    }

    #[test]
    fn status_to_static_covers_common_codes_and_falls_back() {
        assert_eq!(status_to_static(200), "200");
        assert_eq!(status_to_static(404), "404");
        assert_eq!(status_to_static(500), "500");
        // Anything outside the standard range goes to `other` so a
        // hostile client can't blow up metric cardinality by
        // returning arbitrary status codes via a future handler.
        assert_eq!(status_to_static(999), "other");
    }

    #[tokio::test]
    async fn observe_request_renders_counter_and_histogram() {
        let handle = install_recorder().expect("install");
        observe_request("GET", "/api/test-observe", 200, Duration::from_millis(15));
        observe_request("GET", "/api/test-observe", 200, Duration::from_millis(42));
        let rendered = handle.render();
        assert!(
            rendered.contains("astrid_gateway_requests_total")
                && rendered.contains("route=\"/api/test-observe\"")
                && rendered.contains("status=\"200\""),
            "missing requests_total for the labelled series; body:\n{rendered}"
        );
        // The Prometheus exporter renders histograms as a
        // `_bucket` family + `_sum` + `_count`. We just check that
        // the histogram name appears with our route.
        assert!(
            rendered.contains("astrid_gateway_request_duration_seconds")
                && rendered.contains("route=\"/api/test-observe\""),
            "missing request_duration histogram; body:\n{rendered}"
        );
    }

    #[test]
    fn unlabelled_counters_register_at_zero() {
        let handle = install_recorder().expect("install");
        let rendered = handle.render();
        // Each unlabelled counter was touched at `absolute(0)` in
        // `install_recorder`, so it must appear in the scrape body
        // even before any instrumentation lands.
        for name in [
            METRIC_AUTH_FAILURES_TOTAL,
            METRIC_REDEEM_ATTEMPTS_TOTAL,
            METRIC_REDEEM_RATE_LIMITED_TOTAL,
        ] {
            assert!(
                rendered.contains(name),
                "{name} missing from scrape body — describe + touch broken;\n{rendered}"
            );
        }
    }
}
