//! `astrid:http@1.1.0` request-option resolution and the per-request controls
//! that derive from it: scheme/https-only enforcement, cross-origin credential
//! stripping, and subresource-integrity verification.

use std::time::Duration;

use base64::Engine as _;
use reqwest::header::HeaderMap;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::engine::wasm::host::util;
use crate::engine::wasm::limits::HttpLimits;

use super::{ErrorCode, RedirectPolicy, RequestOptions, TimeoutConfig};

/// Host-resolved view of `request-options`: caller fields with host defaults
/// already applied. Threaded through the shared backend so `http_request`
/// (which builds the `@1.0.0`-equivalent default) and `http_request_opts`
/// share one code path.
#[derive(Clone, Debug)]
pub(super) struct ResolvedOptions {
    pub(super) connect_timeout: Option<Duration>,
    pub(super) total_timeout: Option<Duration>,
    /// Per-chunk idle gap (streaming) / `read_timeout` (buffered).
    pub(super) between_bytes_timeout: Option<Duration>,
    /// First-byte deadline. reqwest has no dedicated first-byte timeout, so
    /// this is best-effort: applied as a `read_timeout` floor on the buffered
    /// path when no `between_bytes` is set, and otherwise folded into the
    /// total deadline. Tracked as a follow-up if a tighter mapping is needed.
    pub(super) first_byte_timeout: Option<Duration>,
    pub(super) redirect: RedirectPolicy,
    pub(super) max_redirects: usize,
    pub(super) max_response_bytes: u64,
    pub(super) max_decompressed_bytes: Option<u64>,
    pub(super) auto_decompress: bool,
    pub(super) https_only: bool,
    pub(super) integrity: Option<String>,
    /// True iff the caller EXPLICITLY set `timeouts.total-ms` (so `total_timeout`
    /// is a caller deadline, not the host default). The streaming path clears
    /// the *default* total so a long-lived stream isn't cut at the buffered
    /// default, but keeps an explicit caller total. Tracked as explicitness, not
    /// a value comparison: a caller who explicitly passes a `total-ms` that
    /// happens to equal the configured host default must still have it honoured
    /// (a value-equality check would silently clear it).
    pub(super) total_explicit: bool,
}

impl ResolvedOptions {
    /// The `@1.0.0`-equivalent defaults, read off the resolved [`HttpLimits`]:
    /// follow redirects ≤ `limits.max_redirects`, the host default total
    /// timeout, the host buffered-body cap, auto-decompress on, no https-only,
    /// no SRI. With [`HttpLimits::default`] this reproduces the historical
    /// constants (≤10 redirects, 30s, 10 MiB) exactly.
    pub(super) fn v10_defaults(limits: &HttpLimits) -> Self {
        Self {
            connect_timeout: None,
            total_timeout: Some(limits.default_total_timeout),
            between_bytes_timeout: None,
            first_byte_timeout: None,
            redirect: RedirectPolicy::Follow,
            max_redirects: limits.max_redirects,
            // The configured/default buffered cap, itself clamped to the
            // absolute host payload limit so config can only LOWER it.
            max_response_bytes: limits.max_response_bytes.min(util::MAX_GUEST_PAYLOAD_LEN),
            max_decompressed_bytes: None,
            auto_decompress: true,
            https_only: false,
            integrity: None,
            total_explicit: false,
        }
    }

    /// Resolve caller `request-options` against the host [`HttpLimits`]. `none`
    /// per field keeps the host default. The `max_redirects` and
    /// `max_response_bytes` values are clamped DOWN to the host ceiling — a
    /// caller can only tighten them, never raise them above the operator limit
    /// (and `max_response_bytes` is additionally clamped to the absolute
    /// `MAX_GUEST_PAYLOAD_LEN` host payload limit).
    pub(super) fn from_options(opts: RequestOptions, limits: &HttpLimits) -> Self {
        let mut resolved = Self::v10_defaults(limits);

        if let Some(t) = opts.timeouts {
            let TimeoutConfig {
                connect_ms,
                first_byte_ms,
                between_bytes_ms,
                total_ms,
            } = t;
            if let Some(ms) = connect_ms {
                resolved.connect_timeout = Some(Duration::from_millis(ms));
            }
            if let Some(ms) = first_byte_ms {
                resolved.first_byte_timeout = Some(Duration::from_millis(ms));
            }
            if let Some(ms) = between_bytes_ms {
                resolved.between_bytes_timeout = Some(Duration::from_millis(ms));
            }
            // `none` total keeps the host default; an explicit value overrides
            // it (and may be longer for big downloads). Mark it explicit so the
            // streaming path honours it even when it equals the host default.
            if let Some(ms) = total_ms {
                resolved.total_timeout = Some(Duration::from_millis(ms));
                resolved.total_explicit = true;
            }
        }

        if let Some(r) = opts.redirect {
            resolved.redirect = r;
        }
        if let Some(n) = opts.max_redirects {
            // Caller may request fewer hops, never more than the host ceiling.
            resolved.max_redirects = (n as usize).min(limits.max_redirects);
        }
        if let Some(n) = opts.max_response_bytes {
            // Caller may request a smaller cap, never larger than the host
            // ceiling — which is itself bounded by the absolute payload limit.
            resolved.max_response_bytes = n.min(resolved.max_response_bytes);
        }
        resolved.max_decompressed_bytes = opts.max_decompressed_bytes;
        if let Some(b) = opts.auto_decompress {
            resolved.auto_decompress = b;
        }
        if let Some(b) = opts.https_only {
            resolved.https_only = b;
        }
        resolved.integrity = opts.integrity;

        resolved
    }
}

/// Reject a non-http(s) scheme up front (and enforce `https-only`). reqwest
/// would surface a generic builder error; the typed `SchemeDenied` is the
/// contract arm. Returns `Ok(())` for a permitted scheme.
pub(super) fn check_scheme(url: &str, https_only: bool) -> Result<(), ErrorCode> {
    let parsed = reqwest::Url::parse(url).map_err(|_| ErrorCode::InvalidRequest)?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if !https_only => Ok(()),
        "http" => Err(ErrorCode::SchemeDenied),
        // ws, ftp, file, data, … — never a valid target for the HTTP host.
        _ => Err(ErrorCode::SchemeDenied),
    }
}

/// Two URLs are same-origin if scheme, host, and effective port all match.
/// A cross-origin redirect strips `Authorization` / `Cookie` (the contract's
/// credential-leak defence).
pub(super) fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Strip `Authorization` and `Cookie` from a header map (used on a
/// cross-origin redirect hop).
pub(super) fn strip_credentials(headers: &mut HeaderMap) {
    headers.remove(reqwest::header::AUTHORIZATION);
    headers.remove(reqwest::header::COOKIE);
}

/// Verify a subresource-integrity digest (`sha256-<b64>` / sha384 / sha512)
/// against the buffered body. Returns `IntegrityMismatch` on mismatch and
/// `InvalidRequest` if the SRI string is malformed.
pub(super) fn verify_integrity(integrity: &str, body: &[u8]) -> Result<(), ErrorCode> {
    let (algo, b64) = integrity.split_once('-').ok_or(ErrorCode::InvalidRequest)?;
    let expected = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64))
        .map_err(|_| ErrorCode::InvalidRequest)?;
    let actual: Vec<u8> = match algo {
        "sha256" => Sha256::digest(body).to_vec(),
        "sha384" => Sha384::digest(body).to_vec(),
        "sha512" => Sha512::digest(body).to_vec(),
        _ => return Err(ErrorCode::InvalidRequest),
    };
    // Constant-time compare is not load-bearing here (the body is attacker-
    // chosen, the digest is caller-chosen), but length + value equality is.
    if actual == expected {
        Ok(())
    } else {
        Err(ErrorCode::IntegrityMismatch)
    }
}
