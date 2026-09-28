//! Audit recording for kernel-mediated HTTP exchanges.
//!
//! Every wire request, each redirect hop included, produces two records
//! through the host-audit sink:
//!
//! 1. a pre-commit, appended durably through
//!    [`HostAuditSink::commit`] after the airlock checks pass and before the
//!    request is sent — the host waits for it, so the entry always precedes
//!    the request; and
//! 2. a completion, enqueued once the response body has been read or the
//!    exchange ended early.
//!
//! A request refused by the egress or security gate is recorded as a denied
//! pre-commit instead.
//!
//! Content never reaches the log. The request is committed by BLAKE3 hashes
//! of its path and query, its capsule-supplied headers and its body, each
//! computed after credential redaction:
//!
//! - the value of every credential header ([`CREDENTIAL_HEADERS`]) and every
//!   credential query parameter ([`CREDENTIAL_QUERY_KEYS`]) is replaced by
//!   [`REDACTED`];
//! - every occurrence of a secret value the host handed to this capsule
//!   instance (a secret-typed config read) is replaced by [`REDACTED`] in the
//!   path, the header values and the body.
//!
//! Secrets the host injects itself (see `credentials`) are committed in their
//! placeholder form and only named on the entry.
//!
//! A verifier holding the request can recompute each commitment by applying
//! the same redaction. The canonical header form is one `name:value\n` line
//! per header, names lower-cased, sorted by name (duplicates keep their
//! order). The response body hash covers the body bytes the host read, in
//! order, after transport decoding.

use std::borrow::Cow;
use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_crypto::ContentHash;
use reqwest::header::HeaderMap;
use zeroize::Zeroizing;

use crate::audit_sink::{
    HostAuditEvent, HostAuditOutcome, HostAuditReceipt, HostAuditSink, HostHttpRequest,
    HostHttpResponse,
};
use crate::engine::wasm::host_state::HostState;

/// Replacement for a redacted credential.
pub(crate) const REDACTED: &str = "[REDACTED]";

/// Request headers whose values are credentials. Matched case-insensitively.
pub(crate) const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-auth-token",
    "x-amz-security-token",
    "ocp-apim-subscription-key",
];

/// Query parameters whose values are credentials. Matched case-insensitively
/// on the decoded name.
pub(crate) const CREDENTIAL_QUERY_KEYS: &[&str] = &[
    "key",
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "token",
    "auth",
    "password",
    "secret",
    "client_secret",
    "signature",
    "sig",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
    "x-goog-signature",
    "x-goog-credential",
];

/// Response headers that carry a provider request id.
const PROVIDER_REQUEST_ID_HEADERS: &[&str] = &[
    "x-request-id",
    "request-id",
    "x-amzn-requestid",
    "x-amz-request-id",
    "apim-request-id",
    "x-ms-request-id",
    "cf-ray",
];

/// Longest provider request id value kept (bytes); longer values are cut.
const MAX_REQUEST_ID_LEN: usize = 128;

/// Shortest secret value redacted by value. Shorter values are too likely to
/// occur by chance to be removed from content without corrupting it.
const MIN_REDACTED_SECRET_LEN: usize = 4;

/// Most distinct secret values one host state remembers for redaction.
const MAX_REVEALED_SECRETS: usize = 32;

/// Secret values the host handed to this capsule instance, remembered so the
/// HTTP audit can redact them from request commitments. Values are zeroized
/// on drop and never printed.
#[derive(Clone, Default)]
pub struct RevealedSecrets {
    values: Vec<Zeroizing<String>>,
}

impl RevealedSecrets {
    /// Remember a secret value handed to the guest.
    pub(crate) fn note(&mut self, value: &str) {
        if value.len() < MIN_REDACTED_SECRET_LEN
            || self.values.len() >= MAX_REVEALED_SECRETS
            || self.values.iter().any(|known| known.as_str() == value)
        {
            return;
        }
        self.values.push(Zeroizing::new(value.to_owned()));
    }

    fn iter(&self) -> impl Iterator<Item = &str> {
        self.values.iter().map(|value| value.as_str())
    }
}

impl std::fmt::Debug for RevealedSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RevealedSecrets({} values)", self.values.len())
    }
}

/// Replaces known secret values in request content.
pub(super) struct Redactor<'a> {
    /// Longest first, so a secret containing another is replaced whole.
    secrets: Vec<&'a str>,
}

impl<'a> Redactor<'a> {
    pub(super) fn new(secrets: impl Iterator<Item = &'a str>) -> Self {
        let mut secrets: Vec<&str> = secrets
            .filter(|s| s.len() >= MIN_REDACTED_SECRET_LEN)
            .collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        Self { secrets }
    }

    /// Replace every occurrence of every known secret with [`REDACTED`].
    pub(super) fn redact<'b>(&self, input: &'b [u8]) -> Cow<'b, [u8]> {
        let mut out = Cow::Borrowed(input);
        for secret in &self.secrets {
            if let Some(replaced) = replace_all(&out, secret.as_bytes(), REDACTED.as_bytes()) {
                out = Cow::Owned(replaced);
            }
        }
        out
    }
}

/// Replace every non-overlapping occurrence of `needle`; `None` when there is
/// none.
fn replace_all(haystack: &[u8], needle: &[u8], with: &[u8]) -> Option<Vec<u8>> {
    let first = find(haystack, needle)?;
    let mut out = Vec::with_capacity(haystack.len());
    let mut rest = haystack;
    let mut next = Some(first);
    while let Some(at) = next {
        out.extend_from_slice(&rest[..at]);
        out.extend_from_slice(with);
        rest = &rest[at.saturating_add(needle.len())..];
        next = find(rest, needle);
    }
    out.extend_from_slice(rest);
    Some(out)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// BLAKE3 commitments to one outbound request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RequestCommitment {
    pub(super) path_hash: ContentHash,
    pub(super) headers_hash: ContentHash,
    pub(super) body_hash: ContentHash,
    pub(super) body_len: u64,
}

impl RequestCommitment {
    pub(super) fn compute(
        url: &reqwest::Url,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        redactor: &Redactor<'_>,
    ) -> Self {
        let body = body.unwrap_or_default();
        Self {
            path_hash: ContentHash::hash(&redactor.redact(redacted_path(url).as_bytes())),
            headers_hash: ContentHash::hash(&canonical_headers(headers, redactor)),
            body_hash: ContentHash::hash(&redactor.redact(body)),
            body_len: body.len() as u64,
        }
    }
}

/// Path plus query, with credential query-parameter values replaced.
pub(super) fn redacted_path(url: &reqwest::Url) -> String {
    let mut out = url.path().to_owned();
    if let Some(query) = url.query() {
        out.push('?');
        let pairs: Vec<Cow<'_, str>> = query
            .split('&')
            .map(|pair| {
                let (name, _) = pair.split_once('=').unwrap_or((pair, ""));
                let decoded = url::form_urlencoded::parse(name.as_bytes())
                    .next()
                    .map(|(key, _)| key.to_ascii_lowercase())
                    .unwrap_or_default();
                if pair.contains('=') && CREDENTIAL_QUERY_KEYS.contains(&decoded.as_str()) {
                    Cow::Owned(format!("{name}={REDACTED}"))
                } else {
                    Cow::Borrowed(pair)
                }
            })
            .collect();
        out.push_str(&pairs.join("&"));
    }
    out
}

/// Canonical header form: `name:value\n` per header, names lower-cased and
/// sorted (stable), credential values replaced.
pub(super) fn canonical_headers(headers: &HeaderMap, redactor: &Redactor<'_>) -> Vec<u8> {
    let mut lines: Vec<(&str, Cow<'_, [u8]>)> = headers
        .iter()
        .map(|(name, value)| {
            let name = name.as_str();
            let value = if CREDENTIAL_HEADERS.contains(&name) {
                Cow::Borrowed(REDACTED.as_bytes())
            } else {
                redactor.redact(value.as_bytes())
            };
            (name, value)
        })
        .collect();
    lines.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = Vec::new();
    for (name, value) in lines {
        out.extend_from_slice(name.as_bytes());
        out.push(b':');
        out.extend_from_slice(&value);
        out.push(b'\n');
    }
    out
}

/// Provider request ids from response headers.
fn provider_request_ids(headers: &HeaderMap) -> Vec<(String, String)> {
    PROVIDER_REQUEST_ID_HEADERS
        .iter()
        .filter_map(|name| {
            let value = headers.get(*name)?.to_str().ok()?;
            let mut end = value.len().min(MAX_REQUEST_ID_LEN);
            while !value.is_char_boundary(end) {
                end = end.saturating_sub(1);
            }
            Some(((*name).to_owned(), value[..end].to_owned()))
        })
        .collect()
}

/// Everything needed to pre-commit one wire request, captured from the host
/// state so the durable append can be awaited without borrowing it.
pub(super) struct Precommit {
    sink: Arc<dyn HostAuditSink>,
    principal: PrincipalId,
    method: String,
    host: String,
    port: u16,
    commitment: RequestCommitment,
    redirect_hop: u32,
    injected_secrets: Vec<String>,
}

impl Precommit {
    fn event(&self) -> HostAuditEvent<'_> {
        HostAuditEvent::HttpRequest(HostHttpRequest {
            method: &self.method,
            host: &self.host,
            port: self.port,
            path_hash: self.commitment.path_hash,
            headers_hash: self.commitment.headers_hash,
            body_hash: self.commitment.body_hash,
            body_len: self.commitment.body_len,
            redirect_hop: self.redirect_hop,
            injected_secrets: &self.injected_secrets,
        })
    }

    /// Durably append the request entry, then return the exchange to
    /// complete once the response is known.
    pub(super) async fn commit(self) -> HttpExchange {
        let receipt = self.sink.commit(&self.principal, self.event()).await;
        HttpExchange {
            inner: Some(ExchangeInner {
                sink: self.sink,
                principal: self.principal,
                receipt,
                status: None,
                request_ids: Vec::new(),
                body: None,
            }),
        }
    }

    /// Record the request as refused before it was sent.
    pub(super) fn deny(self, reason: &str) {
        self.sink.record(
            &self.principal,
            self.event(),
            HostAuditOutcome::Denied(reason),
        );
    }
}

impl HostState {
    /// Capture the pre-commit for one wire request; `None` when no audit sink
    /// is installed.
    pub(super) fn http_precommit(
        &self,
        url: &reqwest::Url,
        method: &reqwest::Method,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        redirect_hop: u32,
        injected_secrets: &[String],
    ) -> Option<Precommit> {
        let sink = self.audit_sink.clone()?;
        let redactor = Redactor::new(self.revealed_secrets.iter());
        Some(Precommit {
            sink,
            principal: self.effective_principal(),
            method: method.as_str().to_owned(),
            host: url.host_str().unwrap_or_default().to_owned(),
            port: url.port_or_known_default().unwrap_or(0),
            commitment: RequestCommitment::compute(url, headers, body, &redactor),
            redirect_hop,
            injected_secrets: injected_secrets.to_vec(),
        })
    }
}

/// Running BLAKE3 over response body bytes.
#[derive(Default)]
struct BodyDigest {
    hasher: blake3::Hasher,
    len: u64,
}

struct ExchangeInner {
    sink: Arc<dyn HostAuditSink>,
    principal: PrincipalId,
    receipt: HostAuditReceipt,
    status: Option<u16>,
    request_ids: Vec<(String, String)>,
    body: Option<BodyDigest>,
}

impl ExchangeInner {
    fn emit(self, complete: bool, outcome: HostAuditOutcome<'_>) {
        let (body_hash, body_len) = self.body.as_ref().map_or((None, 0), |digest| {
            (
                Some(ContentHash::from_bytes(
                    *digest.hasher.finalize().as_bytes(),
                )),
                digest.len,
            )
        });
        self.sink.record(
            &self.principal,
            HostAuditEvent::HttpResponse(HostHttpResponse {
                request: &self.receipt,
                status: self.status,
                body_hash,
                body_len,
                complete,
                provider_request_ids: &self.request_ids,
            }),
            outcome,
        );
    }
}

/// Audit state of one wire request between its pre-commit and completion.
///
/// Dropping an exchange that was not finished records an incomplete,
/// failed completion, so a host call cancelled mid-flight still closes its
/// exchange on the log.
#[derive(Default)]
pub(crate) struct HttpExchange {
    inner: Option<ExchangeInner>,
}

impl HttpExchange {
    /// Note the response status and provider request ids.
    pub(super) fn observe_response(&mut self, response: &reqwest::Response) {
        if let Some(inner) = self.inner.as_mut() {
            inner.status = Some(response.status().as_u16());
            inner.request_ids = provider_request_ids(response.headers());
        }
    }

    /// Fold delivered body bytes into the response hash.
    pub(super) fn digest(&mut self, chunk: &[u8]) {
        if let Some(inner) = self.inner.as_mut() {
            let digest = inner.body.get_or_insert_with(BodyDigest::default);
            digest.hasher.update(chunk);
            digest.len = digest.len.saturating_add(chunk.len() as u64);
        }
    }

    /// Start the response hash without adding bytes, so an empty body still
    /// records the hash of empty input.
    pub(super) fn begin_body(&mut self) {
        self.digest(&[]);
    }

    /// Whether the exchange still awaits its completion record.
    pub(super) fn is_open(&self) -> bool {
        self.inner.is_some()
    }

    /// Record the completion. Later calls are no-ops.
    pub(super) fn finish(&mut self, complete: bool, outcome: HostAuditOutcome<'_>) {
        if let Some(inner) = self.inner.take() {
            inner.emit(complete, outcome);
        }
    }
}

impl Drop for HttpExchange {
    fn drop(&mut self) {
        self.finish(
            false,
            HostAuditOutcome::Failed("exchange ended before completion"),
        );
    }
}

impl std::fmt::Debug for HttpExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpExchange")
            .field("open", &self.is_open())
            .finish()
    }
}

/// Render an HTTP error code for a failed completion.
pub(super) fn error_text(error: &super::ErrorCode) -> String {
    format!("{error:?}")
}
