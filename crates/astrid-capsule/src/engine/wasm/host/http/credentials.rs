//! Host-side credential injection for outbound HTTP.
//!
//! A capsule names a secret in a request header value with the placeholder
//! `{{secret:NAME}}` — for example `Authorization: Bearer {{secret:api_key}}`
//! — instead of reading the secret with `get_config` and setting the header
//! itself. The host substitutes the value when it builds the wire request,
//! so the secret never enters guest memory and is never part of an audit
//! commitment (which is computed over the placeholder form).
//!
//! Rules:
//!
//! - Only request header values are substituted; placeholders in the URL or
//!   body are sent as written.
//! - `NAME` must be a secret-typed `[env]` key declared in the capsule's
//!   manifest (`type = "secret"`). Any other name refuses the request with
//!   `capability-denied`. The value is resolved like `get_config`: the
//!   invoking principal's scope first, then the host-wide scope.
//! - Surrounding whitespace is trimmed from the value. When a named secret is
//!   unset or blank, the header is omitted, so a keyless provider receives no
//!   credential header.
//! - Injection happens only toward the origin of the capsule's request: on a
//!   cross-origin redirect every header carrying a placeholder is dropped,
//!   together with `Authorization` and `Cookie`.
//! - The injected names (never values) are recorded on the `HttpRequest`
//!   audit entry.

use reqwest::header::{HeaderMap, HeaderValue};
use zeroize::Zeroizing;

use super::ErrorCode;
use crate::engine::wasm::host_state::HostState;

/// Opening of a secret placeholder in a header value.
const OPEN: &[u8] = b"{{secret:";
/// Closing of a secret placeholder.
const CLOSE: &[u8] = b"}}";

/// A request's wire headers after injection.
pub(super) struct Injected {
    /// Headers to send, with placeholders replaced by secret values.
    pub(super) headers: HeaderMap,
    /// Names of the injected secrets, in first-use order, without repeats.
    pub(super) names: Vec<String>,
}

/// Why injection refused a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum InjectError {
    /// A placeholder is malformed.
    Malformed,
    /// A placeholder names a secret the manifest does not declare.
    Undeclared(String),
    /// The resolved value cannot be sent in a header.
    InvalidValue,
}

impl InjectError {
    pub(super) fn code(&self) -> ErrorCode {
        match self {
            Self::Undeclared(_) => ErrorCode::CapabilityDenied,
            Self::Malformed | Self::InvalidValue => ErrorCode::InvalidRequest,
        }
    }
}

/// Whether a header value contains a secret placeholder.
pub(super) fn has_placeholder(value: &HeaderValue) -> bool {
    find(value.as_bytes(), OPEN).is_some()
}

/// Remove every header that carries a secret placeholder (used on a
/// cross-origin redirect).
pub(super) fn strip_injected(headers: &mut HeaderMap) {
    let names: Vec<_> = headers
        .iter()
        .filter(|(_, value)| has_placeholder(value))
        .map(|(name, _)| name.clone())
        .collect();
    for name in names {
        headers.remove(name);
    }
}

impl HostState {
    /// Substitute secret placeholders in `template`. Headers without a
    /// placeholder are passed through unchanged.
    pub(super) fn inject_credentials(&self, template: &HeaderMap) -> Result<Injected, InjectError> {
        substitute_headers(template, |name| {
            if !self.secret_env.contains(name) {
                return Err(InjectError::Undeclared(name.to_owned()));
            }
            Ok(Zeroizing::new(super::super::sys::resolve_secret(
                self, name,
            )))
        })
    }
}

/// Substitute placeholders in every header value using `resolve`.
pub(super) fn substitute_headers(
    template: &HeaderMap,
    mut resolve: impl FnMut(&str) -> Result<Zeroizing<String>, InjectError>,
) -> Result<Injected, InjectError> {
    let mut headers = HeaderMap::with_capacity(template.len());
    let mut names: Vec<String> = Vec::new();
    for (name, value) in template {
        if !has_placeholder(value) {
            headers.append(name.clone(), value.clone());
            continue;
        }
        let Some(bytes) = substitute(value.as_bytes(), &mut resolve, &mut names)? else {
            // A named secret is unset: omit the header.
            continue;
        };
        let mut value = HeaderValue::from_bytes(&bytes).map_err(|_| InjectError::InvalidValue)?;
        value.set_sensitive(true);
        headers.append(name.clone(), value);
    }
    Ok(Injected { headers, names })
}

/// Replace every placeholder in one header value. `None` when a named secret
/// is unset or blank. Every placeholder is parsed and resolved first, so a
/// blank secret never hides a malformed or undeclared one after it.
fn substitute(
    value: &[u8],
    resolve: &mut impl FnMut(&str) -> Result<Zeroizing<String>, InjectError>,
    names: &mut Vec<String>,
) -> Result<Option<Zeroizing<Vec<u8>>>, InjectError> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut used: Vec<&str> = Vec::new();
    let mut blank = false;
    let mut rest = value;
    while let Some(start) = find(rest, OPEN) {
        out.extend_from_slice(&rest[..start]);
        let after_open = &rest[start.saturating_add(OPEN.len())..];
        let end = find(after_open, CLOSE).ok_or(InjectError::Malformed)?;
        let name = std::str::from_utf8(&after_open[..end]).map_err(|_| InjectError::Malformed)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(InjectError::Malformed);
        }
        let secret = resolve(name)?;
        let secret = secret.trim();
        blank |= secret.is_empty();
        if !used.contains(&name) {
            used.push(name);
        }
        out.extend_from_slice(secret.as_bytes());
        rest = &after_open[end.saturating_add(CLOSE.len())..];
    }
    if blank {
        return Ok(None);
    }
    for name in used {
        if !names.iter().any(|known| known == name) {
            names.push(name.to_owned());
        }
    }
    out.extend_from_slice(rest);
    Ok(Some(out))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
