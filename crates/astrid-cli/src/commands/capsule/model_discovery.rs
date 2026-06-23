//! Live option discovery for dynamic `[env]` selects.
//!
//! A capsule's `[env]` field may declare `options-from` (see
//! [`astrid_capsule::manifest::OptionsFrom`]) to populate a SELECT from a
//! live HTTP endpoint — typically the provider's `/v1/models` — instead of
//! a static `enum_values` list. The fetch runs **here**, in the native
//! installer, because the CLI has network access; the sandboxed capsule
//! never makes the call.
//!
//! Resolution is best-effort by design. Every failure mode — network
//! error, non-2xx, non-JSON, empty list — degrades to a free-text prompt
//! at the call site. This module returns `Result`/`Option` accordingly and
//! never panics on a discovery miss.

use std::collections::HashMap;

use anyhow::Context;
use astrid_capsule::manifest::OptionsFrom;

/// Env key holding the user-configured provider location, by convention.
///
/// The `http` template references this field (e.g. `"{base_url}/v1/models"`),
/// so its value is the trust anchor for the credential-host binding in
/// [`should_send_bearer`]: the bearer is only attached when the resolved
/// fetch host matches the host of this value.
const PROVIDER_BASE_URL_KEY: &str = "base_url";

/// Maximum models-response body size, in bytes.
///
/// Caps an otherwise-unbounded `GET` over an operator-supplied (and thus
/// untrusted) endpoint. Matches the manifest-fetch streaming limit. An
/// over-limit body errors, which the caller maps to the free-text fallback.
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// Substitute `{key}` placeholders in `template` with values from `values`.
///
/// Unknown placeholders are left intact (the caller treats a still-templated
/// URL as a resolution failure). Substitution is single-pass and does not
/// recurse into substituted values.
pub(crate) fn resolve_template(template: &str, values: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in values {
        let pattern = format!("{{{key}}}");
        result = result.replace(&pattern, value);
    }
    result
}

/// Decide whether the `Authorization: Bearer` header may be attached to a
/// discovery `GET` of `http_url`, given the user-configured provider
/// `base_url`.
///
/// # Threat model
///
/// `options-from.http` and `options-from.bearer` are independent capsule-
/// supplied templates with no inherent host binding. Without this check a
/// malicious manifest could declare `http = "https://attacker.com"` and
/// `bearer = "{api_key}"`, exfiltrating the user's provider credential to
/// an arbitrary host the moment the installer resolves the field.
///
/// The bearer is therefore bound to the provider: it is attached **only**
/// when the resolved fetch host equals the host of the user-configured
/// `base_url` value the `http` template is built from. Host comparison is
/// case-insensitive (DNS is case-insensitive); port and scheme must match
/// exactly, so a downgrade or alternate-port redirect to the same hostname
/// does not leak the token. Any parse failure (either URL invalid, or
/// either lacking a host) fails closed — the bearer is withheld.
///
/// The legitimate openai / openai-compat case builds `http` from
/// `{base_url}`, so the hosts (and ports) are identical and the bearer is
/// sent as before.
pub(crate) fn should_send_bearer(http_url: &str, base_url: &str) -> bool {
    let Ok(http) = reqwest::Url::parse(http_url) else {
        return false;
    };
    let Ok(base) = reqwest::Url::parse(base_url) else {
        return false;
    };

    let (Some(http_host), Some(base_host)) = (http.host_str(), base.host_str()) else {
        return false;
    };

    // DNS hostnames are case-insensitive; ports must match exactly so that a
    // same-host redirect to a different port cannot smuggle the credential
    // to an unexpected listener. `port_or_known_default` folds the implicit
    // scheme default (443/80) into the comparison.
    http_host.eq_ignore_ascii_case(base_host)
        && http.port_or_known_default() == base.port_or_known_default()
}

/// Parse a provider models response into a deduped list of option ids.
///
/// `select_hint` names the JSON shape. Only the standard `OpenAI`
/// `data[].id` shape (`{ "data": [ { "id": "..." } ] }`) is recognised;
/// any other hint also falls back to `data[].id` so a typo degrades
/// gracefully rather than silently yielding nothing surprising.
///
/// Ids are returned in server order, de-duplicated (first occurrence
/// wins), with blank/whitespace-only ids dropped. A response whose
/// `data` is absent, not an array, or contains no usable ids yields an
/// empty list — the caller treats that as a discovery miss.
pub(crate) fn parse_options_response(body: &str, select_hint: &str) -> Vec<String> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };

    // The only supported shape is `data[].id`. We accept the documented
    // hint (and treat anything else as the default) rather than building a
    // general JSONPath engine — the contract is the OpenAI models list.
    let _ = select_hint; // shape is fixed; hint reserved for future shapes.

    let Some(data) = json.get("data").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };

    let mut seen = std::collections::HashSet::new();
    let mut ids = Vec::new();
    for entry in data {
        let Some(id) = entry.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let id = id.trim();
        if id.is_empty() {
            continue;
        }
        if seen.insert(id.to_string()) {
            ids.push(id.to_string());
        }
    }
    ids
}

/// Resolve the live option list for a dynamic-select field.
///
/// Substitutes `values` into the `http`/`bearer` templates, performs a
/// `GET`, and parses the response. The `Authorization: Bearer` header is
/// sent only when `bearer` resolves to a non-empty value after trimming
/// **and** the resolved fetch host matches the host of the user-configured
/// provider `base_url` (see [`should_send_bearer`]) — so a capsule cannot
/// exfiltrate the credential to an arbitrary host. The response body is
/// capped at [`MAX_RESPONSE_BYTES`].
///
/// Returns `Ok(non_empty_options)` on success, or `Err` on any failure
/// (unresolved template, network error, non-2xx, oversized body, non-JSON,
/// empty list). The caller maps `Err` to a free-text fallback.
pub(crate) async fn fetch_options(
    opts: &OptionsFrom,
    values: &HashMap<String, String>,
) -> anyhow::Result<Vec<String>> {
    let url = resolve_template(&opts.http, values);
    anyhow::ensure!(
        !url.contains('{'),
        "endpoint still contains unresolved placeholders: {url}"
    );
    anyhow::ensure!(
        url.starts_with("http://") || url.starts_with("https://"),
        "endpoint is not an http(s) URL: {url}"
    );

    let bearer = opts
        .bearer
        .as_ref()
        .map(|b| resolve_template(b, values))
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty());

    // Bind the credential to the configured provider host. A capsule's
    // `http`/`bearer` are independent templates with no inherent host
    // binding, so without this check a manifest could point `http` at an
    // attacker host while still resolving `bearer` to the user's API key.
    // The bearer is attached only when the resolved fetch host matches the
    // host of the user-configured `base_url`; otherwise it is withheld (the
    // request will most likely 401 and fall back to free-text — the correct
    // safe outcome).
    let bearer = bearer.filter(|_| match values.get(PROVIDER_BASE_URL_KEY) {
        Some(base_url) if should_send_bearer(&url, base_url) => true,
        _ => {
            tracing::warn!(
                endpoint = %url,
                "withholding options-from bearer: fetch host does not match the \
                 configured provider ({PROVIDER_BASE_URL_KEY}) host"
            );
            false
        },
    });

    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let mut request = client.get(&url);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }

    let response = request.send().await?;
    anyhow::ensure!(
        response.status().is_success(),
        "models endpoint returned HTTP {}",
        response.status()
    );

    // Cap the body: the endpoint is operator-supplied and otherwise
    // unbounded. Reject up-front on an advertised over-limit length so a
    // hostile `Content-Length` can't force a large buffer, then bound the
    // actual bytes read (the header is advisory and may be absent/lying for
    // a chunked response). An over-limit response errors → free-text
    // fallback.
    anyhow::ensure!(
        response
            .content_length()
            .is_none_or(|len| len <= MAX_RESPONSE_BYTES as u64),
        "models response too large (advertised {} bytes; limit {MAX_RESPONSE_BYTES})",
        response.content_length().unwrap_or_default()
    );
    let body = response.bytes().await?;
    let body = decode_capped_body(&body)?;
    let options = parse_options_response(&body, opts.select_or_default());
    anyhow::ensure!(
        !options.is_empty(),
        "models endpoint returned no usable options"
    );
    Ok(options)
}

/// Bound a fetched response body and decode it as UTF-8.
///
/// Rejects a body larger than [`MAX_RESPONSE_BYTES`] (the operator-supplied
/// endpoint is otherwise unbounded) and any non-UTF-8 payload. Errors map
/// to the free-text fallback at the call site.
fn decode_capped_body(body: &[u8]) -> anyhow::Result<String> {
    anyhow::ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "models response too large ({} bytes; limit {MAX_RESPONSE_BYTES})",
        body.len()
    );
    String::from_utf8(body.to_vec()).context("models response was not valid UTF-8")
}

/// Synchronous bridge to [`fetch_options`] for the blocking install-prompt
/// path.
///
/// The env-prompt routine reads stdin synchronously and is called from
/// both sync and async contexts. Rather than colour that whole chain
/// async, the one short HTTP discovery call runs on a fresh
/// current-thread runtime on a dedicated OS thread, so it never touches —
/// or risks deadlocking — the ambient runtime. The thread is joined
/// before returning, keeping the prompt strictly sequential.
///
/// Returns `Err` on any failure (mirroring [`fetch_options`]); the caller
/// maps that to a free-text fallback.
pub(crate) fn fetch_options_blocking(
    opts: &OptionsFrom,
    values: &HashMap<String, String>,
) -> anyhow::Result<Vec<String>> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("failed to build discovery runtime")?;
                runtime.block_on(fetch_options(opts, values))
            })
            .join()
            .map_err(|_| anyhow::anyhow!("model discovery thread panicked"))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vals(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn resolve_template_substitutes_known_keys() {
        let v = vals(&[("base_url", "https://api.openai.com"), ("api_key", "sk-x")]);
        assert_eq!(
            resolve_template("{base_url}/v1/models", &v),
            "https://api.openai.com/v1/models"
        );
        assert_eq!(resolve_template("{api_key}", &v), "sk-x");
    }

    #[test]
    fn resolve_template_leaves_unknown_keys() {
        let v = vals(&[("known", "x")]);
        assert_eq!(
            resolve_template("{known}/{unknown}", &v),
            "x/{unknown}",
            "unresolved placeholder must remain so the caller can detect the miss"
        );
    }

    #[test]
    fn parse_extracts_ids_in_server_order() {
        let body = r#"{ "data": [ { "id": "gpt-4o" }, { "id": "gpt-4o-mini" }, { "id": "o1" } ] }"#;
        assert_eq!(
            parse_options_response(body, "data[].id"),
            vec!["gpt-4o", "gpt-4o-mini", "o1"]
        );
    }

    #[test]
    fn parse_dedupes_preserving_first_occurrence() {
        let body = r#"{ "data": [ { "id": "a" }, { "id": "b" }, { "id": "a" } ] }"#;
        assert_eq!(parse_options_response(body, "data[].id"), vec!["a", "b"]);
    }

    #[test]
    fn parse_drops_blank_and_missing_ids() {
        let body = r#"{ "data": [ { "id": "  " }, { "id": "real" }, { "name": "no-id" }, { "id": "" } ] }"#;
        assert_eq!(parse_options_response(body, "data[].id"), vec!["real"]);
    }

    #[test]
    fn parse_unknown_hint_falls_back_to_data_id() {
        let body = r#"{ "data": [ { "id": "m1" } ] }"#;
        // A typo'd / unknown hint still parses the canonical shape.
        assert_eq!(parse_options_response(body, "models[].name"), vec!["m1"]);
    }

    #[test]
    fn parse_returns_empty_on_non_json() {
        assert!(parse_options_response("<html>not json</html>", "data[].id").is_empty());
    }

    #[test]
    fn parse_returns_empty_on_missing_data() {
        assert!(parse_options_response(r#"{ "object": "list" }"#, "data[].id").is_empty());
    }

    #[test]
    fn parse_returns_empty_when_data_not_array() {
        assert!(parse_options_response(r#"{ "data": "oops" }"#, "data[].id").is_empty());
    }

    #[tokio::test]
    async fn fetch_rejects_unresolved_template_before_network() {
        // base_url is not provided → the URL keeps a `{...}` placeholder,
        // so resolution fails fast (no network) and the caller falls back.
        let opts = OptionsFrom {
            http: "{base_url}/v1/models".to_string(),
            bearer: None,
            select: None,
            after: vec!["base_url".to_string()],
        };
        let err = fetch_options(&opts, &HashMap::new())
            .await
            .expect_err("unresolved placeholder must error");
        assert!(
            err.to_string().contains("unresolved placeholder"),
            "got: {err}"
        );
    }

    #[test]
    fn bearer_sent_when_fetch_host_matches_configured_provider() {
        // The legitimate openai / openai-compat case: `http` is built from
        // `{base_url}`, so the hosts (and default port) match → bearer sent.
        assert!(should_send_bearer(
            "https://api.openai.com/v1/models",
            "https://api.openai.com"
        ));
        // Case-insensitive host compare (DNS is case-insensitive).
        assert!(should_send_bearer(
            "https://API.OpenAI.com/v1/models",
            "https://api.openai.com"
        ));
        // Explicit matching port also passes.
        assert!(should_send_bearer(
            "https://provider.example:8443/v1/models",
            "https://provider.example:8443"
        ));
    }

    #[test]
    fn bearer_withheld_when_fetch_host_differs_from_provider() {
        // Credential-exfiltration guard: a capsule whose `http` points at a
        // foreign host must NOT receive the bearer, even though `bearer`
        // would resolve to the user's key. This is the regression for the
        // `http = "https://attacker.com"` + `bearer = "{api_key}"` attack.
        assert!(!should_send_bearer(
            "https://attacker.com/v1/models",
            "https://api.openai.com"
        ));
        // Subdomain is a different host — no match.
        assert!(!should_send_bearer(
            "https://api.openai.com.attacker.com/v1/models",
            "https://api.openai.com"
        ));
        // Same host, different explicit port → withheld (can't smuggle the
        // token to an unexpected listener on the configured hostname).
        assert!(!should_send_bearer(
            "https://api.openai.com:8443/v1/models",
            "https://api.openai.com"
        ));
        // Scheme downgrade to the same host → different default port → no.
        assert!(!should_send_bearer(
            "http://api.openai.com/v1/models",
            "https://api.openai.com"
        ));
    }

    #[test]
    fn bearer_withheld_when_either_url_is_unparseable() {
        // Fail closed: an invalid base_url or http URL must never send the
        // credential.
        assert!(!should_send_bearer(
            "https://api.openai.com/v1/models",
            "not a url"
        ));
        assert!(!should_send_bearer("not a url", "https://api.openai.com"));
        // A scheme without a host (mailto:, data:) has no host to bind to.
        assert!(!should_send_bearer(
            "https://api.openai.com/v1/models",
            "mailto:ops@example.com"
        ));
    }

    #[test]
    fn capped_body_decodes_within_limit() {
        let body = br#"{ "data": [ { "id": "gpt-4o" } ] }"#;
        let decoded = decode_capped_body(body).expect("within-limit body must decode");
        assert!(decoded.contains("gpt-4o"));
    }

    #[test]
    fn capped_body_rejects_over_limit() {
        // DoS guard: an over-cap body must error → free-text fallback.
        let oversized = vec![b'x'; MAX_RESPONSE_BYTES + 1];
        let err = decode_capped_body(&oversized).expect_err("over-cap body must error");
        assert!(err.to_string().contains("too large"), "got: {err}");
        // Exactly at the limit is allowed.
        let at_limit = vec![b'x'; MAX_RESPONSE_BYTES];
        assert!(decode_capped_body(&at_limit).is_ok());
    }

    #[tokio::test]
    async fn fetch_rejects_non_http_endpoint() {
        let opts = OptionsFrom {
            http: "file:///etc/passwd".to_string(),
            bearer: None,
            select: None,
            after: vec![],
        };
        let err = fetch_options(&opts, &HashMap::new())
            .await
            .expect_err("non-http endpoint must error");
        assert!(err.to_string().contains("not an http"), "got: {err}");
    }
}
