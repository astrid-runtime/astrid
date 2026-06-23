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
use std::sync::LazyLock;

use anyhow::Context;
use astrid_capsule::manifest::OptionsFrom;
use regex::Regex;

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
/// untrusted) endpoint. A typical `/v1/models` response is KB-scale; the cap
/// exists to stop a hostile or broken endpoint from OOM-ing the installer.
/// 5 MB is generous enough to accommodate the largest legitimate catalogs
/// (large aggregators listing hundreds of models with metadata) without
/// clipping them to the free-text fallback, while still bounding the OOM
/// vector. An over-limit body errors, which the caller maps to the free-text
/// fallback.
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;

/// Matches a single `{key}` placeholder, capturing the bare key.
///
/// `\w+` deliberately excludes `{`/`}`, so a placeholder cannot span another
/// brace and substring keys (`{api}` vs `{api_key}`) are matched whole.
static PLACEHOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{(\w+)\}").expect("static placeholder regex is valid"));

/// Substitute `{key}` placeholders in `template` with values from `values`.
///
/// A single deterministic left-to-right pass over the `{key}` placeholders:
/// each placeholder is replaced by its mapped value, and an unknown key is
/// left intact (the caller treats a still-templated URL as a resolution
/// failure). Because the scan is over the original template — not the
/// growing result — map iteration order is irrelevant and a substituted
/// value can never itself be re-scanned, so substring keys (e.g. `{api}` vs
/// `{api_key}`) and credential values containing `{...}` cannot corrupt the
/// output.
pub(crate) fn resolve_template(template: &str, values: &HashMap<String, String>) -> String {
    PLACEHOLDER
        .replace_all(template, |caps: &regex::Captures<'_>| {
            let key = &caps[1];
            match values.get(key) {
                // Leave an unknown placeholder verbatim so the caller can
                // detect the miss. `caps[0]` is the full `{key}` match.
                Some(value) => value.clone(),
                None => caps[0].to_string(),
            }
        })
        .into_owned()
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
/// when the resolved fetch URL has the same scheme, host, and port as the
/// user-configured `base_url` value the `http` template is built from. Host
/// comparison is case-insensitive (DNS is case-insensitive); scheme and port
/// must match exactly, so a cleartext `http://` downgrade of an `https://`
/// `base_url` — even on the same host and the same explicit port (e.g.
/// `http://provider:443` vs `https://provider`) — or an alternate-port
/// redirect does not leak the token. Any parse failure (either URL invalid,
/// or either lacking a host) fails closed — the bearer is withheld.
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

    // Scheme must match exactly: an `http://` downgrade of an `https://`
    // base_url must never carry the bearer, even on the same host and the
    // same explicit port — otherwise `http://provider:443` would tunnel the
    // credential in cleartext. `Url::scheme` is already lowercased.
    if http.scheme() != base.scheme() {
        return false;
    }

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
    // hostile `Content-Length` can't even start a large transfer (fast
    // path), then stream-read with the same bound so an absent/lying length
    // (e.g. a chunked response with no `Content-Length`) cannot OOM the
    // installer either. An over-limit response errors → free-text fallback.
    anyhow::ensure!(
        response
            .content_length()
            .is_none_or(|len| len <= MAX_RESPONSE_BYTES as u64),
        "models response too large (advertised {} bytes; limit {MAX_RESPONSE_BYTES})",
        response.content_length().unwrap_or_default()
    );
    let body = read_capped_body(response).await?;
    let options = parse_options_response(&body, opts.select_or_default());
    anyhow::ensure!(
        !options.is_empty(),
        "models endpoint returned no usable options"
    );
    Ok(options)
}

/// Stream the response body into memory under a hard [`MAX_RESPONSE_BYTES`]
/// cap, then decode it as UTF-8.
///
/// The body is accumulated chunk-by-chunk and the running total is checked
/// **before** each chunk is appended, so the buffer never exceeds the cap
/// (the transfer is aborted the moment the next chunk would cross it). This
/// is the streaming guard the up-front `Content-Length` check cannot
/// provide: a chunked / unknown-length (or lying-`Content-Length`) response
/// is bounded by the bytes actually read, not by an advisory header.
///
/// Rejects an over-cap body and any non-UTF-8 payload; both errors map to
/// the free-text fallback at the call site.
async fn read_capped_body(response: reqwest::Response) -> anyhow::Result<String> {
    use futures::StreamExt;

    let mut stream = response.bytes_stream();
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("error reading models response body")?;
        // Check before appending so we never hold more than the cap plus the
        // tail of one already-received chunk. The moment the total would
        // exceed the limit we abort — the rest of the stream is dropped.
        anyhow::ensure!(
            body.len().saturating_add(chunk.len()) <= MAX_RESPONSE_BYTES,
            "models response too large (exceeded {MAX_RESPONSE_BYTES} bytes; aborted mid-stream)"
        );
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).context("models response was not valid UTF-8")
}

/// Bound an in-memory body and decode it as UTF-8 (test helper for the
/// streaming guard's cap/decoding logic).
///
/// Rejects a body larger than [`MAX_RESPONSE_BYTES`] and any non-UTF-8
/// payload — the same invariants [`read_capped_body`] enforces while
/// streaming.
#[cfg(test)]
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
    fn resolve_template_substring_keys_are_order_independent() {
        // Regression: a naive HashMap-iteration string-replace could match
        // `{api}` inside `{api_key}` (or vice versa) depending on map order,
        // corrupting the result. The single regex pass replaces each whole
        // placeholder exactly once, so the output is identical regardless of
        // which key the map happens to yield first.
        let template = "{base_url}?a={api}&k={api_key}";
        let expected = "https://h?a=AAA&k=KKK";

        // Build the same logical map twice; insertion order differs but the
        // result must not.
        let mut v1 = HashMap::new();
        v1.insert("api".to_string(), "AAA".to_string());
        v1.insert("api_key".to_string(), "KKK".to_string());
        v1.insert("base_url".to_string(), "https://h".to_string());

        let mut v2 = HashMap::new();
        v2.insert("api_key".to_string(), "KKK".to_string());
        v2.insert("base_url".to_string(), "https://h".to_string());
        v2.insert("api".to_string(), "AAA".to_string());

        assert_eq!(resolve_template(template, &v1), expected);
        assert_eq!(resolve_template(template, &v2), expected);
    }

    #[test]
    fn resolve_template_does_not_rescan_substituted_value() {
        // A substituted value that itself contains a `{key}` sequence must
        // NOT be re-expanded — the scan is over the original template only.
        let v = vals(&[("base_url", "https://h/{api_key}"), ("api_key", "secret")]);
        assert_eq!(
            resolve_template("{base_url}/v1", &v),
            "https://h/{api_key}/v1"
        );
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
        // Scheme downgrade to the same host (implicit ports) → withheld.
        assert!(!should_send_bearer(
            "http://api.openai.com/v1/models",
            "https://api.openai.com"
        ));
        // Scheme-downgrade smuggle: same host, same *explicit* port 443, but
        // `http` vs `https`. Port-only matching (`port_or_known_default`)
        // would have folded these to 443 and leaked the bearer in cleartext;
        // the scheme check withholds it. This is the FIX B regression.
        assert!(!should_send_bearer(
            "http://api.openai.com:443/v1/models",
            "https://api.openai.com"
        ));
        // And the reverse: https fetch against an http-configured base_url.
        assert!(!should_send_bearer(
            "https://api.openai.com:80/v1/models",
            "http://api.openai.com"
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
        // The cap is 5 MB: generous for large aggregator `/v1/models`
        // catalogs, while still bounding the OOM vector.
        assert_eq!(MAX_RESPONSE_BYTES, 5 * 1024 * 1024);

        // DoS guard: an over-cap body (one byte past 5 MB) must error →
        // free-text fallback.
        let oversized = vec![b'x'; MAX_RESPONSE_BYTES + 1];
        let err = decode_capped_body(&oversized).expect_err("over-cap body must error");
        assert!(err.to_string().contains("too large"), "got: {err}");
        // A within-limit body (exactly at 5 MB) is allowed.
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

    #[tokio::test]
    async fn fetch_rejects_oversized_chunked_body_without_buffering_it_all() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Regression for FIX A: a chunked response with NO Content-Length
        // must be rejected by the streaming guard the moment the running
        // total crosses the cap — never buffered whole. We prove this two
        // ways: the fetch errors with "too large", AND the server is never
        // required to send the full oversized payload (the client drops the
        // connection mid-stream, so far fewer than `MAX_RESPONSE_BYTES`
        // bytes leave the server before it gives up).
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        // Bytes the server actually managed to write to the socket. If the
        // streaming guard aborts early, the client closes the connection and
        // the server's writes start failing well before the full payload is
        // sent.
        let sent = Arc::new(AtomicUsize::new(0));
        let sent_srv = Arc::clone(&sent);

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            // Drain the request line/headers (best-effort; we don't parse).
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;

            // Chunked response, deliberately NO Content-Length, so only the
            // streaming guard can bound it.
            let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
            if sock.write_all(head).await.is_err() {
                return;
            }

            // Each chunk is 64 KiB of payload, framed in HTTP/1.1 chunked
            // encoding (`<hex-len>\r\n<data>\r\n`). Send far more than the
            // cap; the client should bail long before we finish.
            let chunk_payload = vec![b'x'; 64 * 1024];
            let frame_header = format!("{:x}\r\n", chunk_payload.len());
            // Cap how many chunks we even attempt so a buggy guard (that
            // buffers everything) still terminates the test rather than
            // looping forever — but we attempt comfortably more than the cap.
            let max_chunks = (MAX_RESPONSE_BYTES / chunk_payload.len()) + 16;
            for _ in 0..max_chunks {
                if sock.write_all(frame_header.as_bytes()).await.is_err() {
                    break;
                }
                if sock.write_all(&chunk_payload).await.is_err() {
                    break;
                }
                if sock.write_all(b"\r\n").await.is_err() {
                    break;
                }
                sent_srv.fetch_add(chunk_payload.len(), Ordering::SeqCst);
            }
            let _ = sock.write_all(b"0\r\n\r\n").await;
        });

        let opts = OptionsFrom {
            http: format!("http://127.0.0.1:{port}/v1/models"),
            bearer: None,
            select: None,
            after: vec![],
        };
        let err = fetch_options(&opts, &HashMap::new())
            .await
            .expect_err("oversized chunked body must error");
        assert!(
            err.to_string().contains("too large"),
            "expected a size-cap error, got: {err}"
        );

        // Let the server observe the dropped connection and stop.
        let _ = server.await;

        // Non-buffering proof: the server could not push the whole oversized
        // payload through — the client aborted mid-stream. We allow a
        // generous slack for socket/TCP buffering (a few hundred KiB in
        // flight), but it must be far below a second full cap's worth.
        let total_sent = sent.load(Ordering::SeqCst);
        assert!(
            total_sent < MAX_RESPONSE_BYTES + 4 * 1024 * 1024,
            "server sent {total_sent} bytes; client did not abort the stream early enough"
        );
    }
}
