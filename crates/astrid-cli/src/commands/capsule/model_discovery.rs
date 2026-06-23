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
/// sent only when `bearer` resolves to a non-empty value after trimming.
///
/// Returns `Ok(non_empty_options)` on success, or `Err` on any failure
/// (unresolved template, network error, non-2xx, non-JSON, empty list).
/// The caller maps `Err` to a free-text fallback.
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

    let body = response.text().await?;
    let options = parse_options_response(&body, opts.select_or_default());
    anyhow::ensure!(
        !options.is_empty(),
        "models endpoint returned no usable options"
    );
    Ok(options)
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
