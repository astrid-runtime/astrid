//! `/api/capsules` — capsule introspection + install.
//!
//! The dashboard's "available capsules" view: list, detail,
//! declared topics, install (forward-compatible).
//!
//! ## Permission surface
//!
//! `POST /api/capsules` exists today, gated by the existing
//! `capsule:install` capability that's already in
//! `astrid_core::capability_grammar::KNOWN_CAPABILITIES` and the
//! kernel's `required_capability` table. Enterprise admins can
//! grant the cap to a group right now (e.g. a
//! `capsule-installers` group with
//! `caps: ["capsule:install"]`); the kernel's cap-gate enforces
//! it before the handler runs.
//!
//! The kernel-side `InstallCapsule` handler is fully implemented
//! (`kernel_router/install.rs`): it unpacks a `.capsule` archive (or
//! installs from a directory containing `Capsule.toml`), content-
//! addresses the WASM/WIT, runs lifecycle hooks, and hot-loads the
//! result. It is deliberately **path-only** — the daemon never fetches
//! URLs. So the gateway resolves GitHub-shaped sources HERE (it is an
//! uplink, the same role the CLI plays): it downloads the `.capsule`
//! release asset to a local temp file and then calls the kernel handler
//! with that local path. Local-path and arbitrary-URL sources are
//! forwarded verbatim; the kernel installs the former and rejects the
//! latter.
//!
//! Routes:
//!
//! * `GET  /api/capsules` — list of capsule ids
//! * `POST /api/capsules` — install (cap-gated; GitHub sources resolved in the gateway)
//! * `GET  /api/capsules/{id}` — manifest excerpt (env defs, etc.)
//! * `GET  /api/capsules/{id}/topics` — declared `TopicDef` entries

use std::sync::Arc;
use std::time::Duration;

use astrid_capsule_install::github_source;
use astrid_core::kernel_api::{CapsuleMetadataEntry, KernelRequest, KernelResponse};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::Request;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CapsuleListResponse {
    pub capsules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CapsuleDetail {
    pub id: String,
    /// Interceptor event patterns declared by the capsule.
    pub interceptor_events: Vec<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CapsuleTopic {
    pub name: String,
    pub direction: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CapsuleTopicsResponse {
    pub topics: Vec<CapsuleTopic>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct InstallRequest {
    /// Source path or package locator. GitHub-shaped sources
    /// (`@org/repo`, `github.com/org/repo`,
    /// `https://github.com/org/repo`) are resolved **by the gateway**:
    /// it downloads the matching `.capsule` release asset to a local
    /// archive and hands the kernel that local path. A local path —
    /// either a directory containing `Capsule.toml` or a `*.capsule`
    /// archive — is forwarded verbatim and interpreted on the daemon
    /// host. Arbitrary non-GitHub URLs (`http(s)://…`, `gh:`) are
    /// forwarded verbatim and rejected kernel-side; the daemon never
    /// fetches URLs.
    pub source: String,
    /// `true` to install into the caller's CWD/workspace-local capsule slot.
    /// Always rejected kernel-side when called via this route — the daemon has
    /// no meaningful CWD. Ignored (forced `false`) for gateway-resolved GitHub
    /// sources.
    #[serde(default)]
    pub workspace: bool,
    /// Optional capsule name selector for a multi-capsule GitHub release
    /// (one `.capsule` asset per capsule). Mirrors the CLI's `--capsule`.
    /// Ignored for local-path sources.
    #[serde(default)]
    pub capsule: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/capsules",
    tag = "capsules",
    responses(
        (status = 200, body = CapsuleListResponse, description = "Loaded capsule ids."),
        (status = 401, body = ErrorBody),
    )
)]
pub async fn list_capsules(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<CapsuleListResponse>> {
    let caller = caller_from(&req)?.clone();
    let client = state.kernel_client_for(&caller)?;
    let resp = client
        .request(KernelRequest::ListCapsules)
        .await
        .map_err(daemon_internal)?;
    match resp {
        // `ListCapsules` returns `KernelResponse::Success(JsonArray)`
        // (kernel_router/mod.rs handler) — a list of capsule-id
        // strings serialised straight into a JSON array. Project
        // that into the typed envelope for the dashboard.
        KernelResponse::Success(v) => {
            let capsules: Vec<String> = serde_json::from_value(v)
                .map_err(|e| internal(format!("malformed capsule list: {e}")))?;
            Ok(Json(CapsuleListResponse { capsules }))
        },
        KernelResponse::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(internal(format!(
            "unexpected response shape for ListCapsules: {other:?}"
        ))),
    }
}

/// `POST /api/capsules` — install a capsule. Cap-gated by
/// `capsule:install` (or `self:capsule:install` for self-scope) at
/// the kernel boundary.
///
/// GitHub-shaped sources are resolved **in the gateway** (it is an
/// uplink, like the CLI): the gateway downloads the chosen `.capsule`
/// release asset to a local temp file and hands the kernel that local
/// path. Local paths and arbitrary URLs are forwarded verbatim — the
/// kernel installs the former and rejects the latter; the daemon never
/// fetches.
///
/// The gateway intentionally implements a **narrower** GitHub path than
/// the CLI: the CLI additionally falls back to clone-and-build, auto-
/// builds a local Cargo directory, and installs every asset of a multi-
/// capsule release ("install all"). The gateway does **none** of those.
/// It requires resolving to exactly one `.capsule` — a release with a
/// single `.capsule` asset, or one selected via the `capsule` field.
#[utoipa::path(
    post,
    path = "/api/capsules",
    tag = "capsules",
    request_body = InstallRequest,
    responses(
        (status = 200, description = "Install completed; body is the `InstallOutput` JSON shape: `{ target_dir, phase, installed_version, previous_version?, wasm_hash?, env_path, env_needs_prompt, missing_imports[], export_conflicts[] }`. May instead be `{ status: 'approval_required', request_id, description, capabilities }` when the kernel needs operator sign-off on dangerous capabilities the capsule declares.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Surfaces every kernel-side `InstallCapsule` failure: capability denial, a non-GitHub URL or `workspace` flag the kernel rejects, AND install/validation failures (missing path, malformed archive, lifecycle-hook error). The kernel returns an undifferentiated error string, so these are not split into distinct status codes here."),
        (status = 404, body = ErrorBody, description = "GitHub release or .capsule asset not found."),
        (status = 400, body = ErrorBody, description = "Ambiguous multi-capsule release (specify `capsule`), or archive too large."),
    )
)]
pub async fn install_capsule(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let body: InstallRequest = crate::routes::principals::read_json_body(req).await?;

    // GitHub-shaped sources are resolved HERE (the gateway is an
    // uplink). Everything else — a local path, or an arbitrary URL —
    // is forwarded verbatim; the kernel installs on-disk paths and
    // rejects URLs, so the daemon never fetches.
    //
    // SSRF note: only GitHub-shaped sources are ever fetched, and the
    // download URL comes from GitHub's own release API for the named
    // repo — the gateway never fetches an attacker-supplied arbitrary
    // URL. An arbitrary `https://…` is NOT GitHub-shaped, so it falls
    // into the else-branch and is rejected by the kernel.
    let (source, workspace, _tmp) =
        if let Some((org, repo)) = github_source::parse_github_source(&body.source) {
            let resolved = resolve_github_source(&org, &repo, body.capsule.as_deref()).await?;
            // The temp dir guard MUST outlive the kernel request below —
            // the kernel reads the archive off disk during the request.
            (resolved.path, false, Some(resolved.guard))
        } else {
            (body.source, body.workspace, None)
        };

    let client = state.kernel_client_for(&caller)?;
    let resp = client
        .request(KernelRequest::InstallCapsule { source, workspace })
        .await
        .map_err(daemon_internal)?;
    match resp {
        KernelResponse::Success(v) => Ok(Json(v)),
        // `ApprovalRequired` is the kernel's way of saying "this
        // capsule wants caps the operator needs to OK out-of-band."
        // Pass it through with structured fields so the dashboard
        // can render the approval prompt rather than treating it
        // as a generic error.
        KernelResponse::ApprovalRequired {
            request_id,
            description,
            capabilities,
        } => Ok(Json(serde_json::json!({
            "status": "approval_required",
            "request_id": request_id,
            "description": description,
            "capabilities": capabilities,
        }))),
        // The kernel returns `Error` for cap-denied (the cap-gate
        // refused), a rejected non-GitHub URL, or an install failure
        // (bad archive, missing path, lifecycle-hook error). Surface as
        // 403 Forbidden — the kernel message reads clearly to operators
        // inspecting the response.
        KernelResponse::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(internal(format!(
            "unexpected response shape for InstallCapsule: {other:?}"
        ))),
    }
}

/// A `.capsule` archive the gateway downloaded from a GitHub release,
/// staged on disk for the kernel to install by path. The `guard` keeps
/// the temp dir (and thus the file at `path`) alive — it MUST outlive
/// the kernel request that reads the file.
struct ResolvedArchive {
    /// Absolute path to the downloaded `.capsule` on disk.
    path: String,
    /// Temp-dir guard; dropping it deletes `path`.
    guard: tempfile::TempDir,
}

/// Hard cap on a downloaded `.capsule` archive (mirrors the CLI).
const MAX_CAPSULE_BYTES: usize = 50 * 1024 * 1024;

/// Resolve a GitHub `(org, repo)` to a locally-staged `.capsule` archive.
///
/// Fetches the latest release via the GitHub API, selects the matching
/// `.capsule` asset (the lone one, or the one named via `capsule`), and
/// streams it to a temp file with a 50 MB cap. The returned guard owns
/// the temp dir; the caller MUST keep it alive across the kernel call.
///
/// This is the ONLY place the gateway performs a network fetch, and only
/// for a GitHub-shaped source — the download URL is taken from GitHub's
/// own release JSON for the named repo, never an attacker-supplied URL.
async fn resolve_github_source(
    org: &str,
    repo: &str,
    capsule: Option<&str>,
) -> GatewayResult<ResolvedArchive> {
    let client = reqwest::Client::builder()
        .user_agent("astrid-gateway")
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| internal(format!("build http client: {e}")))?;

    // Latest release metadata.
    let api_url = format!("https://api.github.com/repos/{org}/{repo}/releases/latest");
    let response = client
        .get(&api_url)
        .send()
        .await
        .map_err(|e| internal(format!("fetch GitHub release for {org}/{repo}: {e}")))?;
    if !response.status().is_success() {
        return Err(github_http_error(
            response.status(),
            &format!("release lookup for {org}/{repo}"),
        ));
    }
    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| internal(format!("decode GitHub release JSON: {e}")))?;
    let assets = json
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);

    // Select exactly one `.capsule` asset.
    let candidates = github_source::capsule_assets(assets);
    let names: Vec<&str> = candidates.iter().map(|(n, _)| n.as_str()).collect();
    let idx = match github_source::pick_capsule(&names, capsule) {
        // No `.capsule` assets in the release at all.
        Ok(None) => return Err(GatewayError::NotFound),
        // Several assets and no/!matching selector — the error names them.
        Err(e) => return Err(GatewayError::BadRequest(e.to_string())),
        Ok(Some(idx)) => idx,
    };
    let (name, download_url) = &candidates[idx];

    // Enforce (not just document) the SSRF containment: the asset URL comes
    // from GitHub's release JSON and is expected to be `https://github.com/…`.
    // Pin scheme+host before issuing the request so a surprising
    // `browser_download_url` can't turn into an arbitrary outbound fetch.
    if !is_allowed_download_url(download_url) {
        return Err(internal(format!(
            "refusing capsule download from non-GitHub URL: {download_url}"
        )));
    }

    // Stream the asset into memory with a hard size cap, then stage it to
    // disk for the kernel to install by path.
    let mut dl = client
        .get(download_url)
        .send()
        .await
        .map_err(|e| internal(format!("download capsule asset {name}: {e}")))?;
    // Guard the status before streaming: a non-2xx body (e.g. a 404/403
    // error page) must not be staged as a `.capsule` and handed to the
    // kernel, which would then fail with an unrelated install error.
    if !dl.status().is_success() {
        return Err(github_http_error(
            dl.status(),
            &format!("download of asset {name}"),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = dl
        .chunk()
        .await
        .map_err(|e| internal(format!("stream capsule asset {name}: {e}")))?
    {
        bytes.extend_from_slice(&chunk);
        if bytes.len() > MAX_CAPSULE_BYTES {
            return Err(GatewayError::BadRequest(
                "capsule archive exceeds 50 MB limit".to_string(),
            ));
        }
    }
    stage_capsule_archive(name, bytes).await
}

/// Stage downloaded `.capsule` bytes into a fresh temp dir and return the
/// guarded path for the kernel to install from.
///
/// The file write runs inside `spawn_blocking`: an archive up to 50 MB
/// would otherwise block a gateway worker thread. The asset name is
/// reduced to its final path component (`file_name`), so a crafted release
/// asset name (e.g. `../../x.capsule`) cannot escape the temp dir. The
/// returned [`ResolvedArchive::guard`] owns the temp dir; the caller MUST
/// keep it alive until the kernel has read the file.
async fn stage_capsule_archive(asset_name: &str, bytes: Vec<u8>) -> GatewayResult<ResolvedArchive> {
    let tmp = tempfile::TempDir::new()
        .map_err(|e| internal(format!("create temp dir for capsule download: {e}")))?;
    let sanitized = std::path::Path::new(asset_name)
        .file_name()
        .unwrap_or_default();
    let download_path = tmp.path().join(sanitized);

    // Move `bytes` into the task (not needed afterwards) and clone only the
    // small path so `download_path` survives for the result. A join error
    // maps to an internal error rather than panicking the worker.
    let write_path = download_path.clone();
    tokio::task::spawn_blocking(move || std::fs::write(&write_path, &bytes))
        .await
        .map_err(|e| internal(format!("join capsule-write task: {e}")))?
        .map_err(|e| internal(format!("write capsule archive to disk: {e}")))?;

    Ok(ResolvedArchive {
        path: download_path.to_string_lossy().into_owned(),
        guard: tmp,
    })
}

#[utoipa::path(
    get,
    path = "/api/capsules/{id}",
    tag = "capsules",
    params(("id" = String, Path, description = "Capsule id")),
    responses(
        (status = 200, body = CapsuleDetail, description = "Manifest excerpt for one capsule."),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn get_capsule(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<CapsuleDetail>> {
    let caller = caller_from(&req)?.clone();
    let client = state.kernel_client_for(&caller)?;
    let resp = client
        .request(KernelRequest::GetCapsuleMetadata)
        .await
        .map_err(daemon_internal)?;
    match resp {
        KernelResponse::CapsuleMetadata(meta) => meta
            .into_iter()
            .find(|m: &CapsuleMetadataEntry| m.name == id)
            .map(|m| {
                Json(CapsuleDetail {
                    id: m.name,
                    interceptor_events: m.interceptor_events,
                })
            })
            .ok_or(GatewayError::NotFound),
        KernelResponse::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(internal(format!(
            "unexpected response shape for GetCapsuleMetadata: {other:?}"
        ))),
    }
}

/// `GET /api/capsules/{id}/topics` — the capsule's declared
/// `[publish]` / `[subscribe]` topics, as the manifest describes
/// them. Today the kernel's `GetCapsuleMetadata` only surfaces
/// interceptor events; topic enumeration through IPC is a TODO
/// (the manifest itself carries the data — see
/// `astrid_capsule::manifest::TopicDef`). This route returns an
/// empty topic list with a deprecation-friendly shape so the
/// dashboard can render the section without crashing; the field
/// fills in once the kernel exposes it.
#[utoipa::path(
    get,
    path = "/api/capsules/{id}/topics",
    tag = "capsules",
    params(("id" = String, Path, description = "Capsule id")),
    responses(
        (status = 200, body = CapsuleTopicsResponse, description = "Declared topics. Empty until kernel-side topic enumeration ships."),
        (status = 401, body = ErrorBody),
    )
)]
pub async fn list_capsule_topics(
    State(_state): State<Arc<GatewayState>>,
    Path(_id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<CapsuleTopicsResponse>> {
    caller_from(&req)?;
    Ok(Json(CapsuleTopicsResponse { topics: vec![] }))
}

// ── helpers (kernel client error mapping) ────────────────────────

#[allow(
    clippy::needless_pass_by_value,
    reason = "consumed by Display formatting"
)]
fn daemon_internal(e: anyhow::Error) -> GatewayError {
    GatewayError::Internal(anyhow::anyhow!("daemon kernel-request: {e}"))
}

fn internal(msg: String) -> GatewayError {
    GatewayError::Internal(anyhow::anyhow!(msg))
}

/// Map a non-success GitHub HTTP status to a gateway error. A `404` is a
/// genuine "not found" (no release for the repo, or the asset vanished
/// between listing and download); anything else is an upstream failure
/// surfaced as a `500`.
fn github_http_error(status: reqwest::StatusCode, context: &str) -> GatewayError {
    if status == reqwest::StatusCode::NOT_FOUND {
        GatewayError::NotFound
    } else {
        internal(format!("{context}: GitHub returned {status}"))
    }
}

/// SSRF containment for the asset download: a GitHub release
/// `browser_download_url` is always `https://github.com/…` (the redirect to
/// the CDN is GitHub's own and followed by the client). Pin scheme+host so a
/// surprising release-JSON value can't become an arbitrary outbound fetch —
/// defence in depth on top of only ever resolving GitHub-shaped sources.
fn is_allowed_download_url(url: &str) -> bool {
    reqwest::Url::parse(url)
        .ok()
        .is_some_and(|u| u.scheme() == "https" && u.host_str() == Some("github.com"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GitHub `404` (no release, or a vanished asset) maps to `NotFound`;
    /// any other non-2xx is an upstream failure surfaced as an internal
    /// error — never silently streamed as a `.capsule` body.
    #[test]
    fn github_http_error_maps_status_codes() {
        assert!(matches!(
            github_http_error(reqwest::StatusCode::NOT_FOUND, "x"),
            GatewayError::NotFound
        ));
        assert!(matches!(
            github_http_error(reqwest::StatusCode::FORBIDDEN, "x"),
            GatewayError::Internal(_)
        ));
        assert!(matches!(
            github_http_error(reqwest::StatusCode::INTERNAL_SERVER_ERROR, "x"),
            GatewayError::Internal(_)
        ));
    }

    /// Only `https://github.com/…` asset URLs are fetched; any other
    /// scheme/host is refused before a request goes out (SSRF containment).
    #[test]
    fn is_allowed_download_url_pins_github_https() {
        assert!(is_allowed_download_url(
            "https://github.com/org/repo/releases/download/v1/cli.capsule"
        ));
        // Wrong scheme, wrong host, the CDN redirect target, and a
        // look-alike host are all refused.
        assert!(!is_allowed_download_url(
            "http://github.com/org/repo/releases/download/v1/cli.capsule"
        ));
        assert!(!is_allowed_download_url(
            "https://evil.example.com/x.capsule"
        ));
        assert!(!is_allowed_download_url(
            "https://objects.githubusercontent.com/x.capsule"
        ));
        assert!(!is_allowed_download_url(
            "https://github.com.evil.example/x.capsule"
        ));
        assert!(!is_allowed_download_url("not a url"));
    }

    /// The staged archive lands on disk inside the guard's temp dir, with
    /// the asset's bytes intact and its file name preserved.
    #[tokio::test]
    async fn stage_capsule_archive_writes_and_round_trips() {
        let bytes = b"fake .capsule archive bytes".to_vec();
        let resolved = stage_capsule_archive("cli.capsule", bytes.clone())
            .await
            .expect("staging should succeed");

        let path = std::path::PathBuf::from(&resolved.path);
        assert!(path.exists(), "staged archive must exist on disk");
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some("cli.capsule"),
            "asset file name is preserved",
        );
        assert!(
            path.starts_with(resolved.guard.path()),
            "archive must live inside the guarded temp dir",
        );
        assert_eq!(
            std::fs::read(&path).expect("read back staged archive"),
            bytes,
            "bytes must round-trip through the spawn_blocking write",
        );
    }

    /// Dropping the [`ResolvedArchive`] guard removes the staged file — the
    /// kernel must finish reading it before the gateway handler returns.
    #[tokio::test]
    async fn stage_capsule_archive_guard_drop_removes_file() {
        let resolved = stage_capsule_archive("x.capsule", b"x".to_vec())
            .await
            .expect("staging should succeed");
        let path = resolved.path.clone();
        assert!(std::path::Path::new(&path).exists());

        drop(resolved);
        assert!(
            !std::path::Path::new(&path).exists(),
            "guard drop must delete the staged archive",
        );
    }

    /// A crafted release-asset name with path traversal is reduced to its
    /// final component, so the write stays inside the temp dir (the asset
    /// name originates from GitHub's release JSON — untrusted input).
    #[tokio::test]
    async fn stage_capsule_archive_sanitizes_path_traversal() {
        let resolved = stage_capsule_archive("../../../etc/evil.capsule", b"x".to_vec())
            .await
            .expect("staging should succeed");

        let path = std::path::PathBuf::from(&resolved.path);
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some("evil.capsule"),
            "traversal components are stripped to the bare file name",
        );
        assert!(
            path.starts_with(resolved.guard.path()),
            "sanitized archive must not escape the temp dir",
        );
    }
}
