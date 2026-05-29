//! `OpenAPI` 3.x specification emission for the gateway routes.
//!
//! The spec is built at compile time from `#[utoipa::path(...)]`
//! annotations on each handler and `#[derive(ToSchema)]` on each
//! request/response type. `GET /api/openapi.json` serves the rendered
//! JSON; drop the URL into Swagger UI, Redoc, Scalar, or
//! `openapi-typescript` to get a typed TS client without any
//! drift-tracking on either side.
//!
//! ## Type-system boundaries
//!
//! A handful of types that flow through gateway responses originate
//! in `astrid-core` (`PrincipalId`, `Quotas`, kernel API enums) and
//! don't carry a `ToSchema` derive — adding `utoipa` as a dep on the
//! kernel-side crates would balloon the build surface for one
//! observability concern. The route schemas use
//! `#[schema(value_type = ...)]` to give utoipa a structural
//! stand-in (typically `String` for opaque IDs) and document the
//! actual shape via `#[schema(example = ...)]` so the generated
//! schema is still useful for clients.
//!
//! ## Security scheme
//!
//! `bearerAuth` (HTTP `Authorization: Bearer ...`) is declared as the
//! default security requirement; the unauthenticated routes
//! (`/api/distribution`, `/api/auth/redeem`, `/api/auth/pair-device/redeem`,
//! `/healthz`, `/metrics`) explicitly clear it via `security(())` on
//! their handler annotation.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use utoipa::OpenApi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

use crate::routes;
use crate::state::GatewayState;

/// Aggregated `OpenAPI` document for every gateway route.
///
/// Adding a new route is a three-step change:
/// 1. `#[utoipa::path(...)]` on the handler.
/// 2. `#[derive(ToSchema)]` on its request/response types.
/// 3. List the handler under `paths(...)` and types under
///    `components(schemas(...))` below.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Astrid Gateway",
        description = "HTTP front for the Astrid admin API — provisioning, \
            principal/group/cap management, capsule install, invite + pair-device \
            onboarding, audit stream, ops probes.",
        version = "0.7.0",
        contact(
            name = "Astrid",
            url = "https://github.com/unicity-astrid/astrid"
        ),
        license(
            name = "MIT OR Apache-2.0",
            url = "https://github.com/unicity-astrid/astrid/blob/main/LICENSE"
        )
    ),
    paths(
        // Discovery (unauthenticated)
        routes::distribution::get_distribution,
        routes::distribution::get_onboarding,
        // Auth
        routes::auth::post_redeem,
        routes::auth::get_me,
        routes::auth::post_refresh,
        routes::auth::post_pair_device_issue,
        routes::auth::post_pair_device_redeem,
        // Principals
        routes::principals::list_principals,
        routes::principals::create_principal,
        routes::principals::get_principal,
        routes::principals::modify_principal,
        routes::principals::delete_principal,
        routes::principals::enable_principal,
        routes::principals::disable_principal,
        routes::principals::list_capabilities,
        // Caps
        routes::caps::grant_caps,
        routes::caps::revoke_caps,
        // Quotas
        routes::quotas::get_quotas,
        routes::quotas::set_quotas,
        // Groups
        routes::groups::list_groups,
        routes::groups::create_group,
        routes::groups::modify_group,
        routes::groups::delete_group,
        // Invites
        routes::invites::issue_invite,
        routes::invites::list_invites,
        routes::invites::revoke_invite,
        // Capsules
        routes::capsules::list_capsules,
        routes::capsules::install_capsule,
        routes::capsules::get_capsule,
        routes::capsules::list_capsule_topics,
        routes::env::get_env_schema,
        routes::env::write_env,
        // Agent invocation
        routes::agent::post_prompt,
        // Audit
        routes::events::get_events,
        routes::audit::get_audit,
        // System
        routes::system::get_status,
        routes::system::reload_capsules,
        // Ops probes
        routes::observability::get_healthz,
        routes::observability::get_metrics,
        // `OpenAPI` spec itself (this very handler)
        get_openapi,
    ),
    components(
        schemas(
            // Auth
            routes::auth::RedeemRequest,
            routes::auth::RedeemResponse,
            routes::auth::MeResponse,
            routes::auth::RefreshResponse,
            routes::auth::PairDeviceIssueRequest,
            routes::auth::PairDeviceRedeemRequest,
            routes::auth::PairDeviceRedeemResponse,
            // Principals
            routes::principals::PrincipalListResponse,
            routes::principals::AgentSummaryView,
            routes::principals::CreatePrincipalRequest,
            routes::principals::ModifyPrincipalRequest,
            routes::principals::CapabilityCatalogResponse,
            routes::principals::CapabilityInfoView,
            // Caps
            routes::caps::GrantRequest,
            routes::caps::RevokeRequest,
            // Quotas
            routes::quotas::QuotaRequest,
            routes::quotas::QuotasView,
            // Groups
            routes::groups::GroupListResponse,
            routes::groups::GroupSummaryView,
            routes::groups::CreateGroupRequest,
            routes::groups::ModifyGroupRequest,
            // Invites
            routes::invites::IssueRequest,
            routes::invites::IssueResponse,
            routes::invites::InviteIssuedView,
            routes::invites::ListResponse,
            routes::invites::InviteSummaryView,
            // Capsules
            routes::capsules::CapsuleListResponse,
            routes::capsules::CapsuleDetail,
            routes::capsules::CapsuleTopic,
            routes::capsules::CapsuleTopicsResponse,
            routes::capsules::InstallRequest,
            // Agent
            routes::agent::PromptRequest,
            routes::agent::PromptReady,
            // Env
            routes::env::EnvFieldSchema,
            routes::env::EnvSchemaResponse,
            routes::env::EnvWriteRequest,
            // Distribution
            routes::distribution::DistributionInfo,
            routes::distribution::OnboardingFields,
            routes::distribution::OnboardingField,
            // Audit history
            routes::audit::AuditEntryView,
            routes::audit::AuditQueryResponse,
            // Errors
            crate::error::ErrorBody,
        )
    ),
    security(
        ("bearerAuth" = [])
    ),
    modifiers(&BearerAuthModifier),
    tags(
        (name = "auth", description = "Bearer session + device pairing"),
        (name = "principals", description = "Per-agent CRUD"),
        (name = "caps", description = "Capability grant / revoke"),
        (name = "quotas", description = "Per-principal quota knobs"),
        (name = "groups", description = "Group CRUD + cap inheritance"),
        (name = "invites", description = "One-shot onboarding tokens"),
        (name = "capsules", description = "Capsule install + introspection"),
        (name = "env", description = "Per-principal capsule configuration"),
        (name = "agent", description = "Agent invocation (SSE response stream)"),
        (name = "audit", description = "Audit-event stream (SSE)"),
        (name = "system", description = "Daemon status + lifecycle"),
        (name = "discovery", description = "Pre-auth onboarding hints"),
        (name = "ops", description = "Health + metrics probes")
    )
)]
pub struct ApiDoc;

/// Attach the `bearerAuth` HTTP security scheme to the components
/// table. `utoipa` doesn't do this automatically — you declare the
/// scheme here so handlers can reference it from
/// `security(("bearerAuth" = []))`.
struct BearerAuthModifier;

impl utoipa::Modify for BearerAuthModifier {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .as_mut()
            .expect("utoipa always populates components when paths are declared");
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("astrid-session-v1")
                    .description(Some(
                        "Bearer token minted by `POST /api/auth/redeem` or \
                         `POST /api/auth/pair-device/redeem`. The gateway \
                         verifies the signature against its boot-time ed25519 \
                         key — the principal stamped on outbound IPC comes \
                         from the token, never from the request body.",
                    ))
                    .build(),
            ),
        );
    }
}

/// `GET /api/openapi.json` — serve the rendered spec.
///
/// Unauthenticated by design: an `OpenAPI` spec is the contract the API
/// publishes about itself. Clients (dashboards, codegen tools) need to
/// read it before they have a bearer.
#[utoipa::path(
    get,
    path = "/api/openapi.json",
    tag = "discovery",
    security(()),
    responses(
        (status = 200, description = "`OpenAPI` 3.x specification (JSON)", content_type = "application/json")
    )
)]
pub async fn get_openapi(
    State(_state): State<Arc<GatewayState>>,
) -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_doc_builds() {
        let doc = ApiDoc::openapi();
        // Sanity: a couple of canary routes must be present. If
        // someone removes a path from the macro by accident this
        // catches it.
        let paths: Vec<&String> = doc.paths.paths.keys().collect();
        assert!(
            paths.iter().any(|p| p.as_str() == "/api/auth/redeem"),
            "missing /api/auth/redeem"
        );
        assert!(
            paths.iter().any(|p| p.as_str() == "/api/capsules"),
            "missing /api/capsules"
        );
        assert!(
            paths.iter().any(|p| p.as_str() == "/healthz"),
            "missing /healthz"
        );
    }

    #[test]
    fn bearer_auth_scheme_declared() {
        let doc = ApiDoc::openapi();
        let components = doc.components.expect("components present");
        assert!(
            components.security_schemes.contains_key("bearerAuth"),
            "bearerAuth scheme must be declared in components.securitySchemes"
        );
    }

    #[test]
    fn doc_serializes_to_json() {
        // The serving handler returns `Json(ApiDoc::openapi())` — if
        // the doc has any non-serializable shape the route would 500
        // at request time. Catch it at test time.
        let doc = ApiDoc::openapi();
        let s = serde_json::to_string(&doc).expect("openapi doc must serialize");
        assert!(
            s.contains("\"openapi\":"),
            "rendered JSON must declare an `OpenAPI` version"
        );
    }
}
