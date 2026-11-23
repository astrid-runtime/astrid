//! Positive and negative controls for the parser fuzz corpora.
#![cfg(all(
    feature = "admin-json-target",
    feature = "config-target",
    feature = "manifest-target"
))]

use astrid_capsule_types::manifest::CapsuleManifest;
use astrid_config::Config;
use astrid_core::kernel_api::{AdminKernelRequest, AdminKernelResponse, KernelRequest};

#[test]
fn admin_seeds_reach_current_wire_parsers() {
    for seed in [
        include_str!("../seeds/admin_json/agent-list.json"),
        include_str!("../seeds/admin_json/newer-method.json"),
    ] {
        let request: AdminKernelRequest = serde_json::from_str(seed).unwrap();
        assert!(request.request_id.is_some());
    }
    let response: AdminKernelResponse =
        serde_json::from_str(include_str!("../seeds/admin_json/success.json")).unwrap();
    assert_eq!(response.request_id.as_deref(), Some("fuzz-response"));
    let request: KernelRequest =
        serde_json::from_str(include_str!("../seeds/admin_json/kernel-request.json")).unwrap();
    assert!(matches!(request, KernelRequest::GetStatus));
    assert!(
        serde_json::from_str::<AdminKernelRequest>(include_str!(
            "../seeds/admin_json/unknown.json"
        ))
        .is_err()
    );
}

#[test]
fn config_seeds_cover_accepted_and_rejected_values() {
    let config: Config =
        toml::from_str(include_str!("../seeds/config_toml/defaults.toml")).unwrap();
    astrid_config::validate::validate(&config).unwrap();
    let encoded = toml::to_string(&config).unwrap();
    let reparsed: Config = toml::from_str(&encoded).unwrap();
    astrid_config::validate::validate(&reparsed).unwrap();
    assert!(toml::from_str::<Config>(include_str!("../seeds/config_toml/invalid.toml")).is_err());
}

#[test]
fn manifest_seeds_cover_normalization_and_rejected_authority_shapes() {
    let manifest: CapsuleManifest =
        toml::from_str(include_str!("../seeds/manifest_toml/normalized.toml")).unwrap();
    assert_eq!(
        manifest.effective_ipc_publish_patterns(),
        ["event.v1.short"]
    );
    assert_eq!(
        manifest.effective_ipc_subscribe_patterns(),
        ["event.v1.long"]
    );
    assert_eq!(manifest.effective_interceptors().len(), 1);
    for seed in [
        include_str!("../seeds/manifest_toml/ambiguous-pins.toml"),
        include_str!("../seeds/manifest_toml/missing-handler.toml"),
    ] {
        assert!(toml::from_str::<CapsuleManifest>(seed).is_err());
    }
}

#[cfg(feature = "gateway-target")]
#[test]
fn gateway_seeds_reach_request_dto_parsers() {
    use astrid_gateway::routes::{agent, caps, principals, sessions};
    let _: agent::PromptRequest =
        serde_json::from_str(include_str!("../seeds/gateway_request_json/prompt.json")).unwrap();
    let _: caps::GrantRequest = serde_json::from_str(include_str!(
        "../seeds/gateway_request_json/capabilities.json"
    ))
    .unwrap();
    let _: principals::CreatePrincipalRequest =
        serde_json::from_str(include_str!("../seeds/gateway_request_json/principal.json")).unwrap();
    // This DTO documents the wire shape; the HTTP route itself uses raw JSON
    // to distinguish absent fields. This test does not exercise that route.
    let _: sessions::SessionUpdateRequest =
        serde_json::from_str(include_str!("../seeds/gateway_request_json/session.json")).unwrap();
}
