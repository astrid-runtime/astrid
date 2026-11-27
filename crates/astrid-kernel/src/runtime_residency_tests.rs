use super::{Refusal, RuntimeResidency, Uplinks, classify};
use crate::classify_runtime_residency;
use astrid_capsule_types::{CapsuleId, manifest::CapsuleManifest};

#[test]
fn runtime_residency_policy_distinguishes_grants_from_providers() {
    let id = CapsuleId::new("uplink-policy").unwrap();
    let mut capability_only = CapsuleManifest::default();
    capability_only.capabilities.uplink = true;

    assert_eq!(
        classify_runtime_residency(&capability_only, &id, false).unwrap(),
        RuntimeResidency::Principal
    );
    assert_eq!(
        classify_runtime_residency(&capability_only, &id, true).unwrap(),
        RuntimeResidency::SystemResident
    );

    let mut provider = CapsuleManifest::default();
    provider
        .uplinks
        .push(astrid_capsule_types::manifest::UplinkDef {
            name: "test".to_string(),
            platform: "test".to_string(),
            profile: astrid_core::UplinkProfile::Chat,
        });
    assert!(classify_runtime_residency(&provider, &id, false).is_err());
    assert_eq!(
        classify_runtime_residency(&provider, &id, true).unwrap(),
        RuntimeResidency::SystemResident
    );

    provider
        .mcp_servers
        .push(astrid_capsule_types::manifest::McpServerDef {
            id: "test".into(),
            description: None,
            server_type: Some("stdio".into()),
            command: Some("test".into()),
            args: Vec::new(),
        });
    assert!(classify_runtime_residency(&provider, &id, true).is_err());
    provider.uplinks.clear();
    assert_eq!(
        classify_runtime_residency(&provider, &id, true).unwrap(),
        RuntimeResidency::Principal
    );
}

#[test]
fn both_uplink_roles_require_operator_approval_for_system_residency() {
    for (provides, capability) in [(true, false), (true, true), (false, true)] {
        assert_eq!(
            classify(
                true,
                Uplinks {
                    provides,
                    capability
                },
                true
            ),
            Err(Refusal::SystemMcp),
        );
        let unlisted = classify(
            false,
            Uplinks {
                provides,
                capability,
            },
            true,
        );
        if provides {
            assert_eq!(unlisted, Err(Refusal::UnapprovedProvider));
        } else {
            assert_eq!(unlisted, Ok(RuntimeResidency::Principal));
        }
    }
}
