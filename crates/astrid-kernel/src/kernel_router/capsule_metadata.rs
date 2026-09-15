//! Principal-bound capsule metadata response construction.

use astrid_core::principal::PrincipalId;
use astrid_events::kernel_api::{
    CapsuleEnvMetadata, CapsuleEnvOptionsFromMetadata, KernelResponse,
};

use super::inventory::{durable_package_details, visible_inventory_manifests};
use super::{AuthorizedRequest, CapsuleVisibility};

pub(super) async fn response(
    kernel: &crate::Kernel,
    authorization: &AuthorizedRequest,
    target: Option<&PrincipalId>,
) -> KernelResponse {
    let visibility = target.map_or_else(
        || CapsuleVisibility::new(authorization),
        |principal| CapsuleVisibility::for_target(authorization, principal),
    );
    let subject = visibility.principal.clone();
    let manifests = visible_inventory_manifests(kernel, &visibility).await;
    let registry = kernel.capsules.read().await;
    let owner_uid = kernel.principal_directory.uid_for(&subject).ok();
    let mut entries = Vec::new();
    for manifest in manifests {
        let source_id = astrid_capsule::capsule::CapsuleId::new(manifest.package.name.clone())
            .ok()
            .and_then(|id| registry.source_id_for(&subject, &id));
        let env = manifest
            .env
            .iter()
            .map(|(name, def)| {
                (
                    name.clone(),
                    CapsuleEnvMetadata {
                        env_type: def.env_type.clone(),
                        request: def.request.clone(),
                        description: def.description.clone(),
                        default: def.default.clone(),
                        enum_values: def.enum_values.clone(),
                        placeholder: def.placeholder.clone(),
                        options_from: def.options_from.as_ref().map(|source| {
                            CapsuleEnvOptionsFromMetadata {
                                http: source.http.clone(),
                                bearer: source.bearer.clone(),
                                select: source.select.clone(),
                                after: source.after.clone(),
                            }
                        }),
                    },
                )
            })
            .collect();
        let (wit_hashes, wasm_hash, update_source) =
            durable_package_details(kernel, owner_uid, &manifest.package.name);
        entries.push(astrid_events::kernel_api::CapsuleMetadataEntry {
            name: manifest.package.name.clone(),
            capabilities: serde_json::to_value(&manifest.capabilities)
                .unwrap_or(serde_json::Value::Null),
            version: manifest.package.version.clone(),
            description: manifest.package.description.clone(),
            interceptor_events: manifest
                .subscribes
                .iter()
                .filter(|(_, def)| def.handler.is_some())
                .map(|(topic, _)| topic.clone())
                .collect(),
            imports: manifest
                .imports
                .iter()
                .map(|(namespace, interfaces)| {
                    (
                        namespace.clone(),
                        interfaces
                            .iter()
                            .map(|(name, def)| (name.clone(), def.version.to_string()))
                            .collect(),
                    )
                })
                .collect(),
            exports: manifest
                .exports
                .iter()
                .map(|(namespace, interfaces)| {
                    (
                        namespace.clone(),
                        interfaces
                            .iter()
                            .map(|(name, def)| (name.clone(), def.version.to_string()))
                            .collect(),
                    )
                })
                .collect(),
            env,
            wit_hashes,
            wasm_hash,
            update_source,
            source_id,
            owner_uid,
        });
    }
    KernelResponse::CapsuleMetadata(entries)
}
