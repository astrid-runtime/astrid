use std::collections::BTreeMap;

use tracing::warn;

use super::CapsuleVisibility;

pub(super) fn durable_wit_hashes(
    kernel: &crate::Kernel,
    owner_uid: Option<astrid_core::identity::PrincipalUid>,
    capsule: &str,
) -> Vec<String> {
    let Some(uid) = owner_uid else {
        return Vec::new();
    };
    let Some(store) = kernel.principal_store.as_ref() else {
        return Vec::new();
    };
    let Ok(id) = astrid_capsule_types::CapsuleId::new(capsule.to_owned()) else {
        return Vec::new();
    };
    let owner = astrid_storage::StateOwner::Principal(uid);
    let Ok(Some(package)) = store.capsules().get(&owner, id.as_str()) else {
        return Vec::new();
    };
    let Ok(metadata) = serde_json::from_slice::<serde_json::Value>(&package.metadata) else {
        return Vec::new();
    };
    let Some(files) = metadata
        .get("wit_files")
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };
    let mut hashes: Vec<String> = files
        .values()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_owned)
        .collect();
    hashes.sort();
    hashes.dedup();
    hashes
}

pub(super) async fn inventory_manifest_map(
    kernel: &crate::Kernel,
    visibility: &CapsuleVisibility,
) -> BTreeMap<String, astrid_capsule::manifest::CapsuleManifest> {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    let mut paths = kernel.durable_principal_capsule_paths(&visibility.principal);
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    let mut paths = Vec::new();
    paths.extend(crate::capsule_discovery_paths_for(
        &kernel.astrid_home,
        &kernel.workspace_root,
        &visibility.principal,
        &kernel.workspace_layout,
    ));
    let workspace_layout = kernel.workspace_layout.clone();
    let workspace_root = kernel.workspace_root.clone();
    let discovered = match tokio::task::spawn_blocking(move || {
        astrid_capsule::discovery::discover_manifests_in_workspace(
            Some(&paths),
            Some(&workspace_root),
            &workspace_layout,
        )
    })
    .await
    {
        Ok(discovered) => discovered,
        Err(err) => {
            warn!(error = %err, "Capsule inventory discovery task failed");
            Vec::new()
        },
    };

    discovered
        .into_iter()
        .filter_map(|(manifest, _)| {
            let id = astrid_capsule::capsule::CapsuleId::new(manifest.package.name.clone()).ok()?;
            visibility.allows(&id).then_some((id.to_string(), manifest))
        })
        .collect()
}

pub(super) async fn visible_inventory_manifests(
    kernel: &crate::Kernel,
    visibility: &CapsuleVisibility,
) -> Vec<astrid_capsule::manifest::CapsuleManifest> {
    let mut manifests = inventory_manifest_map(kernel, visibility).await;
    let registry = kernel.capsules.read().await;
    for capsule in visibility.capsules(&registry) {
        if visibility.allows(capsule.id()) {
            manifests
                .entry(capsule.id().to_string())
                .or_insert_with(|| capsule.manifest().clone());
        }
    }
    manifests.into_values().collect()
}
