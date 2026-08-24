use std::collections::BTreeMap;

use tracing::warn;

use super::CapsuleVisibility;

pub(super) fn durable_package_details(
    kernel: &crate::Kernel,
    owner_uid: Option<astrid_core::identity::PrincipalUid>,
    capsule: &str,
) -> (Vec<String>, Option<String>, Option<String>) {
    let Some(uid) = owner_uid else {
        return (Vec::new(), None, None);
    };
    let Some(store) = kernel.principal_store.as_ref() else {
        return (Vec::new(), None, None);
    };
    let Ok(id) = astrid_capsule_types::CapsuleId::new(capsule.to_owned()) else {
        return (Vec::new(), None, None);
    };
    let owner = astrid_storage::StateOwner::Principal(uid);
    let Ok(Some(package)) =
        astrid_capsule_install::read_verified_durable_package_for_owner(store, &owner, id.as_str())
    else {
        return (Vec::new(), None, None);
    };
    let mut hashes: Vec<String> = package.metadata().wit_files.values().cloned().collect();
    hashes.sort();
    hashes.dedup();
    let wasm_hash = package
        .metadata()
        .wasm_hash
        .as_deref()
        .and_then(|expected| {
            match astrid_capsule_install::wasm::catalog_wasm_hash(store, expected) {
                Ok(hash) => Some(hash),
                Err(error) => {
                    warn!(
                        capsule,
                        expected_hash = expected,
                        error = %error,
                        "durable capsule WASM is absent or invalid in the system catalog"
                    );
                    None
                },
            }
        });
    let update_source = verified_remote_update_source(package.metadata().source.as_deref());
    (hashes, wasm_hash, update_source)
}

fn verified_remote_update_source(source: Option<&str>) -> Option<String> {
    source
        .filter(|source| {
            astrid_capsule_install::github_source::parse_github_source(source).is_some()
        })
        .map(str::to_owned)
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

#[cfg(test)]
mod tests {
    use super::verified_remote_update_source;

    #[test]
    fn update_source_exposes_remote_github_but_never_native_paths() {
        assert_eq!(
            verified_remote_update_source(Some("@astrid-runtime/capsule-registry")),
            Some("@astrid-runtime/capsule-registry".to_owned())
        );
        assert_eq!(
            verified_remote_update_source(Some(
                "https://github.com/astrid-runtime/capsule-registry"
            )),
            Some("https://github.com/astrid-runtime/capsule-registry".to_owned())
        );
        assert_eq!(
            verified_remote_update_source(Some("/tmp/registry.capsule")),
            None
        );
        assert_eq!(
            verified_remote_update_source(Some("./registry.capsule")),
            None
        );
    }
}
