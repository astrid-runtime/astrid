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
        .and_then(|expected| verified_catalog_wasm_hash(store, capsule, expected));
    let update_source = verified_remote_update_source(package.metadata().source.as_deref());
    (hashes, wasm_hash, update_source)
}

fn verified_catalog_wasm_hash(
    store: &astrid_storage::RuntimePrincipalStore,
    capsule: &str,
    expected: &str,
) -> Option<String> {
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
    use std::sync::Arc;

    use super::{verified_catalog_wasm_hash, verified_remote_update_source};
    use astrid_core::dirs::AstridHome;
    use astrid_storage::{KvQuotaResolver, StateOwner};

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

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        })
    }

    #[tokio::test]
    async fn catalog_hash_is_not_exposed_for_missing_or_tampered_wasm() {
        let missing_dir = tempfile::tempdir().expect("missing catalog home");
        let missing_home = AstridHome::from_path(missing_dir.path());
        missing_home.ensure().expect("ensure home");
        let missing_store =
            astrid_storage::open_runtime_principal_store(&missing_home, unlimited_quota())
                .await
                .expect("open store");
        let bytes = b"catalog-authority";
        let hash = blake3::hash(bytes).to_hex().to_string();
        assert_eq!(
            verified_catalog_wasm_hash(&missing_store, "catalog", &hash),
            None,
            "metadata must not advertise a hash when System/bin is absent"
        );

        let valid_name =
            astrid_storage::ContentName::new(format!("bin/{hash}.wasm")).expect("catalog name");
        missing_store
            .content()
            .put(&StateOwner::System, &valid_name, bytes)
            .expect("put catalog bytes");
        assert_eq!(
            verified_catalog_wasm_hash(&missing_store, "catalog", &hash),
            Some(hash.clone())
        );

        let tampered_dir = tempfile::tempdir().expect("tampered catalog home");
        let tampered_home = AstridHome::from_path(tampered_dir.path());
        tampered_home.ensure().expect("ensure home");
        let tampered_store =
            astrid_storage::open_runtime_principal_store(&tampered_home, unlimited_quota())
                .await
                .expect("open tampered store");
        tampered_store
            .content()
            .put(&StateOwner::System, &valid_name, b"tampered")
            .expect("put tampered bytes");
        assert_eq!(
            verified_catalog_wasm_hash(&tampered_store, "catalog", &hash),
            None,
            "metadata must not advertise a hash when System/bin is tampered"
        );
    }
}
