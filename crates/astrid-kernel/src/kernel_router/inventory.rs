//! Private principal-owned package read and discovery.

use std::collections::BTreeMap;
use std::sync::Arc;

use tracing::warn;

use super::AuthorizedRequest;
use super::visibility::CapsuleVisibility;

pub(super) fn durable_package_details(
    kernel: &crate::Kernel,
    authorization: &AuthorizedRequest,
    capsule: &str,
) -> (Vec<String>, Option<String>, Option<String>) {
    let Ok(Some(package)) = read_durable_package(kernel, authorization, capsule) else {
        warn!(
            security_event = true,
            capsule, "Durable package metadata denied or failed verification"
        );
        return (Vec::new(), None, None);
    };
    let mut hashes: Vec<String> = package.metadata().wit_files.values().cloned().collect();
    hashes.sort();
    hashes.dedup();
    let update_source = verified_remote_update_source(package.metadata().source.as_deref());
    (hashes, package.metadata().wasm_hash.clone(), update_source)
}

fn read_durable_package(
    kernel: &crate::Kernel,
    authorization: &AuthorizedRequest,
    capsule: &str,
) -> anyhow::Result<Option<astrid_capsule_install::VerifiedDurableCapsulePackage>> {
    let uid = authenticated_uid(kernel, authorization)?;
    let store = Arc::new(
        kernel
            .principal_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("principal package store is unavailable"))?
            .clone(),
    );
    astrid_capsule_install::read_durable_capsule_package(&store, uid, capsule)
        .map(|introspection| Some(introspection.package))
}

fn verified_remote_update_source(source: Option<&str>) -> Option<String> {
    source
        .filter(|source| {
            astrid_capsule_install::github_source::parse_github_source(source).is_some()
        })
        .map(str::to_owned)
}

fn authenticated_uid(
    kernel: &crate::Kernel,
    authorization: &AuthorizedRequest,
) -> anyhow::Result<astrid_core::identity::PrincipalUid> {
    let identity = authorization
        .authenticated_identity()
        .map_err(|error| anyhow::anyhow!("authenticated principal identity required: {error}"))?;
    identity
        .confirm_live(kernel)
        .map_err(|error| anyhow::anyhow!("authenticated principal is not live: {error}"))?;
    Ok(identity.uid)
}

async fn durable_inventory(
    kernel: &crate::Kernel,
    authorization: &AuthorizedRequest,
) -> anyhow::Result<Vec<astrid_capsule_install::VerifiedDurableCapsulePackage>> {
    let uid = authenticated_uid(kernel, authorization)?;
    let store = Arc::new(
        kernel
            .principal_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("principal package store is unavailable"))?
            .clone(),
    );
    let packages = tokio::task::spawn_blocking(move || {
        astrid_capsule_install::list_durable_capsule_packages(&Arc::clone(&store), uid).map(
            |packages| {
                packages
                    .into_iter()
                    .map(|package| package.package)
                    .collect::<Vec<_>>()
            },
        )
    })
    .await
    .map_err(|error| anyhow::anyhow!("principal package inventory worker failed: {error}"))?
    .map_err(|error| anyhow::anyhow!("verify principal package inventory: {error}"))?;
    Ok(packages)
}

pub(super) async fn inventory_manifest_map(
    kernel: &crate::Kernel,
    authorization: &AuthorizedRequest,
) -> BTreeMap<String, astrid_capsule::manifest::CapsuleManifest> {
    let discovered = match durable_inventory(kernel, authorization).await {
        Ok(discovered) => discovered,
        Err(err) => {
            warn!(
                security_event = true,
                error = %err,
                "Principal package inventory denied or failed verification"
            );
            Vec::new()
        },
    };

    let visibility = CapsuleVisibility::new(authorization);
    discovered
        .into_iter()
        .filter_map(|package| {
            let id =
                astrid_capsule::capsule::CapsuleId::new(package.manifest().package.name.clone())
                    .ok()?;
            visibility
                .allows(&id)
                .then_some((id.to_string(), package.manifest().clone()))
        })
        .collect()
}

pub(super) async fn visible_inventory_manifests(
    kernel: &crate::Kernel,
    authorization: &AuthorizedRequest,
) -> Vec<astrid_capsule::manifest::CapsuleManifest> {
    inventory_manifest_map(kernel, authorization)
        .await
        .into_values()
        .collect()
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
