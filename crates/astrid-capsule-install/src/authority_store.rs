//! Authority verification against the packed system executable catalog.

use std::path::Path;

use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::dirs::AstridHome;
use astrid_storage::RuntimePrincipalStore;

/// Verify an installed manifest using `System/bin/<hash>.wasm`.
///
/// Storage-backed materializations are disposable projections; a native
/// `bin/` file is never accepted as the executable authority source.
pub fn verify_installed_authority_with_store(
    home: &AstridHome,
    target_dir: &Path,
    manifest: &CapsuleManifest,
    store: &RuntimePrincipalStore,
) -> anyhow::Result<()> {
    super::authority::verify_installed_authority_inner(home, target_dir, manifest, Some(store))
}
