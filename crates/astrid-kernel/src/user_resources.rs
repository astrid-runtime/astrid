//! Boot-bound operator resource policy. Never fall back on invalid configuration.

use astrid_capsule::user_cpu::UserCpuAccounting;
use astrid_storage::{OwnershipStore, PrincipalDirectory};
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub(crate) fn load(
    ownership: Arc<OwnershipStore>,
    directory: PrincipalDirectory,
    home: &astrid_core::dirs::AstridHome,
    workspace: &std::path::Path,
    layout: &astrid_core::dirs::WorkspaceLayout,
) -> std::io::Result<Arc<UserCpuAccounting>> {
    let policy = load_policy(home, workspace, layout)?;
    Ok(Arc::new(UserCpuAccounting::new(
        ownership,
        directory,
        policy.default_user_cpu_fuel_per_sec,
        policy.user_cpu_fuel_per_sec,
    )))
}

fn load_policy(
    home: &astrid_core::dirs::AstridHome,
    workspace: &std::path::Path,
    layout: &astrid_core::dirs::WorkspaceLayout,
) -> std::io::Result<astrid_config::resources::ResourceConfig> {
    // The kernel may have been constructed with an explicit home independent
    // of process-wide ASTRID_HOME. Resource authority follows that captured
    // home, never a second ambient home lookup.
    Ok(
        astrid_config::Config::load_with_home_and_layout(Some(workspace), home.root(), layout)
            .map_err(|error| {
                std::io::Error::other(format!("load operator resource allocations: {error}"))
            })?
            .config
            .resources,
    )
}
