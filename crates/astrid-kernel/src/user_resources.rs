//! Boot-bound operator resource policy. Never fall back on invalid configuration.

use astrid_capsule::user_cpu::UserCpuAccounting;
use astrid_storage::{OwnershipStore, PrincipalDirectory};
use std::sync::Arc;

pub(crate) async fn execution_throttle(
    accounting: &UserCpuAccounting,
    profiles: &astrid_capsule::profile_cache::PrincipalProfileCache,
    groups: &arc_swap::ArcSwap<astrid_core::GroupConfig>,
    principal: &astrid_core::PrincipalId,
) -> Result<Option<astrid_capsule::user_cpu::throttle::ExecutionThrottle>, String> {
    // Preserve setup-free installs and avoid imposing a new profile lookup
    // on homes which have no configured user allowance.
    if accounting.resolve(principal).await?.is_none() {
        return Ok(None);
    }
    let profile = profiles
        .resolve(principal)
        .map_err(|error| error.to_string())?;
    let groups = groups.load_full();
    let rate =
        astrid_capsule::engine::wasm::cpu_rate_budget(Some(&profile), Some(&groups), principal);
    accounting.configured_throttle(principal, rate).await
}

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
