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
    policy: &astrid_config::resources::ResourceConfig,
) -> Arc<UserCpuAccounting> {
    Arc::new(UserCpuAccounting::new(
        ownership,
        directory,
        policy.default_user_cpu_fuel_per_sec,
        policy.user_cpu_fuel_per_sec.clone(),
    ))
}

/// Apply operator cache policy after the durable config projection is admitted.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn configure_object_cache(
    store: &astrid_storage::RuntimePrincipalStore,
    policy: &astrid_config::resources::ResourceConfig,
) -> std::io::Result<()> {
    if let Some(bytes) = policy.location_index_memory_bytes {
        let budget = astrid_storage::LocationIndexMemoryBudget::new(bytes.get())
            .map_err(std::io::Error::other)?;
        store
            .set_location_index_memory(budget)
            .map_err(std::io::Error::other)?;
    }
    if let Some(bytes) = policy.decoded_object_cache_bytes {
        store.set_object_cache_capacity(astrid_storage::engine::ObjectCacheCapacity::Bounded(
            bytes.get(),
        ));
    }
    Ok(())
}
