use super::selected_native_artifact;

impl crate::Kernel {
    /// Configure fresh hosted ownership under an already-held native lifecycle guard.
    ///
    /// This dedicated controlling-account operation precedes ordinary Kernel boot:
    /// no capsules, deterministic owner/fleet or user delegation run. An explicit
    /// default target admits only the existing execution/frontend identity schema.
    /// The caller must drop all resources then finalize the lifecycle guard.
    ///
    /// # Errors
    /// Refuses legacy layout, live daemon, unsafe home, existing authority, invalid
    /// policy, non-increasing rotation, and persistence/admission failures.
    pub async fn configure_native_hosted_owner(
        home: &astrid_core::dirs::AstridHome,
        configuration: astrid_core::identity::hosted_owner::HostedOwnerConfiguration,
        target_default: bool,
    ) -> Result<astrid_storage::ownership::HostedOwnerRecord, std::io::Error> {
        configure(home, configuration, target_default, current_time).await
    }
}

fn current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u64::MAX, |time| time.as_secs())
}

async fn configure(
    home: &astrid_core::dirs::AstridHome,
    configuration: astrid_core::identity::hosted_owner::HostedOwnerConfiguration,
    target_default: bool,
    now: impl Fn() -> u64 + Send + Sync,
) -> Result<astrid_storage::ownership::HostedOwnerRecord, std::io::Error> {
    configuration
        .validate_selection(target_default, now())
        .map_err(std::io::Error::other)?;
    let artifact = selected_native_artifact()?;
    if home.layout_version()?.as_deref() == Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION) {
        return Err(std::io::Error::other(
            "legacy ownership migration is not supported by fresh provisioning",
        ));
    }
    home.ensure()?;
    // The caller holds the cross-platform RuntimeLifecycleGuard. Unix also
    // shares the kernel boot singleton; named-pipe hosts have no socket module.
    #[cfg(unix)]
    let _singleton = crate::socket::acquire_boot_singleton_lock(home)?;
    let directory = astrid_storage::PrincipalDirectory::default();
    let profiles = std::sync::Arc::new(
        astrid_capsule::profile_cache::PrincipalProfileCache::with_home(home.clone()),
    );
    let quota = crate::Kernel::storage_quota_resolver(profiles, directory.clone());
    let store =
        astrid_storage::open_runtime_principal_store_with_directory(home, quota, directory.clone())
            .await
            .map_err(std::io::Error::other)?;
    let kv = store.kv();
    let identity: std::sync::Arc<dyn astrid_storage::IdentityStore> =
        std::sync::Arc::new(astrid_storage::KvIdentityStore::with_principal_directory(
            astrid_storage::ScopedKvStore::new(std::sync::Arc::clone(&kv), "system:identity")
                .map_err(std::io::Error::other)?,
            directory.clone(),
        ));
    identity
        .load_principal_directory()
        .await
        .map_err(std::io::Error::other)?;
    let ownership = astrid_storage::OwnershipStore::new(kv, directory.clone())
        .map_err(std::io::Error::other)?;
    let graph = ownership.load().await.map_err(std::io::Error::other)?;
    let state = ownership
        .first_owner_state()
        .await
        .map_err(std::io::Error::other)?;
    if state.is_enrolled()
        || (state.is_pending() && graph.hosted_owner().is_none())
        || graph.fleets().next().is_some()
        || graph.principal_owners().next().is_some()
        || graph
            .hosted_owner()
            .is_some_and(|old| configuration.generation <= old.policy.generation)
    {
        return Err(std::io::Error::other(
            "existing ownership or policy cannot be replaced by fresh provisioning",
        ));
    }
    let target = if target_default {
        crate::seed_default_principal_admin_profile(home).map_err(std::io::Error::other)?;
        let (_, execution) = crate::bootstrap_cli_root_user(&identity, home)
            .await
            .map_err(std::io::Error::other)?;
        let bytes = std::fs::read(home.keys_dir().join("default.key"))?;
        let key = astrid_crypto::KeyPair::from_secret_key(&bytes).map_err(std::io::Error::other)?;
        astrid_core::identity::hosted_owner::HostedOwnerTarget {
            principal: execution.uid,
            public_key: *key.public_key_bytes(),
        }
    } else {
        configuration
            .target
            .clone()
            .ok_or_else(|| std::io::Error::other("missing explicit target"))?
    };
    let alias = directory
        .alias_for(target.principal)
        .map_err(std::io::Error::other)?;
    let profile =
        astrid_core::PrincipalProfile::load(home, &alias).map_err(std::io::Error::other)?;
    if !profile.enabled
        || profile
            .auth
            .device_by_pubkey(&hex::encode(target.public_key))
            .is_none()
    {
        return Err(std::io::Error::other(
            "target is not an enabled registered device",
        ));
    }
    ownership
        .configure_hosted_owner(configuration.with_target(target), artifact, now)
        .await
        .map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests;
