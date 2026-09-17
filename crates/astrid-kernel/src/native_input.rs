//! Boot-only private-input composition; reloads reuse the same registry.

#[cfg(not(target_family = "wasm"))]
use astrid_capsule::elicitation::PendingSecretElicits;
use astrid_capsule::profile_cache::PrincipalProfileCache;
use astrid_core::PrincipalId;
use astrid_core::profile::DeviceKeyId;
#[cfg(not(target_family = "wasm"))]
use std::sync::Arc;

/// Recheck the live principal profile before a private secret reply.
///
/// Handshake identity is cached for the socket lifetime. Secret replies must
/// fail closed if the principal is missing or disabled, or if the device key
/// is no longer registered, including after `pair_device_revoke`.
#[must_use]
pub fn native_input_device_is_live(
    cache: &PrincipalProfileCache,
    principal: &PrincipalId,
    device_key_id: &str,
) -> bool {
    let Ok(key_id) = DeviceKeyId::new(device_key_id) else {
        return false;
    };
    let Ok(profile) = cache.resolve(principal) else {
        return false;
    };
    profile.enabled && profile.auth.device_by_typed_key_id(&key_id).is_some()
}

impl crate::Kernel {
    /// Bind private secret routing before loading boot capsules. This shares
    /// waiter ownership with the native responder; it does not register keys.
    ///
    /// # Errors
    /// A second binding is refused. Changing routing requires a daemon restart.
    #[cfg(not(target_family = "wasm"))]
    pub fn bind_native_secret_inputs(
        &self,
        registry: Arc<PendingSecretElicits>,
    ) -> Result<(), std::io::Error> {
        self.native_secret_inputs
            .set(registry)
            .map_err(|_| std::io::Error::other("native secret input routing is already bound"))
    }

    /// Live profile revalidation for private secret replies.
    ///
    /// This uses the same profile cache that `pair_device_revoke` invalidates.
    /// Cached native handshake identity is not sufficient after revoke or
    /// disable.
    #[must_use]
    pub fn native_input_device_is_live(
        &self,
        principal: &PrincipalId,
        device_key_id: &str,
    ) -> bool {
        native_input_device_is_live(&self.profile_cache, principal, device_key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::PrincipalProfile;
    use astrid_core::dirs::AstridHome;
    use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope};
    use astrid_crypto::KeyPair;

    #[cfg(not(target_family = "wasm"))]
    #[tokio::test]
    async fn native_input_boot_binding_is_write_once() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path().to_path_buf());
        let kernel = crate::test_kernel_with_home(home).await;
        assert!(kernel.native_secret_inputs.get().is_none());
        let registry = Arc::new(PendingSecretElicits::for_principals(
            std::num::NonZeroUsize::MIN,
            [PrincipalId::new("alice").unwrap()].into(),
        ));
        kernel
            .bind_native_secret_inputs(Arc::clone(&registry))
            .unwrap();
        assert!(Arc::ptr_eq(
            kernel.native_secret_inputs.get().unwrap(),
            &registry
        ));
        assert!(
            kernel
                .bind_native_secret_inputs(Arc::new(PendingSecretElicits::new(
                    std::num::NonZeroUsize::MIN
                )))
                .is_err()
        );
        assert!(Arc::ptr_eq(
            kernel.native_secret_inputs.get().unwrap(),
            &registry
        ));
    }

    fn seed_alice_device(kernel: &crate::Kernel) -> (PrincipalId, String, std::path::PathBuf) {
        let principal = PrincipalId::new("alice").unwrap();
        let key = KeyPair::generate();
        let device = DeviceKey::new(key.export_public_key().to_hex(), DeviceScope::Full, None, 0);
        let device_id = device.key_id.clone();
        let path = PrincipalProfile::path_for(&kernel.astrid_home, &principal);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut profile = PrincipalProfile::default();
        profile.auth.public_keys.push(device);
        profile.auth.methods.push(AuthMethod::Keypair);
        profile.save_to_path(&path).unwrap();
        kernel.profile_cache.invalidate(&principal);
        (principal, device_id, path)
    }

    #[tokio::test]
    async fn missing_or_malformed_native_input_device_is_not_live() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path().to_path_buf());
        let kernel = crate::test_kernel_with_home(home).await;
        let (principal, device_id, _) = seed_alice_device(&kernel);
        assert!(kernel.native_input_device_is_live(&principal, &device_id));
        assert!(!kernel.native_input_device_is_live(&principal, "0123456789abcdef"));
        assert!(!kernel.native_input_device_is_live(&principal, "not-a-device-id"));
        assert!(!kernel.native_input_device_is_live(&PrincipalId::new("bob").unwrap(), &device_id));
    }

    #[tokio::test]
    async fn revoked_or_disabled_device_is_not_live_for_native_input() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path().to_path_buf());
        let kernel = crate::test_kernel_with_home(home).await;
        let (principal, device_id, path) = seed_alice_device(&kernel);
        assert!(kernel.native_input_device_is_live(&principal, &device_id));

        let mut profile = PrincipalProfile::load_from_path(&path).unwrap();
        profile.auth.public_keys.clear();
        profile
            .auth
            .methods
            .retain(|method| *method != AuthMethod::Keypair);
        profile.save_to_path(&path).unwrap();
        kernel.profile_cache.invalidate(&principal);
        assert!(!kernel.native_input_device_is_live(&principal, &device_id));

        let key = KeyPair::generate();
        let device = DeviceKey::new(key.export_public_key().to_hex(), DeviceScope::Full, None, 0);
        let restored_id = device.key_id.clone();
        profile.auth.public_keys.push(device);
        profile.enabled = false;
        profile.save_to_path(&path).unwrap();
        kernel.profile_cache.invalidate(&principal);
        assert!(!kernel.native_input_device_is_live(&principal, &restored_id));
    }
}
