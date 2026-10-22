//! Shared authenticating-device scope resolution for kernel authority checks.

use astrid_capabilities::PermissionError;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{DeviceKey, DeviceKeyId, DeviceScope, PrincipalProfile};
use tracing::warn;

/// Resolve the authenticating device's attenuation floor.
///
/// A supplied id must be canonical and registered to `caller`; an invalid,
/// unknown, or revoked id never falls back to full-principal authority.
/// Resolution failures deliberately share the outward scope-denial reason so
/// authorization responses cannot reveal whether a device key exists. The
/// structured security warning retains the operator-visible cause.
pub(super) fn resolve_device_scope(
    profile: &PrincipalProfile,
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    required_cap: &str,
) -> Result<Option<DeviceScope>, PermissionError> {
    resolve_device(profile, caller, device_key_id, required_cap)
        .map(|device| device.map(|device| device.scope.clone()))
}

/// Resolve the registered credential identified by trusted transport metadata.
/// The returned profile entry is not proof by itself: callers must only pass
/// the device id stamped by the authenticating transport, never request JSON.
pub(super) fn resolve_device<'a>(
    profile: &'a PrincipalProfile,
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    required_cap: &str,
) -> Result<Option<&'a DeviceKey>, PermissionError> {
    let Some(raw_key_id) = device_key_id else {
        return Ok(None);
    };
    let key_id = match DeviceKeyId::new(raw_key_id) {
        Ok(key_id) => key_id,
        Err(reason) => {
            warn!(
                security_event = true,
                principal = %caller,
                key_id = %raw_key_id,
                required = required_cap,
                error = %reason,
                "device_key_id is invalid — fail-closed deny"
            );
            return Err(PermissionError::DeviceScopeDenied {
                principal: caller.clone(),
                required: required_cap.to_string(),
            });
        },
    };
    let Some(device) = profile.auth.device_by_typed_key_id(&key_id) else {
        warn!(
            security_event = true,
            principal = %caller,
            key_id = %raw_key_id,
            required = required_cap,
            "device_key_id resolves to no registered key — fail-closed deny"
        );
        return Err(PermissionError::DeviceScopeDenied {
            principal: caller.clone(),
            required: required_cap.to_string(),
        });
    };
    Ok(Some(device))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_resolution_preserves_exact_device_and_has_no_legacy_fallback() {
        let caller = PrincipalId::default();
        let first = DeviceKey::new("a".repeat(64), DeviceScope::Full, None, 0);
        let second = DeviceKey::new("b".repeat(64), DeviceScope::Full, None, 0);
        let mut profile = PrincipalProfile::default();
        profile.auth.public_keys = vec![first.clone(), second.clone()];
        let resolved = resolve_device(&profile, &caller, Some(&second.key_id), "agent:create")
            .unwrap()
            .unwrap();
        assert_eq!(resolved.pubkey, second.pubkey);
        assert_ne!(resolved.pubkey, first.pubkey);
        assert!(
            resolve_device(&profile, &caller, None, "agent:create")
                .unwrap()
                .is_none()
        );
        profile
            .auth
            .public_keys
            .retain(|key| key.key_id != second.key_id);
        assert!(resolve_device(&profile, &caller, Some(&second.key_id), "agent:create").is_err());
        assert!(resolve_device(&profile, &caller, Some("invalid"), "agent:create").is_err());
    }
}
