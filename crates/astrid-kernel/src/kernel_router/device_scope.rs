//! Shared authenticating-device scope resolution for kernel authority checks.

use astrid_capabilities::PermissionError;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{DeviceKeyId, DeviceScope, PrincipalProfile};
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
    Ok(Some(device.scope.clone()))
}
