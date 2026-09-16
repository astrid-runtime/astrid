//! Composition of private local replies with host-owned secret requests.
//!
//! Binding is explicit: a caller selects the principal and already-approved
//! device key. Do not construct this from identity supplied in a reply frame.
//! This is not automatically enabled for every principal/device on daemon boot.

use std::collections::HashMap;
use std::sync::Arc;

use astrid_capsule::elicitation::{PendingSecretElicits, SecretElicitError, SecretElicitId};
use astrid_core::{PrincipalId, profile::DeviceKeyId};
use astrid_uplink::native::private_elicit::{PrivateElicitRejection, PrivateElicitResponder};
use uuid::Uuid;

type LiveDeviceCheck = Arc<dyn Fn(&PrincipalId, &str) -> bool + Send + Sync>;

/// A runtime-owned responder restricted to explicitly trusted principal/device
/// pairs. The uplink supplies the verified identity; the registry owns
/// the capsule/key destination. No request body can replace either boundary.
pub struct NativeSecretResponder {
    registry: Arc<PendingSecretElicits>,
    bindings: HashMap<PrincipalId, DeviceKeyId>,
    device_is_live: Option<LiveDeviceCheck>,
}

impl NativeSecretResponder {
    /// Bind a device fingerprint already approved by the operator/runtime.
    /// This constructor does not grant permissions, register device keys, or
    /// attach live profile revalidation. Production boot attaches a live profile check.
    ///
    /// # Errors
    /// Refuses a malformed fingerprint or the unauthenticated principal.
    pub fn new(
        registry: Arc<PendingSecretElicits>,
        principal: PrincipalId,
        device_key_id: String,
    ) -> Result<Self, PrivateElicitRejection> {
        if principal == PrincipalId::anonymous() {
            return Err(PrivateElicitRejection::Forbidden);
        }
        let device =
            DeviceKeyId::new(device_key_id).map_err(|_| PrivateElicitRejection::Forbidden)?;
        Ok(Self {
            registry,
            bindings: [(principal, device)].into(),
            device_is_live: None,
        })
    }

    /// Recheck the live principal profile after the boot binding matches.
    #[must_use]
    pub(crate) fn with_live_device_check(
        mut self,
        check: impl Fn(&PrincipalId, &str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.device_is_live = Some(Arc::new(check));
        self
    }

    fn device_may_reply(&self, principal: &PrincipalId, device_key_id: &str) -> bool {
        self.bindings
            .get(principal)
            .is_some_and(|device| device.as_str() == device_key_id)
            && self
                .device_is_live
                .as_ref()
                .is_none_or(|check| check(principal, device_key_id))
    }
}

impl PrivateElicitResponder for NativeSecretResponder {
    fn reply(
        &self,
        principal: &PrincipalId,
        device_key_id: &str,
        request_id: Uuid,
        value: Option<String>,
        values: Option<Vec<String>>,
    ) -> Result<(), PrivateElicitRejection> {
        if !self.device_may_reply(principal, device_key_id) {
            return Err(PrivateElicitRejection::Forbidden);
        }
        self.registry
            .reply_for_principal(
                SecretElicitId::from_uuid(request_id),
                principal,
                value,
                values,
            )
            .map_err(|error| match error {
                SecretElicitError::IdentityMismatch => PrivateElicitRejection::Forbidden,
                SecretElicitError::EmptySecret
                | SecretElicitError::EmptyKey
                | SecretElicitError::InvalidAnswer => PrivateElicitRejection::Invalid,
                _ => PrivateElicitRejection::Unavailable,
            })
    }
}

/// Compose operator-selected routing before boot capsules load. Empty bindings
/// keep the legacy transport. This never pairs keys or changes a profile.
///
/// # Errors
/// Refuses malformed config, an invalid pending-request limit, or a second bind.
pub(crate) fn configure(
    kernel: &Arc<astrid_kernel::Kernel>,
    config: &astrid_config::Config,
) -> anyhow::Result<Option<Arc<dyn PrivateElicitResponder>>> {
    let bindings = config.native_input.bindings()?;
    if bindings.is_empty() {
        return Ok(None);
    }
    let capacity = usize::try_from(config.rate_limits.max_pending_requests)
        .ok()
        .and_then(std::num::NonZeroUsize::new)
        .ok_or_else(|| anyhow::anyhow!("native input needs a positive pending-request limit"))?;
    let registry = Arc::new(PendingSecretElicits::for_principals(
        capacity,
        bindings.keys().cloned().collect(),
    ));
    kernel.bind_native_secret_inputs(Arc::clone(&registry))?;
    let kernel = Arc::clone(kernel);
    Ok(Some(Arc::new(
        NativeSecretResponder {
            registry,
            bindings,
            device_is_live: None,
        }
        .with_live_device_check(move |principal, device_key_id| {
            kernel.native_input_device_is_live(principal, device_key_id)
        }),
    )))
}

#[cfg(test)]
mod tests;
