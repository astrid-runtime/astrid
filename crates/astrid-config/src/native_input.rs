//! Boot-bound native input routing. Device pairing remains a separate operation.

use crate::{ConfigError, ConfigResult};
use astrid_core::{PrincipalId, profile::DeviceKeyId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Explicit principal/device bindings. Neither workspace config nor a socket
/// peer may select these. Keys must also pass ordinary profile authentication.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NativeInputConfig {
    /// Principal names mapped to already-paired device fingerprints.
    pub responders: BTreeMap<String, String>,
}

impl NativeInputConfig {
    /// Validate and convert the wire configuration to domain identities.
    ///
    /// # Errors
    /// Rejects malformed principals, anonymous identities and device handles.
    pub fn bindings(&self) -> ConfigResult<HashMap<PrincipalId, DeviceKeyId>> {
        self.responders
            .iter()
            .map(|(principal, device)| {
                let invalid = || ConfigError::ValidationError {
                    field: "native_input.responders".into(),
                    message: "expected a non-anonymous principal and canonical device fingerprint"
                        .into(),
                };
                let principal = PrincipalId::new(principal).map_err(|_| invalid())?;
                if principal == PrincipalId::anonymous() {
                    return Err(invalid());
                }
                let device = DeviceKeyId::new(device.clone()).map_err(|_| invalid())?;
                Ok((principal, device))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
