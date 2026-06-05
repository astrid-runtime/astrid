//! `astrid:uplink@1.0.0` host implementation.

use crate::engine::wasm::bindings::astrid::uplink::host::{
    self as uplink, ErrorCode, UplinkProfile,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

/// Map the WIT-level [`UplinkProfile`] to the core domain type.
fn map_profile(profile: UplinkProfile) -> astrid_core::UplinkProfile {
    match profile {
        UplinkProfile::Chat => astrid_core::UplinkProfile::Chat,
        UplinkProfile::Interactive => astrid_core::UplinkProfile::Interactive,
        UplinkProfile::Notify => astrid_core::UplinkProfile::Notify,
        UplinkProfile::Bridge => astrid_core::UplinkProfile::Bridge,
    }
}

impl uplink::Host for HostState {
    fn uplink_register(
        &mut self,
        name: String,
        platform: String,
        profile: UplinkProfile,
    ) -> Result<String, ErrorCode> {
        if !self.has_uplink_capability {
            return Err(ErrorCode::CapabilityDenied);
        }
        let platform = platform.trim().to_ascii_lowercase();
        if name.trim().is_empty() || platform.is_empty() {
            return Err(ErrorCode::InvalidInput);
        }

        let profile = map_profile(profile);
        let capsule_id = self.capsule_id.as_str().to_owned();
        let security = self.security.clone();
        let handle = self.runtime_handle.clone();
        let blocking_semaphore = self.blocking_semaphore.clone();

        if let Some(gate) = &security {
            let gate = gate.clone();
            let pid = capsule_id.clone();
            let cname = name.clone();
            let plat = platform.clone();
            let check = util::bounded_block_on(&handle, &blocking_semaphore, async move {
                gate.check_uplink_register(&pid, &cname, &plat).await
            });
            if check.is_err() {
                return Err(ErrorCode::CapabilityDenied);
            }
        }

        let source = astrid_core::UplinkSource::new_wasm(&capsule_id)
            .map_err(|e| ErrorCode::Unknown(format!("uplink source: {e}")))?;

        let descriptor = astrid_core::UplinkDescriptor::builder(name, platform)
            .source(source)
            .capabilities(astrid_core::UplinkCapabilities::receive_only())
            .profile(profile)
            .build();

        let uplink_id = descriptor.id.to_string();

        self.register_uplink(descriptor).map_err(|e| {
            if e.contains("limit") {
                ErrorCode::Quota
            } else {
                ErrorCode::InvalidInput
            }
        })?;

        Ok(uplink_id)
    }

    fn uplink_send(
        &mut self,
        uplink_id: String,
        platform_user_id: String,
        content: String,
    ) -> Result<bool, ErrorCode> {
        if !self.has_uplink_capability {
            return Err(ErrorCode::CapabilityDenied);
        }
        if uplink_id.len() > 64 {
            return Err(ErrorCode::InvalidInput);
        }

        let uplink_uuid: uuid::Uuid = uplink_id.parse().map_err(|_| ErrorCode::InvalidInput)?;
        let uplink_id = astrid_core::UplinkId::from_uuid(uplink_uuid);

        let inbound_tx = self.inbound_tx.clone();
        let platform = self
            .registered_uplinks
            .iter()
            .find(|c| c.id == uplink_id)
            .map(|c| c.platform.clone())
            .ok_or(ErrorCode::UnknownUplink)?;

        let tx = inbound_tx.ok_or(ErrorCode::Quota)?;

        let message =
            astrid_core::InboundMessage::builder(uplink_id, platform, platform_user_id, content)
                .build();

        // Per WIT: a send to a principal with no active session returns
        // `false` (intentional drop), not an error.
        match tx.try_send(message) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
