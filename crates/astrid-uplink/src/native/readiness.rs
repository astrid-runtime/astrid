//! Demand-load the authenticated caller before admitting capsule request IPC.

use super::{handshake::AuthenticatedIdentity, private_elicit, routing};
use astrid_core::kernel_api::CapsuleTopicProbe;
use astrid_types::ipc::IpcMessage;
use std::sync::Arc;

#[derive(Clone, Default)]
pub(super) struct ConnectionServices {
    pub(super) private_elicits: Option<Arc<dyn private_elicit::PrivateElicitResponder>>,
    pub(super) topic_probe: Option<CapsuleTopicProbe>,
}

impl From<Option<Arc<dyn private_elicit::PrivateElicitResponder>>> for ConnectionServices {
    fn from(private_elicits: Option<Arc<dyn private_elicit::PrivateElicitResponder>>) -> Self {
        Self {
            private_elicits,
            topic_probe: None,
        }
    }
}

#[derive(Default)]
pub(super) struct InputServices<'a> {
    pub(super) private_elicits: Option<&'a dyn private_elicit::PrivateElicitResponder>,
    pub(super) topic_probe: Option<&'a CapsuleTopicProbe>,
}

impl<'a> From<Option<&'a dyn private_elicit::PrivateElicitResponder>> for InputServices<'a> {
    fn from(private_elicits: Option<&'a dyn private_elicit::PrivateElicitResponder>) -> Self {
        Self {
            private_elicits,
            topic_probe: None,
        }
    }
}

impl ConnectionServices {
    pub(super) fn input_services(&self) -> InputServices<'_> {
        InputServices {
            private_elicits: self.private_elicits.as_deref(),
            topic_probe: self.topic_probe.as_ref(),
        }
    }
}

pub(super) async fn ensure(
    probe: Option<&CapsuleTopicProbe>,
    identity: &AuthenticatedIdentity,
    message: &IpcMessage,
) -> Result<(), &'static str> {
    let Some(probe) = probe else {
        return Ok(());
    };
    let topic = message.topic.as_str();
    // Kernel management and human replies must remain usable during loading.
    // Cancellation retires an existing turn and must never initiate a load.
    if !identity.is_principal_verified()
        || !routing::capsule_request_topic(topic)
        || routing::is_cancel_turn(&message.payload)
    {
        return Ok(());
    }
    let key = format!("\0astrid.scoped-topic\0{}\0{topic}", identity.principal);
    if probe.is_subscribed(&key).await || probe.ensure_subscribed(&key).await {
        Ok(())
    } else {
        Err("this principal's capsule request provider is not ready")
    }
}

#[cfg(test)]
mod tests;
