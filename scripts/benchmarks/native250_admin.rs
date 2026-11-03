//! Diagnostic admin calls over an explicitly authenticated public socket.
//! Uses uplink's deadline/correlation reader; no production client API changes.
use anyhow::{Context, ensure};
use astrid_core::kernel_api::{
    AdminKernelRequest, AdminKernelResponse, AdminRequestKind, AdminResponseBody,
    AgentDeriveKernelRequest, AgentDeriveRequest,
};
use astrid_core::{PrincipalId, SessionId};
use astrid_types::{
    Topic,
    ipc::{IpcMessage, IpcPayload},
};
use astrid_uplink::{
    admin_client::{request_topic, response_topic},
    socket_client::SocketClient,
};
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

pub struct AuthenticatedAdmin {
    socket: SocketClient,
    caller: PrincipalId,
    timeout: Duration,
}

fn response_payload(envelope: &Value) -> Option<&Value> {
    let payload = envelope.get("payload")?;
    if payload.get("type").is_some() && payload.get("value").is_some() {
        payload.get("value")
    } else {
        Some(payload)
    }
}

impl AuthenticatedAdmin {
    pub async fn connect(caller: PrincipalId) -> anyhow::Result<Self> {
        let socket = SocketClient::connect(SessionId::new(), caller.clone()).await?;
        ensure!(
            socket.is_authenticated(),
            "admin principal {caller} did not authenticate"
        );
        Ok(Self {
            socket,
            caller,
            timeout: Duration::from_secs(600),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn request(&mut self, kind: AdminRequestKind) -> anyhow::Result<AdminResponseBody> {
        let topic = request_topic(&kind);
        let response = response_topic(&kind);
        let id = Uuid::new_v4().to_string();
        let payload = serde_json::to_value(AdminKernelRequest::with_request_id(id.clone(), kind))?;
        self.exchange(topic, response, id, payload).await
    }

    pub async fn request_agent_derive(
        &mut self,
        request: AgentDeriveRequest,
    ) -> anyhow::Result<AdminResponseBody> {
        let id = Uuid::new_v4().to_string();
        let payload = serde_json::to_value(AgentDeriveKernelRequest {
            request_id: Some(id.clone()),
            request,
        })?;
        self.exchange(
            Topic::admin_request("agent.derive"),
            Topic::admin_response("agent.derive"),
            id,
            payload,
        )
        .await
    }

    async fn exchange(
        &mut self,
        topic: Topic,
        response: Topic,
        id: String,
        payload: Value,
    ) -> anyhow::Result<AdminResponseBody> {
        self.socket
            .send_message(
                IpcMessage::new(topic, IpcPayload::RawJson(payload), Uuid::nil())
                    .with_principal(self.caller.to_string()),
            )
            .await?;
        let raw = self
            .socket
            .read_until_matching_typed(self.timeout, |raw| {
                raw.get("topic").and_then(Value::as_str) == Some(response.as_str())
                    && response_payload(raw)
                        .and_then(|p| p.get("request_id"))
                        .and_then(Value::as_str)
                        == Some(id.as_str())
            })
            .await?;
        let payload = response_payload(&raw).context("matched admin response lacks payload")?;
        let reply: AdminKernelResponse = serde_json::from_value(payload.clone())?;
        ensure!(
            reply.request_id.as_deref() == Some(id.as_str()),
            "admin response correlation changed"
        );
        Ok(reply.body)
    }
}
