//! Per-transport lifetime around the shared broker, not another tool handler.

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ListToolsResult, PaginatedRequestParams,
    ProtocolVersion, ServerInfo, SubscriptionFilter,
};
use rmcp::service::{NotificationContext, RequestContext, RoleServer, SubscriptionContext};
use rmcp::{ErrorData, ServerHandler};
use tokio_util::sync::CancellationToken;

use super::super::server::AstridMcpServer;

pub(super) struct HttpHandler {
    broker: Arc<AstridMcpServer>,
    principal: astrid_core::PrincipalId,
    root: PathBuf,
    lifetime: CancellationToken,
}

impl HttpHandler {
    pub(super) fn new(
        broker: Arc<AstridMcpServer>,
        principal: astrid_core::PrincipalId,
        root: PathBuf,
    ) -> Self {
        Self {
            broker,
            principal,
            root,
            lifetime: CancellationToken::new(),
        }
    }
}

impl Drop for HttpHandler {
    fn drop(&mut self) {
        self.lifetime.cancel();
    }
}

impl ServerHandler for HttpHandler {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.broker.supported_protocol_versions()
    }

    fn get_info(&self) -> ServerInfo {
        self.broker.get_info()
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.broker.list_tools(request, context).await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.broker.call_tool(request, context).await
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.broker.accepted_subscription_filter(requested)
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        self.broker.listen(context).await
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        // Only legacy sessions initialize. Modern clients use request-scoped
        // subscriptions/listen above. Dropping this RMCP session cancels its
        // watcher even when no later capsule-change event arrives.
        let lifetime = self.lifetime.clone();
        let principal = self.principal.to_string();
        let root = self.root.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = lifetime.cancelled() => {},
                () = super::super::watch::run(context.peer, principal, root) => {},
            }
        });
    }
}
