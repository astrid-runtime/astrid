use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};

use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};
use serde_json::{Value, json};

use super::*;

#[derive(Default)]
struct Probe(AtomicUsize);

impl ServerHandler for Probe {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![
            ProtocolVersion::V_2026_07_28,
            ProtocolVersion::V_2025_11_25,
        ])
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        (requested.tools_list_changed == Some(true))
            .then(|| SubscriptionFilter::builder().tools_list_changed().build())
    }

    async fn listen(
        &self,
        context: rmcp::service::SubscriptionContext,
    ) -> Result<(), rmcp::ErrorData> {
        context.sink().notify_tool_list_changed().await.unwrap();
        Ok(())
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(ListToolsResult::with_all_items(vec![]))
    }

    async fn call_tool(
        &self,
        _: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(CallToolResult::success(vec![ContentBlock::text("invoked")]).into())
    }
}

struct Endpoint {
    url: String,
    probe: Arc<Probe>,
    task: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

async fn endpoint() -> Endpoint {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let probe = Arc::new(Probe::default());
    let cancel = CancellationToken::new();
    let factory_probe = probe.clone();
    let app = router(
        move || Ok(factory_probe.clone()),
        auth::test_token(),
        address,
        cancel.clone(),
    );
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Endpoint {
        url: format!("http://{address}/mcp"),
        probe,
        task,
        cancel,
    }
}

fn request(endpoint: &Endpoint, method: &str) -> reqwest::RequestBuilder {
    let params = json!({"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name":"test", "version":"1"},
        "io.modelcontextprotocol/clientCapabilities": {}
    }});
    let mut body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    if method == "tools/call" {
        body["params"]["name"] = json!("probe");
        body["params"]["arguments"] = json!({});
    }
    if method == "subscriptions/listen" {
        body["params"]["notifications"] = json!({"toolsListChanged":true});
    }
    let request = reqwest::Client::new()
        .post(&endpoint.url)
        .bearer_auth("a".repeat(32))
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", method)
        .json(&body);
    if method == "tools/call" {
        request.header("Mcp-Name", "probe")
    } else {
        request
    }
}

#[tokio::test]
async fn stateless_discovery_and_concurrent_calls_use_the_real_http_service() {
    let endpoint = endpoint().await;
    let response = request(&endpoint, "tools/list").send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("Mcp-Session-Id"));
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["result"]["tools"], json!([]));
    let (a, b) = tokio::join!(
        request(&endpoint, "tools/call").send(),
        request(&endpoint, "tools/call").send()
    );
    for response in [a.unwrap(), b.unwrap()] {
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["result"]["content"][0]["text"], "invoked");
    }
    assert_eq!(endpoint.probe.0.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn auth_origin_and_dns_rebinding_fail_before_handler_dispatch() {
    let endpoint = endpoint().await;
    let missing = reqwest::Client::new()
        .post(&endpoint.url)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 401);
    let bad = request(&endpoint, "tools/list")
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 401);
    let origin = request(&endpoint, "tools/list")
        .header("Origin", "null")
        .send()
        .await
        .unwrap();
    assert_eq!(origin.status(), 403);
    let host = request(&endpoint, "tools/list")
        .header("Host", "attacker.example")
        .send()
        .await
        .unwrap();
    assert_eq!(host.status(), 403);
    assert_eq!(endpoint.probe.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn modern_subscription_emits_acknowledgment_and_tool_change_on_post_stream() {
    let endpoint = endpoint().await;
    let response = request(&endpoint, "subscriptions/listen")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("Mcp-Session-Id"));
    let body = response.text().await.unwrap();
    assert!(
        body.contains("notifications/subscriptions/acknowledged"),
        "{body}"
    );
    assert!(body.contains("notifications/tools/list_changed"), "{body}");
}

#[tokio::test]
async fn legacy_client_can_initialize_then_list_through_the_same_endpoint() {
    let endpoint = endpoint().await;
    let client = reqwest::Client::new();
    let response = client.post(&endpoint.url).bearer_auth("a".repeat(32))
        .header("Accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
            "protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"legacy", "version":"1"}
        }})).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let session = response.headers().get("Mcp-Session-Id").unwrap().clone();
    for (id, method) in [(None, "notifications/initialized"), (Some(2), "tools/list")] {
        let mut body = json!({"jsonrpc":"2.0", "method":method});
        if let Some(id) = id {
            body["id"] = json!(id);
        }
        let response = client
            .post(&endpoint.url)
            .bearer_auth("a".repeat(32))
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-11-25")
            .header("Mcp-Session-Id", session.clone())
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        if id.is_some() {
            assert!(response.text().await.unwrap().contains("tools"));
        }
    }
    assert_eq!(endpoint.probe.0.load(Ordering::Relaxed), 1);
}

#[test]
fn listener_cannot_silently_expose_the_principal_to_the_network() {
    assert!(validate_bind("127.0.0.1:0".parse().unwrap()).is_ok());
    assert!(validate_bind("[::1]:8081".parse().unwrap()).is_ok());
    assert!(validate_bind("0.0.0.0:8081".parse().unwrap()).is_err());
    assert!(validate_bind("192.168.1.2:8081".parse().unwrap()).is_err());
}

#[cfg(unix)]
#[test]
fn credential_requires_a_private_regular_file() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, "a".repeat(32)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(auth::BearerToken::read(&path).is_ok());
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(auth::BearerToken::read(&link).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(auth::BearerToken::read(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, "short").unwrap();
    assert!(auth::BearerToken::read(&path).is_err());
}
