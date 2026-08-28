use super::*;
use rmcp::ServiceExt as _;
use rmcp::model::ProtocolVersion;

#[derive(Clone, Default)]
struct ModernLifecycleServer;

impl rmcp::ServerHandler for ModernLifecycleServer {}

#[derive(Clone, Default)]
struct ModernMrtrServer {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl rmcp::ServerHandler for ModernMrtrServer {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        rmcp::model::ServerInfo::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_protocol_version(ProtocolVersion::V_2026_07_28)
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if request.input_responses.is_none() {
            let params = rmcp::model::ElicitRequestParams::FormElicitationParams {
                meta: None,
                message: "Name?".into(),
                requested_schema: serde_json::from_value(serde_json::json!({
                    "type": "object",
                    "properties": { "name": { "type": "string" } },
                    "required": ["name"]
                }))
                .expect("valid test schema"),
            };
            let mut requests = rmcp::model::InputRequests::new();
            requests.insert(
                "answer".to_string(),
                rmcp::model::InputRequest::Elicitation(rmcp::model::ElicitRequest::new(params)),
            );
            return Ok(rmcp::model::InputRequiredResult::new(
                Some(requests),
                Some("awaiting-name".into()),
            )
            .into());
        }

        let name = request
            .input_responses
            .as_ref()
            .and_then(|responses| responses.get("answer"))
            .and_then(|response| response["content"]["name"].as_str());
        if request.request_state.as_deref() != Some("awaiting-name") || name != Some("Ferris") {
            return Err(rmcp::ErrorData::invalid_params(
                "MRTR response was not preserved",
                None,
            ));
        }
        Ok(
            rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(
                "hello Ferris",
            )])
            .into(),
        )
    }
}

struct TestElicitationHandler;

#[async_trait::async_trait]
impl crate::capabilities::ElicitationHandler for TestElicitationHandler {
    async fn handle_elicitation(
        &self,
        request: astrid_core::ElicitationRequest,
    ) -> astrid_core::ElicitationResponse {
        astrid_core::ElicitationResponse::submit(
            request.request_id,
            serde_json::Value::String("Ferris".to_string()),
        )
    }
}

#[derive(Clone, Default)]
struct LegacyLifecycleServer;

impl rmcp::ServerHandler for LegacyLifecycleServer {
    async fn discover(
        &self,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::DiscoverResult, rmcp::ErrorData> {
        Err(rmcp::ErrorData::method_not_found::<
            rmcp::model::DiscoverRequestMethod,
        >())
    }

    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        std::borrow::Cow::Borrowed(&[ProtocolVersion::V_2025_11_25])
    }
}

async fn negotiated_protocol<S>(server: S) -> ProtocolVersion
where
    S: rmcp::ServerHandler + Send + 'static,
{
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move {
        let service = server
            .serve(server_transport)
            .await
            .expect("test server should start");
        let _ = service.waiting().await;
    });

    let client = AstridClientHandler::new("test-server", Arc::new(CapabilitiesHandler::new()))
        .serve_with_lifecycle(client_transport, mcp_client_lifecycle())
        .await
        .expect("Astrid client should negotiate a lifecycle");
    let protocol = client
        .peer_info()
        .expect("negotiation should record server information")
        .protocol_version
        .clone();
    client.cancel().await.expect("client should stop cleanly");
    tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
        .await
        .expect("server should stop after its client disconnects")
        .expect("server task should not panic");
    protocol
}

#[tokio::test]
async fn client_lifecycle_prefers_modern_discovery() {
    assert_eq!(
        negotiated_protocol(ModernLifecycleServer).await,
        ProtocolVersion::V_2026_07_28
    );
}

#[tokio::test]
async fn client_lifecycle_falls_back_to_legacy_initialize() {
    assert_eq!(
        negotiated_protocol(LegacyLifecycleServer).await,
        ProtocolVersion::V_2025_11_25
    );
}

#[tokio::test]
async fn modern_tool_call_drives_mrtr_through_astrid_elicitation() {
    let server = ModernMrtrServer::default();
    let calls = Arc::clone(&server.calls);
    let (server_transport, client_transport) = tokio::io::duplex(8192);
    let server_task = tokio::spawn(async move {
        let service = server
            .serve(server_transport)
            .await
            .expect("MRTR server should start");
        let _ = service.waiting().await;
    });

    let mut capabilities = CapabilitiesHandler::new();
    capabilities.elicitation = Some(Box::new(TestElicitationHandler));
    let client = AstridClientHandler::new("test-server", Arc::new(capabilities))
        .serve_with_lifecycle(client_transport, mcp_client_lifecycle())
        .await
        .expect("Astrid client should negotiate modern MCP");
    let result = client
        .call_tool(rmcp::model::CallToolRequestParams::new("greet"))
        .await
        .expect("Astrid should satisfy the MRTR input request");
    assert_eq!(
        result.content[0].as_text().expect("text tool result").text,
        "hello Ferris"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);

    client.cancel().await.expect("client should stop cleanly");
    tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
        .await
        .expect("server should stop after its client disconnects")
        .expect("server task should not panic");
}

#[cfg(unix)]
const RELUCTANT_FIXTURE_ENV: &str = "ASTRID_MCP_RELUCTANT_FIXTURE";
#[cfg(unix)]
const RELUCTANT_DESCENDANT_PID_ENV: &str = "ASTRID_MCP_DESCENDANT_PID_FILE";

#[cfg(unix)]
struct ReluctantMcpServer;

#[cfg(unix)]
impl rmcp::ServerHandler for ReluctantMcpServer {}

/// Subprocess-only fixture driven by `stop_awaits_rmcp_process_tree_termination`.
/// It completes the real MCP handshake, spawns a descendant, then refuses
/// to exit after its stdio service closes so rmcp must take its forced
/// process-tree termination path.
#[cfg(unix)]
#[ignore = "subprocess-only MCP fixture"]
#[tokio::test]
async fn reluctant_mcp_server_fixture() {
    if std::env::var_os(RELUCTANT_FIXTURE_ENV).is_none() {
        return;
    }
    let pid_file =
        std::env::var_os(RELUCTANT_DESCENDANT_PID_ENV).expect("fixture descendant pid file");
    let mut descendant = tokio::process::Command::new("/bin/sh");
    descendant
        .arg("-c")
        .arg("echo $$ > \"$1\"; trap '' TERM; while :; do sleep 1; done")
        .arg("astrid-mcp-descendant")
        .arg(pid_file);
    let _descendant = descendant.spawn().expect("spawn fixture descendant");

    let service = ReluctantMcpServer
        .serve(rmcp::transport::stdio())
        .await
        .expect("serve fixture MCP");
    let _ = service.waiting().await;
    std::future::pending::<()>().await;
}

#[cfg(unix)]
fn assert_process_terminated(pid: nix::unistd::Pid) {
    use nix::errno::Errno;
    use nix::sys::signal::kill;

    match kill(pid, None) {
        Err(Errno::ESRCH) => return,
        Ok(()) => {},
        Err(error) => panic!("failed to inspect descendant {pid}: {error}"),
    }

    // The process-group leader can reap only its own children. Once that
    // leader exits, a killed descendant belongs to the platform reaper and
    // can remain visible briefly as a zombie (not an executable process).
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "state=", "-p", &pid.as_raw().to_string()])
        .output()
        .expect("inspect descendant process state");
    if !output.status.success() {
        assert_eq!(
            kill(pid, None),
            Err(Errno::ESRCH),
            "descendant disappeared from ps for an unexpected reason"
        );
        return;
    }

    let state = output
        .stdout
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .map(char::from);
    assert_eq!(
        state,
        Some('Z'),
        "stop returned while descendant {pid} remained executable"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn stop_awaits_rmcp_process_tree_termination() {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    let temp = tempfile::tempdir().expect("tempdir");
    let pid_file = temp.path().join("descendant.pid");
    let executable = std::env::current_exe().expect("current test executable");
    let mut config = ServerConfig::stdio("reluctant", executable.to_string_lossy()).trusted();
    config.args = vec![
        "--ignored".to_string(),
        "--exact".to_string(),
        "server::tests::reluctant_mcp_server_fixture".to_string(),
        "--quiet".to_string(),
        "--nocapture".to_string(),
        "--test-threads=1".to_string(),
    ];
    config
        .env
        .insert(RELUCTANT_FIXTURE_ENV.to_string(), "1".to_string());
    config.env.insert(
        RELUCTANT_DESCENDANT_PID_ENV.to_string(),
        pid_file.to_string_lossy().into_owned(),
    );

    // Exercise the old failure condition: crossing this threshold must
    // warn, not detach the only future that owns tree termination.
    let configs = ServersConfig {
        shutdown_timeout: std::time::Duration::from_millis(1),
        ..ServersConfig::default()
    };
    let manager = Arc::new(ServerManager::new(configs));
    manager
        .add_server("reluctant", config)
        .await
        .expect("register fixture server");
    manager
        .connect_server("reluctant", Arc::new(CapabilitiesHandler::new()), None)
        .await
        .expect("connect real fixture MCP server");

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !pid_file.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixture descendant should report its pid");
    let descendant_pid: i32 = std::fs::read_to_string(&pid_file)
        .expect("read descendant pid")
        .trim()
        .parse()
        .expect("parse descendant pid");
    assert!(kill(Pid::from_raw(descendant_pid), None).is_ok());

    // A reluctant tree must not hold the global running-map lock and stall
    // unrelated MCP peers while rmcp performs its forced shutdown.
    manager.running.write().await.insert(
        "peer".to_string(),
        RunningServer::new(ServerConfig::stdio("peer", "/usr/bin/false")),
    );
    let stopping_manager = Arc::clone(&manager);
    let stopping = tokio::spawn(async move { stopping_manager.stop("reluctant").await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            manager.is_running("peer")
        )
        .await
        .expect("peer lookup must not wait for another server's teardown")
    );

    tokio::time::timeout(std::time::Duration::from_secs(8), stopping)
        .await
        .expect("owned rmcp teardown should remain bounded")
        .expect("stop task should join")
        .expect("stop fixture server");

    assert_process_terminated(Pid::from_raw(descendant_pid));
}

#[cfg(unix)]
#[tokio::test]
async fn process_tree_wrapper_kills_descendants_without_touching_peer_group() {
    let temp = tempfile::tempdir().expect("tempdir");
    let descendant_effect = temp.path().join("descendant-effect");
    let peer_effect = temp.path().join("peer-effect");
    let ready = temp.path().join("ready");

    let mut owned_command = tokio::process::Command::new("/bin/sh");
    owned_command
        .arg("-c")
        .arg("(sleep 0.4; : > \"$1\") & : > \"$2\"; wait")
        .arg("astrid-mcp-test")
        .arg(&descendant_effect)
        .arg(&ready);
    let owned = OwnedProcessTransport::new(wrap_process_tree(owned_command))
        .expect("spawn owned transport");

    let mut peer = tokio::process::Command::new("/bin/sh");
    peer.arg("-c")
        .arg("sleep 0.4; : > \"$1\"")
        .arg("astrid-mcp-peer")
        .arg(&peer_effect);
    let mut peer = peer.spawn().expect("spawn peer process group");

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !ready.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owned descendant should start");

    drop(owned);
    peer.wait().await.expect("wait for peer");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert!(
        !descendant_effect.exists(),
        "a descendant of the retired MCP server must not survive"
    );
    assert!(
        peer_effect.exists(),
        "an unrelated process group must survive"
    );
}

#[tokio::test]
async fn owned_transport_reports_startup_failure_without_spawning() {
    let missing = std::env::temp_dir().join("astrid-mcp-process-wrap-missing-executable");
    let command = tokio::process::Command::new(missing);
    let Err(error) = OwnedProcessTransport::new(wrap_process_tree(command)) else {
        panic!("missing MCP executable should fail startup");
    };

    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[cfg(unix)]
#[tokio::test]
async fn owned_transport_frames_jsonrpc_messages() {
    use rmcp::service::TxJsonRpcMessage;
    use rmcp::transport::Transport as _;

    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("IFS= read -r line; printf '%s\\n' \"$line\"");
    let mut transport =
        OwnedProcessTransport::new(wrap_process_tree(command)).expect("spawn echo transport");

    let outgoing_message = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    });
    let mut expected_message = outgoing_message.clone();
    expected_message["params"] = serde_json::Value::Null;
    let outgoing: TxJsonRpcMessage<RoleClient> =
        serde_json::from_value(outgoing_message).expect("valid client notification");
    transport
        .send(outgoing)
        .await
        .expect("write framed JSON-RPC message");

    let received = tokio::time::timeout(std::time::Duration::from_secs(2), transport.receive())
        .await
        .expect("receive should not hang")
        .expect("newline should frame one JSON-RPC message");
    assert_eq!(
        serde_json::to_value(&received).expect("serialize receive"),
        expected_message
    );

    tokio::time::timeout(std::time::Duration::from_secs(3), transport.close())
        .await
        .expect("close should not hang")
        .expect("echo child should shut down");
}

#[tokio::test]
async fn test_server_manager_creation() {
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs);

    assert!(manager.list_configured().is_empty());
    assert!(manager.list_running().await.is_empty());
}

#[tokio::test]
async fn test_server_not_found() {
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs);

    let result = manager.start("nonexistent").await;
    assert!(matches!(result, Err(McpError::ServerNotFound { .. })));
}

#[tokio::test]
async fn test_is_running() {
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs);

    assert!(!manager.is_running("test").await);
}

#[test]
fn restart_backoff_delays_are_exponential() {
    let backoff = ServerManager::restart_backoff();

    // attempt 0 = no delay (initial attempt).
    assert_eq!(backoff.delay_for_attempt(0), std::time::Duration::ZERO);
    // attempt 1 = 30 s base.
    assert_eq!(
        backoff.delay_for_attempt(1),
        std::time::Duration::from_secs(30)
    );
    // attempt 2 = 30 * 2 = 60 s.
    assert_eq!(
        backoff.delay_for_attempt(2),
        std::time::Duration::from_mins(1)
    );
    // attempt 3 = 30 * 4 = 120 s.
    assert_eq!(
        backoff.delay_for_attempt(3),
        std::time::Duration::from_mins(2)
    );
    // attempt 4 = 30 * 8 = 240 s.
    assert_eq!(
        backoff.delay_for_attempt(4),
        std::time::Duration::from_mins(4)
    );
    // attempt 5 = 30 * 16 = 480 s, capped at 300 s.
    assert_eq!(
        backoff.delay_for_attempt(5),
        std::time::Duration::from_mins(5)
    );
    // further attempts also capped at 300 s.
    assert_eq!(
        backoff.delay_for_attempt(10),
        std::time::Duration::from_mins(5)
    );
}

#[tokio::test]
async fn should_restart_never_policy() {
    let mut configs = ServersConfig::default();
    configs
        .add(ServerConfig::stdio("srv", "cmd").with_restart_policy(RestartPolicy::Never))
        .unwrap();
    let manager = ServerManager::new(configs);

    assert!(!manager.should_restart("srv").await);
}

#[tokio::test]
async fn should_restart_always_policy_no_running_entry() {
    let mut configs = ServersConfig::default();
    configs
        .add(ServerConfig::stdio("srv", "cmd").with_restart_policy(RestartPolicy::Always))
        .unwrap();
    let manager = ServerManager::new(configs);

    // No running entry and no last_restart_attempt → should allow.
    assert!(manager.should_restart("srv").await);
}

#[tokio::test]
async fn should_restart_respects_backoff_cooldown() {
    let mut configs = ServersConfig::default();
    configs
        .add(ServerConfig::stdio("srv", "cmd").with_restart_policy(RestartPolicy::Always))
        .unwrap();
    let manager = ServerManager::new(configs);

    // Manually insert a running server with a very recent last_restart_attempt
    // and restart_count = 1 (so delay_for_attempt(1) = 30 s).
    {
        let mut running = manager.running.write().await;
        let mut server = RunningServer::new(
            ServerConfig::stdio("srv", "cmd").with_restart_policy(RestartPolicy::Always),
        );
        server.restart_count = 1;
        server.last_restart_attempt = Some(Instant::now());
        running.insert("srv".to_string(), server);
    }

    // Cooldown not elapsed → should_restart returns false.
    assert!(!manager.should_restart("srv").await);
}

#[tokio::test]
async fn should_restart_allows_after_cooldown_elapsed() {
    let mut configs = ServersConfig::default();
    configs
        .add(ServerConfig::stdio("srv", "cmd").with_restart_policy(RestartPolicy::Always))
        .unwrap();
    let manager = ServerManager::new(configs);

    // Insert with a restart attempt far in the past.
    {
        let mut running = manager.running.write().await;
        let mut server = RunningServer::new(
            ServerConfig::stdio("srv", "cmd").with_restart_policy(RestartPolicy::Always),
        );
        server.restart_count = 1;
        // 60 seconds ago — the required delay for attempt 1 is 30s, so this
        // is well past the cooldown.
        server.last_restart_attempt = Some(
            Instant::now()
                .checked_sub(std::time::Duration::from_mins(1))
                .expect("failed to sub 60s from Instant"),
        );
        running.insert("srv".to_string(), server);
    }

    assert!(manager.should_restart("srv").await);
}

#[tokio::test]
async fn should_restart_on_failure_respects_max_retries() {
    let mut configs = ServersConfig::default();
    configs
        .add(
            ServerConfig::stdio("srv", "cmd")
                .with_restart_policy(RestartPolicy::OnFailure { max_retries: 2 }),
        )
        .unwrap();
    let manager = ServerManager::new(configs);

    // Insert with restart_count = 2 (already hit the limit).
    {
        let mut running = manager.running.write().await;
        let mut server = RunningServer::new(
            ServerConfig::stdio("srv", "cmd")
                .with_restart_policy(RestartPolicy::OnFailure { max_retries: 2 }),
        );
        server.restart_count = 2;
        running.insert("srv".to_string(), server);
    }

    assert!(!manager.should_restart("srv").await);
}

#[test]
fn test_build_unsandboxed_command() {
    let config = ServerConfig::stdio("test", "echo")
        .with_args(["hello"])
        .with_env("FOO", "bar");

    let cmd = build_unsandboxed_command("test", "echo", &config);

    // Command program should be the original command
    let program = cmd.as_std().get_program().to_string_lossy().to_string();
    assert_eq!(program, "echo");
}

#[test]
fn test_build_sandboxed_command_adds_sandbox_prefix() {
    // Probe-gated: on Linux this needs a working bwrap to exercise the
    // wrapper. CI runners often have bwrap installed but the kernel
    // sysctl blocks user namespaces — sandbox_prefix() returns Err under
    // the default Required policy. Skipping there preserves the test's
    // intent (verify the wrapper is invoked when sandboxing is possible)
    // without making CI dependent on host-kernel configuration.
    #[cfg(target_os = "linux")]
    if !linux_sandbox_actually_available() {
        eprintln!("skipping: bwrap probe failed — sandbox not exercised on this host");
        return;
    }

    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs)
        .with_workspace_root(std::env::temp_dir().join("astrid-test-workspace"));

    let config = ServerConfig::stdio("test", "echo").with_args(["hello"]);

    let cmd = manager
        .build_sandboxed_command("test", "echo", &config)
        .expect("should build sandboxed command");

    let program = cmd.as_std().get_program().to_string_lossy().to_string();

    #[cfg(target_os = "linux")]
    assert_eq!(program, "bwrap", "expected bwrap wrapper, got: {program}");
    #[cfg(target_os = "macos")]
    assert_eq!(program, "sandbox-exec");
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert!(
        std::path::Path::new(&program).is_absolute(),
        "unsupported platform should still use resolved absolute path, got: {program}"
    );
}

/// Linux-only: does the host kernel actually grant unprivileged user
/// namespaces to `bwrap`? Mirrors `astrid_workspace::bwrap_available`
/// but inlined here so the test doesn't depend on internal symbols.
#[cfg(target_os = "linux")]
fn linux_sandbox_actually_available() -> bool {
    std::process::Command::new("bwrap")
        .args(["--unshare-user", "--ro-bind", "/", "/", "--", "/bin/true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn test_build_sandboxed_command_resolves_absolute_binary_path() {
    // Off so the test exercises binary resolution deterministically
    // regardless of host bwrap / `AppArmor` state. Resolution happens
    // before the sandbox-policy decision either way.
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs)
        .with_workspace_root(std::env::temp_dir().join("astrid-test-workspace"))
        .with_sandbox_policy(astrid_workspace::SandboxPolicy::Off);

    let config = ServerConfig::stdio("test", "echo");

    let cmd = manager
        .build_sandboxed_command("test", "echo", &config)
        .expect("should build sandboxed command");

    // The resolved binary should appear as an absolute path — either in
    // the args (when sandbox wraps it) or as the program itself (when
    // sandbox is unavailable, e.g. bwrap blocked by AppArmor in CI).
    let expected = which::which("echo").expect("echo should be in PATH");
    let program = cmd.as_std().get_program().to_string_lossy().to_string();
    let args: Vec<_> = cmd
        .as_std()
        .get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect();
    let found_in_args = args.iter().any(|a| std::path::Path::new(a) == expected);
    let found_as_program = std::path::Path::new(&program) == expected;
    assert!(
        found_in_args || found_as_program,
        "resolved absolute path {} should appear in program or args, got program={program}, args={args:?}",
        expected.display()
    );
}

#[test]
fn test_build_sandboxed_command_rejects_unresolvable_binary() {
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs)
        .with_workspace_root(std::env::temp_dir().join("astrid-test-workspace"));

    let config = ServerConfig::stdio("test", "nonexistent-binary-xyz-12345");

    let result = manager.build_sandboxed_command("test", "nonexistent-binary-xyz-12345", &config);
    assert!(result.is_err(), "unresolvable binary should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Cannot resolve binary"),
        "error should mention resolution: {err}"
    );
}

#[test]
fn test_trusted_server_bypasses_sandbox() {
    let config = ServerConfig::stdio("test", "echo").trusted();

    let cmd = build_unsandboxed_command("test", "echo", &config);

    let program = cmd.as_std().get_program().to_string_lossy().to_string();
    assert_eq!(
        program, "echo",
        "trusted server should run without sandbox wrapper"
    );
}

#[test]
fn test_sandboxed_command_clears_env() {
    // Off so env scrubbing is tested independently of host sandbox state.
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs)
        .with_workspace_root(std::env::temp_dir().join("astrid-test-workspace"))
        .with_sandbox_policy(astrid_workspace::SandboxPolicy::Off);

    let config = ServerConfig::stdio("test", "echo").with_env("SAFE_VAR", "value");

    let cmd = manager
        .build_sandboxed_command("test", "echo", &config)
        .expect("should build command");

    let envs: Vec<_> = cmd
        .as_std()
        .get_envs()
        .filter_map(|(k, v)| {
            v.map(|v| {
                (
                    k.to_string_lossy().to_string(),
                    v.to_string_lossy().to_string(),
                )
            })
        })
        .collect();

    // Config env vars should be passed through
    let has_safe_var = envs.iter().any(|(k, v)| k == "SAFE_VAR" && v == "value");
    assert!(has_safe_var, "config env vars should be passed through");

    // PATH should be the fixed value, not inherited from parent
    let path_val = envs
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.as_str());
    assert_eq!(
        path_val,
        Some("/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"),
        "PATH should be the fixed sandbox path, not inherited"
    );

    // Vars not in the safe list or config should not be present
    let has_random_env = envs
        .iter()
        .any(|(k, _)| k == "CARGO_HOME" || k == "RUSTUP_HOME");
    assert!(
        !has_random_env,
        "env_clear should have removed non-allowlisted vars"
    );
}

#[test]
fn test_sandboxed_command_blocks_dangerous_env() {
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs)
        .with_workspace_root(std::env::temp_dir().join("astrid-test-workspace"))
        .with_sandbox_policy(astrid_workspace::SandboxPolicy::Off);

    let config = ServerConfig::stdio("test", "echo")
        .with_env("LD_PRELOAD", "/evil.so")
        .with_env("SAFE_VAR", "ok");

    let cmd = manager
        .build_sandboxed_command("test", "echo", &config)
        .expect("should build command");

    let envs: Vec<_> = cmd
        .as_std()
        .get_envs()
        .filter_map(|(k, v)| {
            v.map(|v| {
                (
                    k.to_string_lossy().to_string(),
                    v.to_string_lossy().to_string(),
                )
            })
        })
        .collect();

    let has_ld_preload = envs.iter().any(|(k, _)| k == "LD_PRELOAD");
    assert!(!has_ld_preload, "LD_PRELOAD should be blocked");

    let has_safe = envs.iter().any(|(k, _)| k == "SAFE_VAR");
    assert!(has_safe, "safe config env should pass through");
}

#[test]
fn test_writable_root_priority_cwd_first() {
    // Off so the writable-root precedence logic is tested independently
    // of host sandbox state. The cwd-as-current-dir behaviour we assert
    // here is what the unsandboxed branch sets regardless of policy.
    let cwd_dir = std::env::temp_dir().join("astrid-test-cwd");
    let ws_dir = std::env::temp_dir().join("astrid-test-ws");

    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs)
        .with_workspace_root(ws_dir.clone())
        .with_sandbox_policy(astrid_workspace::SandboxPolicy::Off);

    let mut config = ServerConfig::stdio("test", "echo");
    config.cwd = Some(cwd_dir.clone());

    let cmd = manager
        .build_sandboxed_command("test", "echo", &config)
        .expect("should build command");

    let current_dir = cmd.as_std().get_current_dir();
    assert_eq!(
        current_dir,
        Some(cwd_dir.as_path()),
        "config.cwd should win over workspace_root as the command's current_dir"
    );
}

#[test]
fn test_writable_root_priority_workspace_second() {
    // Off so workspace_root fallback is tested deterministically.
    let ws_dir = std::env::temp_dir().join("astrid-test-ws2");

    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs)
        .with_workspace_root(ws_dir.clone())
        .with_sandbox_policy(astrid_workspace::SandboxPolicy::Off);

    let config = ServerConfig::stdio("test", "echo");
    // No cwd set, should fall back to workspace_root for sandbox config.

    let cmd = manager
        .build_sandboxed_command("test", "echo", &config)
        .expect("should build command");

    // Under Off the sandbox prefix is suppressed, so the assertion is
    // that the command builds successfully — the only way it can fail
    // here without a sandbox involved is if the writable_root resolution
    // chain breaks (e.g. workspace_root not picked up when cwd is None).
    let program = cmd.as_std().get_program().to_string_lossy().to_string();
    assert!(
        std::path::Path::new(&program).is_absolute(),
        "resolved binary should be absolute, got: {program}"
    );
}

#[test]
fn test_resolve_astrid_home_succeeds() {
    // Should succeed as long as $HOME is set (which it is in test environments)
    let result = ServerManager::resolve_astrid_home();
    assert!(result.is_ok(), "should resolve astrid home from $HOME");

    let path = result.expect("already checked");
    assert!(
        path.to_string_lossy().ends_with(".astrid"),
        "path should end with .astrid, got: {}",
        path.display()
    );
}

#[test]
fn test_relative_allowed_paths_rejected() {
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs)
        .with_workspace_root(std::env::temp_dir().join("astrid-test-workspace"));

    let config = ServerConfig::stdio("test", "echo")
        .with_read_path(std::path::PathBuf::from("relative/path"));

    let result = manager.build_sandboxed_command("test", "echo", &config);
    assert!(
        matches!(result, Err(McpError::ConfigError(_))),
        "relative allowed_read_paths should be rejected"
    );

    let config = ServerConfig::stdio("test", "echo")
        .with_write_path(std::path::PathBuf::from("another/relative"));

    let result = manager.build_sandboxed_command("test", "echo", &config);
    assert!(
        matches!(result, Err(McpError::ConfigError(_))),
        "relative allowed_write_paths should be rejected"
    );
}

#[test]
fn test_double_quote_in_paths_rejected() {
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs)
        .with_workspace_root(std::env::temp_dir().join("astrid-test-workspace"));

    let config = ServerConfig::stdio("test", "echo")
        .with_read_path(std::path::PathBuf::from("/data/tricky\"path"));

    let result = manager.build_sandboxed_command("test", "echo", &config);
    assert!(
        matches!(result, Err(McpError::ConfigError(_))),
        "paths with double-quotes should be rejected to prevent SBPL injection"
    );

    let config = ServerConfig::stdio("test", "echo")
        .with_write_path(std::path::PathBuf::from("/output/also\"bad"));

    let result = manager.build_sandboxed_command("test", "echo", &config);
    assert!(
        matches!(result, Err(McpError::ConfigError(_))),
        "write paths with double-quotes should also be rejected"
    );
}

#[test]
fn test_with_workspace_root() {
    let configs = ServersConfig::default();
    let manager =
        ServerManager::new(configs).with_workspace_root(std::path::PathBuf::from("/my/workspace"));

    assert_eq!(
        manager.workspace_root,
        Some(std::path::PathBuf::from("/my/workspace"))
    );
}

#[test]
fn test_validate_sandbox_path_rejects_non_utf8() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let bad_bytes: &[u8] = b"/tmp/\xff\xfe/workspace";
    let bad_path = std::path::Path::new(OsStr::from_bytes(bad_bytes));
    let result = ServerManager::validate_sandbox_path(bad_path, "test_field");
    assert!(
        matches!(result, Err(McpError::ConfigError(ref msg)) if msg.contains("not valid UTF-8")),
        "non-UTF-8 path should be rejected, got: {result:?}"
    );
}

#[test]
fn test_validate_sandbox_path_rejects_null_byte() {
    let bad_path = std::path::Path::new("/tmp/evil\0path");
    let result = ServerManager::validate_sandbox_path(bad_path, "test_field");
    assert!(
        matches!(result, Err(McpError::ConfigError(ref msg)) if msg.contains("forbidden characters")),
        "path with null byte should be rejected, got: {result:?}"
    );
}

#[test]
fn test_validate_sandbox_path_accepts_valid_utf8() {
    let good_path = std::path::Path::new("/tmp/valid-workspace");
    let result = ServerManager::validate_sandbox_path(good_path, "test_field");
    assert!(result.is_ok(), "valid UTF-8 path should be accepted");
}

#[test]
fn test_build_sandboxed_command_rejects_non_utf8_workspace_root() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let bad_bytes: &[u8] = b"/tmp/\xff\xfe/workspace";
    let bad_path = std::path::PathBuf::from(OsStr::from_bytes(bad_bytes));

    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs).with_workspace_root(bad_path);

    let config = ServerConfig::stdio("test", "echo");
    let result = manager.build_sandboxed_command("test", "echo", &config);
    assert!(
        matches!(result, Err(McpError::ConfigError(_))),
        "non-UTF-8 workspace root should be rejected through build_sandboxed_command, got: {result:?}"
    );
}

#[tokio::test]
async fn start_rejects_traversal_name() {
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs);

    let result = manager.start("../evil").await;
    assert!(result.is_err(), "expected rejection for traversal name");
}

#[tokio::test]
async fn add_server_rejects_traversal_name() {
    let configs = ServersConfig::default();
    let manager = ServerManager::new(configs);

    let config = ServerConfig::stdio("../evil", "cmd");
    let result = manager.add_server("../evil", config).await;
    assert!(result.is_err(), "expected rejection for traversal name");
}
