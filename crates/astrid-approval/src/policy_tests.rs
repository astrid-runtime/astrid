//! Tests for `policy.rs`. Split out to keep `policy.rs` under the 1000-line CI
//! threshold. Included via `#[path]` from its sibling.

use super::*;

// -----------------------------------------------------------------------
// Default policy tests
// -----------------------------------------------------------------------

#[test]
fn test_default_blocks_dangerous_commands() {
    let policy = SecurityPolicy::default();

    let action = SensitiveAction::ExecuteCommand {
        command: "sudo".to_string(),
        args: vec!["rm".to_string()],
    };
    assert!(policy.check(&action).is_blocked());

    let action = SensitiveAction::ExecuteCommand {
        command: "mkfs".to_string(),
        args: vec![],
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_default_blocks_rm_rf_root() {
    let policy = SecurityPolicy::default();

    let action = SensitiveAction::ExecuteCommand {
        command: "rm".to_string(),
        args: vec!["-rf".to_string(), "/".to_string()],
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_default_blocks_system_paths() {
    let policy = SecurityPolicy::default();

    let action = SensitiveAction::FileWriteOutsideSandbox {
        path: "/etc/passwd".to_string(),
    };
    assert!(policy.check(&action).is_blocked());

    let action = SensitiveAction::FileDelete {
        path: "/boot/vmlinuz".to_string(),
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_default_requires_approval_for_delete() {
    let policy = SecurityPolicy::default();

    let action = SensitiveAction::FileDelete {
        path: "/home/user/file.txt".to_string(),
    };
    assert!(policy.check(&action).requires_approval());
}

#[test]
fn test_default_requires_approval_for_network() {
    let policy = SecurityPolicy::default();

    let action = SensitiveAction::NetworkRequest {
        host: "api.example.com".to_string(),
        port: 443,
    };
    assert!(policy.check(&action).requires_approval());
}

// -----------------------------------------------------------------------
// Permissive policy tests
// -----------------------------------------------------------------------

#[test]
fn test_permissive_allows_everything() {
    let policy = SecurityPolicy::permissive();

    let action = SensitiveAction::McpToolCall {
        server: "anything".to_string(),
        tool: "anything".to_string(),
    };
    assert!(policy.check(&action).is_allowed());

    let action = SensitiveAction::NetworkRequest {
        host: "evil.com".to_string(),
        port: 80,
    };
    assert!(policy.check(&action).is_allowed());
}

// -----------------------------------------------------------------------
// MCP tool checks
// -----------------------------------------------------------------------

#[test]
fn test_blocked_mcp_tool() {
    let mut policy = SecurityPolicy::permissive();
    policy.blocked_tools.insert("danger:nuke".to_string());

    let action = SensitiveAction::McpToolCall {
        server: "danger".to_string(),
        tool: "nuke".to_string(),
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_blocked_mcp_server() {
    let mut policy = SecurityPolicy::permissive();
    policy.blocked_tools.insert("danger".to_string());

    let action = SensitiveAction::McpToolCall {
        server: "danger".to_string(),
        tool: "any_tool".to_string(),
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_approval_required_mcp_tool() {
    let mut policy = SecurityPolicy::permissive();
    policy
        .approval_required_tools
        .insert("filesystem:write_file".to_string());

    let action = SensitiveAction::McpToolCall {
        server: "filesystem".to_string(),
        tool: "write_file".to_string(),
    };
    assert!(policy.check(&action).requires_approval());

    // Different tool on same server is allowed
    let action = SensitiveAction::McpToolCall {
        server: "filesystem".to_string(),
        tool: "read_file".to_string(),
    };
    assert!(policy.check(&action).is_allowed());
}

#[test]
fn test_approval_required_mcp_server() {
    let mut policy = SecurityPolicy::permissive();
    policy
        .approval_required_tools
        .insert("filesystem".to_string());

    // All tools on this server require approval
    let action = SensitiveAction::McpToolCall {
        server: "filesystem".to_string(),
        tool: "anything".to_string(),
    };
    assert!(policy.check(&action).requires_approval());
}

// -----------------------------------------------------------------------
// File path checks
// -----------------------------------------------------------------------

#[test]
fn test_denied_path() {
    let mut policy = SecurityPolicy::permissive();
    policy.denied_paths.push("/secrets/**".to_string());

    let action = SensitiveAction::FileWriteOutsideSandbox {
        path: "/secrets/key.pem".to_string(),
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_allowed_path_enforcement() {
    let mut policy = SecurityPolicy::permissive();
    policy.allowed_paths.push("/home/user/**".to_string());

    // Allowed path
    let action = SensitiveAction::FileWriteOutsideSandbox {
        path: "/home/user/docs/file.txt".to_string(),
    };
    assert!(policy.check(&action).requires_approval()); // allowed but still needs approval for write outside sandbox

    // Not in allowed paths
    let action = SensitiveAction::FileWriteOutsideSandbox {
        path: "/var/lib/data.db".to_string(),
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_path_traversal_blocked() {
    let policy = SecurityPolicy::permissive();

    let action = SensitiveAction::FileWriteOutsideSandbox {
        path: "/home/user/../../etc/passwd".to_string(),
    };
    assert!(policy.check(&action).is_blocked());
}

// -----------------------------------------------------------------------
// Network checks
// -----------------------------------------------------------------------

#[test]
fn test_denied_host() {
    let mut policy = SecurityPolicy::permissive();
    policy.denied_hosts.push("evil.com".to_string());

    let action = SensitiveAction::NetworkRequest {
        host: "evil.com".to_string(),
        port: 443,
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_allowed_hosts_enforcement() {
    let mut policy = SecurityPolicy::permissive();
    policy.allowed_hosts.push("api.example.com".to_string());

    let action = SensitiveAction::NetworkRequest {
        host: "api.example.com".to_string(),
        port: 443,
    };
    assert!(policy.check(&action).is_allowed());

    let action = SensitiveAction::NetworkRequest {
        host: "other.com".to_string(),
        port: 443,
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_transmit_data_checks_host() {
    let mut policy = SecurityPolicy::permissive();
    policy.denied_hosts.push("evil.com".to_string());

    let action = SensitiveAction::TransmitData {
        destination: "evil.com".to_string(),
        data_type: "report".to_string(),
    };
    assert!(policy.check(&action).is_blocked());
}

// -----------------------------------------------------------------------
// Argument size
// -----------------------------------------------------------------------

#[test]
fn test_argument_size_limit() {
    let mut policy = SecurityPolicy::permissive();
    policy.max_argument_size = 100;

    let action = SensitiveAction::ExecuteCommand {
        command: "echo".to_string(),
        args: vec!["x".repeat(200)],
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_argument_size_within_limit() {
    let mut policy = SecurityPolicy::permissive();
    policy.max_argument_size = 100;

    let action = SensitiveAction::ExecuteCommand {
        command: "echo".to_string(),
        args: vec!["hello".to_string()],
    };
    // Within size limit, but execute still requires approval
    assert!(policy.check(&action).requires_approval());
}

// -----------------------------------------------------------------------
// Always-requires-approval actions
// -----------------------------------------------------------------------

#[test]
fn test_financial_always_requires_approval() {
    let policy = SecurityPolicy::permissive();

    let action = SensitiveAction::FinancialTransaction {
        amount: "100.00".to_string(),
        recipient: "merchant".to_string(),
    };
    let result = policy.check(&action);
    assert!(result.requires_approval());
}

#[test]
fn test_access_control_always_requires_approval() {
    let policy = SecurityPolicy::permissive();

    let action = SensitiveAction::AccessControlChange {
        resource: "/var/data".to_string(),
        change: "chmod 777".to_string(),
    };
    let result = policy.check(&action);
    assert!(result.requires_approval());
}

#[test]
fn test_capability_grant_requires_approval() {
    let policy = SecurityPolicy::permissive();

    let action = SensitiveAction::CapabilityGrant {
        resource_pattern: "mcp://server:*".to_string(),
        permissions: vec![astrid_core::types::Permission::Invoke],
    };
    assert!(policy.check(&action).requires_approval());
}

// -----------------------------------------------------------------------
// PolicyResult
// -----------------------------------------------------------------------

#[test]
fn test_policy_result_display() {
    let allowed = PolicyResult::Allowed;
    assert_eq!(allowed.to_string(), "allowed");

    let blocked = PolicyResult::Blocked {
        reason: "test".to_string(),
    };
    assert!(blocked.to_string().contains("blocked"));
}

#[test]
fn test_builtin_task_requires_approval() {
    let policy = SecurityPolicy::default();
    let action = SensitiveAction::McpToolCall {
        server: "builtin".to_string(),
        tool: "task".to_string(),
    };
    assert!(
        policy.check(&action).requires_approval(),
        "builtin:task should require approval by default"
    );
}

// -----------------------------------------------------------------------
// Serialization
// -----------------------------------------------------------------------

#[test]
fn test_policy_serialization() {
    let policy = SecurityPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let deserialized: SecurityPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.blocked_tools.len(), policy.blocked_tools.len());
    assert!(deserialized.require_approval_for_delete);
    assert!(deserialized.blocked_capsules.is_empty());
}

// -----------------------------------------------------------------------
// Plugin policy tests
// -----------------------------------------------------------------------

#[test]
fn test_blocked_plugin() {
    let mut policy = SecurityPolicy::permissive();
    policy.blocked_capsules.insert("evil-plugin".to_string());

    let action = SensitiveAction::CapsuleExecution {
        capsule_id: "evil-plugin".to_string(),
        capability: "anything".to_string(),
    };
    assert!(policy.check(&action).is_blocked());

    let action = SensitiveAction::CapsuleHttpRequest {
        capsule_id: "evil-plugin".to_string(),
        url: "https://safe.com".to_string(),
        method: "GET".to_string(),
    };
    assert!(policy.check(&action).is_blocked());

    let action = SensitiveAction::CapsuleFileAccess {
        capsule_id: "evil-plugin".to_string(),
        path: "/tmp/safe".to_string(),
        mode: astrid_core::types::Permission::Read,
    };
    assert!(policy.check(&action).is_blocked());
}

#[test]
fn test_plugin_requires_approval() {
    let policy = SecurityPolicy::permissive();

    let action = SensitiveAction::CapsuleExecution {
        capsule_id: "good-plugin".to_string(),
        capability: "config_read".to_string(),
    };
    assert!(policy.check(&action).requires_approval());
}

#[test]
fn test_plugin_http_denied_host() {
    let mut policy = SecurityPolicy::permissive();
    policy.denied_hosts.push("evil.com".to_string());

    let action = SensitiveAction::CapsuleHttpRequest {
        capsule_id: "weather".to_string(),
        url: "https://evil.com/api".to_string(),
        method: "GET".to_string(),
    };
    assert!(policy.check(&action).is_blocked());

    // Same plugin, different host — requires approval (not blocked)
    let action = SensitiveAction::CapsuleHttpRequest {
        capsule_id: "weather".to_string(),
        url: "https://safe.com/api".to_string(),
        method: "GET".to_string(),
    };
    assert!(policy.check(&action).requires_approval());
}

#[test]
fn test_plugin_file_denied_path() {
    let mut policy = SecurityPolicy::permissive();
    policy.denied_paths.push("/etc/**".to_string());

    let action = SensitiveAction::CapsuleFileAccess {
        capsule_id: "cache".to_string(),
        path: "/etc/passwd".to_string(),
        mode: astrid_core::types::Permission::Read,
    };
    assert!(policy.check(&action).is_blocked());

    // Safe path — requires approval (not blocked)
    let action = SensitiveAction::CapsuleFileAccess {
        capsule_id: "cache".to_string(),
        path: "/tmp/cache.json".to_string(),
        mode: astrid_core::types::Permission::Read,
    };
    assert!(policy.check(&action).requires_approval());
}

// -----------------------------------------------------------------------
// Host extraction tests
// -----------------------------------------------------------------------

#[test]
fn test_extract_host_from_url() {
    use super::extract_host_from_url;

    assert_eq!(
        extract_host_from_url("https://example.com"),
        Some("example.com")
    );
    assert_eq!(
        extract_host_from_url("https://example.com:8080"),
        Some("example.com")
    );
    assert_eq!(
        extract_host_from_url("https://example.com/path"),
        Some("example.com")
    );
    assert_eq!(
        extract_host_from_url("https://example.com:443/path"),
        Some("example.com")
    );
    assert_eq!(
        extract_host_from_url("http://user:pass@example.com/path"),
        Some("example.com")
    );
    assert_eq!(extract_host_from_url("not-a-url"), None);
    assert_eq!(extract_host_from_url(""), None);
    assert_eq!(extract_host_from_url("://"), None);
}

#[test]
fn test_plugin_policy_serialization() {
    let mut policy = SecurityPolicy::default();
    policy.blocked_capsules.insert("bad-plugin".to_string());

    let json = serde_json::to_string(&policy).unwrap();
    let deserialized: SecurityPolicy = serde_json::from_str(&json).unwrap();
    assert!(deserialized.blocked_capsules.contains("bad-plugin"));
}
