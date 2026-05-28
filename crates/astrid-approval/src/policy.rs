//! Security policy — hard boundaries for agent actions.
//!
//! The [`SecurityPolicy`] defines what actions are blocked outright, what
//! actions require human approval, and what actions are allowed freely.
//! It represents the **admin-configured** layer of the security model.
//!
//! # Policy Check Order
//!
//! 1. Is the tool explicitly blocked? -> `Blocked`
//! 2. Does the path match a denied path? -> `Blocked`
//! 3. Does the host match a denied host? -> `Blocked`
//! 4. Does the action exceed argument size limits? -> `Blocked`
//! 5. Is the tool in the approval-required set? -> `RequiresApproval`
//! 6. Is the action a delete and `require_approval_for_delete`? -> `RequiresApproval`
//! 7. Is the action a network request and `require_approval_for_network`? -> `RequiresApproval`
//! 8. Otherwise -> `Allowed`

use globset::Glob;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

use crate::action::SensitiveAction;
use crate::request::RiskAssessment;

/// Security policy defining hard boundaries for agent actions.
///
/// # Example
///
/// ```
/// use astrid_approval::policy::{SecurityPolicy, PolicyResult};
/// use astrid_approval::SensitiveAction;
///
/// let policy = SecurityPolicy::default();
///
/// // Blocked tool
/// let action = SensitiveAction::ExecuteCommand {
///     command: "rm".to_string(),
///     args: vec!["-rf".to_string(), "/".to_string()],
/// };
/// let result = policy.check(&action);
/// assert!(matches!(result, PolicyResult::Blocked { .. }));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Tools that are never allowed (e.g., "rm -rf", "sudo").
    ///
    /// Matched against `ExecuteCommand.command` and `McpToolCall` as "server:tool".
    pub blocked_tools: HashSet<String>,

    /// Tools that require explicit user approval.
    ///
    /// Matched against `McpToolCall` as "server:tool".
    pub approval_required_tools: HashSet<String>,

    /// Glob patterns for allowed file paths.
    ///
    /// If non-empty, only paths matching at least one pattern are allowed.
    /// If empty, path filtering is not applied (all paths pass this check).
    pub allowed_paths: Vec<String>,

    /// Glob patterns for denied file paths.
    ///
    /// Paths matching any pattern are blocked. Checked before `allowed_paths`.
    pub denied_paths: Vec<String>,

    /// Allowed network hosts.
    ///
    /// If non-empty, only connections to these hosts are allowed.
    /// If empty, host filtering is not applied.
    pub allowed_hosts: Vec<String>,

    /// Denied network hosts (checked before `allowed_hosts`).
    pub denied_hosts: Vec<String>,

    /// Maximum size of tool arguments in bytes. 0 = no limit.
    pub max_argument_size: usize,

    /// Whether file deletion always requires approval.
    pub require_approval_for_delete: bool,

    /// Whether network requests always require approval.
    pub require_approval_for_network: bool,

    /// Plugins that are completely blocked from execution.
    pub blocked_capsules: HashSet<String>,
}

impl SecurityPolicy {
    /// Create a new empty policy (everything allowed).
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            blocked_tools: HashSet::new(),
            approval_required_tools: HashSet::new(),
            allowed_paths: Vec::new(),
            denied_paths: Vec::new(),
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            max_argument_size: 0,
            require_approval_for_delete: false,
            require_approval_for_network: false,
            blocked_capsules: HashSet::new(),
        }
    }

    /// Check an action against this policy.
    #[must_use]
    pub fn check(&self, action: &SensitiveAction) -> PolicyResult {
        match action {
            SensitiveAction::ExecuteCommand { command, args } => {
                self.check_execute_command(command, args)
            },
            SensitiveAction::McpToolCall { server, tool } => self.check_mcp_tool(server, tool),
            SensitiveAction::FileRead { path } => self.check_file_path(path, "file read"),
            SensitiveAction::FileWriteOutsideSandbox { path } => {
                self.check_file_path(path, "file write outside sandbox")
            },
            SensitiveAction::FileDelete { path } => self.check_file_delete(path),
            SensitiveAction::NetworkRequest { host, .. } => self.check_network(host),
            SensitiveAction::TransmitData { destination, .. } => self.check_network(destination),
            SensitiveAction::FinancialTransaction { .. } => PolicyResult::RequiresApproval(
                RiskAssessment::new("Financial transactions always require approval"),
            ),
            SensitiveAction::AccessControlChange { .. } => PolicyResult::RequiresApproval(
                RiskAssessment::new("Access control changes always require approval"),
            ),
            SensitiveAction::CapabilityGrant { .. } => PolicyResult::RequiresApproval(
                RiskAssessment::new("Capability grants require approval"),
            ),
            SensitiveAction::CapsuleExecution { capsule_id, .. }
            | SensitiveAction::CapsuleHttpRequest { capsule_id, .. }
            | SensitiveAction::CapsuleFileAccess { capsule_id, .. }
            | SensitiveAction::CapsuleNetBind { capsule_id, .. } => {
                self.check_capsule_action(capsule_id, action)
            },
        }
    }

    /// Check an execute command action.
    fn check_execute_command(&self, command: &str, args: &[String]) -> PolicyResult {
        // Check blocked tools
        if self.blocked_tools.contains(command) {
            return PolicyResult::Blocked {
                reason: format!("command '{command}' is blocked by policy"),
            };
        }

        // Also check "command arg" combinations (e.g. "rm -rf")
        if !args.is_empty() {
            let full_command = format!("{command} {}", args.join(" "));
            for blocked in &self.blocked_tools {
                if full_command.starts_with(blocked) {
                    return PolicyResult::Blocked {
                        reason: format!(
                            "command '{full_command}' matches blocked pattern '{blocked}'"
                        ),
                    };
                }
            }
        }

        // Check argument size
        if self.max_argument_size > 0 {
            let total_size: usize = args.iter().map(String::len).sum();
            if total_size > self.max_argument_size {
                return PolicyResult::Blocked {
                    reason: format!(
                        "argument size {total_size} exceeds limit {}",
                        self.max_argument_size
                    ),
                };
            }
        }

        PolicyResult::RequiresApproval(RiskAssessment::new(format!("command execution: {command}")))
    }

    /// Check an MCP tool call.
    fn check_mcp_tool(&self, server: &str, tool: &str) -> PolicyResult {
        let qualified = format!("{server}:{tool}");

        // Check blocked tools
        if self.blocked_tools.contains(&qualified)
            || self.blocked_tools.contains(server)
            || self.blocked_tools.contains(tool)
        {
            return PolicyResult::Blocked {
                reason: format!("tool '{qualified}' is blocked by policy"),
            };
        }

        // Check approval-required tools
        if self.approval_required_tools.contains(&qualified)
            || self.approval_required_tools.contains(server)
        {
            return PolicyResult::RequiresApproval(RiskAssessment::new(format!(
                "tool '{qualified}' requires approval",
            )));
        }

        PolicyResult::Allowed
    }

    /// Check a file path against allowed/denied patterns.
    fn check_file_path(&self, path: &str, operation: &str) -> PolicyResult {
        // Reject path traversal using std::path::Path::components() for robustness
        if std::path::Path::new(path)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return PolicyResult::Blocked {
                reason: "path contains traversal sequence (..)".to_string(),
            };
        }

        // Check denied paths first
        if matches_any_glob(&self.denied_paths, path) {
            return PolicyResult::Blocked {
                reason: format!("path '{path}' is denied by policy"),
            };
        }

        // Check allowed paths (if configured)
        if !self.allowed_paths.is_empty() && !matches_any_glob(&self.allowed_paths, path) {
            return PolicyResult::Blocked {
                reason: format!("path '{path}' is not in allowed paths"),
            };
        }

        PolicyResult::RequiresApproval(RiskAssessment::new(format!("{operation}: {path}")))
    }

    /// Check a file delete action.
    fn check_file_delete(&self, path: &str) -> PolicyResult {
        // First check path rules
        let path_result = self.check_file_path(path, "file delete");
        if matches!(path_result, PolicyResult::Blocked { .. }) {
            return path_result;
        }

        // File deletion always requires approval if configured
        if self.require_approval_for_delete {
            return PolicyResult::RequiresApproval(RiskAssessment::new(format!(
                "file deletion requires approval: {path}",
            )));
        }

        path_result
    }

    /// Check a plugin action with layered enforcement.
    ///
    /// 1. Plugin in `blocked_capsules`? -> Blocked
    /// 2. `CapsuleHttpRequest` URL host in `denied_hosts`? -> Blocked
    /// 3. `CapsuleFileAccess` path matches `denied_paths`? -> Blocked
    /// 4. Otherwise -> `RequiresApproval` (plugins always need approval)
    ///
    /// `CapsuleNetBind` intentionally has no path-based check here because the
    /// socket is pre-bound by the kernel — the capsule does not control the bind
    /// address. The `ManifestSecurityGate::check_net_bind` enforces the manifest
    /// capability, and this policy layer gates approval for the capsule itself.
    fn check_capsule_action(&self, capsule_id: &str, action: &SensitiveAction) -> PolicyResult {
        // 1. Check blocked plugins
        if self.blocked_capsules.contains(capsule_id) {
            return PolicyResult::Blocked {
                reason: format!("capsule '{capsule_id}' is blocked by policy"),
            };
        }

        // 2. CapsuleHttpRequest: check denied_hosts
        if let SensitiveAction::CapsuleHttpRequest { url, .. } = action
            && let Some(host) = extract_host_from_url(url)
            && self.denied_hosts.iter().any(|h| h == host)
        {
            return PolicyResult::Blocked {
                reason: format!("capsule '{capsule_id}' HTTP request to denied host '{host}'"),
            };
        }

        // 3. CapsuleFileAccess: check denied_paths
        if let SensitiveAction::CapsuleFileAccess { path, .. } = action
            && matches_any_glob(&self.denied_paths, path)
        {
            return PolicyResult::Blocked {
                reason: format!("capsule '{capsule_id}' file access to denied path '{path}'"),
            };
        }

        // 4. Plugins always require approval
        PolicyResult::RequiresApproval(RiskAssessment::new(format!(
            "capsule '{capsule_id}' action requires approval",
        )))
    }

    /// Check a network host.
    fn check_network(&self, host: &str) -> PolicyResult {
        // Check denied hosts first
        if self.denied_hosts.iter().any(|h| h == host) {
            return PolicyResult::Blocked {
                reason: format!("host '{host}' is denied by policy"),
            };
        }

        // Check allowed hosts (if configured)
        if !self.allowed_hosts.is_empty() && !self.allowed_hosts.iter().any(|h| h == host) {
            return PolicyResult::Blocked {
                reason: format!("host '{host}' is not in allowed hosts"),
            };
        }

        if self.require_approval_for_network {
            return PolicyResult::RequiresApproval(RiskAssessment::new(format!(
                "network access requires approval: {host}",
            )));
        }

        PolicyResult::Allowed
    }
}

impl Default for SecurityPolicy {
    /// Sensible defaults:
    /// - Blocks dangerous commands (`rm -rf`, `sudo`, `mkfs`, `dd`)
    /// - Blocks `/etc`, `/boot`, `/sys` paths
    /// - Requires approval for deletes and network access
    /// - 1 MB argument size limit
    fn default() -> Self {
        let blocked_tools: HashSet<String> = [
            "rm -rf /",
            "rm -rf /*",
            "sudo",
            "su",
            "mkfs",
            "dd",
            "chmod 777",
            "shutdown",
            "reboot",
            "init",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let denied_paths: Vec<String> = vec![
            "/etc/**".to_string(),
            "/boot/**".to_string(),
            "/sys/**".to_string(),
            "/proc/**".to_string(),
            "/dev/**".to_string(),
        ];

        Self {
            blocked_tools,
            approval_required_tools: ["builtin:task".to_string()].into_iter().collect(),
            allowed_paths: Vec::new(),
            denied_paths,
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            max_argument_size: 1024 * 1024, // 1 MB
            require_approval_for_delete: true,
            require_approval_for_network: true,
            blocked_capsules: HashSet::new(),
        }
    }
}

/// Extract the host from a URL string without depending on the `url` crate.
///
/// Handles `scheme://host`, `scheme://host:port`, and `scheme://host/path` forms.
/// Returns `None` if the URL doesn't contain `://`.
fn extract_host_from_url(url: &str) -> Option<&str> {
    let after_scheme = url.split("://").nth(1)?;
    // Strip userinfo if present (user:pass@host)
    let after_auth = after_auth_part(after_scheme);
    // Take everything before port or path
    let host = after_auth
        .split_once(':')
        .or_else(|| after_auth.split_once('/'))
        .map_or(after_auth, |(h, _)| h);
    if host.is_empty() { None } else { Some(host) }
}

/// Strip optional `user:pass@` from the authority component.
fn after_auth_part(authority: &str) -> &str {
    // Only consider '@' before the first '/' (path start)
    let before_path = authority.split('/').next().unwrap_or(authority);
    match before_path.rfind('@') {
        // Safety: pos is from rfind() within authority, pos+1 is within bounds
        #[expect(clippy::arithmetic_side_effects)]
        Some(pos) => &authority[pos + 1..],
        None => authority,
    }
}

/// Check if a path matches any glob pattern in the list.
fn matches_any_glob(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|pattern| {
        Glob::new(pattern)
            .ok()
            .is_some_and(|g| g.compile_matcher().is_match(path))
    })
}

/// Result of a policy check.
#[derive(Debug, Clone)]
pub enum PolicyResult {
    /// Action is allowed without further checks.
    Allowed,
    /// Action requires human approval.
    RequiresApproval(RiskAssessment),
    /// Action is blocked by policy — never allowed.
    Blocked {
        /// Why the action was blocked.
        reason: String,
    },
}

impl PolicyResult {
    /// Check if this result allows the action.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Check if this result requires approval.
    #[must_use]
    pub fn requires_approval(&self) -> bool {
        matches!(self, Self::RequiresApproval(_))
    }

    /// Check if this result blocks the action.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }
}

impl fmt::Display for PolicyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::RequiresApproval(assessment) => write!(f, "requires approval: {assessment}"),
            Self::Blocked { reason } => write!(f, "blocked: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
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
}
