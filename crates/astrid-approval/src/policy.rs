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
#[path = "policy_tests.rs"]
mod tests;
