//! Sensitive action classification.
//!
//! [`SensitiveAction`] categorizes risky operations that may require
//! human approval before execution. Each variant captures the relevant
//! context needed for informed decision-making.

use astrid_core::types::Permission;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A sensitive action that may require human approval.
///
/// Each variant represents a category of operation with enough context
/// for a human to make an informed allow/deny decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum SensitiveAction {
    /// Read a file or search the filesystem.
    ///
    /// Even read-only operations can expose sensitive data (credentials,
    /// private keys, personal information). Sensitive actions are gated by the
    /// allowance and approval system before they execute.
    FileRead {
        /// Path or pattern being read/searched.
        path: String,
    },

    /// Delete a file.
    FileDelete {
        /// Path to the file being deleted.
        path: String,
    },

    /// Write a file outside the operational workspace.
    FileWriteOutsideSandbox {
        /// Path to the file being written.
        path: String,
    },

    /// Execute a shell command.
    ExecuteCommand {
        /// The command to execute.
        command: String,
        /// Command arguments.
        args: Vec<String>,
    },

    /// Make a network request.
    NetworkRequest {
        /// Target host.
        host: String,
        /// Target port.
        port: u16,
    },

    /// Transmit data to an external destination.
    TransmitData {
        /// Where the data is being sent.
        destination: String,
        /// Type/classification of the data.
        data_type: String,
    },

    /// Perform a financial transaction.
    FinancialTransaction {
        /// Amount (as string to avoid floating-point issues).
        amount: String,
        /// Recipient identifier.
        recipient: String,
    },

    /// Change access control settings.
    AccessControlChange {
        /// The resource whose access is changing.
        resource: String,
        /// Description of the change.
        change: String,
    },

    /// Grant a capability token.
    CapabilityGrant {
        /// Resource pattern the capability covers.
        resource_pattern: String,
        /// Permissions being granted.
        permissions: Vec<Permission>,
    },

    /// Call an MCP tool that requires approval.
    McpToolCall {
        /// MCP server name.
        server: String,
        /// Tool name.
        tool: String,
    },

    /// Execute a capsule capability (host function call from WASM sandbox).
    CapsuleExecution {
        /// Capsule identifier.
        capsule_id: String,
        /// Capability being invoked (e.g., `config_read`, `kv_write`).
        capability: String,
    },

    /// Capsule requesting an outbound HTTP request.
    CapsuleHttpRequest {
        /// Capsule identifier.
        capsule_id: String,
        /// Target URL.
        url: String,
        /// HTTP method (GET, POST, etc.).
        method: String,
    },

    /// Capsule requesting file system access.
    CapsuleFileAccess {
        /// Capsule identifier.
        capsule_id: String,
        /// File path being accessed.
        path: String,
        /// Access mode (Read, Write, Delete).
        mode: Permission,
    },

    /// Capsule requesting to accept connections on a bound socket.
    CapsuleNetBind {
        /// Capsule identifier.
        capsule_id: String,
    },
}

impl SensitiveAction {
    /// Get a short label for the action type.
    #[must_use]
    pub fn action_type(&self) -> &'static str {
        match self {
            Self::FileRead { .. } => "file_read",
            Self::FileDelete { .. } => "file_delete",
            Self::FileWriteOutsideSandbox { .. } => "file_write_outside_sandbox",
            Self::ExecuteCommand { .. } => "execute_command",
            Self::NetworkRequest { .. } => "network_request",
            Self::TransmitData { .. } => "transmit_data",
            Self::FinancialTransaction { .. } => "financial_transaction",
            Self::AccessControlChange { .. } => "access_control_change",
            Self::CapabilityGrant { .. } => "capability_grant",
            Self::McpToolCall { .. } => "mcp_tool_call",
            Self::CapsuleExecution { .. } => "capsule_execution",
            Self::CapsuleHttpRequest { .. } => "capsule_http_request",
            Self::CapsuleFileAccess { .. } => "capsule_file_access",
            Self::CapsuleNetBind { .. } => "capsule_net_bind",
        }
    }

    /// Get a human-readable summary of the action.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::FileRead { path } => format!("Read: {path}"),
            Self::FileDelete { path } => format!("Delete file: {path}"),
            Self::FileWriteOutsideSandbox { path } => {
                format!("Write file outside workspace: {path}")
            },
            Self::ExecuteCommand { command, args } => {
                if args.is_empty() {
                    format!("Execute: {command}")
                } else {
                    format!("Execute: {command} {}", args.join(" "))
                }
            },
            Self::NetworkRequest { host, port } => format!("Network request to {host}:{port}"),
            Self::TransmitData {
                destination,
                data_type,
            } => format!("Transmit {data_type} to {destination}"),
            Self::FinancialTransaction { amount, recipient } => {
                format!("Financial transaction: {amount} to {recipient}")
            },
            Self::AccessControlChange { resource, change } => {
                format!("Access control change on {resource}: {change}")
            },
            Self::CapabilityGrant {
                resource_pattern,
                permissions,
            } => {
                let perms: Vec<_> = permissions.iter().map(ToString::to_string).collect();
                format!(
                    "Grant capability: [{}] on {resource_pattern}",
                    perms.join(", ")
                )
            },
            Self::McpToolCall { server, tool } => format!("MCP tool call: {server}/{tool}"),
            Self::CapsuleExecution {
                capsule_id,
                capability,
            } => format!("Capsule '{capsule_id}' wants to invoke capability '{capability}'"),
            Self::CapsuleHttpRequest {
                capsule_id,
                url,
                method,
            } => format!("Capsule '{capsule_id}' wants to {method} {url}"),
            Self::CapsuleFileAccess {
                capsule_id,
                path,
                mode,
            } => format!("Capsule '{capsule_id}' wants to {mode} {path}"),
            Self::CapsuleNetBind { capsule_id } => {
                format!("Capsule '{capsule_id}' wants to accept socket connections (net_bind)")
            },
        }
    }
}

impl fmt::Display for SensitiveAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_type_labels() {
        let action = SensitiveAction::FileDelete {
            path: "/tmp/test".to_string(),
        };
        assert_eq!(action.action_type(), "file_delete");

        let action = SensitiveAction::McpToolCall {
            server: "fs".to_string(),
            tool: "read".to_string(),
        };
        assert_eq!(action.action_type(), "mcp_tool_call");
    }

    #[test]
    fn test_action_summary() {
        let action = SensitiveAction::FileDelete {
            path: "/home/user/important.txt".to_string(),
        };
        assert_eq!(action.summary(), "Delete file: /home/user/important.txt");

        let action = SensitiveAction::ExecuteCommand {
            command: "rm".to_string(),
            args: vec!["-rf".to_string(), "/tmp/build".to_string()],
        };
        assert_eq!(action.summary(), "Execute: rm -rf /tmp/build");

        let action = SensitiveAction::CapabilityGrant {
            resource_pattern: "mcp://filesystem:*".to_string(),
            permissions: vec![Permission::Read, Permission::Write],
        };
        assert!(action.summary().contains("read, write"));
        assert!(action.summary().contains("mcp://filesystem:*"));
    }

    #[test]
    fn test_display_matches_summary() {
        let action = SensitiveAction::McpToolCall {
            server: "github".to_string(),
            tool: "create_issue".to_string(),
        };
        assert_eq!(action.to_string(), action.summary());
    }

    #[test]
    fn test_capsule_net_bind_action() {
        let action = SensitiveAction::CapsuleNetBind {
            capsule_id: "cli-proxy".to_string(),
        };
        assert_eq!(action.action_type(), "capsule_net_bind");
        assert_eq!(
            action.summary(),
            "Capsule 'cli-proxy' wants to accept socket connections (net_bind)"
        );
        assert_eq!(action.to_string(), action.summary());

        // Serialization roundtrip
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: SensitiveAction = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.action_type(), "capsule_net_bind");
    }

    #[test]
    fn test_capsule_action_type_labels() {
        assert_eq!(
            SensitiveAction::CapsuleExecution {
                capsule_id: "weather".to_string(),
                capability: "config_read".to_string(),
            }
            .action_type(),
            "capsule_execution"
        );
        assert_eq!(
            SensitiveAction::CapsuleHttpRequest {
                capsule_id: "weather".to_string(),
                url: "https://api.weather.com".to_string(),
                method: "GET".to_string(),
            }
            .action_type(),
            "capsule_http_request"
        );
        assert_eq!(
            SensitiveAction::CapsuleFileAccess {
                capsule_id: "weather".to_string(),
                path: "/tmp/cache.json".to_string(),
                mode: Permission::Read,
            }
            .action_type(),
            "capsule_file_access"
        );
    }

    #[test]
    fn test_capsule_summaries() {
        let action = SensitiveAction::CapsuleExecution {
            capsule_id: "weather".to_string(),
            capability: "config_read".to_string(),
        };
        assert_eq!(
            action.summary(),
            "Capsule 'weather' wants to invoke capability 'config_read'"
        );

        let action = SensitiveAction::CapsuleHttpRequest {
            capsule_id: "weather".to_string(),
            url: "https://api.weather.com/v1".to_string(),
            method: "POST".to_string(),
        };
        assert_eq!(
            action.summary(),
            "Capsule 'weather' wants to POST https://api.weather.com/v1"
        );

        let action = SensitiveAction::CapsuleFileAccess {
            capsule_id: "cache".to_string(),
            path: "/tmp/cache.json".to_string(),
            mode: Permission::Write,
        };
        assert_eq!(
            action.summary(),
            "Capsule 'cache' wants to write /tmp/cache.json"
        );
    }

    #[test]
    fn test_capsule_display_matches_summary() {
        let action = SensitiveAction::CapsuleExecution {
            capsule_id: "test".to_string(),
            capability: "cap".to_string(),
        };
        assert_eq!(action.to_string(), action.summary());
    }

    #[test]
    fn test_capsule_serialization_roundtrip() {
        let actions = vec![
            SensitiveAction::CapsuleExecution {
                capsule_id: "p1".to_string(),
                capability: "cap1".to_string(),
            },
            SensitiveAction::CapsuleHttpRequest {
                capsule_id: "p2".to_string(),
                url: "https://example.com".to_string(),
                method: "GET".to_string(),
            },
            SensitiveAction::CapsuleFileAccess {
                capsule_id: "p3".to_string(),
                path: "/tmp/file".to_string(),
                mode: Permission::Delete,
            },
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let deserialized: SensitiveAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action.action_type(), deserialized.action_type());
            assert_eq!(action.summary(), deserialized.summary());
        }
    }

    #[test]
    fn test_action_serialization() {
        let action = SensitiveAction::NetworkRequest {
            host: "api.example.com".to_string(),
            port: 443,
        };
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: SensitiveAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action.action_type(), deserialized.action_type());
    }
}
