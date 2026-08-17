//! Human-facing presentation for capsule capability grants.
//!
//! Enforcement consumes the raw manifest. Humans must not be asked to infer
//! security meaning from field names such as `net_connect` or from an easily
//! missed `:*` port wildcard. This module translates every capability into an
//! action, its exact scope, and its impact so CLI and dashboard surfaces can
//! render the same semantics instead of each inventing their own wording.

use serde::Serialize;

use crate::manifest::{CapabilitiesDef, CapabilityExpansion};

/// A capability rendered for an install or upgrade consent surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticCapability {
    /// Manifest field name, kept for correlation with raw policy.
    pub capability: String,
    /// Plain-language action enabled by this grant.
    pub action: String,
    /// Exact scopes, in deterministic manifest order.
    pub scope: Vec<String>,
    /// What a non-expert should understand before approving.
    pub impact: String,
}

/// Translate every held capability in a manifest.
#[must_use]
pub fn semantic_capabilities(capabilities: &CapabilitiesDef) -> Vec<SemanticCapability> {
    let mut result = Vec::new();

    let CapabilitiesDef {
        uplink,
        net,
        kv,
        fs_read,
        fs_write,
        host_process,
        allow_persistent,
        net_bind,
        net_connect,
        identity,
        allow_prompt_injection,
    } = capabilities;

    if *uplink {
        result.push(SemanticCapability {
            capability: "uplink".into(),
            action: "Run continuously as an uplink service".into(),
            scope: vec![],
            impact: "Can receive messages and remain active between turns.".into(),
        });
    }
    if !net.is_empty() {
        result.push(SemanticCapability {
            capability: "net".into(),
            action: "Make web requests to approved domains".into(),
            scope: net.clone(),
            impact: "Can send requests and request data to these domains.".into(),
        });
    }
    if !kv.is_empty() {
        result.push(SemanticCapability {
            capability: "kv".into(),
            action: "Use Astrid key-value storage".into(),
            scope: kv.clone(),
            impact: "Can store and retrieve values in the listed namespaces.".into(),
        });
    }
    if !fs_read.is_empty() {
        result.push(SemanticCapability {
            capability: "fs_read".into(),
            action: "Read files and folders".into(),
            scope: fs_read.clone(),
            impact: "Can inspect the listed locations; treat credentials and personal data as sensitive.".into(),
        });
    }
    if !fs_write.is_empty() {
        result.push(SemanticCapability {
            capability: "fs_write".into(),
            action: "Create or change files and folders".into(),
            scope: fs_write.clone(),
            impact: "Can modify the listed locations.".into(),
        });
    }
    if !host_process.is_empty() {
        result.push(SemanticCapability {
            capability: "host_process".into(),
            action: "Launch approved host programs".into(),
            scope: host_process.clone(),
            impact: "Can run the listed executables inside the OS sandbox.".into(),
        });
    }
    if *allow_persistent {
        result.push(SemanticCapability {
            capability: "allow_persistent".into(),
            action: "Keep host processes running after a tool call".into(),
            scope: vec![],
            impact: "A child can outlive the capsule invocation until it exits or is stopped."
                .into(),
        });
    }
    if !net_bind.is_empty() {
        let (unix, tcp): (Vec<_>, Vec<_>) = net_bind
            .iter()
            .partition(|entry| entry.starts_with("unix:"));
        if !tcp.is_empty() {
            result.push(SemanticCapability {
                capability: "net_bind".into(),
                action: "Accept local TCP connections".into(),
                scope: tcp.iter().map(|entry| bind_scope(entry)).collect(),
                impact: "Other local programs can connect to these allowed endpoints.".into(),
            });
        }
        if !unix.is_empty() {
            result.push(SemanticCapability {
                capability: "net_bind".into(),
                action: "Create local Unix sockets".into(),
                scope: unix.into_iter().cloned().collect(),
                impact: "Local processes may communicate with this capsule through those sockets."
                    .into(),
            });
        }
    }
    if !net_connect.is_empty() {
        result.push(SemanticCapability {
            capability: "net_connect".into(),
            action: "Connect to approved network services".into(),
            scope: net_connect
                .iter()
                .map(|entry| connect_scope(entry))
                .collect(),
            impact: "Can send data to and receive data from these endpoints.".into(),
        });
    }
    if !identity.is_empty() {
        result.push(SemanticCapability {
            capability: "identity".into(),
            action: "Use linked identity operations".into(),
            scope: identity.clone(),
            impact:
                "Identity links identify accounts across systems; 'admin' can create identities."
                    .into(),
        });
    }
    if *allow_prompt_injection {
        result.push(SemanticCapability {
            capability: "allow_prompt_injection".into(),
            action: "Change the agent's system instructions".into(),
            scope: vec![],
            impact: "Can alter hidden instructions that guide future behavior; grant only to trusted capsules.".into(),
        });
    }

    result
}

/// Translate one newly-added authority expansion.
#[must_use]
pub fn semantic_expansion(expansion: &CapabilityExpansion) -> SemanticCapability {
    let action = match expansion.name.as_str() {
        "uplink" => "Run continuously as an uplink service",
        "net" => "Make web requests to additional domains",
        "kv" => "Use additional Astrid key-value namespaces",
        "fs_read" => "Read additional files or folders",
        "fs_write" => "Change additional files or folders",
        "host_process" => "Launch additional host programs",
        "allow_persistent" => "Keep host processes running after a tool call",
        "net_bind" => "Accept additional local network connections",
        "net_connect" => "Connect to additional network services",
        "identity" => "Use additional identity operations",
        "allow_prompt_injection" => "Change the agent's system instructions",
        _ => "Use additional host capability",
    };
    let scope = expansion
        .added
        .iter()
        .map(|value| match expansion.name.as_str() {
            "net_connect" => connect_scope(value),
            "net_bind" => bind_scope(value),
            "allow_persistent" | "allow_prompt_injection" | "uplink" => "enabled".to_string(),
            _ => value.clone(),
        })
        .collect();
    let impact = match expansion.name.as_str() {
        "net_connect" | "net" => {
            "This is new outbound authority; check the destination before approving."
        },
        "net_bind" => {
            "This is a new local listening endpoint; wildcard ports also cover ephemeral ports."
        },
        "fs_write" => "This expands where this capsule can modify data.",
        "host_process" => "This expands which host executables the capsule can launch.",
        "identity" => "This expands identity authority; 'admin' is the highest level.",
        "allow_prompt_injection" => {
            "This can change hidden agent instructions; treat it as high trust."
        },
        _ => "This grants authority beyond the previously approved install.",
    };

    SemanticCapability {
        capability: expansion.name.clone(),
        action: action.into(),
        scope,
        impact: impact.into(),
    }
}

fn connect_scope(entry: &str) -> String {
    let Some((host, port)) = entry.rsplit_once(':') else {
        return entry.to_string();
    };
    let host = if host == "*" { "any host" } else { host };
    if port == "*" {
        format!("{host}: any port, including OS-assigned ephemeral ports")
    } else {
        format!("{host}: port {port}")
    }
}

fn bind_scope(entry: &str) -> String {
    connect_scope(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_wildcards_are_explicit_about_ephemeral_ports() {
        let expansion = CapabilityExpansion {
            name: "net_connect".into(),
            added: vec![
                "api.example.com:443".into(),
                "service.example.com:*".into(),
                "*:*".into(),
            ],
        };
        let semantic = semantic_expansion(&expansion);
        assert_eq!(
            semantic.scope,
            [
                "api.example.com: port 443",
                "service.example.com: any port, including OS-assigned ephemeral ports",
                "any host: any port, including OS-assigned ephemeral ports",
            ]
        );
    }

    #[test]
    fn semantic_expansion_translates_every_known_capability() {
        let cases = [
            (
                "uplink",
                vec!["enabled"],
                "Run continuously as an uplink service",
                vec!["enabled"],
                "This grants authority beyond the previously approved install.",
            ),
            (
                "net",
                vec!["api.example"],
                "Make web requests to additional domains",
                vec!["api.example"],
                "This is new outbound authority; check the destination before approving.",
            ),
            (
                "kv",
                vec!["records"],
                "Use additional Astrid key-value namespaces",
                vec!["records"],
                "This grants authority beyond the previously approved install.",
            ),
            (
                "fs_read",
                vec!["/workspace"],
                "Read additional files or folders",
                vec!["/workspace"],
                "This grants authority beyond the previously approved install.",
            ),
            (
                "fs_write",
                vec!["/workspace"],
                "Change additional files or folders",
                vec!["/workspace"],
                "This expands where this capsule can modify data.",
            ),
            (
                "host_process",
                vec!["git"],
                "Launch additional host programs",
                vec!["git"],
                "This expands which host executables the capsule can launch.",
            ),
            (
                "allow_persistent",
                vec!["enabled"],
                "Keep host processes running after a tool call",
                vec!["enabled"],
                "This grants authority beyond the previously approved install.",
            ),
            (
                "net_bind",
                vec!["127.0.0.1:9", "127.0.0.1:*"],
                "Accept additional local network connections",
                vec![
                    "127.0.0.1: port 9",
                    "127.0.0.1: any port, including OS-assigned ephemeral ports",
                ],
                "This is a new local listening endpoint; wildcard ports also cover ephemeral ports.",
            ),
            (
                "net_connect",
                vec!["api.example:443", "api.example:*"],
                "Connect to additional network services",
                vec![
                    "api.example: port 443",
                    "api.example: any port, including OS-assigned ephemeral ports",
                ],
                "This is new outbound authority; check the destination before approving.",
            ),
            (
                "identity",
                vec!["admin"],
                "Use additional identity operations",
                vec!["admin"],
                "This expands identity authority; 'admin' is the highest level.",
            ),
            (
                "allow_prompt_injection",
                vec!["enabled"],
                "Change the agent's system instructions",
                vec!["enabled"],
                "This can change hidden agent instructions; treat it as high trust.",
            ),
        ];

        for (name, added, action, scope, impact) in cases {
            let expansion = CapabilityExpansion {
                name: name.to_string(),
                added: added.into_iter().map(str::to_string).collect(),
            };
            let semantic = semantic_expansion(&expansion);
            assert_eq!(semantic.capability, name);
            assert_eq!(semantic.action, action);
            assert_eq!(semantic.scope, scope);
            assert_eq!(semantic.impact, impact);
        }

        for name in ["allow_persistent", "allow_prompt_injection", "uplink"] {
            let expansion = CapabilityExpansion {
                name: name.to_string(),
                added: vec!["true".to_string()],
            };
            assert_eq!(
                semantic_expansion(&expansion).scope,
                ["enabled"],
                "boolean authority must render consistently even for non-canonical input"
            );
        }
    }

    #[test]
    fn high_impact_capabilities_are_not_flattened() {
        let capabilities = CapabilitiesDef {
            uplink: true,
            net: vec![],
            kv: vec![],
            fs_read: vec!["/workspace/read".into()],
            fs_write: vec!["/workspace/write".into()],
            host_process: vec!["git".into()],
            allow_persistent: true,
            net_bind: vec!["127.0.0.1:*".into(), "unix:*".into()],
            net_connect: vec![],
            identity: vec![],
            allow_prompt_injection: true,
        };
        let semantic = semantic_capabilities(&capabilities);
        assert_eq!(semantic.len(), 8);
        assert!(
            semantic
                .iter()
                .any(|item| item.action == "Change the agent's system instructions")
        );
        assert!(
            semantic
                .iter()
                .flat_map(|item| item.scope.iter())
                .any(|scope| scope.contains("any port, including OS-assigned ephemeral ports"))
        );
    }
}
