//! Human-readable descriptions of audit actions.

use super::AuditAction;

impl AuditAction {
    /// Describe the MCP-prefixed actions (tool/capsule call, resource,
    /// prompt, elicitation, sampling). Returns `None` for non-MCP actions so
    /// [`description`](Self::description) can fall through. Factored out to
    /// keep `description` under the function-length lint.
    fn describe_mcp(&self) -> Option<String> {
        let s = match self {
            Self::McpToolCall { server, tool, .. } => {
                format!("Called tool {server}:{tool}")
            },
            Self::CapsuleToolCall {
                capsule_id, tool, ..
            } => {
                format!("Called capsule tool {capsule_id}:{tool}")
            },
            Self::McpResourceRead { server, uri } => {
                format!("Read resource {server}:{uri}")
            },
            Self::McpPromptGet { server, name } => {
                format!("Got prompt {server}:{name}")
            },
            Self::McpElicitation { request_id, schema } => {
                format!("Elicitation {request_id} ({schema})")
            },
            Self::McpUrlElicitation {
                interaction_type, ..
            } => {
                format!("URL elicitation ({interaction_type})")
            },
            Self::McpSampling { model, .. } => {
                format!("Sampling request to {model}")
            },
            _ => return None,
        };
        Some(s)
    }

    /// Describe the host-call actions (file, network, process, HTTP).
    /// Returns `None` for other actions.
    fn describe_host_call(&self) -> Option<String> {
        let s = match self {
            Self::FileRead { path, .. } => format!("Read file {path}"),
            Self::FileWrite { path, .. } => format!("Wrote file {path}"),
            Self::FileDelete { path, .. } => format!("Deleted file {path}"),
            Self::NetConnect { host, port, .. } => format!("Connected to {host}:{port}"),
            Self::NetBind { addr, .. } => format!("Bound socket {addr}"),
            Self::NetAccept {
                local_addr,
                peer_addr,
                ..
            } => format!("Accepted connection from {peer_addr} on {local_addr}"),
            Self::ProcessSpawn { command, .. } => format!("Spawned process {command}"),
            Self::HttpRequest {
                sequence,
                method,
                host,
                port,
                ..
            } => format!("HTTP request #{sequence} {method} {host}:{port}"),
            Self::HttpResponse {
                sequence, status, ..
            } => match status {
                Some(status) => format!("HTTP response #{sequence} status {status}"),
                None => format!("HTTP response #{sequence} without status"),
            },
            _ => return None,
        };
        Some(s)
    }

    /// Describe authority and code-identity changes (capabilities,
    /// approvals, capsule install/load). Returns `None` for other actions.
    fn describe_authority(&self) -> Option<String> {
        let s = match self {
            Self::CapabilityCreated { resource, .. } => {
                format!("Created capability for {resource}")
            },
            Self::CapabilityRevoked { token_id, .. } => {
                format!("Revoked capability {token_id}")
            },
            Self::CapabilityChanged {
                target_principal,
                kind,
                via,
                ..
            } => format!("Changed {kind} grants of {target_principal} via {via}"),
            Self::ApprovalRequested {
                action_type,
                resource,
                ..
            } => {
                format!("Approval requested: {action_type} on {resource}")
            },
            Self::ApprovalGranted { action, .. } => format!("Approved: {action}"),
            Self::ApprovalDenied { action, .. } => format!("Denied: {action}"),
            Self::CapsuleInstalled {
                capsule_id,
                version,
                ..
            } => format!("Installed capsule {capsule_id}@{version}"),
            Self::CapsuleLoaded {
                capsule_id,
                version,
                trigger,
                ..
            } => format!("Loaded capsule {capsule_id}@{version} ({trigger})"),
            _ => return None,
        };
        Some(s)
    }

    /// Get a human-readable description of the action.
    ///
    /// Grouped actions are described by the `describe_*` helpers; each helper
    /// returns `Some` for exactly the variants routed to it, so the fallbacks
    /// are never taken — they keep the call total instead of panicking. Split
    /// this way to stay under the function-length lint.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::McpToolCall { .. }
            | Self::CapsuleToolCall { .. }
            | Self::McpResourceRead { .. }
            | Self::McpPromptGet { .. }
            | Self::McpElicitation { .. }
            | Self::McpUrlElicitation { .. }
            | Self::McpSampling { .. } => self.describe_mcp().unwrap_or_default(),
            Self::FileRead { .. }
            | Self::FileWrite { .. }
            | Self::FileDelete { .. }
            | Self::NetConnect { .. }
            | Self::NetBind { .. }
            | Self::NetAccept { .. }
            | Self::ProcessSpawn { .. }
            | Self::HttpRequest { .. }
            | Self::HttpResponse { .. } => self.describe_host_call().unwrap_or_default(),
            Self::CapabilityCreated { .. }
            | Self::CapabilityRevoked { .. }
            | Self::CapabilityChanged { .. }
            | Self::ApprovalRequested { .. }
            | Self::ApprovalGranted { .. }
            | Self::ApprovalDenied { .. }
            | Self::CapsuleInstalled { .. }
            | Self::CapsuleLoaded { .. } => self.describe_authority().unwrap_or_default(),
            Self::SessionStarted { platform, .. } => {
                format!("Session started via {platform}")
            },
            Self::SessionEnded { reason, .. } => {
                format!("Session ended: {reason}")
            },
            Self::ContextSummarized { evicted_count, .. } => {
                format!("Summarized {evicted_count} messages")
            },
            Self::LlmRequest { model, .. } => {
                format!("LLM request to {model}")
            },
            Self::ServerStarted { name, .. } => {
                format!("Started server {name}")
            },
            Self::ServerStopped { name, .. } => {
                format!("Stopped server {name}")
            },
            Self::ElicitationSent { server, .. } => {
                format!("Elicitation from {server}")
            },
            Self::ElicitationReceived { action, .. } => {
                format!("Elicitation response: {action}")
            },
            Self::SecurityViolation { violation_type, .. } => {
                format!("Security violation: {violation_type}")
            },
            Self::SubAgentSpawned { description, .. } => {
                format!("Spawned sub-agent: {description}")
            },
            Self::ConfigReloaded => "Configuration reloaded".to_string(),
            Self::AdminRequest {
                method,
                required_capability,
                target_principal,
                params: _,
                device_key_id: _,
            } => match target_principal {
                Some(target) => {
                    format!("Admin {method} on {target} (capability {required_capability})")
                },
                None => format!("Admin {method} (capability {required_capability})"),
            },
        }
    }
}
