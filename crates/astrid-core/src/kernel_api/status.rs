//! Daemon status wire types.

use serde::{Deserialize, Serialize};

/// Daemon runtime status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Process ID of the daemon.
    pub pid: u32,
    /// Daemon uptime in seconds.
    pub uptime_secs: u64,
    /// Daemon version string.
    pub version: String,
    /// Whether the daemon is running in ephemeral mode.
    pub ephemeral: bool,
    /// Number of currently connected clients.
    pub connected_clients: u32,
    /// Per-principal breakdown of `connected_clients`.
    ///
    /// Empty on older daemons and when no clients are connected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections_by_principal: Vec<PrincipalConnectionCount>,
    /// Names of loaded capsules.
    pub loaded_capsules: Vec<String>,
    /// Highest capsule-install batch protocol revision supported by this daemon.
    ///
    /// Absent on older daemons, which must use the ordinary per-member path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_install_batch_protocol: Option<u16>,
}

/// Per-principal connection count entry on [`DaemonStatus`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalConnectionCount {
    /// The principal holding the connections.
    pub principal: String,
    /// Number of active connections owned by this principal.
    pub count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_status_without_batch_protocol_decodes_as_unsupported() {
        let status: DaemonStatus = serde_json::from_value(serde_json::json!({
            "pid": 1,
            "uptime_secs": 2,
            "version": "2026.9.2",
            "ephemeral": false,
            "connected_clients": 0,
            "loaded_capsules": []
        }))
        .expect("legacy daemon status");
        assert_eq!(status.capsule_install_batch_protocol, None);
    }
}
