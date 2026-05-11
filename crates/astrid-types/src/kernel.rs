//! Kernel management API request and response types.

use astrid_core::PrincipalId;
use astrid_core::profile::Quotas;
use serde::{Deserialize, Serialize};

/// The well-known system session UUID string used by the background daemon.
///
/// All kernel-internal IPC messages are published with this `source_id`.
/// WASM capsules that verify message provenance should compare against
/// this constant. Mirrors `astrid_core::SessionId::SYSTEM`.
pub const SYSTEM_SESSION_UUID: &str = "00000000-0000-0000-0000-000000000000";

/// Management API requests directed at the core daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum KernelRequest {
    /// Request to install a capsule from a local or remote path.
    InstallCapsule {
        /// The path or URL to the `.capsule` archive.
        source: String,
        /// True if this should be installed locally in the workspace.
        workspace: bool,
    },
    /// Request to approve a capability grant (usually following an `ApprovalNeeded` response).
    ApproveCapability {
        /// The unique ID of the request being approved.
        request_id: String,
        /// Cryptographic signature proving Root Identity authorization.
        signature: String,
    },
    /// Request the list of currently loaded capsules.
    ListCapsules,
    /// Reload all capsules from the file system.
    ReloadCapsules,
    /// Request the list of globally registered slash commands.
    GetCommands,
    /// Request metadata about loaded capsules (manifests, providers, interceptors).
    /// The kernel's equivalent of `/proc` — exposing process table info.
    GetCapsuleMetadata,
    /// Request the daemon to shut down gracefully.
    Shutdown {
        /// Optional reason for shutdown.
        reason: Option<String>,
    },
    /// Request daemon status information.
    GetStatus,
}

/// Management API responses from the core daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum KernelResponse {
    /// The request succeeded.
    Success(serde_json::Value),
    /// A list of available slash commands across all capsules.
    Commands(Vec<CommandInfo>),
    /// Metadata about loaded capsules.
    CapsuleMetadata(Vec<CapsuleMetadataEntry>),
    /// The request failed.
    Error(String),
    /// Daemon status information.
    Status(DaemonStatus),
    /// The request requires user capability approval before it can proceed.
    ApprovalRequired {
        /// Unique ID for this specific action request.
        request_id: String,
        /// Description of what is being requested.
        description: String,
        /// The specific capabilities required (e.g. `["host_process", "fs_write"]`).
        capabilities: Vec<String>,
    },
}

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
    /// Names of loaded capsules.
    pub loaded_capsules: Vec<String>,
}

/// Metadata entry for a loaded capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleMetadataEntry {
    /// The capsule's unique name.
    pub name: String,
    /// Interceptor event patterns declared by this capsule.
    pub interceptor_events: Vec<String>,
}

/// Information about a registered slash command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInfo {
    /// The slash command trigger (e.g. `/git`).
    pub name: String,
    /// A brief description of what the command does.
    pub description: String,
    /// The capsule that provides this command.
    pub provider_capsule: String,
}

// ---------------------------------------------------------------------------
// Admin management API (issue #672 — Layer 6)
// ---------------------------------------------------------------------------

/// Admin management API request wrapper carrying an optional client
/// correlation ID and the typed request kind.
///
/// `request_id` is echoed back on [`AdminKernelResponse::request_id`] so
/// clients with multiple in-flight requests on the same response topic
/// can disambiguate. Single-client deployments may leave it `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKernelRequest {
    /// Optional client-supplied correlation ID. Echoed verbatim on the
    /// response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The typed request body — `tag = "method", content = "params"`.
    #[serde(flatten)]
    pub kind: AdminRequestKind,
}

impl AdminKernelRequest {
    /// Build a request with no correlation ID.
    #[must_use]
    pub const fn new(kind: AdminRequestKind) -> Self {
        Self {
            request_id: None,
            kind,
        }
    }

    /// Build a request with a correlation ID.
    #[must_use]
    pub fn with_request_id(request_id: impl Into<String>, kind: AdminRequestKind) -> Self {
        Self {
            request_id: Some(request_id.into()),
            kind,
        }
    }
}

impl From<AdminRequestKind> for AdminKernelRequest {
    fn from(kind: AdminRequestKind) -> Self {
        Self::new(kind)
    }
}

/// Typed admin request body — flattened into [`AdminKernelRequest`] on
/// the wire as `{ "method": "...", "params": {...} }`.
///
/// Every variant is gated by the Layer 5 capability-enforcement preamble
/// through a sibling of
/// [`required_capability`](../../astrid-kernel/src/kernel_router.rs) —
/// see `required_capability_for_admin_request` for the exact mapping.
/// Mutating variants are serialized through the kernel's admin write lock
/// so concurrent callers cannot interleave on `groups.toml` / `profile.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum AdminRequestKind {
    /// Create a new agent identity. `name` must pass
    /// [`PrincipalId::new`](astrid_core::PrincipalId::new). Defaults to
    /// the built-in `agent` group when `groups` is empty.
    AgentCreate {
        /// Human-readable name and principal identifier for the new agent.
        name: String,
        /// Group memberships for the new principal; empty → `["agent"]`.
        #[serde(default)]
        groups: Vec<String>,
        /// Per-principal capability grants beyond group inheritance.
        #[serde(default)]
        grants: Vec<String>,
    },
    /// Delete an existing agent identity. The `default` principal is
    /// rejected unconditionally. The principal's home directory is NOT
    /// scrubbed — reclamation is an ops concern.
    AgentDelete {
        /// Principal to delete.
        principal: PrincipalId,
    },
    /// Set `enabled = true` on the target principal's profile.
    AgentEnable {
        /// Principal to enable.
        principal: PrincipalId,
    },
    /// Set `enabled = false` on the target principal's profile.
    /// In-flight invocations finish under the old value; new invocations
    /// are refused.
    AgentDisable {
        /// Principal to disable.
        principal: PrincipalId,
    },
    /// List every agent principal with a profile on disk.
    AgentList,
    /// Partial-update an existing agent's group memberships. Built-in
    /// group names (`admin`, `agent`, `restricted`) and custom groups
    /// loaded from `groups.toml` are both accepted as identifiers;
    /// validation that the named groups exist happens at the new
    /// profile's `validate` step. Mutations are idempotent — adding an
    /// already-present group or removing an absent one is a no-op.
    AgentModify {
        /// Principal to modify.
        principal: PrincipalId,
        /// Groups to add (idempotent).
        #[serde(default)]
        add_groups: Vec<String>,
        /// Groups to remove (idempotent — missing entries are no-ops).
        /// Removing the last group leaves the agent in zero groups,
        /// which the `agent` built-in does NOT auto-restore; operators
        /// who want a baseline should add `agent` explicitly.
        #[serde(default)]
        remove_groups: Vec<String>,
    },
    /// Replace the target principal's [`Quotas`] block. Values are
    /// validated before the atomic profile write.
    QuotaSet {
        /// Principal whose quotas are being set.
        principal: PrincipalId,
        /// Replacement quota values.
        quotas: Quotas,
    },
    /// Read the target principal's current [`Quotas`] block.
    QuotaGet {
        /// Principal whose quotas are being read.
        principal: PrincipalId,
    },
    /// Create a custom group, validated through the same rules the boot
    /// loader applies to `groups.toml`.
    GroupCreate {
        /// Name of the new custom group.
        name: String,
        /// Capability patterns conferred by the new group.
        capabilities: Vec<String>,
        /// Human-readable description.
        #[serde(default)]
        description: Option<String>,
        /// Required when `capabilities` contains the universal `*` pattern.
        #[serde(default)]
        unsafe_admin: bool,
    },
    /// Remove a custom group. Built-in groups (`admin`, `agent`,
    /// `restricted`) are rejected.
    GroupDelete {
        /// Name of the group to remove.
        name: String,
    },
    /// Partial-update a custom group. Every provided field replaces the
    /// corresponding field on the existing group. Built-ins are rejected.
    GroupModify {
        /// Name of the group to modify.
        name: String,
        /// New capability patterns, if changing.
        #[serde(default)]
        capabilities: Option<Vec<String>>,
        /// New description, if changing. Outer `None` = keep, inner
        /// `None` = clear.
        #[serde(default)]
        description: Option<Option<String>>,
        /// New `unsafe_admin` flag, if changing.
        #[serde(default)]
        unsafe_admin: Option<bool>,
    },
    /// List every group (built-in + custom) with its capability set.
    GroupList,
    /// Append capability patterns to the principal's `grants` vec. Does
    /// NOT clear matching revokes — revoke precedence is preserved.
    CapsGrant {
        /// Principal receiving the grants.
        principal: PrincipalId,
        /// Capability patterns to add.
        capabilities: Vec<String>,
        /// Required when `capabilities` contains the universal `*`
        /// pattern. Mirrors the `unsafe_admin` rail on
        /// [`Self::GroupCreate`] / [`Self::GroupModify`] so an
        /// individual grant cannot escalate a principal to universal
        /// admin without an explicit acknowledgement.
        #[serde(default)]
        unsafe_admin: bool,
    },
    /// Append capability patterns to the principal's `revokes` vec. Safe
    /// to call on caps the principal does not currently hold
    /// (pre-emptive revoke).
    CapsRevoke {
        /// Principal losing the capabilities.
        principal: PrincipalId,
        /// Capability patterns to revoke.
        capabilities: Vec<String>,
    },
}

/// Admin management API response wrapper carrying the echoed
/// correlation ID and the typed response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKernelResponse {
    /// Echoed `request_id` from the [`AdminKernelRequest`] this response
    /// answers. `None` when the client did not provide one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The typed response body — `tag = "status", content = "data"`.
    #[serde(flatten)]
    pub body: AdminResponseBody,
}

impl AdminKernelResponse {
    /// Build a response with the given body and no correlation ID.
    #[must_use]
    pub const fn new(body: AdminResponseBody) -> Self {
        Self {
            request_id: None,
            body,
        }
    }

    /// Build a response that echoes a request's correlation ID.
    #[must_use]
    pub fn for_request(request_id: Option<String>, body: AdminResponseBody) -> Self {
        Self { request_id, body }
    }
}

/// Typed admin response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum AdminResponseBody {
    /// Generic success payload — used by mutating variants where the
    /// interesting result is "the write landed."
    Success(serde_json::Value),
    /// Response for [`AdminRequestKind::AgentList`].
    AgentList(Vec<AgentSummary>),
    /// Response for [`AdminRequestKind::GroupList`].
    GroupList(Vec<GroupSummary>),
    /// Response for [`AdminRequestKind::QuotaGet`].
    Quotas(Quotas),
    /// The request failed.
    Error(String),
}

/// Summary of an agent principal returned by
/// [`AdminKernelRequest::AgentList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSummary {
    /// The principal identifier.
    pub principal: PrincipalId,
    /// Whether the principal is currently enabled (master switch).
    pub enabled: bool,
    /// Group memberships as written to `profile.toml`.
    pub groups: Vec<String>,
    /// Direct capability grants beyond group inheritance.
    pub grants: Vec<String>,
    /// Explicit revokes (highest-precedence deny).
    pub revokes: Vec<String>,
}

/// Summary of a group returned by [`AdminKernelRequest::GroupList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSummary {
    /// Group name.
    pub name: String,
    /// Capability patterns conferred by this group.
    pub capabilities: Vec<String>,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the group opted in to granting the universal `*`.
    pub unsafe_admin: bool,
    /// `true` for built-in groups (`admin`, `agent`, `restricted`).
    /// Clients should treat built-ins as read-only.
    pub builtin: bool,
}
