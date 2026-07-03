//! Kernel management API request and response types.
//!
//! These types describe the CLI ↔ daemon RPC surface (admin requests,
//! status queries, capsule lifecycle ops). They live in `astrid-core`
//! because they reference `PrincipalId` and `Quotas` from this crate.
//!
//! Capsule-facing IPC types live in `astrid-types` (which intentionally
//! has no dependency on `astrid-core` — it must compile on
//! `wasm32-unknown-unknown` without dragging in the kernel).

mod readiness;
pub use readiness::{AgentLoopReadiness, AgentReadinessProbe, CapsuleTopicProbe, MissingImport};

use crate::PrincipalId;
use crate::profile::Quotas;
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
    /// Reload a single capsule by id without a daemon restart: hot-swap it if
    /// already loaded (picking up the new on-disk bytes a reinstall wrote), or
    /// load it if not yet registered. Lets a fresh `astrid capsule install` /
    /// `update` make the capsule usable without restarting the daemon.
    ReloadCapsule {
        /// The capsule id (its `[package].name`).
        id: String,
    },
    /// Unload a single capsule by id without a daemon restart: unregister it
    /// from the running daemon so it stops receiving events and its tools leave
    /// the surface. Lets a fresh `astrid capsule remove` take effect live. The
    /// on-disk removal is authoritative and dependency-checked by the CLI; this
    /// only mirrors that into the running registry.
    UnloadCapsule {
        /// The capsule id (its `[package].name`).
        id: String,
    },
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
    /// Request agent-loop readiness: whether the loaded capsule set can serve
    /// an agent chat turn. Read-only, name-agnostic — see [`AgentLoopReadiness`].
    GetAgentReadiness,
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
    /// Agent-loop readiness report.
    AgentReadiness(AgentLoopReadiness),
    /// The request requires user capability approval before it can proceed.
    ApprovalRequired {
        /// Unique ID for this specific action request.
        request_id: String,
        /// Description of what is being requested.
        description: String,
        /// The specific capabilities required (e.g. `["host_process", "fs_write"]`).
        capabilities: Vec<String>,
    },
    /// Liveness / keepalive signal that a long-running request is still being
    /// processed. Serializes as `{"status":"Working"}` (the enum uses
    /// `PascalCase` variant names on the wire, matching `Success` / `Error`).
    ///
    /// The kernel emits this periodically on a request's response topic while a
    /// slow handler (chiefly `InstallCapsule`, which loads and runs a capsule's
    /// `#[install]` hook) is still in flight. It is **never** a terminal
    /// response: an uplink that receives it resets its inactivity window and
    /// keeps waiting for the real response, and it never reaches an HTTP client
    /// — the uplink swallows it (see `astrid-uplink`'s `KernelClient::request`).
    /// A stray late `Working` that races out after the terminal response is
    /// harmless: the uplink skips it and returns the already-received terminal.
    Working,
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
    /// Per-principal breakdown of `connected_clients`. Each entry is
    /// `(principal, count)`; the sum equals `connected_clients`. Empty
    /// on daemons that don't yet expose per-principal connection
    /// attribution (older builds, or when no clients are connected).
    /// Used by `astrid who` to show who is actually on the daemon
    /// rather than the bare count.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections_by_principal: Vec<PrincipalConnectionCount>,
    /// Names of loaded capsules.
    pub loaded_capsules: Vec<String>,
}

/// Per-principal connection count entry on [`DaemonStatus`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalConnectionCount {
    /// The principal (agent) holding the connections.
    pub principal: String,
    /// Number of active connections owned by this principal.
    pub count: u32,
}

/// Metadata entry for a loaded capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleMetadataEntry {
    /// The capsule's unique name.
    pub name: String,
    /// Interceptor event patterns declared by this capsule.
    pub interceptor_events: Vec<String>,
}

/// How a capsule-declared command is surfaced to operators.
///
/// A capsule declares commands via `[[command]]` in its `Capsule.toml`.
/// The `kind` selects the surface:
///
/// * [`CommandKind::Slash`] — an in-TUI slash command (`/git`), dispatched
///   through the chat loop. This is the historical behaviour and the
///   default when `kind` is absent, so every pre-existing manifest keeps
///   parsing and behaving identically.
/// * [`CommandKind::Cli`] — a top-level CLI verb invocable as
///   `astrid capsule <verb> [args...]`, dispatched to the providing capsule
///   over IPC as a non-interactive one-shot.
///
/// # CLI-verb wire contract (kernel does NOT interpret it)
///
/// The kernel plays no part in running a CLI verb beyond surfacing its
/// existence through `GetCommands`. Dispatch is pure capsule-space IPC:
///
/// * **Run** — the CLI publishes an `IpcPayload::RawJson` message on the
///   provider-targeted topic `cli.v1.command.run.<provider_capsule>` with
///   body `{ "req_id": <uuid>, "command": <verb>, "args": [<string>...] }`.
/// * **Result** — the capsule replies on `cli.v1.command.result.<req_id>`
///   with body `{ "req_id": <uuid>, "exit_code": <number>,
///   "output": <string>, "error": <string?> }`.
///
/// **Security rationale for the provider-targeted run topic:** a capsule
/// subscribes only `cli.v1.command.run.<its-own-id>`, so a capsule never
/// observes the command arguments addressed to a *different* capsule.
/// Per-`req_id` result topics keep concurrent invocations isolated. The
/// kernel routes these topics but never reads or validates the payload
/// bodies — they are capsule-space contract, not kernel surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommandKind {
    /// In-TUI slash command (default). Listed and dispatched by the chat
    /// loop, never as a top-level CLI verb.
    #[default]
    Slash,
    /// Top-level CLI verb: `astrid capsule <verb> [args...]`.
    Cli,
}

impl CommandKind {
    /// Returns `true` for the default kind so serializers can omit it
    /// (matches the rest of the manifest fields' conventions).
    #[must_use]
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Slash)
    }
}

/// Built-in `astrid capsule` subcommand names that a capsule-declared CLI
/// verb (`kind = "cli"`) may NOT shadow.
///
/// A `kind = "cli"` command whose name appears here is rejected at manifest
/// parse time (fail closed) so a capsule cannot mask or impersonate a
/// built-in verb such as `install` or `remove`.
///
/// **This list MUST stay in sync with the `CapsuleCommands` clap enum in
/// `astrid-cli` (`cli.rs`).** A unit test in astrid-cli asserts every
/// `CapsuleCommands` variant's clap name appears here; if you add a
/// built-in `astrid capsule` subcommand, add its name here too.
pub const RESERVED_CAPSULE_VERBS: &[&str] = &[
    "new", "install", "update", "list", "remove", "tree", "deps", "build", "check", "config",
    "show", "run", "help",
];

/// Information about a registered capsule command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInfo {
    /// The command trigger (e.g. `git`; rendered `/git` for slash commands).
    pub name: String,
    /// A brief description of what the command does.
    pub description: String,
    /// The capsule that provides this command.
    pub provider_capsule: String,
    /// How this command is surfaced (slash vs CLI verb). Defaults to
    /// [`CommandKind::Slash`] for wire compatibility with daemons that
    /// predate the field.
    #[serde(default, skip_serializing_if = "CommandKind::is_default")]
    pub kind: CommandKind,
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

/// Requested capability scope for a [`AdminRequestKind::PairDeviceIssue`]
/// token — what the redeemed device is allowed to do with the principal's
/// authority.
///
/// The kernel resolves this against the ISSUER's *effective* capability set at
/// issue time (no-escalation: a device can never confer more than the issuer
/// holds, where the issuer's effective set is itself narrowed by the issuer's
/// own authenticating device scope) and stamps the resolved
/// [`DeviceScope`](crate::DeviceScope) onto the minted token, so the redeemed
/// device is attenuated to exactly the granted scope on every transport.
///
/// On the wire it is an internally-tagged object: `{ "kind": "full" }`,
/// `{ "kind": "preset", "name": "use-only" }`, or
/// `{ "kind": "explicit", "allow": [...], "deny": [...] }`. The `scope` field
/// on `PairDeviceIssue` defaults to [`PairScopeArg::Full`] when omitted, so
/// pre-scope callers (and single-tenant admin flows) keep their existing
/// behaviour — but minting a `Full` device additionally requires the issuer to
/// hold `self:auth:pair:admin`, enforced in the handler.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PairScopeArg {
    /// Mint an unattenuated device — it acts with the principal's full
    /// effective capability set. Requires the issuer to hold
    /// `self:auth:pair:admin`. The default when `scope` is omitted (the
    /// permissive default is still gated on the admin cap, so it does not
    /// relax authority).
    #[default]
    Full,
    /// Resolve a named scope preset (e.g. `"use-only"`) via
    /// [`DeviceScope::preset`](crate::DeviceScope::preset). An unknown name is
    /// rejected at issue time.
    Preset {
        /// The preset name.
        name: String,
    },
    /// An explicit allow/deny capability scope. Every `allow` pattern must be
    /// held by the issuer (subset check); `deny` patterns purely restrict.
    Explicit {
        /// Capability patterns the device may exercise.
        #[serde(default)]
        allow: Vec<String>,
        /// Capability patterns the device is forbidden to exercise (deny wins).
        #[serde(default)]
        deny: Vec<String>,
    },
}

/// Serde default for [`AdminRequestKind::PairDeviceIssue::scope`] — `Full`,
/// for back-compat with callers that predate the `scope` field. A `Full` mint
/// is independently gated on `self:auth:pair:admin` in the handler, so the
/// permissive *default* does not relax the *authority* required to use it.
fn default_pair_scope() -> PairScopeArg {
    PairScopeArg::Full
}

/// Per-device summary returned by [`AdminRequestKind::PairDeviceList`].
///
/// Carries only non-secret, fingerprint-level identity — the deterministic
/// `key_id`, the operator label, the granted [`DeviceScope`](crate::DeviceScope),
/// and the pairing timestamp. The raw ed25519 public key is **never** surfaced;
/// the `key_id` (derived from the already-public pubkey) is the stable handle
/// for listing and revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeyInfo {
    /// Deterministic per-device fingerprint handle.
    pub key_id: String,
    /// Operator/user-facing label captured at pairing time, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Capability attenuation scope the device authenticates under.
    pub scope: crate::DeviceScope,
    /// Unix epoch seconds when the device was paired (`0` for migrated
    /// legacy keys that predate pairing-time recording).
    pub created_at: i64,
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
        /// Opt-in inheritance source. When `Some`, the new principal
        /// receives a full copy of this source principal's `.config/env/`,
        /// per-capsule KV namespaces, and per-capsule secret files. When
        /// `None` (the default) the new principal inherits **nothing** —
        /// least privilege, no silent credential leak from `default`.
        ///
        /// `#[serde(default)]` keeps older serialized requests (no field)
        /// deserializing as `None`, which is the secure default.
        #[serde(default)]
        inherit_from: Option<PrincipalId>,
        /// Opt-in clone source. When `Some`, the new principal is a full
        /// replica of this source: its capability **profile** (groups,
        /// grants, revokes, network egress, process-spawn allow-list,
        /// quotas) AND its **state** (the same env/KV/secret copy
        /// `inherit_from` performs). The source's `auth` (public keys /
        /// authenticators) is deliberately NOT copied — each principal keeps
        /// its own identity. Mutually exclusive with `inherit_from`,
        /// `groups`, and `grants` (the source determines all of them); the
        /// kernel rejects a request that sets both `clone_from` and any of
        /// those. When the source confers admin (resolves to `*`), the
        /// request is rejected unless `allow_admin_clone` is set.
        ///
        /// `#[serde(default)]` keeps older requests deserializing as `None`.
        #[serde(default)]
        clone_from: Option<PrincipalId>,
        /// Acknowledge cloning an admin-conferring source (one that resolves
        /// to the universal `*`). Without it, `clone_from` of such a source
        /// is rejected — mirrors `--unsafe-admin` on `caps grant '*'` and
        /// `group create --caps '*'`. Ignored unless `clone_from` is set.
        #[serde(default)]
        allow_admin_clone: bool,
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
        /// Granted capsule ids to add (idempotent). Grants the principal
        /// access to invoke the named capsule's user-invocable tool
        /// surface; the kernel gates `tool.v1.execute.*` /
        /// `cli.v1.command.execute` at dispatch against this set. New
        /// principals start with none; admins (`*`) bypass the gate.
        #[serde(default)]
        add_capsules: Vec<String>,
        /// Granted capsule ids to remove (idempotent — missing entries
        /// are no-ops). Revokes the principal's access to the named
        /// capsule's tool surface.
        #[serde(default)]
        remove_capsules: Vec<String>,
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
    /// Read the target principal's current resource **usage** vs budget —
    /// the cross-capsule CPU total plus the configured ceilings. Read-only,
    /// scoped exactly like [`QuotaGet`](Self::QuotaGet) (`self:quota:get` /
    /// `quota:get`): a principal can read its own usage, an admin can read
    /// anyone's.
    UsageGet {
        /// Principal whose usage is being read.
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
    /// Mint a signed capability token granting `principal` access to
    /// `resource` (issue #929). Lets an operator pre-grant tool access (e.g.
    /// `mcp://server:tool`) so the agent never hits a per-use approval
    /// elicitation. The token is signed by the runtime key — the same key the
    /// approval interceptor trusts as issuer — so it authorizes immediately
    /// and survives daemon restarts (persistent scope). Revocable via
    /// [`Self::CapsTokenRevoke`]; principal-scoped (a token minted for Alice
    /// never authorizes Bob); admin-gated by `caps:token:mint`.
    CapsTokenMint {
        /// Principal the token is minted for. Only this principal can
        /// consume it (issue #668 cross-principal binding).
        principal: PrincipalId,
        /// Resource pattern the token grants, e.g. `mcp://server:tool`.
        resource: String,
        /// Permission to grant. Defaults to `"invoke"` when absent. Parsed
        /// into [`Permission`](astrid_core::types::Permission); an unknown
        /// string is rejected with a bad-input error.
        #[serde(default)]
        permission: Option<String>,
        /// Token lifetime in seconds. `None` = permanent (valid until
        /// revoked); `Some(n)` = expires after `n` seconds.
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
    /// Revoke a previously minted capability token by its id (issue #929).
    /// Revocation is global and final — the token no longer authorizes for
    /// any principal. Admin-gated by `caps:token:revoke`.
    CapsTokenRevoke {
        /// The token id to revoke (the `token_id` string returned by
        /// [`Self::CapsTokenMint`]).
        token_id: String,
    },
    /// List the capability tokens minted for `principal` (issue #929).
    /// Returns only non-revoked, non-expired tokens owned by that principal.
    /// Admin-gated by `caps:token:list`.
    CapsTokenList {
        /// Principal whose tokens are listed.
        principal: PrincipalId,
    },
    /// Issue a new invite token. Capability-gated by `invite:issue`.
    /// The kernel persists the token under `etc/invites.toml` with
    /// expiry + remaining use count, and the caller publishes the
    /// returned redeem URL out-of-band.
    InviteIssue {
        /// Group new redeemers join. Must already exist (built-in or
        /// custom) — validated against the live `GroupConfig`.
        group: String,
        /// Seconds until the token expires. `None` = no expiry (the
        /// max-uses counter is the only stop). Capped server-side to
        /// 30 days to bound forever-tokens.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_secs: Option<u64>,
        /// Maximum number of successful redemptions before the token is
        /// invalidated. Zero is rejected (issuing a dead token serves
        /// no purpose).
        max_uses: u32,
        /// Free-form short label (e.g. "alice's tablet") attached to
        /// the persisted record. Surfaced by `InviteList`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<String>,
    },
    /// Redeem an invite token. The token IS the auth: the kernel-side
    /// dispatcher special-cases this variant to skip the capability
    /// preamble (the caller principal does not yet exist), and the
    /// handler verifies the token, mints a fresh principal via the
    /// existing `AgentCreate` machinery, registers the supplied
    /// ed25519 public key on the new principal's profile, and decrements
    /// the token's use counter (deleting the record on the last use).
    InviteRedeem {
        /// Opaque token bytes (URL-safe base64) returned from a prior
        /// `InviteIssue`.
        token: String,
        /// Hex-encoded ed25519 public key (32 bytes / 64 hex chars).
        /// Registered on the new principal's `AuthConfig.public_keys`.
        public_key: String,
        /// Optional human-friendly name attached to the minted principal.
        /// When `Some(s)`, the kernel generates the underlying
        /// `PrincipalId` from `s` (slugified, collision-checked); when
        /// `None`, a random `agent-<8-hex>` id is allocated.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
    },
    /// List outstanding invite tokens. Gated by `invite:list`.
    InviteList,
    /// Revoke an outstanding invite token without consuming it.
    /// Gated by `invite:revoke`.
    InviteRevoke {
        /// The opaque token to invalidate.
        token: String,
    },
    /// Issue a pair-device token. Gated by `self:auth:pair` (the
    /// caller can only mint pair-tokens for their own principal —
    /// the kernel ignores any target field on the wire and ties the
    /// token to the caller). Used to add a new device's ed25519
    /// public key to an existing principal's `AuthConfig.public_keys`
    /// without minting a separate principal.
    PairDeviceIssue {
        /// Seconds until the token expires. Capped server-side to
        /// 1 hour — pair-tokens are intended for immediate use on a
        /// neighbouring device, not for long-lived sharing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_secs: Option<u64>,
        /// Free-form short label (e.g. "alice's phone") persisted
        /// alongside the new public key on
        /// `AuthConfig.public_keys` once the token is redeemed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        /// Capability scope the redeemed device will authenticate under.
        /// Defaults to [`PairScopeArg::Full`] when omitted, for back-compat
        /// with pre-scope callers; a `Full` mint is independently gated on
        /// `self:auth:pair:admin` in the handler, and an `Explicit`/`Preset`
        /// scope is validated to be a subset of the issuer's effective
        /// capabilities (no escalation).
        #[serde(default = "default_pair_scope")]
        scope: PairScopeArg,
    },
    /// Redeem a pair-device token. Like `InviteRedeem`, the kernel
    /// dispatcher special-cases this to bypass the capability
    /// preamble — the token IS the auth. The handler verifies the
    /// token, appends the supplied public key to the issuing
    /// principal's `AuthConfig.public_keys`, and decrements / deletes
    /// the token record.
    PairDeviceRedeem {
        /// The opaque token from a prior `PairDeviceIssue`.
        token: String,
        /// Hex-encoded ed25519 public key (32 bytes / 64 hex chars).
        public_key: String,
    },
    /// List the paired devices (registered keys) on a principal's
    /// `AuthConfig.public_keys`. Gated by `self:auth:pair` (self form) /
    /// `auth:pair` (global form) exactly like [`PairDeviceIssue`] — a caller
    /// lists their own devices unless they hold the global form. The response
    /// carries only fingerprint-level identity ([`DeviceKeyInfo`]); the raw
    /// pubkey is never surfaced.
    PairDeviceList {
        /// Principal whose devices are listed.
        principal: PrincipalId,
    },
    /// Revoke a single paired device by its deterministic `key_id`, removing
    /// the matching [`DeviceKey`](crate::DeviceKey) from the principal's
    /// `AuthConfig.public_keys`. If it was the last keypair entry the
    /// `AuthMethod::Keypair` method is dropped too (mirrors the add side). A
    /// revoked device fails closed at the kernel cap-gate immediately (its key
    /// is gone from `public_keys`), and the gateway evicts any live bearer
    /// scoped to that `key_id`. Gated by `self:auth:pair` (self form) /
    /// `auth:pair` (global form), like [`PairDeviceIssue`].
    PairDeviceRevoke {
        /// Principal whose device is being revoked.
        principal: PrincipalId,
        /// The deterministic `key_id` of the device to remove.
        key_id: String,
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
    /// Response for [`AdminRequestKind::UsageGet`].
    Usage(ResourceUsage),
    /// Response for [`AdminRequestKind::InviteIssue`] — the freshly
    /// minted token plus its persisted metadata. The redemption URL is
    /// derived client-side from the deployment's public gateway base
    /// URL; the kernel never knows where the gateway is reachable.
    Invite(InviteIssued),
    /// Response for [`AdminRequestKind::InviteRedeem`] — the new
    /// principal id (so the redeemer can locally pin the binding) and
    /// the assigned group. The redeemer also gets back the issuing
    /// public-key fingerprint so out-of-band verification of the
    /// minted principal becomes possible.
    InviteRedeemed(InviteRedeemed),
    /// Response for [`AdminRequestKind::InviteList`].
    InviteList(Vec<InviteSummary>),
    /// Response for [`AdminRequestKind::PairDeviceIssue`].
    PairToken(PairTokenIssued),
    /// Response for [`AdminRequestKind::PairDeviceRedeem`].
    PairTokenRedeemed(PairTokenRedeemed),
    /// Response for [`AdminRequestKind::PairDeviceList`] — the principal's
    /// paired devices as fingerprint-level summaries (never the raw pubkey).
    PairDeviceListed(Vec<DeviceKeyInfo>),
    /// Response for [`AdminRequestKind::PairDeviceRevoke`] — the `key_id`
    /// of the device that was removed.
    PairDeviceRevoked {
        /// The `key_id` of the revoked device.
        key_id: String,
    },
    /// The request failed.
    Error(String),
}

/// Per-principal resource usage vs configured budget — the payload of
/// [`AdminRequestKind::UsageGet`], rendered by `astrid quota`/`astrid top` and
/// `GET /api/sys/principals/{id}/usage` so per-principal usage is measurable.
///
/// **CPU** is the live cross-capsule aggregate: the kernel's shared fuel ledger
/// sums every interceptor's exact wasmtime-fuel cost per invoking principal
/// across all capsules. **Memory** is reported as a per-principal *peak*
/// (`memory_bytes_peak_total`): the kernel's shared memory ledger records the
/// high-water linear-memory size each invoking principal grows a Store to,
/// max'd across all capsules. A live cross-capsule *current* total
/// (`memory_bytes_current_total`) is not implemented — under pooled, shared
/// Stores it is not cleanly attributable — so it stays `None`; the limit field
/// reports the per-instance ceiling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Principal this usage report describes.
    pub principal: PrincipalId,
    /// Cumulative interceptor CPU burned across ALL capsules, in wasmtime fuel
    /// units (exact deterministic instruction count, monotonic for the process
    /// lifetime).
    pub cpu_fuel_consumed_total: u64,
    /// Configured CPU rate ceiling ([`Quotas::max_cpu_fuel_per_sec`]), always
    /// `> 0` (validation rejects `0` — there is no "unlimited" sentinel;
    /// unbounded CPU is a capability, surfaced by `exempt`).
    pub cpu_fuel_per_sec_limit: u64,
    /// Whether the principal is exempt from resource budgets — it holds
    /// `system:resources:unbounded`, `net_bind`, or `uplink` (admins via `*`).
    /// When `true` the limit fields are advisory, never enforced.
    pub exempt: bool,
    /// Per-capsule-instance memory ceiling ([`Quotas::max_memory_bytes`]). This
    /// is a per-Store cap, not a cross-capsule total.
    pub memory_bytes_limit_per_instance: u64,
    /// Current cross-capsule resident memory total, or `None` — a live
    /// "current" total is not cleanly attributable under pooled, shared Stores,
    /// so the peak (below) is the reported memory signal instead.
    pub memory_bytes_current_total: Option<u64>,
    /// Peak cross-capsule linear-memory high-water mark this principal has
    /// driven, in bytes, max'd across every capsule it invokes (from the shared
    /// memory ledger). `None` while no peak has been recorded — including
    /// single-tenant deployments before any guest grows memory. The principal
    /// that *grows* a Store owns the peak; one reusing an already-grown Store
    /// without growing is not charged.
    pub memory_bytes_peak_total: Option<u64>,
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

/// Response payload for [`AdminRequestKind::InviteIssue`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteIssued {
    /// Opaque token (URL-safe base64). The caller delivers this to the
    /// redeemer out-of-band — e.g. printed by the CLI, surfaced by the
    /// gateway as a redeem URL fragment, or pasted into a chat.
    pub token: String,
    /// Group the redeemer will join on success.
    pub group: String,
    /// Number of remaining redemptions before the token is invalidated.
    pub remaining_uses: u32,
    /// Wall-clock Unix-epoch timestamp at which the token expires.
    /// `None` when the issuer requested no expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_epoch: Option<u64>,
    /// Operator-supplied label (`metadata` from the issue request).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

/// Response payload for [`AdminRequestKind::InviteRedeem`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRedeemed {
    /// The freshly minted principal id. The redeemer pins this locally
    /// alongside its keypair so subsequent gateway sessions can verify
    /// the binding.
    pub principal: PrincipalId,
    /// Group the new principal is now a member of.
    pub group: String,
    /// SHA-256 fingerprint (hex) of the registered ed25519 public key.
    /// Lets the redeemer verify that the kernel registered the key it
    /// sent rather than substituting one of its own.
    pub public_key_fingerprint: String,
}

/// Response payload for [`AdminRequestKind::PairDeviceIssue`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairTokenIssued {
    /// Opaque token. The issuing device hands this to the new
    /// device out-of-band (QR code, NFC, manual copy).
    pub token: String,
    /// Principal the new device's key will attach to (always the
    /// caller, never request-body derived).
    pub principal: PrincipalId,
    /// Wall-clock Unix-epoch timestamp at which the token expires.
    pub expires_at_epoch: u64,
    /// Operator-supplied label (echoed; not yet bound).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Response payload for [`AdminRequestKind::PairDeviceRedeem`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairTokenRedeemed {
    /// The principal the new device is now bound to.
    pub principal: PrincipalId,
    /// SHA-256 fingerprint (hex) of the registered ed25519 key.
    /// Lets the redeemer verify the kernel registered the key it
    /// sent rather than substituting one of its own.
    pub public_key_fingerprint: String,
    /// Deterministic `key_id` of the registered device key (the stable
    /// per-device handle derived from the pubkey). The gateway mints the new
    /// device's bearer scoped to THIS `key_id` so the device authenticates
    /// with — and is attenuated to — its own registered key.
    pub key_id: String,
}

/// Summary of an outstanding invite returned by
/// [`AdminRequestKind::InviteList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteSummary {
    /// SHA-256 fingerprint (hex) of the token — the kernel does not
    /// leak the raw token through list responses. Issuers retain the
    /// raw value from the original [`InviteIssued`] response.
    pub token_fingerprint: String,
    /// Group the redeemer will join.
    pub group: String,
    /// Remaining redemptions.
    pub remaining_uses: u32,
    /// Wall-clock Unix-epoch timestamp at which the token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_epoch: Option<u64>,
    /// Wall-clock Unix-epoch timestamp at which the token was issued.
    pub issued_at_epoch: u64,
    /// Operator-supplied label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
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

#[cfg(test)]
mod tests;
