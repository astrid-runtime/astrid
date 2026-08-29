use super::{DeviceKeyInfo, EnvEntry, PrincipalId, Quotas, StorageMountLeaseV1};
use serde::{Deserialize, Serialize};

/// Coordinate carried by a Station publication lock.
///
/// This deliberately mirrors Station's JSON shape without linking the core
/// API to the standalone Station crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StationCoordinate {
    /// Namespace portion of the Station coordinate.
    pub namespace: String,
    /// Capsule name portion of the Station coordinate.
    pub name: String,
}

/// Exact Station `station-lock-v2` wire record.
///
/// The record is stored as typed owner control state, not inside a capsule
/// package or Astrid's content-addressed stores. Field names intentionally
/// match Station's lock wire; there is no Astrid-specific second schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StationLock {
    /// Stable Station lock discriminator. Must be `station-lock-v2`.
    pub schema: String,
    /// Station identity.
    pub station_id: String,
    /// Pinned trust-root fingerprint.
    pub trust_root: String,
    /// Published capsule coordinate.
    pub coordinate: StationCoordinate,
    /// Canonical semantic version.
    pub version: String,
    /// Sealed publication digest.
    pub publication_digest: String,
    /// Transport artifact byte length.
    pub artifact_size: u64,
    /// Transport media type.
    pub artifact_media_type: String,
    /// Transport SHA-256 digest.
    pub artifact_sha256: String,
    /// Transport BLAKE3 digest.
    pub artifact_blake3: String,
    /// Digest of the exact Capsule.toml bytes under Astrid's manifest domain.
    pub manifest_digest: String,
    /// Capsule content-tree digest.
    pub capsule_content_digest: String,
    /// Embedded package digest.
    pub package_digest: String,
    /// Number of components in the package.
    pub component_count: u32,
    /// Component-set digest.
    pub component_digest: String,
    /// WIT map/aggregate digest.
    pub wit_digest: String,
    /// Effective capability declaration digest.
    pub capability_digest: String,
    /// Full IPC definition digest.
    pub ipc_digest: String,
    /// Runtime ABI digest.
    pub runtime_abi_digest: String,
    /// Dependency declaration digest.
    pub dependency_digest: String,
    /// Build provenance digest.
    pub provenance_digest: String,
    /// Source provenance digest.
    pub source_digest: String,
}

/// Durable provenance for one authenticated principal's distro installation.
///
/// This is control-plane state, not an ordinary home file. The kernel stores
/// it in a UID-keyed control namespace so an alias rename or reuse cannot
/// redirect the record to a different principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistroProvenance {
    /// Schema version of the resolved distro manifest.
    pub schema_version: u32,
    /// Stable distro identifier.
    pub distro_id: String,
    /// Resolved distro version.
    pub distro_version: String,
    /// ISO-8601 timestamp at which resolution completed.
    pub resolved_at: String,
    /// Exact resolved capsule set.
    #[serde(default)]
    pub capsules: Vec<DistroCapsuleProvenance>,
    /// BLAKE3 digest of the source manifest, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
}

/// One exact capsule resolution recorded by [`DistroProvenance`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistroCapsuleProvenance {
    /// Capsule package identifier.
    pub name: String,
    /// Exact installed version.
    pub version: String,
    /// Fully resolved source locator.
    pub source: String,
    /// BLAKE3 digest of the installed WASM bytes.
    pub hash: String,
    /// Concrete tag, branch, or commit selected by resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_ref: Option<String>,
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
    /// Response for [`AdminRequestKind::EnvList`].
    EnvList(Vec<EnvEntry>),
    /// Response for [`AdminRequestKind::DistroLockGet`].
    DistroLock(Box<Option<DistroProvenance>>),
    /// Response for [`AdminRequestKind::StationLockGet`].
    StationLock(Box<Option<StationLock>>),
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
    /// O(1) system-wide audit accounting and retention state.
    AuditStats(AuditStats),
    /// Signed archive receipt summary produced by `AuditPrune`.
    AuditPruned(Box<AuditPruneResult>),
    /// Bounded audit ingestion queue health.
    AuditHealth(AuditHealth),
    /// Response for [`AdminRequestKind::StorageMountIssue`].
    StorageMountLease(Box<StorageMountLeaseV1>),
    /// The request failed.
    Error(String),
}

/// O(1) system-wide audit accounting and retention state returned by the
/// operator admin API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    /// Number of entries represented by the durable projection.
    pub total_count: u64,
    /// Canonical bytes represented by the durable projection.
    pub total_bytes: u64,
    /// Number of sealed segments in global seal order.
    pub sealed_segments: u64,
    /// Number of active and sealed segments.
    pub segments: u64,
    /// Number of sealed segments currently eligible for pruning.
    pub eligible_segments: u64,
    /// Maximum entries configured for the system projection.
    pub cap_entries: u64,
    /// Maximum bytes configured for the system projection.
    pub cap_bytes: u64,
    /// Whether retention/accounting is degraded.
    pub degraded: bool,
    /// Most recent retention/accounting error, when degraded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Signed archive receipt summary returned after an audit prune operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPruneResult {
    /// Signed receipt generation.
    pub generation: u64,
    /// BLAKE3 digest of the complete signed receipt bytes.
    pub receipt_hash: String,
    /// Session chain that supplied the pruned segment.
    pub session: String,
    /// Principal chain, or `None` for the system chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Exact sealed segment number covered by the receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment: Option<u64>,
    /// Global seal ordinal for the covered segment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ordinal: Option<u64>,
    /// Number of entries omitted by this receipt.
    pub omitted_count: u64,
    /// Canonical bytes omitted by this receipt.
    pub omitted_bytes: u64,
    /// Number of suffix entries retained.
    pub retained_count: u64,
    /// Canonical bytes retained by this chain.
    pub retained_bytes: u64,
    /// Logical entries made unreachable by the prune plan.
    pub logical_reclaimed_count: u64,
    /// Logical canonical bytes made unreachable by the prune plan.
    pub logical_reclaimed_bytes: u64,
    /// Physical bytes reclaimed by the storage engine compactor, if known.
    pub physical_reclaimed_bytes: u64,
    /// Whether physical compaction is still pending or unavailable.
    pub physical_reclaim_pending: bool,
}

/// Bounded audit ingestion queue health returned by the operator admin API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditHealth {
    /// Events accepted into the bounded queue.
    pub accepted: u64,
    /// Events durably persisted by the writer.
    pub persisted: u64,
    /// Events whose durable append failed.
    pub failed: u64,
    /// Number of queue-full backpressure observations.
    pub queue_full: u64,
    /// Events currently queued for persistence.
    pub queue_depth: u64,
    /// Whether the dedicated writer is alive.
    pub worker_alive: bool,
    /// Whether ingestion is degraded.
    pub degraded: bool,
    /// Most recent writer error, if degraded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
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
    /// Stable durable UID resolved by the kernel's principal directory.
    /// This is optional for compatibility with pre-UID profile fixtures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_uid: Option<crate::identity::PrincipalUid>,
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
    /// Typed `astrid_inv_` bearer token. The caller delivers this to the
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
    /// Domain-separated `blake3:<hex>` fingerprint of the registered Ed25519 public key.
    /// Lets the redeemer verify that the kernel registered the key it
    /// sent rather than substituting one of its own.
    pub public_key_fingerprint: String,
}

/// Response payload for [`AdminRequestKind::PairDeviceIssue`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairTokenIssued {
    /// Typed `astrid_pair_` bearer token. The issuing device hands this to the new
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
    /// Domain-separated `blake3:<hex>` fingerprint of the registered Ed25519 key.
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
    /// Domain-separated `blake3:<hex>` fingerprint of the token — the kernel does not
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
