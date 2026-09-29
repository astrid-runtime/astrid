//! Audit log settings: `[audit]` and its operator-only `[audit.retention]`
//! table.

use serde::{Deserialize, Serialize};

/// Audit log storage settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Path to the on-disk audit log. `None` means in-memory only.
    pub path: Option<String>,
    /// Maximum size of the audit log in megabytes before rotation.
    pub max_size_mb: u64,
    /// Wait after the first queued host-audit event so concurrent host
    /// calls share one volume persist. Layout-2 signing plus `sync_volume`
    /// is on-CPU; 50ms left a 27-capsule home at 100% and starved `GetStatus`.
    pub host_coalesce_ms: u64,
    /// Max signed host-audit entries per writer flush. Capped at the
    /// durable audit atomic-batch size (128) so one persist stays one
    /// `apply_batch` instead of falling back to per-entry CAS.
    pub host_batch_max: u64,
    /// In-memory host-audit queue. Producers never block the WASM/tokio
    /// workers: overflow folds into a pending count instead of `send()`.
    pub host_queue_capacity: u64,
    /// Persist allowed `stat`/`exists`/`readdir` as signed `FileRead`
    /// entries. Default off: POSIX path probes are not OS-level security
    /// events, and aos-fs issues thousands per second. Denied probes still
    /// persist as FileRead-Denied.
    pub host_path_probes: bool,
    /// Host-call classes that fail closed: the effect runs only after a
    /// write-ahead audit entry is durable, and the call fails if it cannot
    /// be recorded. Classes: `file_read`, `file_write`, `file_delete`,
    /// `net_connect`, `net_bind`, `process_spawn`.
    pub host_fail_closed: Vec<String>,
    /// `[audit.retention]`: anchor-aware pruning and archiving.
    pub retention: AuditRetentionConfig,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: None,
            max_size_mb: 100,
            host_coalesce_ms: 5_000,
            host_batch_max: 128,
            host_queue_capacity: 4096,
            host_path_probes: false,
            host_fail_closed: Vec::new(),
            retention: AuditRetentionConfig::default(),
        }
    }
}

/// `[audit.retention]`: how pruning treats history that an external
/// anchoring service has not yet certified.
///
/// A chain with an anchored watermark (recorded through `audit.anchor_mark`)
/// is never pruned past it, whatever these settings say. They add a
/// requirement for chains without one, and an archive step before deletion.
/// A workspace config cannot change them: only the operator's config applies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditRetentionConfig {
    /// Refuse to prune a chain that has no anchored watermark. When the
    /// global audit cap is reached and no segment may be pruned, entries are
    /// kept over the cap and the audit state reports degraded instead. Off
    /// by default, so installations that do not anchor keep bounded
    /// retention.
    pub require_anchor: bool,
    /// Absolute directory that receives every pruned segment before it is
    /// deleted, as `<session>/<chain>/<generation>.jsonl`: the signed prune
    /// receipt, then each removed entry. A prune whose archive cannot be
    /// written deletes nothing. The daemon makes the directories private to
    /// its user. `None` (the default) deletes without archiving.
    pub archive_dir: Option<String>,
}
