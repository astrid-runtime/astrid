use serde::{Deserialize, Serialize};

/// Default global entry cap. Operators can replace the projection during
/// provisioning; the default keeps recovery and retention work bounded.
pub(crate) const DEFAULT_GLOBAL_MAX_ENTRIES: u64 = 1_000_000;
/// Default global canonical-byte cap (`1 GiB`).
pub(crate) const DEFAULT_GLOBAL_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// O(1) system-wide audit accounting and retention caps.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GlobalMetadata {
    pub(crate) schema: u8,
    pub(crate) total_count: u64,
    pub(crate) total_bytes: u64,
    pub(crate) sealed_segments: u64,
    pub(crate) segments: u64,
    pub(crate) eligible_segments: u64,
    pub(crate) next_seal_ordinal: u64,
    pub(crate) cap_entries: u64,
    pub(crate) cap_bytes: u64,
    pub(crate) degraded: bool,
    pub(crate) last_error: Option<String>,
}

impl Default for GlobalMetadata {
    fn default() -> Self {
        Self {
            schema: 1,
            total_count: 0,
            total_bytes: 0,
            sealed_segments: 0,
            segments: 0,
            eligible_segments: 0,
            next_seal_ordinal: 0,
            cap_entries: DEFAULT_GLOBAL_MAX_ENTRIES,
            cap_bytes: DEFAULT_GLOBAL_MAX_BYTES,
            degraded: false,
            last_error: None,
        }
    }
}
