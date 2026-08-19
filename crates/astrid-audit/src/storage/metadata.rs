use astrid_capabilities::AuditEntryId;
use astrid_crypto::ContentHash;

/// Recoverable O(1) accounting for one signed chain segment.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub(crate) struct ChainMetadata {
    pub(crate) schema: u8,
    pub(crate) segment: u64,
    pub(crate) sealed: bool,
    pub(crate) count: u64,
    pub(crate) bytes: u64,
    pub(crate) head: Option<AuditEntryId>,
    pub(crate) head_hash: ContentHash,
    /// Entries in the current segment (chain totals remain in `count`).
    #[serde(default)]
    pub(crate) segment_count: u64,
    /// Canonical bytes in the current segment.
    #[serde(default)]
    pub(crate) segment_bytes: u64,
    /// First entry in the current segment.
    #[serde(default)]
    pub(crate) segment_first: Option<AuditEntryId>,
    /// Durable global seal ordinal for the current segment.
    #[serde(default)]
    pub(crate) seal_ordinal: Option<u64>,
}
