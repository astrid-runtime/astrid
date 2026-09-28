//! Wire types for anchor-safe audit retention: `audit.anchor_mark`, with
//! which an external anchoring service records how far each chain has been
//! certified, and `audit.anchor_status`, which reports every chain's
//! watermark and how far anchoring lags behind it.
//!
//! Positions count entries from a chain's genesis, pruned ones included. The
//! head of a chain that `audit.heads` reports with `omitted_total` O and
//! `count` C is at position `O + C`, and its `head_hash_hex` is the hash to
//! anchor there.

use serde::{Deserialize, Serialize};

use super::AUDIT_OMITTED_TOTAL_UNKNOWN;
use crate::{PrincipalId, SessionId};

/// Most chains one `audit.anchor_mark` request may list.
pub const AUDIT_ANCHOR_MARK_MAX_CHAINS: usize = 4_096;

/// Parameters of [`super::AdminRequestKind::AuditAnchorMark`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorMarkRequest {
    /// The external certification that covers every listed chain.
    pub evidence: AuditAnchorEvidence,
    /// Chains and the positions the evidence certifies, at most
    /// [`AUDIT_ANCHOR_MARK_MAX_CHAINS`], each chain once.
    pub chains: Vec<AuditAnchorMarkChain>,
}

/// One chain position in an [`AuditAnchorMarkRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorMarkChain {
    /// Session that owns the chain.
    pub session: SessionId,
    /// Principal alias of the chain; `None` selects the session's system
    /// chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalId>,
    /// Entries certified, counted from the chain's genesis: the
    /// `omitted_total + count` of the anchored `audit.heads` record.
    pub position: u64,
    /// Hex content hash of the entry at `position - 1`: the anchored
    /// record's `head_hash_hex`.
    pub head_hash_hex: String,
}

/// Evidence of the certification behind an anchor mark. The kernel checks
/// its shape and stores it with each chain's watermark; it does not verify
/// the certification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorEvidence {
    /// Network the checkpoint was certified on, for example
    /// `unicity:testnet2`.
    pub network: String,
    /// Hex digest of the checkpoint that commits to the chain heads.
    pub checkpoint_digest_hex: String,
    /// Position of that checkpoint in the anchoring service's chain of
    /// links.
    pub link_position: u64,
    /// Round of the network that certified the checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certifying_round: Option<u64>,
    /// Hex digest of the seal (certificate) that certified the checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_digest_hex: Option<String>,
}

impl AuditAnchorEvidence {
    /// Check the evidence's shape: a non-empty network of at most 128
    /// characters, and digests of 1 to 64 bytes as lowercase or uppercase
    /// hex.
    ///
    /// # Errors
    ///
    /// Returns a description of the first field that fails.
    pub fn validate(&self) -> Result<(), String> {
        if self.network.is_empty() || self.network.chars().count() > 128 {
            return Err("anchor evidence network must have 1 to 128 characters".to_owned());
        }
        check_digest("checkpoint_digest_hex", &self.checkpoint_digest_hex)?;
        if let Some(seal) = &self.seal_digest_hex {
            check_digest("seal_digest_hex", seal)?;
        }
        Ok(())
    }
}

fn check_digest(field: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.len().is_multiple_of(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if valid {
        Ok(())
    } else {
        Err(format!(
            "anchor evidence {field} must be 1 to 64 bytes of hex"
        ))
    }
}

/// Response to [`super::AdminRequestKind::AuditAnchorMark`]: one outcome per
/// requested chain, in request order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorMarkResult {
    /// Per-chain outcomes.
    pub chains: Vec<AuditAnchorMarkOutcome>,
}

/// What `audit.anchor_mark` did with one chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAnchorMarkStatus {
    /// The watermark moved to the requested position.
    Advanced,
    /// The watermark already stood at the requested position and hash.
    Unchanged,
    /// The mark was refused; `error` says why. Other chains are unaffected.
    Rejected,
}

/// One chain's outcome in an [`AuditAnchorMarkResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorMarkOutcome {
    /// Session UUID, hyphenated lowercase.
    pub session: String,
    /// Principal alias, or `null` for the session's system chain.
    pub principal: Option<PrincipalId>,
    /// What happened.
    pub status: AuditAnchorMarkStatus,
    /// The chain's watermark after the call; 0 when it has none.
    pub anchored_position: u64,
    /// Why the mark was rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response to [`super::AdminRequestKind::AuditAnchorStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorStatusReport {
    /// Whether the operator requires a watermark before any chain is
    /// pruned.
    pub require_anchor_before_prune: bool,
    /// Set while the global cap is exceeded because every prunable segment
    /// holds unanchored history; says why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_hold: Option<String>,
    /// Every chain, in storage-key order.
    pub chains: Vec<AuditAnchorChainStatus>,
}

/// One chain in an [`AuditAnchorStatusReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorChainStatus {
    /// Session UUID, hyphenated lowercase.
    pub session: String,
    /// Principal alias, or `null` for the session's system chain.
    pub principal: Option<PrincipalId>,
    /// Retained entries.
    pub count: u64,
    /// Entries pruned from the chain's start, or
    /// [`AUDIT_OMITTED_TOTAL_UNKNOWN`].
    pub omitted_total: u64,
    /// Anchored watermark, if one was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_position: Option<u64>,
    /// Hex hash of the entry at `anchored_position - 1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_head_hash_hex: Option<String>,
    /// RFC 3339 time the watermark was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_at: Option<String>,
    /// Evidence stored with the watermark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
}

impl AuditAnchorChainStatus {
    /// Position of the chain head (`omitted_total + count`), or `None` when
    /// the pruned total is unknown.
    #[must_use]
    pub fn head_position(&self) -> Option<u64> {
        (self.omitted_total != AUDIT_OMITTED_TOTAL_UNKNOWN)
            .then(|| self.omitted_total.saturating_add(self.count))
    }

    /// Entries not yet anchored, or `None` when the pruned total is unknown.
    #[must_use]
    pub fn lag(&self) -> Option<u64> {
        self.head_position()
            .map(|head| head.saturating_sub(self.anchored_position.unwrap_or(0)))
    }
}

#[cfg(test)]
#[path = "audit_anchor_tests.rs"]
mod tests;
