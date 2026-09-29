//! Wire types for the read-only audit anchoring surface: `audit.heads`, a
//! runtime-key-signed snapshot of every audit chain head, and `audit.export`,
//! a paged raw export of one chain's signed entries.

use serde::{Deserialize, Serialize};

use crate::{PrincipalId, SessionId};

/// Domain tag that opens every signed `audit.heads` byte string.
pub const AUDIT_HEADS_DOMAIN_V1: &str = "astrid.audit.heads.v1";

/// [`AuditHeadsChain::omitted_total`] of a chain whose pruned total cannot be
/// known, such as a chain pruned more than once before the runtime recorded
/// the total (only the latest prune receipt is kept). It is signed like any
/// other value but makes no claim about the count, so it must not be
/// compared as a number.
pub const AUDIT_OMITTED_TOTAL_UNKNOWN: u64 = u64::MAX;

/// Parameters of [`super::AdminRequestKind::AuditExport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExportRequest {
    /// Session that owns the chain. The daemon's system session is the nil
    /// UUID.
    pub session: SessionId,
    /// Principal alias of the chain; `None` selects the session's system
    /// chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalId>,
    /// Zero-based index into the retained chain to start at. Ignored when
    /// `cursor` is present.
    #[serde(default)]
    pub from: u64,
    /// Resume point returned as `next_cursor` by an earlier page. The
    /// kernel checks that it names an entry of the requested chain; the
    /// index it carries is taken as given (see [`AuditExportPage::from`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum entries in the page. The kernel applies a default and a cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Also return the chain's prune receipts from this generation on, in
    /// [`AuditExportPage::prune_receipts`]. Omit for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipts_from: Option<u64>,
}

/// Runtime-key-signed snapshot of every audit chain head.
///
/// `signature_hex` is an Ed25519 signature by the runtime key over the raw
/// bytes of `signed_bytes_hex` (no pre-hash). Those bytes are
/// [`Self::signed_bytes_v1`] of this snapshot's own fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHeadsSnapshot {
    /// Hex of the exact signed bytes.
    pub signed_bytes_hex: String,
    /// Hex of the 64-byte Ed25519 signature over the signed bytes.
    pub signature_hex: String,
    /// Hex of the 32-byte runtime Ed25519 public key.
    pub runtime_public_key_hex: String,
    /// Snapshot time in nanoseconds since the Unix epoch.
    pub snapshot_time_ns: u64,
    /// Every chain, in signed order.
    pub chains: Vec<AuditHeadsChain>,
}

/// One chain in an [`AuditHeadsSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHeadsChain {
    /// Session UUID, hyphenated lowercase.
    pub session: String,
    /// Principal alias, or `null` for the session's system chain.
    pub principal: Option<PrincipalId>,
    /// Retained entries in the chain. Pruning lowers this.
    pub count: u64,
    /// Entries pruned from the front of the chain over its lifetime, read
    /// from the same committed state as `count`, or
    /// [`AUDIT_OMITTED_TOTAL_UNKNOWN`]. A known total never decreases, so
    /// `omitted_total + count` counts every entry the chain has held.
    pub omitted_total: u64,
    /// Hex BLAKE3 content hash of the head entry (what the next entry's
    /// `previous_hash` links to), or 64 zeros for an empty chain.
    pub head_hash_hex: String,
    /// Head entry id, if the chain has entries.
    pub head_id: Option<String>,
    /// Stored RFC 3339 timestamp of the head entry. Entry signatures cover
    /// whole seconds only.
    pub last_timestamp: Option<String>,
    /// Latest prune receipt summary, if the chain was ever pruned. Not part
    /// of the signed bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prune: Option<AuditHeadsPrune>,
}

/// Summary of a chain's latest signed prune receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHeadsPrune {
    /// Receipt generation; 0 for the chain's first prune.
    pub generation: u64,
    /// Entries omitted by this receipt's generation.
    pub omitted_count: u64,
    /// Hex content hash of the last omitted entry. The first retained entry
    /// links to it.
    pub omitted_terminal_hash_hex: String,
    /// Hex BLAKE3 of the receipt bytes as stored.
    pub receipt_hash_hex: String,
}

impl AuditHeadsChain {
    /// [`Self::omitted_total`], or `None` for
    /// [`AUDIT_OMITTED_TOTAL_UNKNOWN`].
    #[must_use]
    pub fn known_omitted_total(&self) -> Option<u64> {
        (self.omitted_total != AUDIT_OMITTED_TOTAL_UNKNOWN).then_some(self.omitted_total)
    }
}

impl AuditHeadsSnapshot {
    /// Build the canonical signed bytes (format v1) from this snapshot's
    /// fields. `lp(x)` is a big-endian `u32` length followed by `x`:
    ///
    /// ```text
    /// lp("astrid.audit.heads.v1") || u64 snapshot_time_ns || u32 chain_count
    /// || per chain: lp(session) || u8 has_principal || [lp(principal)]
    ///               || u64 count || u64 omitted_total || 32-byte head_hash
    /// ```
    ///
    /// Integers are big-endian. Chains must be strictly ascending by
    /// `(session, principal)`, with the system chain (no principal) first
    /// within a session and strings compared bytewise. An unknown
    /// `omitted_total` is signed as [`AUDIT_OMITTED_TOTAL_UNKNOWN`], eight
    /// `0xff` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when chains are unsorted or duplicated, a head hash
    /// is not 32 bytes of hex, or a length does not fit its prefix.
    pub fn signed_bytes_v1(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        push_lp(&mut out, AUDIT_HEADS_DOMAIN_V1.as_bytes())?;
        out.extend_from_slice(&self.snapshot_time_ns.to_be_bytes());
        let chain_count =
            u32::try_from(self.chains.len()).map_err(|_| "too many chains".to_owned())?;
        out.extend_from_slice(&chain_count.to_be_bytes());
        let mut previous: Option<(&str, Option<&str>)> = None;
        for chain in &self.chains {
            let key = (
                chain.session.as_str(),
                chain.principal.as_ref().map(PrincipalId::as_str),
            );
            if previous.is_some_and(|previous| previous >= key) {
                return Err("chains are not strictly sorted by (session, principal)".to_owned());
            }
            previous = Some(key);
            let head_hash: [u8; 32] = hex::decode(&chain.head_hash_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| format!("invalid head hash for chain {}", chain.session))?;
            push_lp(&mut out, chain.session.as_bytes())?;
            match &chain.principal {
                None => out.push(0),
                Some(principal) => {
                    out.push(1);
                    push_lp(&mut out, principal.as_str().as_bytes())?;
                },
            }
            out.extend_from_slice(&chain.count.to_be_bytes());
            out.extend_from_slice(&chain.omitted_total.to_be_bytes());
            out.extend_from_slice(&head_hash);
        }
        Ok(out)
    }
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let len = u32::try_from(bytes.len()).map_err(|_| "field too long".to_owned())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// One page of a chain's raw signed entries returned by `AuditExport`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditExportPage {
    /// Session UUID, hyphenated lowercase.
    pub session: String,
    /// Principal alias, or `null` for the session's system chain.
    pub principal: Option<PrincipalId>,
    /// Retained-chain index of the first entry in this page.
    ///
    /// When the page resumes from a cursor, this is the index the cursor
    /// carries, and entry indices and `next_index` follow from it. The
    /// kernel bounds it by the retained count but does not authenticate it,
    /// and a prune after the cursor was issued leaves it too high by the
    /// entries removed. A verifier takes positions from entry links and the
    /// signed `audit.heads` count and omitted total, not from these indices.
    pub from: u64,
    /// Entries in chain order.
    pub entries: Vec<AuditExportEntry>,
    /// Retained-chain index of the entry after this page.
    pub next_index: u64,
    /// Cursor that resumes after this page, including after later appends.
    /// `None` only when nothing has been read from the chain yet.
    pub next_cursor: Option<String>,
    /// Whether no further entry existed when the page was read.
    pub complete: bool,
    /// Retained count from the chain metadata, read just before the page.
    pub chain_count: u64,
    /// Hex head hash from the chain metadata, read just before the page.
    pub chain_head_hash_hex: String,
    /// Latest prune receipt as stored, if the chain was ever pruned. The
    /// first retained entry links to its `omitted_terminal_hash`.
    pub prune_receipt: Option<serde_json::Value>,
    /// Hex BLAKE3 of the stored prune receipt bytes.
    pub prune_receipt_hash_hex: Option<String>,
    /// Hex of the bytes the prune receipt signature covers.
    pub prune_receipt_signing_data_hex: Option<String>,
    /// With `receipts_from`: the chain's prune receipts from that generation
    /// on, oldest first, a bounded number per page. Each links to the one
    /// before by `prior_receipt_hash`; generations pruned before the runtime
    /// kept every receipt are missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prune_receipts: Vec<AuditExportReceipt>,
    /// The `receipts_from` that continues the receipt list, when this page
    /// holds the most receipts a page may.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_receipts_from: Option<u64>,
}

/// One signed prune receipt in [`AuditExportPage::prune_receipts`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditExportReceipt {
    /// Receipt generation; 0 for the chain's first prune.
    pub generation: u64,
    /// The receipt as stored.
    pub receipt: serde_json::Value,
    /// Hex BLAKE3 of the stored receipt bytes: the next generation's
    /// `prior_receipt_hash`.
    pub receipt_hash_hex: String,
    /// Hex of the bytes the receipt signature covers.
    pub signing_data_hex: String,
}

/// One raw signed audit entry in an [`AuditExportPage`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditExportEntry {
    /// Retained-chain index.
    pub index: u64,
    /// Entry id (UUID).
    pub id: String,
    /// Stored RFC 3339 timestamp. The signature covers whole seconds only.
    pub timestamp: String,
    /// Hex hash of the previous entry; zeros for the genesis entry.
    pub previous_hash_hex: String,
    /// Hex `BLAKE3(signing_data)`, the value the next entry's
    /// `previous_hash` links to.
    pub content_hash_hex: String,
    /// Hex Ed25519 signature over `signing_data`.
    pub signature_hex: String,
    /// Hex Ed25519 public key embedded in the entry.
    pub public_key_hex: String,
    /// Hex of the exact bytes that are signed and hashed.
    pub signing_data_hex: String,
    /// The entry as stored, including `previous_hash`, `runtime_key` and
    /// `signature`.
    pub entry: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::super::{AdminKernelRequest, AdminRequestKind};
    use super::*;

    fn chain(principal: Option<&str>, count: u64, omitted: u64, fill: u8) -> AuditHeadsChain {
        AuditHeadsChain {
            session: SessionId::SYSTEM.0.to_string(),
            principal: principal.map(|alias| PrincipalId::new(alias).unwrap()),
            count,
            omitted_total: omitted,
            head_hash_hex: hex::encode([fill; 32]),
            head_id: None,
            last_timestamp: None,
            prune: None,
        }
    }

    fn snapshot(chains: Vec<AuditHeadsChain>) -> AuditHeadsSnapshot {
        AuditHeadsSnapshot {
            signed_bytes_hex: String::new(),
            signature_hex: String::new(),
            runtime_public_key_hex: String::new(),
            snapshot_time_ns: 1_790_000_000_123_456_789,
            chains,
        }
    }

    /// Known-answer vector for external verifiers of the v1 heads encoding.
    #[test]
    fn heads_signed_bytes_v1_matches_known_answer() {
        let bytes = snapshot(vec![
            chain(None, 3, 0, 0x11),
            chain(Some("alice"), 2, 5, 0x22),
        ])
        .signed_bytes_v1()
        .unwrap();
        let expected = concat!(
            "000000156173747269642e61756469742e68656164732e7631",
            "18d75b842b4ecd15",
            "00000002",
            "0000002430303030303030302d303030302d303030302d303030302d303030303030303030303030",
            "00",
            "0000000000000003",
            "0000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "0000002430303030303030302d303030302d303030302d303030302d303030303030303030303030",
            "01",
            "00000005616c696365",
            "0000000000000002",
            "0000000000000005",
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        assert_eq!(hex::encode(bytes), expected);
    }

    #[test]
    fn heads_signed_bytes_v1_signs_an_unknown_omitted_total_as_all_ones() {
        let unknown = chain(Some("bob"), 4, AUDIT_OMITTED_TOTAL_UNKNOWN, 0x33);
        assert_eq!(unknown.known_omitted_total(), None);
        assert_eq!(chain(None, 4, 9, 0x33).known_omitted_total(), Some(9));
        let bytes = snapshot(vec![unknown]).signed_bytes_v1().unwrap();
        let expected_tail = concat!(
            "01",
            "00000003626f62",
            "0000000000000004",
            "ffffffffffffffff",
            "3333333333333333333333333333333333333333333333333333333333333333",
        );
        assert!(hex::encode(bytes).ends_with(expected_tail));
    }

    #[test]
    fn heads_signed_bytes_v1_rejects_unsorted_or_duplicate_chains() {
        let unsorted = snapshot(vec![chain(Some("alice"), 1, 0, 1), chain(None, 1, 0, 1)]);
        assert!(unsorted.signed_bytes_v1().is_err());
        let duplicate = snapshot(vec![
            chain(Some("bob"), 1, 0, 1),
            chain(Some("bob"), 2, 0, 2),
        ]);
        assert!(duplicate.signed_bytes_v1().is_err());
        let mut short_hash = chain(None, 1, 0, 1);
        short_hash.head_hash_hex = "ab".to_owned();
        assert!(snapshot(vec![short_hash]).signed_bytes_v1().is_err());
    }

    #[test]
    fn audit_requests_use_adjacent_method_params_wire_shape() {
        let heads =
            serde_json::to_value(AdminKernelRequest::from(AdminRequestKind::AuditHeads)).unwrap();
        assert_eq!(heads["method"], "AuditHeads");
        let export = AdminRequestKind::AuditExport(AuditExportRequest {
            session: SessionId::SYSTEM,
            principal: Some(PrincipalId::new("alice").unwrap()),
            from: 0,
            cursor: Some("3:cursor".to_owned()),
            limit: Some(10),
            receipts_from: None,
        });
        let value = serde_json::to_value(AdminKernelRequest::from(export)).unwrap();
        assert_eq!(value["method"], "AuditExport");
        assert_eq!(value["params"]["session"], SessionId::SYSTEM.0.to_string());
        assert_eq!(value["params"]["principal"], "alice");
        assert_eq!(value["params"]["cursor"], "3:cursor");
        let minimal: AdminKernelRequest = serde_json::from_value(serde_json::json!({
            "method": "AuditExport",
            "params": { "session": SessionId::SYSTEM.0.to_string() }
        }))
        .unwrap();
        let AdminRequestKind::AuditExport(request) = minimal.kind else {
            panic!("expected AuditExport");
        };
        assert_eq!(request.from, 0);
        assert!(request.principal.is_none() && request.cursor.is_none());
        assert!(request.receipts_from.is_none());
    }
}
