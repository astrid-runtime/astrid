//! Bounded retention and signed archive anchors.

use astrid_capabilities::AuditEntryId;
use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::{ContentHash, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

use crate::entry::AuditEntry;
use crate::error::{AuditError, AuditResult};
use crate::log::AuditLog;

const MAX_RETENTION_RING: usize = 8192;
const MAX_RESUME_PAGES: usize = 16_384;

/// Operator-selected bounded retention for one audit chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditRetentionPolicy {
    /// Maximum retained entries per chain.
    pub retain_entries: usize,
    /// Optional maximum retained canonical bytes per chain.
    pub retain_bytes: Option<u64>,
}

/// Signed receipt for an omitted archive prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPruneReceipt {
    /// Receipt schema version.
    pub schema: u8,
    /// Session whose chain was compacted.
    pub session: String,
    /// Principal chain, or `None` for the system chain.
    pub principal: Option<String>,
    /// Number of retained entries after pruning.
    pub retained_count: u64,
    /// Canonical bytes retained after pruning.
    pub retained_bytes: u64,
    /// Number of omitted prefix entries.
    pub omitted_count: u64,
    /// Canonical bytes omitted from the prefix.
    pub omitted_bytes: u64,
    /// Incremental digest of omitted canonical entry bytes.
    pub omitted_digest: String,
    /// Terminal content hash of the omitted prefix.
    pub omitted_terminal_hash: String,
    /// Retained chain head after pruning.
    pub retained_head: Option<AuditEntryId>,
    /// Monotonic receipt generation for this chain.
    pub generation: u64,
    /// Last durable session-index cursor in the omitted prefix.
    pub cutoff_cursor: Option<String>,
    /// First retained entry ID, if a suffix remains.
    pub first_retained: Option<AuditEntryId>,
    /// Previous hash carried by the first retained entry.
    pub first_retained_previous_hash: String,
    /// Hash of the prior generation receipt, if any.
    pub prior_receipt_hash: Option<String>,
    /// Exact sealed segment number covered by this receipt.
    #[serde(default)]
    pub segment: Option<u64>,
    /// Durable global seal ordinal for the covered segment.
    #[serde(default)]
    pub seal_ordinal: Option<u64>,
    /// Public key that signed this receipt.
    pub public_key: PublicKey,
    /// Signature over all receipt fields except this signature.
    pub signature: Signature,
}

#[derive(Serialize)]
struct UnsignedReceipt<'a> {
    schema: u8,
    session: &'a str,
    principal: &'a Option<String>,
    retained_count: u64,
    retained_bytes: u64,
    omitted_count: u64,
    omitted_bytes: u64,
    omitted_digest: &'a str,
    omitted_terminal_hash: &'a str,
    retained_head: &'a Option<AuditEntryId>,
    generation: u64,
    cutoff_cursor: &'a Option<String>,
    first_retained: &'a Option<AuditEntryId>,
    first_retained_previous_hash: &'a str,
    prior_receipt_hash: &'a Option<String>,
    segment: &'a Option<u64>,
    seal_ordinal: &'a Option<u64>,
    public_key: PublicKey,
}

impl AuditPruneReceipt {
    fn unsigned(&self) -> UnsignedReceipt<'_> {
        UnsignedReceipt {
            schema: self.schema,
            session: &self.session,
            principal: &self.principal,
            retained_count: self.retained_count,
            retained_bytes: self.retained_bytes,
            omitted_count: self.omitted_count,
            omitted_bytes: self.omitted_bytes,
            omitted_digest: &self.omitted_digest,
            omitted_terminal_hash: &self.omitted_terminal_hash,
            retained_head: &self.retained_head,
            generation: self.generation,
            cutoff_cursor: &self.cutoff_cursor,
            first_retained: &self.first_retained,
            first_retained_previous_hash: &self.first_retained_previous_hash,
            prior_receipt_hash: &self.prior_receipt_hash,
            segment: &self.segment,
            seal_ordinal: &self.seal_ordinal,
            public_key: self.public_key,
        }
    }

    fn signing_bytes(&self) -> AuditResult<Vec<u8>> {
        serde_json::to_vec(&self.unsigned())
            .map_err(|error| AuditError::SerializationError(error.to_string()))
    }

    pub(crate) fn verify(&self) -> AuditResult<()> {
        if self.schema != 1 {
            return Err(AuditError::StorageError(
                "unsupported audit prune receipt schema".to_owned(),
            ));
        }
        let bytes = self.signing_bytes()?;
        self.signature
            .verify(&bytes, self.public_key.as_bytes())
            .map_err(AuditError::CryptoError)
    }
}

struct RetentionScan {
    retained_count: u64,
    retained_bytes: u64,
    omitted_count: u64,
    omitted_bytes: u64,
    omitted_digest: String,
    omitted_terminal_hash: String,
    retained_head: Option<AuditEntryId>,
    cutoff_cursor: Option<String>,
    first_retained: Option<AuditEntryId>,
    first_retained_previous_hash: String,
}

async fn scan_retention(
    log: &AuditLog,
    session_id: &SessionId,
    principal: Option<&PrincipalId>,
    policy: AuditRetentionPolicy,
) -> AuditResult<RetentionScan> {
    let mut retained: VecDeque<AuditEntry> = VecDeque::new();
    let mut retained_cursors: VecDeque<String> = VecDeque::new();
    let mut omitted_count = 0_u64;
    let mut omitted_bytes = 0_u64;
    let mut omitted_terminal_hash = ContentHash::zero();
    let mut omitted_digest = blake3::Hasher::new_derive_key("astrid audit archive prefix v1");
    let mut retained_bytes = 0_u64;
    let mut cutoff_cursor = None;
    let mut first_retained_previous_hash = ContentHash::zero();
    let mut after = None;
    loop {
        let page = log
            .storage()
            .get_session_entries_page(session_id, after.as_deref(), 256)
            .await?;
        if page.is_empty() {
            break;
        }
        let next_after = page.last().map(|(cursor, _)| cursor.clone());
        for (cursor, entry) in page {
            if entry.principal.as_ref() != principal {
                continue;
            }
            let encoded = serde_json::to_vec(&entry)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?;
            retained_bytes =
                retained_bytes.saturating_add(u64::try_from(encoded.len()).unwrap_or(u64::MAX));
            retained.push_back(entry);
            while retained.len() > policy.retain_entries
                || policy
                    .retain_bytes
                    .is_some_and(|limit| retained_bytes > limit && retained.len() > 1)
            {
                let old_cursor = retained_cursors.pop_front().ok_or_else(|| {
                    AuditError::StorageError("audit retention cursor underflow".to_owned())
                })?;
                let old = retained.pop_front().ok_or_else(|| {
                    AuditError::StorageError("audit retention ring underflow".to_owned())
                })?;
                let old_bytes = serde_json::to_vec(&old)
                    .map_err(|error| AuditError::SerializationError(error.to_string()))?;
                retained_bytes = retained_bytes
                    .saturating_sub(u64::try_from(old_bytes.len()).unwrap_or(u64::MAX));
                omitted_digest.update(&old_bytes);
                omitted_count = omitted_count.saturating_add(1);
                omitted_bytes = omitted_bytes
                    .saturating_add(u64::try_from(old_bytes.len()).unwrap_or(u64::MAX));
                omitted_terminal_hash = old.content_hash();
                cutoff_cursor = Some(old_cursor);
            }
            retained_cursors.push_back(cursor);
        }
        after = next_after;
    }

    if let Some(first) = retained.front() {
        first_retained_previous_hash = first.previous_hash;
    }
    Ok(RetentionScan {
        retained_count: u64::try_from(retained.len()).unwrap_or(u64::MAX),
        retained_bytes,
        omitted_count,
        omitted_bytes,
        omitted_digest: omitted_digest.finalize().to_hex().to_string(),
        omitted_terminal_hash: omitted_terminal_hash.to_hex(),
        retained_head: retained.back().map(|entry| entry.id.clone()),
        cutoff_cursor,
        first_retained: retained.front().map(|entry| entry.id.clone()),
        first_retained_previous_hash: first_retained_previous_hash.to_hex(),
    })
}

async fn prior_receipt(
    log: &AuditLog,
    session_id: &SessionId,
    principal: Option<&PrincipalId>,
) -> AuditResult<(u64, Option<String>)> {
    let previous_receipt = log.storage().prune_receipt(session_id, principal).await?;
    Ok(if let Some(previous) = previous_receipt {
        let previous_receipt: AuditPruneReceipt = serde_json::from_slice(&previous)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        previous_receipt.verify()?;
        (
            previous_receipt.generation.saturating_add(1),
            Some(blake3::hash(&previous).to_hex().to_string()),
        )
    } else {
        (0, None)
    })
}

async fn persist_prune(
    log: &AuditLog,
    session_id: &SessionId,
    principal: Option<&PrincipalId>,
    receipt: &AuditPruneReceipt,
) -> AuditResult<AuditPruneReceipt> {
    let encoded = serde_json::to_vec(receipt)
        .map_err(|error| AuditError::SerializationError(error.to_string()))?;
    // The backend advances a durable deletion plan by one bounded page. Keep
    // resuming that same plan until its signed receipt is published; a crash
    // or cancellation simply leaves the cursor for the next invocation.
    for _ in 0..MAX_RESUME_PAGES {
        log.storage()
            .prune_chain(
                session_id,
                principal,
                usize::try_from(receipt.retained_count).unwrap_or(usize::MAX),
                encoded.clone(),
            )
            .await?;
        if let Some(current) = log.storage().prune_receipt(session_id, principal).await?
            && current == encoded
        {
            return serde_json::from_slice(&current)
                .map_err(|error| AuditError::SerializationError(error.to_string()));
        }
    }
    Err(AuditError::StorageError(
        "audit prune remains resumable after bounded page budget".to_owned(),
    ))
}

pub(crate) async fn prune_chain(
    log: &AuditLog,
    session_id: &SessionId,
    principal: Option<&PrincipalId>,
    policy: AuditRetentionPolicy,
) -> AuditResult<AuditPruneReceipt> {
    prune_chain_segment(log, session_id, principal, policy, None).await
}

pub(crate) async fn prune_chain_segment(
    log: &AuditLog,
    session_id: &SessionId,
    principal: Option<&PrincipalId>,
    policy: AuditRetentionPolicy,
    selected_segment: Option<(u64, Option<u64>)>,
) -> AuditResult<AuditPruneReceipt> {
    if policy.retain_entries == 0 {
        return Err(AuditError::StorageError(
            "audit retention requires at least one retained entry".to_owned(),
        ));
    }
    if policy.retain_entries > MAX_RETENTION_RING {
        return Err(AuditError::StorageError(format!(
            "audit retention exceeds bounded planner ring ({MAX_RETENTION_RING} entries)"
        )));
    }
    if policy.retain_bytes == Some(0) {
        return Err(AuditError::StorageError(
            "audit retention bytes must be greater than zero".to_owned(),
        ));
    }
    let scan = scan_retention(log, session_id, principal, policy).await?;
    let selected_segment = match selected_segment {
        Some((segment, ordinal)) => (Some(segment), ordinal),
        None => log
            .storage()
            .chain_metadata(session_id, principal)
            .await?
            .map_or((None, None), |metadata| {
                (Some(metadata.segment), metadata.seal_ordinal)
            }),
    };
    let (generation, prior_receipt_hash) = prior_receipt(log, session_id, principal).await?;
    let receipt = AuditPruneReceipt {
        schema: 1,
        session: session_id.to_string(),
        principal: principal.map(ToString::to_string),
        retained_count: scan.retained_count,
        retained_bytes: scan.retained_bytes,
        omitted_count: scan.omitted_count,
        omitted_bytes: scan.omitted_bytes,
        omitted_digest: scan.omitted_digest,
        omitted_terminal_hash: scan.omitted_terminal_hash,
        retained_head: scan.retained_head,
        generation,
        cutoff_cursor: scan.cutoff_cursor,
        first_retained: scan.first_retained,
        first_retained_previous_hash: scan.first_retained_previous_hash,
        prior_receipt_hash,
        segment: selected_segment.0,
        seal_ordinal: selected_segment.1,
        public_key: log.runtime_public_key(),
        signature: Signature::from_bytes([0; 64]),
    };
    let mut receipt = receipt;
    let bytes = receipt.signing_bytes()?;
    let signature = log.sign_archive_receipt(&bytes);
    receipt.signature = signature;
    persist_prune(log, session_id, principal, &receipt).await
}

pub(crate) fn verify_anchor(
    receipt: &AuditPruneReceipt,
    first_previous: &ContentHash,
) -> AuditResult<bool> {
    receipt.verify()?;
    Ok(receipt.omitted_terminal_hash == first_previous.to_hex()
        && receipt.first_retained_previous_hash == first_previous.to_hex())
}
