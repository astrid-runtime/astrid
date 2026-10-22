//! `audit.anchor_mark` and `audit.anchor_status`: the anchoring service
//! records how far each chain is externally anchored, and retention never
//! prunes past that point.

use std::collections::HashSet;
use std::sync::Arc;

use astrid_audit::{AuditChainAnchorStatus, AuditError, AuditLog};
use astrid_core::kernel_api::{
    AUDIT_ANCHOR_MARK_MAX_CHAINS, AUDIT_OMITTED_TOTAL_UNKNOWN, AdminResponseBody,
    AuditAnchorChainStatus, AuditAnchorMarkChain, AuditAnchorMarkOutcome, AuditAnchorMarkRequest,
    AuditAnchorMarkResult, AuditAnchorMarkStatus, AuditAnchorStatusReport,
};
use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::ContentHash;

use crate::Kernel;

/// Rejections quoted in the audit row of a partly rejected mark.
const QUOTED_REJECTIONS: usize = 8;

/// Record anchored watermarks for every listed chain. Each chain is checked
/// and recorded independently; a rejected chain leaves the others' marks in
/// place.
pub(super) async fn anchor_mark(
    kernel: &Arc<Kernel>,
    request: AuditAnchorMarkRequest,
) -> AdminResponseBody {
    match mark_chains(kernel.audit_log.as_ref(), request).await {
        Ok(result) => AdminResponseBody::AuditAnchorMarked(Box::new(result)),
        Err(error) => AdminResponseBody::Error(format!("audit anchor mark failed: {error}")),
    }
}

async fn mark_chains(
    log: &AuditLog,
    request: AuditAnchorMarkRequest,
) -> Result<AuditAnchorMarkResult, String> {
    request.evidence.validate()?;
    if request.chains.is_empty() {
        return Err("no chains to mark".to_owned());
    }
    if request.chains.len() > AUDIT_ANCHOR_MARK_MAX_CHAINS {
        return Err(format!(
            "{} chains exceed the limit of {AUDIT_ANCHOR_MARK_MAX_CHAINS} per request",
            request.chains.len()
        ));
    }
    let mut seen = HashSet::new();
    for chain in &request.chains {
        if !seen.insert((&chain.session, chain.principal.as_ref())) {
            return Err(format!(
                "chain {} is listed more than once",
                label(&chain.session, chain.principal.as_ref())
            ));
        }
    }
    let evidence = serde_json::to_value(&request.evidence).map_err(|error| error.to_string())?;
    let mut chains = Vec::with_capacity(request.chains.len());
    for chain in request.chains {
        chains.push(mark_chain(log, chain, &evidence).await);
    }
    Ok(AuditAnchorMarkResult { chains })
}

async fn mark_chain(
    log: &AuditLog,
    chain: AuditAnchorMarkChain,
    evidence: &serde_json::Value,
) -> AuditAnchorMarkOutcome {
    let principal = chain.principal.as_ref();
    let marked = match ContentHash::from_hex(&chain.head_hash_hex) {
        Ok(head_hash) => log
            .mark_anchored(
                &chain.session,
                principal,
                chain.position,
                head_hash,
                evidence.clone(),
            )
            .await
            .map_err(|error| match error {
                AuditError::AnchorRejected(reason) => reason,
                other => other.to_string(),
            }),
        Err(_) => Err(format!(
            "chain {}: head_hash_hex must be 32 bytes of hex",
            label(&chain.session, principal)
        )),
    };
    let (status, anchored_position, error) = match marked {
        Ok(result) if result.advanced => (
            AuditAnchorMarkStatus::Advanced,
            result.watermark.position,
            None,
        ),
        Ok(result) => (
            AuditAnchorMarkStatus::Unchanged,
            result.watermark.position,
            None,
        ),
        Err(error) => {
            let anchored = log
                .anchor_watermark(&chain.session, principal)
                .await
                .ok()
                .flatten()
                .map_or(0, |watermark| watermark.position);
            (AuditAnchorMarkStatus::Rejected, anchored, Some(error))
        },
    };
    AuditAnchorMarkOutcome {
        session: chain.session.0.to_string(),
        principal: chain.principal,
        status,
        anchored_position,
        error,
    }
}

fn label(session: &SessionId, principal: Option<&PrincipalId>) -> String {
    match principal {
        Some(principal) => format!("{} {principal}", session.0),
        None => format!("{} (system)", session.0),
    }
}

/// The failure to record for a mark whose chains were partly or wholly
/// rejected, since its success row is skipped.
pub(super) fn rejected_marks(body: &AdminResponseBody) -> Option<String> {
    let AdminResponseBody::AuditAnchorMarked(result) = body else {
        return None;
    };
    let rejected: Vec<_> = result
        .chains
        .iter()
        .filter(|chain| chain.status == AuditAnchorMarkStatus::Rejected)
        .collect();
    if rejected.is_empty() {
        return None;
    }
    let quoted = rejected
        .iter()
        .take(QUOTED_REJECTIONS)
        .filter_map(|chain| chain.error.as_deref())
        .collect::<Vec<_>>()
        .join("; ");
    Some(format!(
        "audit anchor mark rejected {} of {} chains: {quoted}{}",
        rejected.len(),
        result.chains.len(),
        if rejected.len() > QUOTED_REJECTIONS {
            "; ..."
        } else {
            ""
        }
    ))
}

/// Report every chain's anchored watermark and the retention state. It
/// requires `audit:heads`: it reveals the same per-chain positions and head
/// hashes as the heads snapshot, and the anchoring service holds it.
pub(super) async fn anchor_status(kernel: &Arc<Kernel>) -> AdminResponseBody {
    let log = kernel.audit_log.as_ref();
    let records = match log.anchor_status().await {
        Ok(records) => records,
        Err(error) => {
            return AdminResponseBody::Error(format!("audit anchor status unavailable: {error}"));
        },
    };
    if records.len() > AUDIT_ANCHOR_MARK_MAX_CHAINS {
        return AdminResponseBody::Error(format!(
            "audit anchor status: {} chains exceed the unpaged report limit of \
             {AUDIT_ANCHOR_MARK_MAX_CHAINS}",
            records.len()
        ));
    }
    let retention_hold = match log.global_stats().await {
        Ok(stats) => stats.retention_hold,
        Err(error) => {
            return AdminResponseBody::Error(format!("audit anchor status unavailable: {error}"));
        },
    };
    let mut chains: Vec<_> = records.iter().map(chain_status).collect();
    chains.sort_by(|left, right| chain_order(left).cmp(&chain_order(right)));
    AdminResponseBody::AuditAnchorStatus(Box::new(AuditAnchorStatusReport {
        require_anchor_before_prune: log.require_anchor_before_prune(),
        retention_hold,
        chains,
    }))
}

fn chain_order(chain: &AuditAnchorChainStatus) -> (&str, Option<&str>) {
    (
        chain.session.as_str(),
        chain.principal.as_ref().map(PrincipalId::as_str),
    )
}

fn chain_status(record: &AuditChainAnchorStatus) -> AuditAnchorChainStatus {
    let watermark = record.watermark.as_ref();
    AuditAnchorChainStatus {
        session: record.session_id.0.to_string(),
        principal: record.principal.clone(),
        count: record.count,
        omitted_total: record.omitted_total.unwrap_or(AUDIT_OMITTED_TOTAL_UNKNOWN),
        anchored_position: watermark.map(|mark| mark.position),
        anchored_head_hash_hex: watermark.map(|mark| mark.head_hash.to_hex()),
        anchored_at: watermark.map(|mark| {
            mark.recorded_at
                .0
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
        }),
        evidence: watermark.map(|mark| mark.evidence.clone()),
    }
}
