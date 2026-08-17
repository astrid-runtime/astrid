use astrid_core::SessionId;

use crate::error::{AuditError, AuditResult};

pub(super) fn chain_head_key(
    session_id: &SessionId,
    principal: Option<&astrid_core::PrincipalId>,
) -> String {
    match principal {
        Some(p) => format!("{}:{}", session_id.0, p),
        None => session_id.0.to_string(),
    }
}

pub(super) fn parse_sequence(bytes: &[u8]) -> AuditResult<u64> {
    let encoded: [u8; 8] = bytes.try_into().map_err(|_| {
        AuditError::StorageError("invalid audit session sequence encoding".to_string())
    })?;
    Ok(u64::from_be_bytes(encoded))
}
