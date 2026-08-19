use super::key_types::SessionSequence;
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

pub(super) fn parse_sequence(bytes: &[u8]) -> AuditResult<SessionSequence> {
    SessionSequence::from_bytes(bytes).map_err(|error| AuditError::StorageError(error.to_owned()))
}
