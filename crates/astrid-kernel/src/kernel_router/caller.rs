use astrid_core::principal::PrincipalId;
use astrid_events::ipc::IpcMessage;

/// Stable outward denial for a management request with no authenticated caller.
pub(super) const MANAGEMENT_CALLER_REQUIRED: &str =
    "management request denied: missing or invalid principal";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CallerResolutionError {
    Missing,
    Invalid,
}

impl CallerResolutionError {
    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::Missing => "missing principal",
            Self::Invalid => "invalid principal",
        }
    }
}

/// Resolve the authenticated caller from a management IPC envelope.
///
/// The kernel never supplies the interactive CLI's active-principal default:
/// that deliberate UX choice is made by the local client before it publishes.
/// Once a request reaches this authority boundary, an absent or malformed
/// principal must not acquire the bootstrap `default` principal's authority.
pub(super) fn resolve_caller(message: &IpcMessage) -> Result<PrincipalId, CallerResolutionError> {
    let raw = message
        .principal
        .as_deref()
        .ok_or(CallerResolutionError::Missing)?;
    PrincipalId::new(raw).map_err(|_| CallerResolutionError::Invalid)
}

/// Resolve one connection-tracking identity without granting bootstrap authority.
///
/// A missing identity is the explicit no-capability `anonymous` principal used by
/// the legacy handshake. A malformed identity is rejected so a forged lifecycle
/// message cannot move any principal's counter.
pub(super) fn resolve_connection_principal(
    message: &IpcMessage,
) -> Result<PrincipalId, CallerResolutionError> {
    match message.principal.as_deref() {
        Some(raw) => PrincipalId::new(raw).map_err(|_| CallerResolutionError::Invalid),
        None => Ok(PrincipalId::anonymous()),
    }
}
