//! Test-only fluent audit-entry builder.

use astrid_capabilities::AuditEntryId;
use astrid_core::SessionId;

use crate::entry::{AuditAction, AuditOutcome, AuthorizationProof};
use crate::error::AuditResult;
use crate::log::AuditLog;

pub(crate) struct AuditBuilder<'a> {
    log: &'a AuditLog,
    session_id: SessionId,
    action: Option<AuditAction>,
    authorization: Option<AuthorizationProof>,
}

impl<'a> AuditBuilder<'a> {
    pub(crate) fn new(log: &'a AuditLog, session_id: SessionId) -> Self {
        Self {
            log,
            session_id,
            action: None,
            authorization: None,
        }
    }

    #[must_use]
    pub(crate) fn action(mut self, action: AuditAction) -> Self {
        self.action = Some(action);
        self
    }

    #[must_use]
    pub(crate) fn authorization(mut self, auth: AuthorizationProof) -> Self {
        self.authorization = Some(auth);
        self
    }

    pub(crate) async fn success(self) -> AuditResult<AuditEntryId> {
        self.log
            .append(
                self.session_id,
                self.action.expect("action required"),
                self.authorization
                    .unwrap_or(AuthorizationProof::NotRequired {
                        reason: "unspecified".to_string(),
                    }),
                AuditOutcome::success(),
            )
            .await
    }

    pub(crate) async fn success_with(
        self,
        details: impl Into<String>,
    ) -> AuditResult<AuditEntryId> {
        self.log
            .append(
                self.session_id,
                self.action.expect("action required"),
                self.authorization
                    .unwrap_or(AuthorizationProof::NotRequired {
                        reason: "unspecified".to_string(),
                    }),
                AuditOutcome::success_with(details),
            )
            .await
    }

    pub(crate) async fn failure(self, error: impl Into<String>) -> AuditResult<AuditEntryId> {
        self.log
            .append(
                self.session_id,
                self.action.expect("action required"),
                self.authorization
                    .unwrap_or(AuthorizationProof::NotRequired {
                        reason: "unspecified".to_string(),
                    }),
                AuditOutcome::failure(error),
            )
            .await
    }
}
