//! Host-administered enrollment shares graph-v1 and the ownership CAS.
//!
//! The host account controlling the admitted private volume is trusted. Public
//! native calls cannot install policy; they must present both external signatures.

use astrid_core::FirstOwnerClaim;
use astrid_core::identity::hosted_owner::{
    HostedOwnerChallenge, HostedOwnerDevice, HostedOwnerEnvelope, HostedOwnerError,
    HostedOwnerPolicy,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{FirstOwnerEnrollment, HOSTED_GRAPH_FORMAT_VERSION, OwnershipError, OwnershipSnapshot};

mod transitions;

pub use astrid_core::kernel_api::hosted_owner::HostedOwnerCompletion;

/// Durable format-three hosted provisioning state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedOwnerRecord {
    /// Policy installed only by explicit native administration.
    pub policy: HostedOwnerPolicy,
    /// Stable admitted installation domain.
    pub installation: Uuid,
    /// Provisioning session; survives restart, changes on cancellation/rotation.
    pub session: Uuid,
    /// Explicitly selected native executable bytes, not a boot attestation.
    pub artifact: [u8; 32],
    /// Current credential incarnation; retirement invalidates it durably.
    pub device: Option<HostedOwnerDevice>,
    /// Current unsigned signing packet; no ownership authority is granted.
    pub challenge: Option<HostedOwnerChallenge>,
    /// Complete two-role evidence retained across interrupted commit/restart.
    pub pending: Option<HostedOwnerEnvelope>,
    /// Historical enrolled result, retained after credential retirement.
    pub completion: Option<HostedOwnerCompletion>,
}

impl OwnershipSnapshot {
    /// Inspect durable hosted facts. The result alone grants no authority.
    #[must_use]
    pub const fn hosted_owner(&self) -> Option<&HostedOwnerRecord> {
        self.hosted.as_ref()
    }

    pub(super) fn require_standalone_enrollment(&self) -> Result<(), OwnershipError> {
        if self.hosted.is_some() {
            return Err(HostedOwnerError::Stale.into());
        }
        Ok(())
    }

    pub(super) fn validate_hosted(&self) -> Result<(), OwnershipError> {
        let Some(hosted) = &self.hosted else {
            if self.format_version == HOSTED_GRAPH_FORMAT_VERSION {
                return Err(HostedOwnerError::Invalid.into());
            }
            return Ok(());
        };
        hosted.policy.validate()?;
        if self.format_version != HOSTED_GRAPH_FORMAT_VERSION
            || hosted.installation.is_nil()
            || hosted.session.is_nil()
            || hosted.artifact == [0; 32]
        {
            return Err(HostedOwnerError::Invalid.into());
        }
        if let Some(challenge) = &hosted.challenge {
            challenge.validate()?;
            hosted.check_context(challenge)?;
        }
        match (
            self.first_owner_state(),
            &hosted.pending,
            &hosted.completion,
        ) {
            (
                FirstOwnerEnrollment::Unenrolled | FirstOwnerEnrollment::Cancelled { .. },
                None,
                None,
            ) => {},
            (FirstOwnerEnrollment::Pending { claim }, Some(envelope), None) => {
                envelope.verify()?;
                hosted.check_context(&envelope.challenge)?;
                if envelope.challenge.claim != claim {
                    return Err(HostedOwnerError::Invalid.into());
                }
            },
            (FirstOwnerEnrollment::Enrolled { claim }, Some(envelope), Some(completion)) => {
                // Historical evidence is immutable, but the live credential/session
                // may have been retired. Never demand or recreate its old binding.
                envelope.verify()?;
                if envelope.challenge.claim != claim
                    || completion.request_digest != claim.canonical_digest()
                    || completion.user != claim.user_uid()
                    || completion.fleet != claim.fleet_uid()
                    || completion.principal != claim.principal_uid()
                    || completion.binding_generation.is_nil()
                    || !self.local_user_binding_initialized
                {
                    return Err(HostedOwnerError::Invalid.into());
                }
            },
            _ => return Err(HostedOwnerError::Invalid.into()),
        }
        Ok(())
    }
}

impl HostedOwnerRecord {
    fn check_context(&self, packet: &HostedOwnerChallenge) -> Result<(), HostedOwnerError> {
        if packet.policy != self.policy
            || packet.installation != self.installation
            || packet.session != self.session
            || packet.artifact != self.artifact
            || self.device.as_ref() != Some(&packet.device)
        {
            return Err(HostedOwnerError::Stale);
        }
        Ok(())
    }

    fn check_live(&self, packet: &HostedOwnerChallenge, now: u64) -> Result<(), HostedOwnerError> {
        self.check_context(packet)?;
        if now >= self.policy.expires_at.get() || packet.claim.is_expired_at(now) {
            return Err(HostedOwnerError::Expired);
        }
        Ok(())
    }
}

fn unsigned(claim: &FirstOwnerClaim) -> FirstOwnerClaim {
    claim.with_signature([0; 64])
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod cas_tests;
