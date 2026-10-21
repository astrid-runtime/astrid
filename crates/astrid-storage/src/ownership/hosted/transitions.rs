//! Every time-dependent decision runs inside the graph CAS retry closure.

use super::{HostedOwnerCompletion, HostedOwnerRecord, unsigned};
use crate::ownership::{
    FirstOwnerEnrollment, HOSTED_GRAPH_FORMAT_VERSION, OwnershipError, OwnershipStore,
};
use astrid_core::identity::hosted_owner::{
    HostedOwnerChallenge, HostedOwnerDevice, HostedOwnerEnvelope, HostedOwnerError,
    HostedOwnerPolicy,
};
use astrid_core::{FirstOwnerClaim, FleetIdentity, PrincipalUid, UserIdentity};
use uuid::Uuid;

impl OwnershipStore {
    /// Install/rotate a policy from the explicit controlling-account composition path.
    ///
    /// This is an internal host authority operation, never a socket operation.
    /// Existing enrolled ownership cannot be replaced by this fresh-only adapter.
    ///
    /// # Errors
    /// Rejects existing authority, non-increasing policy, expiry and invalid keys.
    pub async fn configure_hosted_owner(
        &self,
        policy: HostedOwnerPolicy,
        artifact: [u8; 32],
        now: impl Fn() -> u64 + Send + Sync,
    ) -> Result<HostedOwnerRecord, OwnershipError> {
        policy.validate()?;
        self.mutate(|graph| {
            if (graph.hosted.is_none() && graph.first_owner_state().is_pending())
                || graph.first_owner_state().is_enrolled()
                || graph.has_legacy_authority()
                || artifact == [0; 32]
            {
                return Err(HostedOwnerError::Stale.into());
            }
            if now() >= policy.expires_at.get() {
                return Err(HostedOwnerError::Expired.into());
            }
            let installation = if let Some(old) = &graph.hosted {
                if policy.generation <= old.policy.generation {
                    return Err(HostedOwnerError::Stale.into());
                }
                old.installation
            } else {
                Uuid::new_v4()
            };
            Self::advance_counters(graph)?;
            graph.set_first_owner_state(&FirstOwnerEnrollment::Unenrolled);
            let record = HostedOwnerRecord {
                policy: policy.clone(),
                installation,
                session: Uuid::new_v4(),
                artifact,
                device: None,
                challenge: None,
                pending: None,
                completion: None,
            };
            graph.format_version = HOSTED_GRAPH_FORMAT_VERSION;
            graph.hosted = Some(record.clone());
            Ok(record)
        })
        .await
    }

    /// Issue public signing facts for an independently authenticated live device.
    /// The native caller must hold the device/policy lifecycle gate throughout.
    ///
    /// # Errors
    /// Rejects absent policy, stale enrollment, identities, expiry or target changes.
    pub async fn challenge_hosted_owner(
        &self,
        principal: PrincipalUid,
        public_key: [u8; 32],
        user: UserIdentity,
        fleet: FleetIdentity,
        expires_at: u64,
        now: impl Fn() -> u64 + Send + Sync,
    ) -> Result<HostedOwnerChallenge, OwnershipError> {
        user.validate()?;
        fleet.validate()?;
        if fleet.genesis.created_by != user.uid {
            return Err(HostedOwnerError::Invalid.into());
        }
        self.mutate(|graph| {
            if !matches!(
                graph.first_owner_state(),
                FirstOwnerEnrollment::Unenrolled | FirstOwnerEnrollment::Cancelled { .. }
            ) || !self.principals.contains_uid(principal)
            {
                return Err(HostedOwnerError::Stale.into());
            }
            let hosted = graph.hosted.as_mut().ok_or(HostedOwnerError::Stale)?;
            if principal != hosted.policy.target.principal
                || public_key != hosted.policy.target.public_key
            {
                return Err(HostedOwnerError::Stale.into());
            }
            if now() >= expires_at || expires_at > hosted.policy.expires_at.get() {
                return Err(HostedOwnerError::Expired.into());
            }
            let device = match &hosted.device {
                Some(device)
                    if device.principal == principal && device.public_key == public_key =>
                {
                    device.clone()
                },
                Some(_) => return Err(HostedOwnerError::Stale.into()),
                None => HostedOwnerDevice {
                    principal,
                    public_key,
                    incarnation: Uuid::new_v4(),
                },
            };
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce).map_err(|_| HostedOwnerError::Invalid)?;
            let mut packet = HostedOwnerChallenge {
                version: 1,
                policy: hosted.policy.clone(),
                installation: hosted.installation,
                session: hosted.session,
                artifact: hosted.artifact,
                device,
                user: user.clone(),
                fleet: fleet.clone(),
                claim: FirstOwnerClaim::from_parts_with_authority(
                    [0; 32],
                    [0; 32],
                    [0; 32],
                    [0; 32],
                    user.uid,
                    fleet.uid,
                    principal,
                    user.genesis.initial_public_key,
                    nonce,
                    graph.authority_generation.get(),
                    expires_at,
                    graph.authority_epoch.get(),
                    [0; 64],
                )
                .map_err(|_| HostedOwnerError::Invalid)?,
            };
            packet.claim = FirstOwnerClaim::from_parts_with_authority(
                packet.installation_commitment(),
                packet.session_commitment(),
                packet.artifact,
                packet.genesis_commitment()?,
                user.uid,
                fleet.uid,
                principal,
                user.genesis.initial_public_key,
                *packet.claim.nonce(),
                graph.authority_generation.get(),
                expires_at,
                graph.authority_epoch.get(),
                [0; 64],
            )
            .map_err(|_| HostedOwnerError::Invalid)?;
            packet.validate()?;
            hosted.device = Some(packet.device.clone());
            hosted.challenge = Some(packet.clone());
            Ok(packet)
        })
        .await
    }

    /// Persist both verified authorizations as Pending without granting authority.
    ///
    /// # Errors
    /// Rejects forged, stale or expired statements; all failures leave state unchanged.
    pub async fn begin_hosted_owner(
        &self,
        envelope: &HostedOwnerEnvelope,
        now: impl Fn() -> u64 + Send + Sync,
    ) -> Result<(), OwnershipError> {
        envelope.verify()?;
        self.mutate(|graph| {
            let state = graph.first_owner_state();
            let hosted = graph.hosted.as_mut().ok_or(HostedOwnerError::Stale)?;
            if state.is_enrolled() {
                return if hosted.pending.as_ref() == Some(envelope) {
                    Ok(())
                } else {
                    Err(HostedOwnerError::Stale.into())
                };
            }
            hosted.check_live(&envelope.challenge, now())?;
            let expected = hosted.challenge.as_ref().ok_or(HostedOwnerError::Stale)?;
            let mut supplied = envelope.challenge.clone();
            supplied.claim = unsigned(&supplied.claim);
            if expected != &supplied
                || envelope.challenge.claim.authority_epoch() != graph.authority_epoch
                || envelope.challenge.claim.authority_generation() != graph.authority_generation
            {
                return Err(HostedOwnerError::Stale.into());
            }
            hosted.pending = Some(envelope.clone());
            graph.set_first_owner_state(&FirstOwnerEnrollment::Pending {
                claim: envelope.challenge.claim,
            });
            Ok(())
        })
        .await
    }

    /// Commit owner graph, payer, binding, initialized marker and outcome in one CAS.
    ///
    /// # Errors
    /// Rejects stale current policy/device, altered evidence or expired admission.
    /// Exact historical replay returns the receipt without recreating any authority.
    pub async fn commit_hosted_owner(
        &self,
        envelope: &HostedOwnerEnvelope,
        now: impl Fn() -> u64 + Send + Sync,
    ) -> Result<HostedOwnerCompletion, OwnershipError> {
        envelope.verify()?;
        self.mutate(|graph| {
            let hosted = graph.hosted.as_ref().ok_or(HostedOwnerError::Stale)?;
            if hosted.pending.as_ref() != Some(envelope) {
                return Err(HostedOwnerError::Stale.into());
            }
            if let Some(completion) = &hosted.completion {
                return Ok(completion.clone());
            }
            hosted.check_live(&envelope.challenge, now())?;
            let packet = &envelope.challenge;
            Self::apply_first_owner_commit(
                &self.principals,
                graph,
                &packet.claim,
                &packet.user,
                &packet.fleet,
                &now,
            )?;
            let completion = HostedOwnerCompletion {
                request_digest: packet.claim.canonical_digest(),
                user: packet.user.uid,
                fleet: packet.fleet.uid,
                principal: packet.device.principal,
                binding_generation: Uuid::new_v4(),
            };
            if graph.local_user_binding_initialized || !graph.user_bindings.is_empty() {
                return Err(HostedOwnerError::Stale.into());
            }
            graph
                .user_bindings
                .push(super::super::user_bindings::UserDeviceBinding::first_owner(
                    completion.binding_generation,
                    packet.device.principal,
                    packet.device.public_key,
                    packet.user.uid,
                    packet.fleet.uid,
                ));
            graph.local_user_binding_initialized = true;
            graph
                .hosted
                .as_mut()
                .ok_or(HostedOwnerError::Stale)?
                .completion = Some(completion.clone());
            Ok(completion)
        })
        .await
    }

    /// Cancel only an outstanding fresh ceremony, without touching enrolled grants.
    ///
    /// # Errors
    /// Rejects enrolled ownership or a different registered device target.
    pub async fn cancel_hosted_owner(
        &self,
        principal: PrincipalUid,
        public_key: [u8; 32],
    ) -> Result<(), OwnershipError> {
        self.mutate(|graph| {
            if graph.first_owner_state().is_enrolled() {
                return Err(HostedOwnerError::Stale.into());
            }
            let hosted = graph.hosted.as_mut().ok_or(HostedOwnerError::Stale)?;
            if !hosted.device.as_ref().is_some_and(|device| {
                device.principal == principal && device.public_key == public_key
            }) {
                return Err(HostedOwnerError::Stale.into());
            }
            hosted.device = None;
            hosted.challenge = None;
            hosted.pending = None;
            hosted.session = Uuid::new_v4();
            Self::advance_counters(graph)?;
            graph.set_first_owner_state(&FirstOwnerEnrollment::Unenrolled);
            Ok(())
        })
        .await
    }

    /// Retire captured authority before the supported registered-device removal.
    /// The caller holds the native device lifecycle gate across both operations.
    /// A later profile-write failure stays safely revoked and can be retried.
    ///
    /// # Errors
    /// Returns storage/counter failures without permitting profile removal.
    pub async fn retire_hosted_owner_device(
        &self,
        principal: PrincipalUid,
        public_key: [u8; 32],
    ) -> Result<(), OwnershipError> {
        self.mutate(|graph| {
            let Some(hosted) = graph.hosted.as_mut() else {
                return Ok(());
            };
            // Every hosted delegated credential has a retirement boundary,
            // including later devices which never participated in first ownership.
            graph
                .user_bindings
                .retain(|binding| !binding.matches_device(principal, &public_key));
            if !hosted.device.as_ref().is_some_and(|device| {
                device.principal == principal && device.public_key == public_key
            }) {
                return Ok(());
            }
            hosted.device = None;
            hosted.challenge = None;
            hosted.session = Uuid::new_v4();
            if hosted.completion.is_none() {
                hosted.pending = None;
                Self::advance_counters(graph)?;
                graph.set_first_owner_state(&FirstOwnerEnrollment::Unenrolled);
            }
            Ok(())
        })
        .await
    }
}
