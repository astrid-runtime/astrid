//! Host-authorized provisioning. This module never installs a deployment anchor.

mod configure;

use astrid_core::kernel_api::hosted_owner::{
    HostedEnrollmentPhase, HostedOwnerRequest, HostedOwnerResponse,
};
use astrid_core::{PrincipalId, profile::DeviceKeyId};
use astrid_storage::FirstOwnerEnrollment;

impl crate::Kernel {
    /// Handle a direct native control after a verified local handshake.
    ///
    /// The daemon is the only composition path. Capsules have no event-bus
    /// router for this endpoint. The shared admin gate serializes profile key
    /// retirement with every policy/challenge/commit revalidation.
    ///
    /// # Errors
    /// Rejects unavailable credentials, forged/stale proof and storage failures.
    pub async fn native_hosted_owner_request(
        &self,
        principal: &PrincipalId,
        device_key_id: &str,
        request: HostedOwnerRequest,
    ) -> Result<HostedOwnerResponse, &'static str> {
        let key_id = DeviceKeyId::new(device_key_id).map_err(|_| "forbidden")?;
        let _gate = self.admin_write_lock.lock().await;
        let profile = self
            .profile_cache
            .resolve(principal)
            .map_err(|_| "forbidden")?;
        if !profile.enabled {
            return Err("forbidden");
        }
        let device = profile
            .auth
            .device_by_typed_key_id(&key_id)
            .ok_or("forbidden")?;
        let public_key: [u8; 32] = hex::decode(&device.pubkey)
            .map_err(|_| "forbidden")?
            .try_into()
            .map_err(|_| "forbidden")?;
        let uid = self
            .principal_directory
            .uid_for(principal)
            .map_err(|_| "forbidden")?;
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(u64::MAX, |time| time.as_secs())
        };
        match request {
            HostedOwnerRequest::Inspect {} => self.inspect_native_hosted_owner().await,
            HostedOwnerRequest::Challenge {
                user,
                fleet,
                expires_at,
            } => {
                let graph = self
                    .ownership_store
                    .load()
                    .await
                    .map_err(|_| "unavailable")?;
                if graph
                    .hosted_owner()
                    .is_none_or(|record| Some(record.artifact) != selected_native_artifact().ok())
                {
                    return Err("rejected");
                }
                let challenge = self
                    .ownership_store
                    .challenge_hosted_owner(uid, public_key, user, fleet, expires_at, now)
                    .await
                    .map_err(|_| "rejected")?;
                Ok(HostedOwnerResponse::Challenge {
                    challenge: Box::new(challenge),
                })
            },
            HostedOwnerRequest::Provision { envelope } => {
                if Some(envelope.challenge.artifact) != selected_native_artifact().ok() {
                    return Err("rejected");
                }
                if envelope.challenge.device.principal != uid
                    || envelope.challenge.device.public_key != public_key
                {
                    return Err("forbidden");
                }
                self.ownership_store
                    .begin_hosted_owner(&envelope, now)
                    .await
                    .map_err(|_| "rejected")?;
                let completion = self
                    .ownership_store
                    .commit_hosted_owner(&envelope, now)
                    .await
                    .map_err(|_| "rejected")?;
                Ok(HostedOwnerResponse::Enrolled { completion })
            },
            HostedOwnerRequest::Cancel {} => {
                self.ownership_store
                    .cancel_hosted_owner(uid, public_key)
                    .await
                    .map_err(|_| "rejected")?;
                Ok(HostedOwnerResponse::Cancelled)
            },
        }
    }

    async fn inspect_native_hosted_owner(&self) -> Result<HostedOwnerResponse, &'static str> {
        let graph = self
            .ownership_store
            .load()
            .await
            .map_err(|_| "unavailable")?;
        let enrollment = match self
            .ownership_store
            .first_owner_state()
            .await
            .map_err(|_| "unavailable")?
        {
            FirstOwnerEnrollment::Unenrolled => HostedEnrollmentPhase::Unenrolled,
            FirstOwnerEnrollment::Pending { .. } => HostedEnrollmentPhase::Pending,
            FirstOwnerEnrollment::Enrolled { .. } => HostedEnrollmentPhase::Enrolled,
            FirstOwnerEnrollment::Cancelled { .. } => HostedEnrollmentPhase::Cancelled,
        };
        let record = graph.hosted_owner();
        Ok(HostedOwnerResponse::Inspected {
            enrollment,
            policy: record.map(|record| record.policy.clone()),
            installation: record.map(|record| record.installation),
            completion: record.and_then(|record| record.completion.clone()),
        })
    }
}

/// Digest of the running native executable. This is selected hosted software,
/// never evidence that firmware/kernel/boot were authenticated.
fn selected_native_artifact() -> Result<[u8; 32], std::io::Error> {
    static DIGEST: std::sync::OnceLock<Result<[u8; 32], String>> = std::sync::OnceLock::new();
    DIGEST
        .get_or_init(|| {
            let mut file =
                std::fs::File::open(std::env::current_exe().map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            let mut hasher = blake3::Hasher::new();
            std::io::copy(&mut file, &mut hasher).map_err(|error| error.to_string())?;
            Ok(*hasher.finalize().as_bytes())
        })
        .as_ref()
        .copied()
        .map_err(|error| std::io::Error::other(error.clone()))
}
