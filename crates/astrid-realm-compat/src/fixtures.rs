//! Honest two-principal fixtures. UID bytes are the stamp seam, not a mint.

use astrid_provider::HostPrincipal;

/// Map trusted stamp UID bytes onto the provider principal seam.
///
/// This does not mint a stamp, lease, or grant. Stamp construction stays
/// crate-private in `astrid-capsule`.
#[must_use]
pub const fn host_principal_from_stamp_uid(uid: [u8; 32]) -> HostPrincipal {
    HostPrincipal::from_principal_uid_bytes(uid)
}

/// Alice stamp-seam principal used by two-principal tests.
#[must_use]
pub const fn alice_principal() -> HostPrincipal {
    host_principal_from_stamp_uid([0xA1; 32])
}

/// Bob stamp-seam principal used by two-principal tests.
#[must_use]
pub const fn bob_principal() -> HostPrincipal {
    host_principal_from_stamp_uid([0xB2; 32])
}

#[cfg(test)]
pub(crate) fn instance_for(principal: HostPrincipal) -> astrid_provider::AdmittedInstance {
    use crate::interpreter::{COMPAT_PROVIDER_GENERATION, COMPAT_PROVIDER_ID};
    use astrid_provider::{AdmittedInstance, ApplicationClosure, InstanceId};
    use astrid_resource_types::{ApplicationGenerationRef, ObjectGeneration, OwnerId, ResourceId};

    AdmittedInstance::new(
        InstanceId::new(
            ResourceId::from_bytes([0x31; 32]),
            ObjectGeneration::INITIAL,
        ),
        ApplicationClosure::new(
            ApplicationGenerationRef::from_bytes([0x21; 32]),
            COMPAT_PROVIDER_ID,
            COMPAT_PROVIDER_GENERATION,
        ),
        OwnerId::principal(*principal.as_bytes()),
    )
}

#[cfg(test)]
pub(crate) fn job_for(
    principal: HostPrincipal,
    argv: &[&[u8]],
) -> Result<astrid_provider::Job, astrid_provider::ProviderError> {
    use astrid_provider::{AttachmentSet, Job, JobArgv, StreamSet};
    use astrid_resource_types::{CausalRequestId, OperationId};

    Ok(Job::for_instance(
        OperationId::from_bytes([0x41; 16]),
        &instance_for(principal),
        &JobArgv::try_from_args(argv)?,
        &AttachmentSet::EMPTY,
        &StreamSet::EMPTY,
        CausalRequestId::from_bytes([0x51; 16]),
        principal,
    ))
}

#[cfg(test)]
mod tests {
    use super::{alice_principal, bob_principal, host_principal_from_stamp_uid};
    use astrid_provider::HostPrincipal;

    #[test]
    fn stamp_uid_seam_is_not_a_mint() {
        assert_eq!(
            host_principal_from_stamp_uid([0xA1; 32]),
            HostPrincipal::from_principal_uid_bytes([0xA1; 32])
        );
        assert_ne!(alice_principal(), bob_principal());
    }
}
