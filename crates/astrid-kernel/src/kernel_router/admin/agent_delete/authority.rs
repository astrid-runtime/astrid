//! Authenticated deletion context; ownership is checked at reservation time.

use astrid_core::{PrincipalId, PrincipalUid};
use astrid_events::kernel_api::AdminResponseBody;
use astrid_storage::{OwnershipError, PrincipalDeletionGuard};

use super::super::handlers::{err_bad_input, err_internal};
use crate::{Kernel, kernel_router::AuthorizedRequest};

pub(in crate::kernel_router::admin) struct DeletionAuthority {
    caller: PrincipalUid,
    key: [u8; 32],
}

impl DeletionAuthority {
    pub(in crate::kernel_router::admin) fn resolve(
        kernel: &Kernel,
        caller: &PrincipalId,
        authorization: Option<&AuthorizedRequest>,
        device: Option<&str>,
    ) -> Result<Option<Self>, AdminResponseBody> {
        let resolved;
        let authorization = if let Some(authorization) = authorization {
            authorization
        } else {
            resolved =
                super::super::super::authorize_request(kernel, caller, device, "agent:delete")
                    .map_err(|error| err_bad_input(error.to_string()))?;
            &resolved
        };
        let Some(key) = authorization.authenticated_public_key else {
            // Legacy unowned deletion remains available under its existing
            // capability. Owned deletion will reject absent user authority.
            return Ok(None);
        };
        let caller = kernel
            .principal_directory
            .uid_for(caller)
            .map_err(|error| err_internal(error.to_string()))?;
        Ok(Some(Self { caller, key }))
    }

    pub(super) async fn reserve(
        authority: Option<&Self>,
        kernel: &Kernel,
        uid: PrincipalUid,
        alias: &PrincipalId,
    ) -> Result<PrincipalDeletionGuard, OwnershipError> {
        match authority {
            Some(authority) => {
                kernel
                    .ownership_store
                    .guard_principal_deletion_for_device(
                        uid,
                        alias.clone(),
                        authority.caller,
                        &authority.key,
                    )
                    .await
            },
            None => {
                kernel
                    .ownership_store
                    .guard_principal_deletion_for_alias(uid, alias.clone())
                    .await
            },
        }
    }

    pub(super) async fn resume(
        authority: Option<&Self>,
        kernel: &Kernel,
        alias: &PrincipalId,
    ) -> Result<Option<PrincipalDeletionGuard>, OwnershipError> {
        match authority {
            Some(authority) => {
                kernel
                    .ownership_store
                    .resume_principal_deletion_for_device(alias, authority.caller, &authority.key)
                    .await
            },
            None => {
                kernel
                    .ownership_store
                    .resume_principal_deletion_by_alias(alias)
                    .await
            },
        }
    }
}
