//! Invitations carry issuer ownership, never an impersonation grant.
use crate::{Kernel, kernel_router::AuthorizedRequest};
use astrid_core::PrincipalId;
use astrid_events::kernel_api::AdminResponseBody;
use astrid_storage::ownership::CreationDelegation;

pub(in crate::kernel_router::admin) async fn capture(
    kernel: &Kernel,
    caller: &PrincipalId,
    authorized: Option<&AuthorizedRequest>,
    device_id: Option<&str>,
) -> Result<CreationDelegation, AdminResponseBody> {
    let resolved;
    let authorized = if let Some(value) = authorized {
        value
    } else {
        resolved =
            super::super::super::authorize_request(kernel, caller, device_id, "invite:issue")
                .map_err(|error| super::err_unauthorized(error.to_string()))?;
        &resolved
    };
    let key = authorized.authenticated_public_key.ok_or_else(|| {
        super::err_unauthorized("invite issuance requires a user-delegated device".into())
    })?;
    let principal = kernel
        .principal_directory
        .uid_for(caller)
        .map_err(|error| super::err_unauthorized(error.to_string()))?;
    kernel
        .ownership_store
        .capture_creation_delegation(principal, &key)
        .await
        .map_err(|error| super::err_unauthorized(error.to_string()))
}

pub(super) async fn validate(
    kernel: &Kernel,
    delegation: Option<&CreationDelegation>,
) -> Result<(), AdminResponseBody> {
    let delegation = delegation.ok_or_else(|| {
        super::err_unauthorized(
            "invite has no issuer ownership; ask its issuer to create a new invitation".into(),
        )
    })?;
    let caller = kernel
        .principal_directory
        .alias_for(delegation.principal())
        .map_err(|error| super::err_unauthorized(error.to_string()))?;
    let profile = astrid_core::profile::PrincipalProfile::load_from_path(
        &astrid_core::profile::PrincipalProfile::path_for(&kernel.astrid_home, &caller),
    )
    .map_err(|error| super::err_unauthorized(error.to_string()))?;
    let key = astrid_crypto::PublicKey::from(*delegation.public_key()).to_hex();
    let device = profile.auth.device_by_pubkey(&key).ok_or_else(|| {
        super::err_unauthorized("invitation issuer device is no longer registered".into())
    })?;
    let current = capture(kernel, &caller, None, Some(&device.key_id)).await?;
    if &current != delegation {
        return Err(super::err_unauthorized(
            "invitation issuer delegation has changed".into(),
        ));
    }
    Ok(())
}
