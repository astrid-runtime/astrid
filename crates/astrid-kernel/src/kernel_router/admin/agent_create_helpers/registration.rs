//! Register a fresh identity without publishing its profile to capsule loaders.

use super::super::handlers::{AGENT_IDENTITY_PLATFORM, err_bad_input, err_internal};
use super::create::{build_create_profile, mint_principal_keypair};
use super::rollback::{remove_principal_key, rollback_created_identity};
use astrid_core::{principal::PrincipalId, profile::PrincipalProfile};
use astrid_events::kernel_api::AdminResponseBody;
use std::sync::Arc;

pub(super) struct RegisteredPrincipal {
    pub(super) profile: PrincipalProfile,
    pub(super) user_id: uuid::Uuid,
}

/// Register identity and credentials without publishing an enumerable profile.
/// The caller must assign ownership before making the profile visible to loaders.
#[allow(clippy::too_many_arguments)]
pub(super) async fn register_new_principal(
    kernel: &Arc<crate::Kernel>,
    principal: PrincipalId,
    profile_path: std::path::PathBuf,
    groups: Vec<String>,
    grants: Vec<String>,
    clone_from: Option<PrincipalId>,
    allow_admin_clone: bool,
) -> Result<RegisteredPrincipal, AdminResponseBody> {
    if let Err(error) = kernel
        .ownership_store
        .ensure_alias_available(&principal)
        .await
    {
        return Err(err_bad_input(format!(
            "principal alias `{principal}` is unavailable: {error}"
        )));
    }

    // Build the profile: a `clone_from` replica (validated + admin-guarded) or
    // a fresh profile from the supplied groups/grants. Runs under the lock so
    // the clone source is pinned across the read.
    let mut profile = match build_create_profile(
        kernel,
        &principal,
        groups,
        grants,
        clone_from.as_ref(),
        allow_admin_clone,
    ) {
        Ok(p) => p,
        Err(resp) => return Err(resp),
    };

    // Mint a per-principal ed25519 keypair so this principal can authenticate
    // its local socket connections (issue #45/#852): the private key lands in
    // system custody under `keys/` (NOT the principal home — the agent sandbox
    // denies it, but the operator/OS-user CLI can read it to sign), and the
    // public key + the `Keypair` auth method are registered on the profile so
    // the handshake can verify a signature against it.
    let initial_public_key = match mint_principal_keypair(kernel, &principal, &mut profile) {
        Ok(public_key) => public_key,
        Err(resp) => return Err(resp),
    };

    if let Err(e) = profile.validate() {
        remove_principal_key(kernel, &principal);
        return Err(err_bad_input(format!("profile rejected: {e}")));
    }

    let user = match kernel
        .identity_store
        .create_principal(principal.clone(), initial_public_key)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            remove_principal_key(kernel, &principal);
            return Err(err_internal(format!(
                "identity store create_user failed: {e}"
            )));
        },
    };
    if let Err(e) = kernel
        .identity_store
        .link(
            AGENT_IDENTITY_PLATFORM,
            principal.as_str(),
            user.id,
            "system",
        )
        .await
    {
        rollback_created_identity(kernel, &principal, user.id, &profile_path, false).await;
        return Err(err_internal(format!("identity store link failed: {e}")));
    }

    Ok(RegisteredPrincipal {
        profile,
        user_id: user.id,
    })
}
