//! Human-scoped discovery. A returned row is not permission to act as it.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_events::kernel_api::{AdminResponseBody, AgentSummary};

use super::{err_bad_input, err_internal, success_json};
use crate::{Kernel, kernel_router::AuthorizedRequest};

#[cfg(test)]
mod tests;

pub(super) async fn list(
    kernel: &Arc<Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    device_key_id: Option<&str>,
) -> AdminResponseBody {
    // Discovery is a read of current assignments. It must not adopt leftovers
    // or otherwise mutate the ownership graph.
    let key = match authorization {
        Some(authority) => authority.authenticated_public_key,
        None => match super::super::super::authorize_request(
            kernel,
            caller,
            device_key_id,
            "self:agent:list",
        ) {
            Ok(authority) => authority.authenticated_public_key,
            Err(error) => return err_bad_input(error.to_string()),
        },
    };
    let Some(key) = key else {
        return err_bad_input("principal discovery requires a user-delegated device".into());
    };
    let caller_uid = match kernel.principal_directory.uid_for(caller) {
        Ok(uid) => uid,
        Err(error) => return err_internal(error.to_string()),
    };
    let graph = match kernel.ownership_store.load().await {
        Ok(graph) => graph,
        Err(error) => return err_internal(error.to_string()),
    };
    let Some(user) = graph.user_for_device(caller_uid, &key) else {
        return err_bad_input("principal discovery requires current user delegation".into());
    };
    let visible: std::collections::BTreeSet<_> = graph
        .principal_owners_for_user(user)
        .map(|owner| owner.principal_uid)
        .collect();
    let mut summaries = Vec::new();
    // Filter authoritative identities before reading profiles: no global
    // roster is returned for the client to filter, even for an administrator.
    for (principal, uid) in kernel.principal_directory.bindings() {
        if !visible.contains(&uid) {
            continue;
        }
        let profile = match kernel.profile_cache.resolve(&principal) {
            Ok(profile) => profile,
            Err(error) => {
                return err_internal(format!("owned principal profile unavailable: {error}"));
            },
        };
        summaries.push(AgentSummary {
            owner_uid: Some(uid),
            principal,
            enabled: profile.enabled,
            groups: profile.groups.clone(),
            grants: profile.grants.clone(),
            revokes: profile.revokes.clone(),
        });
    }
    summaries.sort_by(|a, b| a.principal.as_str().cmp(b.principal.as_str()));
    AdminResponseBody::AgentList(summaries)
}

pub(super) async fn claim(
    kernel: &Arc<Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    device_key_id: Option<&str>,
    principal: PrincipalId,
) -> AdminResponseBody {
    let authority = match super::creation_authority::CreationAuthority::resolve(
        kernel,
        caller,
        authorization,
        device_key_id,
    )
    .await
    {
        Ok(authority) => authority,
        Err(error) => return error,
    };
    let _guard = kernel.admin_write_lock.lock().await;
    if kernel.principal_directory.uid_for(&principal).is_err() {
        return err_bad_input(format!("principal {principal} is not an admitted identity"));
    }
    match authority.assign(kernel, &principal).await {
        Ok(()) => success_json(serde_json::json!({
            "principal": principal.as_str(),
        })),
        Err(error) => error,
    }
}
