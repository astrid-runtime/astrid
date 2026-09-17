//! User delegation for principal creation, independent of clone source.

use std::sync::Arc;

use astrid_core::{PrincipalId, PrincipalUid};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

use super::{err_bad_input, err_internal, principal_profile_path, require_principal_exists};
use crate::{Kernel, kernel_router::AuthorizedRequest};

pub(in crate::kernel_router::admin) struct CreationAuthority {
    creator: PrincipalUid,
    public_key: [u8; 32],
}

impl CreationAuthority {
    pub(super) async fn resolve(
        kernel: &Kernel,
        caller: &PrincipalId,
        authorization: Option<&AuthorizedRequest>,
        device_key_id: Option<&str>,
    ) -> Result<Self, AdminResponseBody> {
        let key = if let Some(authorization) = authorization {
            authorization.authenticated_public_key
        } else {
            // Direct dispatch still requires current capability/device checks;
            // absence of a transport credential never implies a local user.
            super::super::super::authorize_request(kernel, caller, device_key_id, "agent:create")
                .map_err(|error| err_bad_input(error.to_string()))?
                .authenticated_public_key
        }
        .ok_or_else(|| {
            err_bad_input("principal creation requires a user-delegated device".to_owned())
        })?;
        let creator = kernel
            .principal_directory
            .uid_for(caller)
            .map_err(|error| err_internal(error.to_string()))?;
        let graph = kernel
            .ownership_store
            .load()
            .await
            .map_err(|error| err_internal(error.to_string()))?;
        let user = graph.user_for_device(creator, &key).ok_or_else(|| {
            err_bad_input("principal creation requires a current user delegation".to_owned())
        })?;
        let manager = graph
            .principal_owner(creator)
            .and_then(|owner| graph.fleet(owner.fleet_uid))
            .and_then(|fleet| fleet.membership(user))
            .is_some_and(|membership| membership.role.can_manage());
        if !manager {
            return Err(err_bad_input(
                "principal creation requires current fleet management authority".to_owned(),
            ));
        }
        Ok(Self {
            creator,
            public_key: key,
        })
    }

    pub(in crate::kernel_router::admin) async fn assign(
        &self,
        kernel: &Kernel,
        principal: &PrincipalId,
    ) -> Result<(), AdminResponseBody> {
        let created = kernel
            .principal_directory
            .uid_for(principal)
            .map_err(|error| err_internal(error.to_string()))?;
        kernel
            .ownership_store
            .assign_created_principal_for_device(created, self.creator, &self.public_key)
            .await
            .map_err(|error| {
                err_bad_input(format!("principal ownership assignment failed: {error}"))
            })
    }

    /// Keyless backfill may repair credentials, never mint into a foreign fleet.
    async fn authorize_existing_target(
        &self,
        kernel: &Kernel,
        principal: &PrincipalId,
    ) -> Result<(), AdminResponseBody> {
        let graph = kernel
            .ownership_store
            .load()
            .await
            .map_err(|error| err_internal(error.to_string()))?;
        let Ok(target) = kernel.principal_directory.uid_for(principal) else {
            return Ok(());
        };
        let Some(owner) = graph.principal_owner(target) else {
            return Ok(());
        };
        let creator_fleet = graph
            .principal_owner(self.creator)
            .map(|owner| owner.fleet_uid);
        if creator_fleet == Some(owner.fleet_uid) {
            return Ok(());
        }
        Err(err_bad_input(
            "cannot mint credentials for a principal owned by another fleet".to_owned(),
        ))
    }
}

/// Handle an [`AdminRequestKind::AgentCreate`]. Split from the dispatch match
/// arm to keep that router under the per-function line cap; the caller
/// guarantees the variant, so the fallback is unreachable in practice.
pub(super) async fn create_from_req(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    device_key_id: Option<&str>,
    req: AdminRequestKind,
) -> AdminResponseBody {
    let authority =
        match CreationAuthority::resolve(kernel, caller, authorization, device_key_id).await {
            Ok(authority) => authority,
            Err(response) => return response,
        };
    create_with_authority(kernel, req, &authority).await
}

async fn create_with_authority(
    kernel: &Arc<crate::Kernel>,
    req: AdminRequestKind,
    authority: &CreationAuthority,
) -> AdminResponseBody {
    let parsed = match parse_create_request(req) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let ParsedCreate {
        principal,
        groups,
        grants,
        inherit_from,
        clone_from,
        allow_admin_clone,
    } = parsed;

    // Acquire the admin write lock BEFORE validating the inheritance source.
    // The source's existence is state this lock protects: every admin mutator
    // (create/delete/...) takes it, so checking the source outside the lock
    // would let a concurrent delete remove it between the existence check and
    // the inheritance copy below (TOCTOU) — the creation would then silently
    // produce an empty agent instead of inheriting. Holding the lock pins the
    // source in place across the check-then-copy.
    let _guard = kernel.admin_write_lock.lock().await;

    // Self-inherit is meaningless (the source home tree does not exist yet),
    // and a non-existent source must fail loudly rather than silently
    // producing an empty agent the operator believes was provisioned.
    if let Some(ref source) = inherit_from {
        if *source == principal {
            return err_bad_input(format!(
                "inherit_from source {source} is the same as the new principal"
            ));
        }
        let source_path = principal_profile_path(kernel, source);
        if let Err(e) = require_principal_exists(source, &source_path) {
            return err_bad_input(format!("inherit_from source rejected: {e}"));
        }
    }

    let profile_path = principal_profile_path(kernel, &principal);

    // Collision: a profile on disk means this principal already exists. Rather
    // than unconditionally reject, defer to the keypair-backfill heal — a bare
    // re-create of an existing KEYLESS (pre-#45/#852) principal surgically adds
    // its missing keypair so `astrid-up`'s per-boot re-run auto-heals upgraders;
    // an already-keyed principal (or any shaping input) still errors. See
    // `agent_create_helpers::backfill_keypair` for the full rationale + invariants.
    if profile_path.exists() {
        // A backfill is not a re-create: any profile-shaping input (last arg)
        // keeps the hard "already exists" error rather than being silently
        // dropped. Foreign-fleet identities are not credential-repaired here.
        if let Err(response) = authority
            .authorize_existing_target(kernel, &principal)
            .await
        {
            return response;
        }
        let response = super::super::agent_create_helpers::backfill_keypair(
            kernel,
            &principal,
            &profile_path,
            clone_from.is_some()
                || inherit_from.is_some()
                || !groups.is_empty()
                || !grants.is_empty(),
        )
        .await;
        if matches!(response, AdminResponseBody::Error(_)) {
            return response;
        }
        if let Err(response) = authority.assign(kernel, &principal).await {
            return response;
        }
        return response;
    }

    // A genuinely new principal: build its profile, mint its keypair, register
    // its identity, and provision its home tree + state.
    super::super::agent_create_helpers::provision_new_principal(
        kernel,
        principal,
        profile_path,
        groups,
        grants,
        inherit_from,
        clone_from,
        allow_admin_clone,
        true,
        Some(authority),
    )
    .await
}

struct ParsedCreate {
    principal: PrincipalId,
    groups: Vec<String>,
    grants: Vec<String>,
    inherit_from: Option<PrincipalId>,
    clone_from: Option<PrincipalId>,
    allow_admin_clone: bool,
}

fn parse_create_request(req: AdminRequestKind) -> Result<ParsedCreate, AdminResponseBody> {
    let AdminRequestKind::AgentCreate {
        name,
        groups,
        grants,
        inherit_from,
        clone_from,
        allow_admin_clone,
    } = req
    else {
        return Err(err_internal(
            "create_from_req received a non-AgentCreate variant".to_string(),
        ));
    };
    let principal = match PrincipalId::new(name.clone()) {
        Ok(p) => p,
        Err(e) => return Err(err_bad_input(format!("invalid principal name: {e}"))),
    };

    // `default` (the bootstrap anchor) and `anonymous` (the no-capability
    // identity stamped on unauthenticated connections, #45/#852) are reserved.
    if let Some(reason) = principal.reserved_reason() {
        return Err(err_bad_input(format!("principal {name:?} is {reason}")));
    }

    // `clone_from` is a full replica: the source supplies groups, grants,
    // revokes, network, process, quotas, AND the state copy. Mixing it with
    // the profile-shaping inputs is ambiguous, so reject rather than silently
    // pick a winner. The CLI also enforces this via clap `conflicts_with`; the
    // kernel enforces it too — defense in depth against a hand-built request.
    if clone_from.is_some() && (inherit_from.is_some() || !groups.is_empty() || !grants.is_empty())
    {
        return Err(err_bad_input(
            "clone_from is mutually exclusive with inherit_from, groups, and grants".to_string(),
        ));
    }

    Ok(ParsedCreate {
        principal,
        groups,
        grants,
        inherit_from,
        clone_from,
        allow_admin_clone,
    })
}
