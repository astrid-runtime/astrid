//! Resolve mount lease authority and its immutable storage target.

use super::{
    FilesystemPath, Kernel, PrincipalId, StateOwner, StorageFilesystemTargetV1,
    StorageProviderViewV1, WorkspaceBranchStore,
};

#[derive(Clone, Copy)]
pub(super) enum LeaseAuthority {
    Management { allow_cross_owner: bool },
    Process(astrid_core::PrincipalUid),
}

pub(super) async fn resolve_owner(
    kernel: &Kernel,
    caller: &PrincipalId,
    authority: LeaseAuthority,
    view: &StorageProviderViewV1,
    target: StorageFilesystemTargetV1,
) -> Result<(StateOwner, StorageFilesystemTargetV1), String> {
    let allow_cross_owner = matches!(
        authority,
        LeaseAuthority::Management {
            allow_cross_owner: true
        }
    );
    let caller_uid = || {
        let observed = kernel
            .principal_directory
            .uid_for(caller)
            .map_err(|error| error.to_string())?;
        match authority {
            LeaseAuthority::Process(expected) if expected != observed => {
                Err("process projection owner changed".to_owned())
            },
            _ => Ok(observed),
        }
    };
    let owner = match view {
        StorageProviderViewV1::Principal(principal) => {
            if principal != caller && !allow_cross_owner {
                return Err("principal filesystem view belongs to another principal".to_owned());
            }
            if principal == caller {
                StateOwner::Principal(caller_uid()?)
            } else {
                kernel
                    .principal_directory
                    .uid_for(principal)
                    .map(StateOwner::Principal)
                    .map_err(|error| {
                        format!(
                            "principal `{principal}` has no immutable storage identity: {error}"
                        )
                    })?
            }
        },
        StorageProviderViewV1::Fleet(fleet) => {
            if !allow_cross_owner {
                let caller_uid = caller_uid()?;
                let ownership = kernel
                    .ownership_store()
                    .load()
                    .await
                    .map_err(|error| format!("read fleet ownership graph: {error}"))?;
                let admitted = ownership
                    .principal_owner(caller_uid)
                    .is_some_and(|owner| owner.fleet_uid == *fleet);
                if !admitted {
                    return Err(
                        "requested fleet filesystem is outside the caller's fleet".to_owned()
                    );
                }
            }
            StateOwner::Fleet(*fleet)
        },
        StorageProviderViewV1::Admin => {
            if !allow_cross_owner {
                return Err("system filesystem view requires global storage authority".to_owned());
            }
            StateOwner::System
        },
    };

    if let StorageFilesystemTargetV1::WorkspaceBranch { workspace } = &target {
        let store = kernel
            .principal_store
            .clone()
            .ok_or_else(|| "native principal store is unavailable".to_owned())?;
        let branches = WorkspaceBranchStore::new(store.content());
        let descriptor = branches
            .describe(&owner, *workspace)
            .map_err(|error| format!("resolve workspace branch: {error}"))?;
        // A caller-scoped branch lease may only target the branch that the
        // kernel's durable workspace binding assigned to that immutable UID.
        // Fleet membership authorizes the shared base owner, not another
        // principal's divergent branch. Global storage authority may inspect
        // an explicitly selected branch through the administrative path.
        if !allow_cross_owner {
            let caller_uid = caller_uid()?;
            if descriptor.binding_uid() != Some(caller_uid) {
                return Err(
                    "workspace branch is not bound to the authenticated principal".to_owned(),
                );
            }
        }
    }
    if let StorageFilesystemTargetV1::OwnerSubtree { prefix } = &target {
        if prefix != "home" && prefix != "shared" {
            return Err("owner subtree prefix is not a kernel-admitted attachment".to_owned());
        }
        if prefix == "home" && !matches!(owner, StateOwner::Principal(_)) {
            return Err("principal HOME must resolve to the principal owner".to_owned());
        }
        if prefix == "shared" && !matches!(owner, StateOwner::Fleet(_)) {
            return Err("Fleet shared attachment requires a Fleet owner".to_owned());
        }
        FilesystemPath::new(prefix.clone())
            .map_err(|error| format!("resolve owner subtree prefix: {error}"))?;
    }

    Ok((owner, target))
}
