//! Resolve mount lease authority and its immutable storage target.

pub(super) mod callback;
pub(super) mod worker;
mod requester;
pub(super) mod reservation;
pub(super) mod subtree;
pub(super) use requester::same_requester;
use subtree::{BoundSubtree, Owner, Subtree};

use super::{
    Kernel, PrincipalId, StateOwner, StorageFilesystemTargetV1, StorageProviderViewV1,
    WorkspaceBranchStore,
};

/// Internal destinations can only designate a subtree admitted at issue time.
#[derive(Clone, Copy)]
pub(super) enum LeaseTarget {
    OwnerRoot(StateOwner),
    WorkspaceBranch(StateOwner, astrid_core::WorkspaceUid),
    Subtree(BoundSubtree<astrid_core::PrincipalUid, astrid_core::FleetUid>),
}

impl LeaseTarget {
    pub(super) fn wire(self) -> StorageFilesystemTargetV1 {
        match self {
            Self::OwnerRoot(_) => StorageFilesystemTargetV1::OwnerRoot,
            Self::WorkspaceBranch(_, workspace) => {
                StorageFilesystemTargetV1::WorkspaceBranch { workspace }
            },
            Self::Subtree(subtree) => StorageFilesystemTargetV1::OwnerSubtree {
                prefix: match subtree {
                    BoundSubtree::PrincipalHome(_) => Subtree::PrincipalHome,
                    BoundSubtree::FleetShared(_) => Subtree::FleetShared,
                }
                .prefix()
                .to_owned(),
            },
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum LeaseAuthority {
    Management { allow_cross_owner: bool },
    Process(astrid_core::PrincipalUid),
}

impl LeaseAuthority {
    pub(super) fn requester(
        self,
        kernel: &Kernel,
        caller: &PrincipalId,
    ) -> Result<(Option<astrid_core::PrincipalUid>, bool), String> {
        match self {
            Self::Process(uid) => kernel
                .principal_directory
                .bound_uid(caller, Some(uid))
                .map(|bound| (Some(bound), false))
                .map_err(|_| "process projection owner changed".to_owned()),
            Self::Management { allow_cross_owner } => {
                match kernel.principal_directory.uid_for(caller) {
                    Ok(uid) => Ok((Some(uid), allow_cross_owner)),
                    Err(_) if allow_cross_owner => Ok((None, true)),
                    Err(error) => Err(format!("resolve storage lease requester: {error}")),
                }
            },
        }
    }
}

pub(super) async fn resolve_owner(
    kernel: &Kernel,
    caller: &PrincipalId,
    requester_uid: Option<astrid_core::PrincipalUid>,
    allow_cross_owner: bool,
    view: &StorageProviderViewV1,
    target: StorageFilesystemTargetV1,
) -> Result<LeaseTarget, String> {
    let caller_uid = || {
        requester_uid
            .ok_or_else(|| format!("principal `{caller}` has no immutable storage identity"))
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
    let target = match target {
        StorageFilesystemTargetV1::OwnerRoot => LeaseTarget::OwnerRoot(owner),
        StorageFilesystemTargetV1::WorkspaceBranch { workspace } => {
            LeaseTarget::WorkspaceBranch(owner, workspace)
        },
        StorageFilesystemTargetV1::OwnerSubtree { prefix } => {
            let subtree = Subtree::parse(&prefix).ok_or_else(|| {
                "owner subtree prefix is not a kernel-admitted attachment".to_owned()
            })?;
            let bound_owner = match owner {
                StateOwner::System => Owner::System,
                StateOwner::Principal(uid) => Owner::Principal(uid),
                StateOwner::Fleet(uid) => Owner::Fleet(uid),
            };
            LeaseTarget::Subtree(subtree.bind(bound_owner).ok_or_else(|| match subtree {
                Subtree::PrincipalHome => {
                    "principal HOME must resolve to the principal owner".to_owned()
                },
                Subtree::FleetShared => "Fleet shared attachment requires a Fleet owner".to_owned(),
            })?)
        },
    };
    Ok(target)
}
