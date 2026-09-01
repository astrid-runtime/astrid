//! Typed identity and targets for process storage projections.
//!
//! These types stay kernel-internal. A mutable principal alias never enters a
//! projection key; the acting UID, durable owner, kernel generation, and full
//! target set must match before a cached provider pair can be reused.

use std::sync::Arc;

use astrid_core::{FleetUid, PrincipalUid, WorkspaceUid};
use astrid_storage::StateOwner;

use super::process_identity::parent_start_identity;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProjectionGeneration {
    pub(crate) parent_pid: u32,
    pub(crate) start_identity: Arc<str>,
}

impl ProjectionGeneration {
    pub(crate) fn capture() -> Result<Self, String> {
        let parent_pid = std::process::id();
        let start_identity = Arc::from(
            parent_start_identity(parent_pid)
                .ok_or_else(|| {
                    "resolve process creation identity for provider lifetime".to_owned()
                })?
                .as_str(),
        );
        Ok(Self {
            parent_pid,
            start_identity,
        })
    }
}

/// Honest logical namespace for one mountable process projection target.
///
/// There is no `UserHome` variant. Runtime admission rejects `StateOwner::User`
/// before a target can be converted, so a user-private root cannot be silently
/// substituted with a principal view.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ProcessProjectionTarget {
    AgentHome(PrincipalUid),
    WorkspaceBranch {
        owner: StateOwner,
        workspace: WorkspaceUid,
    },
    FleetShared(FleetUid),
}

impl ProcessProjectionTarget {
    pub(crate) fn durable_owner(&self) -> StateOwner {
        match self {
            Self::AgentHome(uid) => StateOwner::Principal(*uid),
            Self::WorkspaceBranch { owner, .. } => *owner,
            Self::FleetShared(uid) => StateOwner::Fleet(*uid),
        }
    }

    pub(crate) fn durable_target(
        &self,
    ) -> astrid_core::storage_filesystem::StorageFilesystemTargetV1 {
        use astrid_core::storage_filesystem::StorageFilesystemTargetV1;

        match self {
            Self::AgentHome(_) => StorageFilesystemTargetV1::OwnerSubtree {
                prefix: "home".to_owned(),
            },
            Self::WorkspaceBranch { workspace, .. } => StorageFilesystemTargetV1::WorkspaceBranch {
                workspace: *workspace,
            },
            Self::FleetShared(_) => StorageFilesystemTargetV1::OwnerSubtree {
                prefix: "shared".to_owned(),
            },
        }
    }
}

/// The complete target set fixed when a projection is admitted.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProcessProjectionTargetSet {
    pub(crate) workspace: ProcessProjectionTarget,
    pub(crate) owner_home: ProcessProjectionTarget,
    pub(crate) fleet_shared: Option<ProcessProjectionTarget>,
}

impl ProcessProjectionTargetSet {
    pub(crate) fn branch(
        owner: StateOwner,
        acting_uid: PrincipalUid,
        workspace: WorkspaceUid,
        fleet_shared: Option<FleetUid>,
    ) -> Result<Self, String> {
        let fleet_shared = match (owner, fleet_shared) {
            (StateOwner::Principal(_), None) => None,
            (StateOwner::Fleet(fleet_uid), Some(shared_uid)) if shared_uid == fleet_uid => {
                Some(ProcessProjectionTarget::FleetShared(shared_uid))
            },
            (StateOwner::System | StateOwner::User(_), _) => {
                return Err("owner is not process-mountable".to_owned());
            },
            (StateOwner::Fleet(_), None) => {
                return Err("Fleet workspace requires its Fleet shared target".to_owned());
            },
            (_, Some(_)) => {
                return Err("principal workspace cannot include Fleet shared storage".to_owned());
            },
        };
        Ok(Self {
            workspace: ProcessProjectionTarget::WorkspaceBranch { owner, workspace },
            owner_home: ProcessProjectionTarget::AgentHome(acting_uid),
            fleet_shared,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        let workspace_owner = self.workspace.durable_owner();
        if !matches!(
            workspace_owner,
            StateOwner::Principal(_) | StateOwner::Fleet(_)
        ) {
            return Err("workspace branch owner is not process-mountable".to_owned());
        }
        if let Some(shared) = &self.fleet_shared {
            if shared.durable_owner() != workspace_owner {
                return Err("Fleet shared target does not match the workspace owner".to_owned());
            }
        } else if matches!(workspace_owner, StateOwner::Fleet(_)) {
            return Err("Fleet workspace must include the Fleet shared target".to_owned());
        }
        let ProcessProjectionTarget::AgentHome(acting_uid) = &self.owner_home else {
            return Err("process owner target must be an agent-private HOME".to_owned());
        };
        match self.workspace {
            ProcessProjectionTarget::WorkspaceBranch { .. } => {},
            _ => return Err("process workspace target must be a workspace branch".to_owned()),
        }
        if matches!(workspace_owner, StateOwner::Principal(_)) && self.fleet_shared.is_some() {
            return Err("principal workspace must not include Fleet shared storage".to_owned());
        }
        let _ = acting_uid;
        Ok(())
    }
}

/// Kernel-internal projection admission identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProcessProjectionBinding {
    pub(crate) owner: StateOwner,
    pub(crate) acting_uid: PrincipalUid,
    pub(crate) generation: ProjectionGeneration,
    pub(crate) targets: ProcessProjectionTargetSet,
}

impl ProcessProjectionBinding {
    pub(crate) fn new(
        owner: StateOwner,
        acting_uid: PrincipalUid,
        generation: ProjectionGeneration,
        targets: ProcessProjectionTargetSet,
    ) -> Result<Self, String> {
        let binding = Self {
            owner,
            acting_uid,
            generation,
            targets,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        match self.owner {
            StateOwner::Principal(_) | StateOwner::Fleet(_) => {},
            StateOwner::System => return Err("system owner is not process-mountable".to_owned()),
            StateOwner::User(_) => {
                return Err("user owner is not process-mountable".to_owned());
            },
        }
        let ProcessProjectionTarget::WorkspaceBranch {
            owner: target_owner,
            ..
        } = &self.targets.workspace
        else {
            return Err("process binding must target a workspace branch".to_owned());
        };
        if *target_owner != self.owner {
            return Err("workspace branch owner does not match projection owner".to_owned());
        }
        let ProcessProjectionTarget::AgentHome(home_uid) = &self.targets.owner_home else {
            return Err("process HOME target is not agent-private".to_owned());
        };
        if *home_uid != self.acting_uid {
            return Err("agent HOME target does not match the acting principal".to_owned());
        }
        self.targets.validate()
    }
}
