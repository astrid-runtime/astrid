//! Trusted alias-to-UID binding captured before capability evaluation.

use std::sync::Arc;

use astrid_capabilities::{CapabilityCheck, PermissionError};
use astrid_core::groups::GroupConfig;
use astrid_core::profile::{DeviceScope, PrincipalProfile};
use astrid_core::{PrincipalUid, principal::PrincipalId};
use tracing::warn;

use super::device_scope::resolve_device_scope;

const REQUIRED_PRINCIPAL_IDENTITY: &str = "principal:identity";

/// Trusted caller alias plus the immutable UID bound before policy lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizedPrincipal {
    pub(crate) alias: PrincipalId,
    pub(crate) uid: PrincipalUid,
}

impl AuthorizedPrincipal {
    pub(crate) fn bound(alias: PrincipalId, uid: PrincipalUid) -> Self {
        Self { alias, uid }
    }

    pub(crate) fn bind(
        kernel: &crate::Kernel,
        alias: &PrincipalId,
    ) -> Result<Self, PermissionError> {
        match kernel.principal_directory.uid_for(alias) {
            Ok(uid) => Ok(Self::bound(alias.clone(), uid)),
            Err(error) => {
                warn!(
                    security_event = true,
                    principal = %alias,
                    error = %error,
                    "Admin identity bind failed — fail-closed deny"
                );
                Err(PermissionError::MissingCapability {
                    principal: alias.clone(),
                    required: REQUIRED_PRINCIPAL_IDENTITY.to_owned(),
                })
            },
        }
    }

    pub(crate) fn confirm_live(&self, kernel: &crate::Kernel) -> Result<(), PermissionError> {
        match kernel.principal_directory.uid_for(&self.alias) {
            Ok(uid) if uid == self.uid => Ok(()),
            Ok(_) | Err(_) => {
                warn!(
                    security_event = true,
                    principal = %self.alias,
                    "Authorized principal identity drifted — fail-closed deny"
                );
                Err(PermissionError::MissingCapability {
                    principal: self.alias.clone(),
                    required: REQUIRED_PRINCIPAL_IDENTITY.to_owned(),
                })
            },
        }
    }
}

/// Authorization inputs pinned at the request's policy decision point.
#[derive(Debug)]
pub(crate) struct AuthorizedRequest {
    pub(crate) principal: PrincipalId,
    pub(crate) identity: Option<AuthorizedPrincipal>,
    pub(crate) profile: Arc<PrincipalProfile>,
    pub(crate) groups: Arc<GroupConfig>,
    pub(crate) device_scope: Option<DeviceScope>,
}

impl AuthorizedRequest {
    #[cfg(test)]
    pub(crate) fn principal_uid(&self) -> Option<PrincipalUid> {
        self.identity.as_ref().map(|identity| identity.uid)
    }

    pub(crate) fn capability_check(&self) -> CapabilityCheck<'_> {
        let check = CapabilityCheck::new(
            self.profile.as_ref(),
            self.groups.as_ref(),
            self.principal.clone(),
        );
        match &self.device_scope {
            Some(scope) => check.with_device_scope(scope),
            None => check,
        }
    }
}

/// Evaluate the capability check for `caller` against the kernel's resolved
/// group config and the caller's profile.
///
/// Returns the pinned authorization snapshot on success, or the policy reason
/// on denial. Profile resolution failures (malformed TOML, IO error) are
/// themselves treated as deny — fail-closed — with a synthesized
/// `MissingCapability` so the deny path has a single shape in the audit log.
pub(crate) fn authorize_request(
    kernel: &crate::Kernel,
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    required_cap: &str,
) -> Result<AuthorizedRequest, PermissionError> {
    authorize_request_with_identity(kernel, caller, device_key_id, required_cap, None)
}

/// Same capability gate as [`authorize_request`], using a UID bound *before*
/// profile lookup when `identity` is `Some`.
pub(crate) fn authorize_request_with_identity(
    kernel: &crate::Kernel,
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    required_cap: &str,
    identity: Option<AuthorizedPrincipal>,
) -> Result<AuthorizedRequest, PermissionError> {
    if let Some(identity) = &identity {
        identity.confirm_live(kernel)?;
        if identity.alias != *caller {
            return Err(PermissionError::MissingCapability {
                principal: caller.clone(),
                required: REQUIRED_PRINCIPAL_IDENTITY.to_owned(),
            });
        }
    }
    let profile = match kernel.profile_cache.resolve(caller) {
        Ok(profile) => profile,
        Err(error) => {
            warn!(
                security_event = true,
                principal = %caller,
                error = %error,
                "Profile resolution failed — fail-closed deny"
            );
            return Err(PermissionError::MissingCapability {
                principal: caller.clone(),
                required: required_cap.to_owned(),
            });
        },
    };
    // Enabled gate runs BEFORE the capability check so a disabled
    // principal cannot exercise any management API surface — even one
    // they would otherwise be authorized for. The `default` principal
    // is bootstrap-managed and `caps.revoke`/`agent.disable` against
    // it are rejected up front, so this check cannot lock the
    // single-tenant path.
    if !profile.enabled {
        warn!(
            security_event = true,
            principal = %caller,
            required = required_cap,
            "Disabled principal denied — fail-closed enforcement"
        );
        return Err(PermissionError::PrincipalDisabled {
            principal: caller.clone(),
        });
    }
    let groups = kernel.groups.load_full();

    let device_scope = resolve_device_scope(profile.as_ref(), caller, device_key_id, required_cap)?;

    let mut check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), caller.clone());
    if let Some(scope) = &device_scope {
        check = check.with_device_scope(scope);
    }
    check.require(required_cap)?;
    if let Some(identity) = &identity {
        identity.confirm_live(kernel)?;
        confirm_policy_still_holds(
            kernel,
            caller,
            required_cap,
            device_scope.as_ref(),
            identity,
        )?;
    }
    Ok(AuthorizedRequest {
        principal: caller.clone(),
        identity,
        profile,
        groups,
        device_scope,
    })
}

fn confirm_policy_still_holds(
    kernel: &crate::Kernel,
    caller: &PrincipalId,
    required_cap: &str,
    device_scope: Option<&DeviceScope>,
    identity: &AuthorizedPrincipal,
) -> Result<(), PermissionError> {
    identity.confirm_live(kernel)?;
    #[cfg(test)]
    confirm_policy_identity_gate::pause(kernel);
    let Ok(profile) = kernel.profile_cache.resolve(caller) else {
        return Err(PermissionError::MissingCapability {
            principal: caller.clone(),
            required: required_cap.to_owned(),
        });
    };
    if !profile.enabled {
        return Err(PermissionError::PrincipalDisabled {
            principal: caller.clone(),
        });
    }
    let groups = kernel.groups.load_full();
    let mut check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), caller.clone());
    if let Some(scope) = device_scope {
        check = check.with_device_scope(scope);
    }
    check.require(required_cap)?;
    identity.confirm_live(kernel)
}

pub(crate) async fn pause_authorize_identity_for_test(kernel: &Arc<crate::Kernel>) {
    #[cfg(test)]
    identity_gate::pause(kernel).await;
    #[cfg(not(test))]
    let _ = kernel;
}

#[cfg(test)]
pub(crate) use identity_gate::arm_authorize_identity_gate;

#[cfg(test)]
pub(crate) use confirm_policy_identity_gate::arm_confirm_policy_identity_gate;

#[cfg(test)]
mod identity_gate {
    use std::sync::{Arc, LazyLock};

    use dashmap::DashMap;

    pub(crate) struct IdentityGate {
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
    }

    impl IdentityGate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entered: tokio::sync::Semaphore::new(0),
                release: tokio::sync::Semaphore::new(0),
            })
        }
    }

    pub(crate) struct IdentityGateGuard {
        kernel: Arc<crate::Kernel>,
        gate: Arc<IdentityGate>,
    }

    impl IdentityGateGuard {
        pub(crate) fn gate(&self) -> &IdentityGate {
            &self.gate
        }
    }

    impl Drop for IdentityGateGuard {
        fn drop(&mut self) {
            self.gate.release.add_permits(1);
            GATES.remove(&kernel_key(&self.kernel));
        }
    }

    impl IdentityGate {
        pub(crate) async fn wait_until_entered(&self) {
            self.entered
                .acquire()
                .await
                .expect("identity gate entered")
                .forget();
        }

        pub(crate) fn release(&self) {
            self.release.add_permits(1);
        }
    }

    static GATES: LazyLock<DashMap<usize, Arc<IdentityGate>>> = LazyLock::new(DashMap::new);

    pub(crate) fn arm_authorize_identity_gate(kernel: &Arc<crate::Kernel>) -> IdentityGateGuard {
        let gate = IdentityGate::new();
        GATES.insert(kernel_key(kernel), Arc::clone(&gate));
        IdentityGateGuard {
            kernel: Arc::clone(kernel),
            gate,
        }
    }

    pub(super) async fn pause(kernel: &Arc<crate::Kernel>) {
        let gate = GATES
            .get(&kernel_key(kernel))
            .map(|entry| Arc::clone(entry.value()));
        if let Some(gate) = gate {
            gate.entered.add_permits(1);
            if let Ok(permit) = gate.release.acquire().await {
                permit.forget();
            }
        }
    }

    fn kernel_key(kernel: &crate::Kernel) -> usize {
        std::ptr::from_ref(kernel) as usize
    }
}

#[cfg(test)]
mod confirm_policy_identity_gate {
    use std::sync::{Arc, Condvar, LazyLock, Mutex};

    use dashmap::DashMap;

    struct GateState {
        entered: bool,
        released: bool,
    }

    pub(crate) struct ConfirmPolicyIdentityGate {
        state: Mutex<GateState>,
        changed: Condvar,
    }

    impl ConfirmPolicyIdentityGate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(GateState {
                    entered: false,
                    released: false,
                }),
                changed: Condvar::new(),
            })
        }

        fn pause(&self) {
            let mut state = self.state.lock().expect("confirm policy gate state");
            state.entered = true;
            self.changed.notify_all();
            while !state.released {
                state = self.changed.wait(state).expect("confirm policy gate wait");
            }
        }

        fn has_entered(&self) -> bool {
            self.state
                .lock()
                .expect("confirm policy gate state")
                .entered
        }

        pub(crate) async fn wait_until_entered(&self) {
            while !self.has_entered() {
                tokio::task::yield_now().await;
            }
        }

        pub(crate) fn release(&self) {
            let mut state = self.state.lock().expect("confirm policy gate state");
            state.released = true;
            self.changed.notify_all();
        }
    }

    pub(crate) struct ConfirmPolicyIdentityGateGuard {
        kernel: Arc<crate::Kernel>,
        gate: Arc<ConfirmPolicyIdentityGate>,
    }

    impl ConfirmPolicyIdentityGateGuard {
        pub(crate) fn gate(&self) -> &ConfirmPolicyIdentityGate {
            &self.gate
        }
    }

    impl Drop for ConfirmPolicyIdentityGateGuard {
        fn drop(&mut self) {
            self.gate.release();
            GATES.remove(&kernel_key(&self.kernel));
        }
    }

    static GATES: LazyLock<DashMap<usize, Arc<ConfirmPolicyIdentityGate>>> =
        LazyLock::new(DashMap::new);

    pub(crate) fn arm_confirm_policy_identity_gate(
        kernel: &Arc<crate::Kernel>,
    ) -> ConfirmPolicyIdentityGateGuard {
        let gate = ConfirmPolicyIdentityGate::new();
        GATES.insert(Arc::as_ptr(kernel) as usize, Arc::clone(&gate));
        ConfirmPolicyIdentityGateGuard {
            kernel: Arc::clone(kernel),
            gate,
        }
    }

    pub(super) fn pause(kernel: &crate::Kernel) {
        let gate = GATES
            .get(&kernel_key(kernel))
            .map(|entry| Arc::clone(entry.value()));
        if let Some(gate) = gate {
            gate.pause();
        }
    }

    fn kernel_key(kernel: &crate::Kernel) -> usize {
        std::ptr::from_ref(kernel) as usize
    }
}
