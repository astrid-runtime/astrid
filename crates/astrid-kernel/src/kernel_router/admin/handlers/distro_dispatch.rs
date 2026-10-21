//! Dispatch for the Distro provenance admin family.

use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

use crate::Kernel;

/// Handle one already-authorized Distro request, if this module owns it.
pub(super) async fn dispatch(
    kernel: &Arc<Kernel>,
    caller: &PrincipalId,
    req: &AdminRequestKind,
) -> Option<AdminResponseBody> {
    match req {
        AdminRequestKind::DistroLockGet { principal } => {
            Some(super::super::distro_handlers::get(kernel, principal).await)
        },
        AdminRequestKind::DistroLockSet {
            principal,
            lock,
            expected_hash,
        } => Some(
            super::super::distro_handlers::set(
                kernel,
                principal,
                lock.clone(),
                expected_hash.clone(),
            )
            .await,
        ),
        AdminRequestKind::DistroSelfGrant => {
            Some(super::super::distro_handlers::self_grant(kernel, caller).await)
        },
        _ => None,
    }
}
