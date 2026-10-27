//! Serialize fresh capsule publication with the existing runtime view locks.

use astrid_capsule_types::CapsuleId;
use astrid_core::principal::PrincipalId;

/// The caller holds the admin write lock. Only target views are locked, in a
/// canonical order shared by create and derive; unrelated principals and the
/// source remain free to load. Drop these before this task's own readiness
/// check, or transfer them into rollback until retirement closes admission.
pub(super) async fn lock_initializing_capsules(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
    capsules: &[String],
) -> Result<Vec<crate::CapsuleViewGuard>, String> {
    let mut ids = capsules
        .iter()
        .map(|name| {
            CapsuleId::new(name.clone())
                .map_err(|error| format!("invalid initializing capsule '{name}': {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
    ids.dedup();
    let mut views = Vec::with_capacity(ids.len());
    for id in ids {
        views.push(kernel.lock_capsule_view(principal, &id).await);
    }
    Ok(views)
}
