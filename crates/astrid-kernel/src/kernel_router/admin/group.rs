//! Layer 6 group admin handlers (issue #672).
//!
//! Split out of [`super::handlers`] to keep that file under the repo's
//! per-file line cap. These handlers share the same enforcement-preamble
//! contract and helper surface as the rest of the admin handlers — the
//! shared helpers live in [`super::handlers`] and are re-used here via
//! `pub(super)`.

use std::sync::Arc;

use astrid_core::groups::{Group, GroupConfig};
use astrid_events::kernel_api::{AdminResponseBody, GroupSummary};

use super::handlers::{err_bad_input, err_internal, success_json};

pub(super) async fn group_create(
    kernel: &Arc<crate::Kernel>,
    name: String,
    capabilities: Vec<String>,
    description: Option<String>,
    unsafe_admin: bool,
) -> AdminResponseBody {
    let group = Group {
        capabilities,
        description,
        unsafe_admin,
    };
    let _guard = kernel.admin_write_lock.lock().await;
    let current = kernel.groups.load_full();
    let next = match current.insert_custom_group(name, group) {
        Ok(n) => n,
        Err(e) => return err_bad_input(format!("group.create rejected: {e}")),
    };
    commit_group_config(kernel, next)
}

pub(super) async fn group_delete(kernel: &Arc<crate::Kernel>, name: String) -> AdminResponseBody {
    let _guard = kernel.admin_write_lock.lock().await;
    let current = kernel.groups.load_full();
    let next = match current.remove_group(&name) {
        Ok(n) => n,
        Err(e) => return err_bad_input(format!("group.delete rejected: {e}")),
    };
    commit_group_config(kernel, next)
}

// `Option<Option<String>>` intentionally encodes three states: `None` =
// keep existing description, `Some(None)` = clear it, `Some(Some(v))` =
// replace with `v`. Collapsing to a single `Option` would conflate "no
// change" with "clear" at the wire format. Clippy's `option_option` lint
// is overly cautious for partial-update APIs.
#[allow(clippy::option_option)]
pub(super) async fn group_modify(
    kernel: &Arc<crate::Kernel>,
    name: String,
    capabilities: Option<Vec<String>>,
    description: Option<Option<String>>,
    unsafe_admin: Option<bool>,
) -> AdminResponseBody {
    let _guard = kernel.admin_write_lock.lock().await;
    let current = kernel.groups.load_full();
    let next = match current.modify_custom_group(&name, capabilities, description, unsafe_admin) {
        Ok(n) => n,
        Err(e) => return err_bad_input(format!("group.modify rejected: {e}")),
    };
    commit_group_config(kernel, next)
}

pub(super) fn group_list(kernel: &Arc<crate::Kernel>) -> AdminResponseBody {
    let cfg = kernel.groups.load_full();
    let mut summaries: Vec<GroupSummary> = cfg
        .iter()
        .map(|(name, group)| GroupSummary {
            name: name.clone(),
            capabilities: group.capabilities.clone(),
            description: group.description.clone(),
            unsafe_admin: group.unsafe_admin,
            builtin: GroupConfig::is_builtin_name(name),
        })
        .collect();
    summaries.sort_by(|a, b| a.name.cmp(&b.name));
    AdminResponseBody::GroupList(summaries)
}

/// Commit a new [`GroupConfig`] to disk and the
/// [`ArcSwap`](arc_swap::ArcSwap). Caller must hold the admin write lock.
fn commit_group_config(kernel: &Arc<crate::Kernel>, next: GroupConfig) -> AdminResponseBody {
    let path = GroupConfig::path_for(&kernel.astrid_home);
    if let Err(e) = next.save_to_path(&path) {
        return err_internal(format!("groups.toml save failed: {e}"));
    }
    kernel.groups.store(Arc::new(next));
    success_json(serde_json::json!({ "status": "ok" }))
}
