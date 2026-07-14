use std::sync::OnceLock;

use astrid_core::dirs::WorkspaceLayout;

static WORKSPACE_LAYOUT: OnceLock<WorkspaceLayout> = OnceLock::new();

pub(crate) fn initialize(layout: WorkspaceLayout) -> Result<(), WorkspaceLayout> {
    WORKSPACE_LAYOUT.set(layout)
}

pub(crate) fn current() -> &'static WorkspaceLayout {
    WORKSPACE_LAYOUT.get_or_init(WorkspaceLayout::default)
}
