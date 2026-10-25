//! One home-bound configuration snapshot for kernel construction.

use std::path::Path;

use astrid_core::dirs::{AstridHome, WorkspaceLayout};

pub(crate) fn load(
    home: &AstridHome,
    workspace: &Path,
    layout: &WorkspaceLayout,
) -> std::io::Result<astrid_config::ResolvedConfig> {
    astrid_config::Config::load_with_home_and_layout(Some(workspace), home.root(), layout)
        .map_err(|error| std::io::Error::other(format!("load admitted-home boot policy: {error}")))
}
