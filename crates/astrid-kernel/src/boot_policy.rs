//! One captured-home configuration snapshot after native admission.
use std::path::Path;

/// Load one complete boot policy snapshot from the captured runtime home and workspace.
///
/// A workspace can tighten host-call admission, so an unreadable merged policy
/// must stop boot rather than discard either the operator or workspace layer.
pub(crate) fn load_config(
    home: &astrid_core::dirs::AstridHome,
    workspace_root: &Path,
    workspace_layout: &astrid_core::dirs::WorkspaceLayout,
) -> std::io::Result<astrid_config::Config> {
    astrid_config::Config::load_with_home_and_layout(
        Some(workspace_root),
        home.root(),
        workspace_layout,
    )
    .map(|resolved| resolved.config)
    .map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "cannot load boot policy from runtime home {}: {error}",
                home.root().display()
            ),
        )
    })
}
