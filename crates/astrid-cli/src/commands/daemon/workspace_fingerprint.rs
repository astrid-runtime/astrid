//! Workspace identity checks for an already-running daemon.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use astrid_core::dirs::{
    AstridHome, DEFAULT_WORKSPACE_STATE_DIR, WorkspaceLayout,
    checked_workspace_selection_fingerprint,
};

/// Return the layouts a daemon rooted at `root` may have used.
///
/// A normal project has one identity: the layout selected by the CLI. The
/// Astrid home is special because the AOS product daemon uses `.aos` while the
/// Astrid CLI defaults to `.astrid`; both are valid identities for that one
/// runtime home. The returned layouts are ordered with the current CLI layout
/// first and contain no duplicates.
pub(crate) fn layouts_for_workspace_root(
    root: &Path,
    resolved_home: &AstridHome,
) -> Vec<WorkspaceLayout> {
    let current = crate::workspace_layout::current().clone();
    let mut layouts = vec![current];

    let root_is_runtime_home = std::fs::canonicalize(root)
        .ok()
        .zip(std::fs::canonicalize(resolved_home.root()).ok())
        .is_some_and(|(root, home)| root == home);
    if root_is_runtime_home {
        for layout in [
            WorkspaceLayout::new(".aos").expect("the built-in AOS layout is valid"),
            WorkspaceLayout::new(DEFAULT_WORKSPACE_STATE_DIR)
                .expect("the default workspace layout is valid"),
        ] {
            if !layouts.contains(&layout) {
                layouts.push(layout);
            }
        }
    }

    layouts
}

/// Compute all acceptable fingerprints for the selected daemon root.
pub(crate) fn expected_workspace_fingerprints(
    workspace_root: Option<&Path>,
) -> Result<Vec<String>> {
    let root = workspace_root.map_or_else(
        || std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        Path::to_path_buf,
    );
    let resolved_home = AstridHome::resolve().context("failed to resolve Astrid home")?;
    let mut fingerprints = Vec::new();
    for layout in layouts_for_workspace_root(&root, &resolved_home) {
        let fingerprint = checked_workspace_selection_fingerprint(&root, &layout)
            .context("selected workspace state path is unsafe")?;
        if !fingerprints.contains(&fingerprint) {
            fingerprints.push(fingerprint);
        }
    }
    Ok(fingerprints)
}

/// Validate the versioned readiness metadata emitted by the daemon.
pub(crate) fn validate_daemon_workspace_metadata(
    metadata: &str,
    expected: &[String],
) -> Result<()> {
    let Some(actual) = metadata.trim().strip_prefix("v1:") else {
        anyhow::bail!(
            "running daemon does not expose workspace selection metadata; run `astrid restart`"
        );
    };
    if !expected.iter().any(|fingerprint| fingerprint == actual) {
        anyhow::bail!(
            "running daemon belongs to another project or workspace layout; run `astrid restart` from this project"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_home_accepts_aos_fingerprint_for_default_cli_layout() {
        let home_root = tempfile::tempdir().expect("home root");
        let project_root = tempfile::tempdir().expect("project root");
        let resolved_home = AstridHome::from_path(home_root.path());
        let layouts = layouts_for_workspace_root(home_root.path(), &resolved_home);

        let names = layouts
            .iter()
            .map(WorkspaceLayout::state_dir_name)
            .collect::<Vec<_>>();
        assert!(names.contains(&".aos"));
        assert!(names.contains(&DEFAULT_WORKSPACE_STATE_DIR));
        assert_eq!(
            names.len(),
            names
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            "runtime-home layouts must be unique"
        );

        let aos = WorkspaceLayout::new(".aos").expect("AOS layout");
        let aos_fingerprint = checked_workspace_selection_fingerprint(home_root.path(), &aos)
            .expect("AOS fingerprint");
        let expected = layouts
            .iter()
            .map(|layout| {
                checked_workspace_selection_fingerprint(home_root.path(), layout)
                    .expect("runtime-home fingerprint")
            })
            .collect::<Vec<_>>();
        validate_daemon_workspace_metadata(&format!("v1:{aos_fingerprint}"), &expected)
            .expect("AOS daemon identity must attach from the runtime home");

        let project_fingerprint =
            checked_workspace_selection_fingerprint(project_root.path(), &aos)
                .expect("project fingerprint");
        assert!(
            !expected.contains(&project_fingerprint),
            "an unrelated project must not share the runtime-home identity"
        );
    }

    #[test]
    fn different_project_rejects_aos_fingerprint() {
        let home_root = tempfile::tempdir().expect("home root");
        let project_root = tempfile::tempdir().expect("project root");
        let resolved_home = AstridHome::from_path(home_root.path());
        let aos = WorkspaceLayout::new(".aos").expect("AOS layout");
        let daemon_fingerprint = checked_workspace_selection_fingerprint(home_root.path(), &aos)
            .expect("home AOS fingerprint");
        let expected = layouts_for_workspace_root(project_root.path(), &resolved_home)
            .into_iter()
            .map(|layout| {
                checked_workspace_selection_fingerprint(project_root.path(), &layout)
                    .expect("project fingerprint")
            })
            .collect::<Vec<_>>();

        assert!(
            validate_daemon_workspace_metadata(&format!("v1:{daemon_fingerprint}"), &expected)
                .is_err(),
            "the default CLI layout must reject a runtime-home AOS daemon in another project"
        );
    }
}
