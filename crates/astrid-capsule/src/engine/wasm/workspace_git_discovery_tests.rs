use super::workspace_is_git_managed;

fn init_git_worktree(root: &std::path::Path) {
    let git_dir = root.join(".git");
    std::fs::create_dir_all(git_dir.join("objects")).unwrap();
    std::fs::create_dir_all(git_dir.join("refs")).unwrap();
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
}

#[test]
#[cfg(unix)]
fn symlinked_workspace_follows_physical_git_target() {
    let root = tempfile::tempdir().unwrap();
    let lexical_parent = root.path().join("lexical-parent");
    let physical_workspace = root.path().join("physical").join("workspace");
    std::fs::create_dir_all(&lexical_parent).unwrap();
    std::fs::create_dir_all(&physical_workspace).unwrap();
    init_git_worktree(&lexical_parent);
    init_git_worktree(&physical_workspace);

    let workspace_link = lexical_parent.join("workspace-link");
    std::os::unix::fs::symlink(&physical_workspace, &workspace_link).unwrap();

    assert!(workspace_is_git_managed(&workspace_link));
    let (candidate, _) = gix_discover::upwards(&workspace_link).unwrap();
    let (git_dir, worktree) = candidate.into_repository_and_work_tree_directories();
    assert_eq!(git_dir, workspace_link.join(".git"));
    assert_eq!(worktree.as_deref(), Some(workspace_link.as_path()));
    assert_eq!(
        std::fs::canonicalize(git_dir).unwrap(),
        physical_workspace.join(".git").canonicalize().unwrap()
    );
}

#[test]
#[cfg(unix)]
fn symlink_to_non_git_target_is_not_git_managed() {
    let root = tempfile::tempdir().unwrap();
    let lexical_parent = root.path().join("lexical-parent");
    let physical_workspace = root.path().join("physical").join("workspace");
    std::fs::create_dir_all(&lexical_parent).unwrap();
    std::fs::create_dir_all(&physical_workspace).unwrap();
    init_git_worktree(&lexical_parent);

    let workspace_link = lexical_parent.join("workspace-link");
    std::os::unix::fs::symlink(&physical_workspace, &workspace_link).unwrap();

    assert!(!workspace_is_git_managed(&workspace_link));
}
