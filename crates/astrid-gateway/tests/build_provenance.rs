#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .expect("fixture Git command");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn linked_worktree_tracks_its_head_and_common_branch_ref() {
    let fixture = tempfile::tempdir().unwrap();
    let canonical_root = fixture.path().canonicalize().unwrap();
    let root = canonical_root.as_path();
    git(root, &["init", "--initial-branch=main"]);
    git(
        root,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "--no-gpg-sign",
            "-m",
            "fixture",
        ],
    );
    let linked = root.join("linked");
    git(
        root,
        &[
            "worktree",
            "add",
            "-b",
            "candidate",
            linked.to_str().unwrap(),
        ],
    );
    let paths = build_script::git_dependency_paths(&linked);
    assert_eq!(paths[0], root.join(".git/worktrees/linked/HEAD"));
    assert!(paths.contains(&root.join(".git/refs/heads/candidate")));
    assert!(paths.contains(&root.join(".git/packed-refs")));
    git(root, &["pack-refs", "--all"]);
    assert_eq!(build_script::git_dependency_paths(&linked), paths);
    git(&linked, &["checkout", "--detach"]);
    assert_eq!(
        build_script::git_dependency_paths(&linked),
        vec![paths[0].clone()]
    );
}

#[test]
fn source_archive_has_no_git_dependencies() {
    let fixture = tempfile::tempdir().unwrap();
    assert!(build_script::git_dependency_paths(fixture.path()).is_empty());
}

#[test]
#[ignore = "runs nested Cargo builds against a disposable linked worktree"]
fn source_identical_commit_rebuilds_emitted_provenance() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = 'astrid-build-provenance-fixture'\nversion = '0.0.0'\nedition = '2024'\n[workspace]\n",
    ).unwrap();
    std::fs::write(root.join("build.rs"), include_str!("../build.rs")).unwrap();
    std::fs::write(root.join("src/main.rs"),
        "fn main() { println!(\"astrid_build_info{{git_sha=\\\"{}\\\"}} 1\", env!(\"ASTRID_GIT_SHA\")); }\n",
    ).unwrap();
    git(&root, &["init", "--initial-branch=main"]);
    git(&root, &["add", "."]);
    let commit = [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--allow-empty",
        "--no-gpg-sign",
        "-m",
        "fixture",
    ];
    git(&root, &commit);
    let linked = root.join("linked");
    git(
        &root,
        &[
            "worktree",
            "add",
            "-b",
            "candidate",
            linked.to_str().unwrap(),
        ],
    );
    let rendered = || {
        let output = Command::new("cargo")
            .current_dir(&linked)
            .args(["run", "--quiet", "--offline"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    let before = rendered();
    git(&linked, &commit);
    let after = rendered();
    assert_ne!(
        before, after,
        "source-identical commit must refresh provenance"
    );
    let head = Command::new("git")
        .current_dir(&linked)
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .unwrap();
    assert!(after.contains(String::from_utf8(head.stdout).unwrap().trim()));
    git(&root, &["pack-refs", "--all"]);
    assert_eq!(rendered(), after);
}
