use super::*;

fn tree() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    for agent in 0..128 {
        let nested = temp
            .path()
            .join(format!("projection/agents/{agent}/profile/keys"));
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("data"), b"already packed").unwrap();
    }
    temp
}

#[test]
fn packed_retirement_barriers_depend_on_surviving_parents_not_agent_count() {
    for durability in [
        RetirementDurability::EveryDirectory,
        RetirementDurability::ContainingDirectory,
    ] {
        let temp = tree();
        let projection = temp.path().join("projection");
        let mut barriers = Vec::new();
        let mut sync = |path: &Path| {
            barriers.push(path.to_path_buf());
            sync_directory(path)
        };
        if durability == RetirementDurability::ContainingDirectory {
            retire_packed_projection_tree_with_sync(&projection, &mut sync).unwrap();
        } else {
            retire_tree_root_with_durability(
                &projection,
                false,
                &mut |_| Ok(()),
                durability,
                &mut sync,
            )
            .unwrap();
        }
        assert!(!projection.exists());
        assert_eq!(barriers.last().unwrap(), temp.path());
        if durability == RetirementDurability::ContainingDirectory {
            assert_eq!(barriers, [temp.path()]);
        } else {
            assert!(barriers.len() > 128);
        }
    }
}

#[test]
fn packed_retirement_parent_barrier_failure_is_observable_and_root_retry_is_safe() {
    let temp = tree();
    std::fs::write(temp.path().join("astrid.volume"), b"durable authority").unwrap();
    let projection = temp.path().join("projection");
    let error = retire_tree_root_with_durability(
        &projection,
        false,
        &mut |_| Ok(()),
        RetirementDurability::ContainingDirectory,
        &mut |_| Err(io::Error::other("injected parent barrier failure")),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected parent barrier failure")
    );
    assert!(!projection.exists());
    crate::dirs::retire_packed_projection_root(temp.path()).unwrap();
    assert_eq!(
        std::fs::read(temp.path().join("astrid.volume")).unwrap(),
        b"durable authority"
    );
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn packed_retirement_rejects_redirect_before_removing_any_original_bytes() {
    let temp = tree();
    let outside = tempfile::tempdir().unwrap();
    let projection = temp.path().join("projection");
    std::os::unix::fs::symlink(outside.path(), projection.join("redirect")).unwrap();
    assert!(retire_packed_projection_tree(&projection).is_err());
    assert_eq!(
        std::fs::read(projection.join("agents/0/profile/keys/data")).unwrap(),
        b"already packed"
    );
}
