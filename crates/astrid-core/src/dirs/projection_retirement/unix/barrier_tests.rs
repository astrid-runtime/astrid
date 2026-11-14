use std::cell::RefCell;
use std::io;

use super::retire_with_io_hooks;

#[test]
fn nested_retirement_barriers_commit_only_root_namespace_removals() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    for directory in ["a/nested/deep", "b/nested"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
        std::fs::write(root.join(directory).join("file"), b"packed").unwrap();
    }
    std::fs::write(root.join("astrid.volume"), b"durable authority").unwrap();
    std::fs::write(root.join("z-file"), b"packed").unwrap();
    let events = RefCell::new(Vec::new());
    retire_with_io_hooks(
        root,
        || Ok(()),
        |path| {
            events.borrow_mut().push(format!(
                "unlink:{}",
                path.strip_prefix(root).unwrap().display()
            ));
            Ok(())
        },
        |directory, path| {
            events.borrow_mut().push(format!(
                "sync:{}",
                path.strip_prefix(root).unwrap().display()
            ));
            directory.sync_all()
        },
    )
    .unwrap();
    let events = events.into_inner();
    let syncs = events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.starts_with("sync:"))
        .collect::<Vec<_>>();
    assert_eq!(
        syncs.len(),
        3,
        "one root barrier per top-level directory plus final root: {events:?}"
    );
    for (index, event) in syncs {
        assert_eq!(
            event, "sync:",
            "removed descendants need no independent durability barrier"
        );
        assert!(["unlink:a", "unlink:b", "unlink:z-file"].contains(&events[index - 1].as_str()));
    }
    assert_eq!(events.last().unwrap(), "sync:");
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
}

#[test]
fn root_barrier_failure_is_returned_and_retirement_can_be_retried() {
    for fail_at in [1, 2] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("a/nested")).unwrap();
        std::fs::write(root.join("a/nested/file"), b"packed").unwrap();
        std::fs::write(root.join("astrid.volume"), b"durable authority").unwrap();
        let mut barriers = 0;
        let error = retire_with_io_hooks(
            root,
            || Ok(()),
            |_| Ok(()),
            |directory, path| {
                assert_eq!(path, root);
                barriers += 1;
                if barriers == fail_at {
                    return Err(io::Error::from_raw_os_error(nix::libc::EIO));
                }
                directory.sync_all()
            },
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(nix::libc::EIO));
        assert_eq!(barriers, fail_at);
        assert_eq!(
            std::fs::read(root.join("astrid.volume")).unwrap(),
            b"durable authority"
        );
        crate::dirs::retire_projection_root(root).unwrap();
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
    }
}

#[test]
fn late_child_prevents_directory_removal_and_successful_retirement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let directory = root.join("a");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(root.join("astrid.volume"), b"durable authority").unwrap();
    let error = super::retire_with_hooks(
        root,
        || Ok(()),
        |path| {
            assert_eq!(path, directory);
            std::fs::write(directory.join("late"), b"unreceipted")
        },
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(nix::libc::ENOTEMPTY));
    assert_eq!(
        std::fs::read(directory.join("late")).unwrap(),
        b"unreceipted"
    );
}

#[test]
fn external_links_and_open_files_do_not_restore_retired_root_names() {
    use std::io::Read as _;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    std::fs::create_dir_all(root.join("a")).unwrap();
    let packed = root.join("a/file");
    std::fs::write(&packed, b"published").unwrap();
    std::fs::write(root.join("astrid.volume"), b"durable authority").unwrap();
    let outside = temp.path().join("external-link");
    std::fs::hard_link(&packed, &outside).unwrap();
    let mut opened = std::fs::File::open(&packed).unwrap();
    crate::dirs::retire_projection_root(&root).unwrap();
    assert!(!packed.exists());
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    assert_eq!(std::fs::read(outside).unwrap(), b"published");
    let mut bytes = Vec::new();
    opened.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"published");
}

#[test]
fn preflight_inventory_rejects_late_entries_before_deletion() {
    for late in [
        "late-file",
        "late-directory/child",
        "a/late-file",
        "a/late-directory/child",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("a")).unwrap();
        std::fs::write(root.join("a/packed"), b"published").unwrap();
        std::fs::write(root.join("astrid.volume"), b"durable authority").unwrap();
        let extra = root.join(late);
        let result = super::retire_with_hook(root, || {
            std::fs::create_dir_all(extra.parent().unwrap())?;
            std::fs::write(&extra, b"unreceipted")
        });
        assert!(result.is_err(), "late entry was accepted: {late}");
        assert_eq!(std::fs::read(extra).unwrap(), b"unreceipted");
    }
}

#[test]
fn retirement_rejects_canonical_survivor_replacement_after_preflight() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    std::fs::create_dir(&root).unwrap();
    let volume = root.join("astrid.volume");
    std::fs::write(&volume, b"durable authority").unwrap();
    std::fs::write(root.join("projection"), b"published").unwrap();
    let retained = temp.path().join("retained.volume");
    let result = super::retire_with_hook(&root, || {
        std::fs::rename(&volume, &retained)?;
        std::fs::write(&volume, b"replacement")
    });
    assert!(
        result.is_err(),
        "replacement canonical survivor was accepted"
    );
    assert_eq!(std::fs::read(retained).unwrap(), b"durable authority");
    assert_eq!(std::fs::read(volume).unwrap(), b"replacement");
}

#[test]
fn prepared_inventory_exposes_only_relative_projection_files() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("a/empty")).unwrap();
    std::fs::write(root.join("a/file"), b"published").unwrap();
    std::fs::write(root.join("astrid.volume"), b"durable authority").unwrap();
    let volume = std::fs::File::open(root.join("astrid.volume")).unwrap();
    let plan = super::PreparedProjectionRetirement::prepare(root).unwrap();
    assert_eq!(
        plan.regular_files().collect::<Vec<_>>(),
        [std::path::Path::new("a/file")]
    );
    plan.retire(&volume).unwrap();
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
}

#[test]
fn engine_held_volume_replaced_before_preflight_prevents_every_unlink() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    std::fs::create_dir(&root).unwrap();
    let volume = root.join("astrid.volume");
    std::fs::write(&volume, b"durable authority").unwrap();
    let held = std::fs::File::open(&volume).unwrap();
    std::fs::rename(&volume, temp.path().join("held.volume")).unwrap();
    std::fs::write(&volume, b"replacement").unwrap();
    std::fs::write(root.join("packed"), b"published").unwrap();
    let plan = super::PreparedProjectionRetirement::prepare(&root).unwrap();
    assert!(plan.retire(&held).is_err());
    assert_eq!(std::fs::read(root.join("packed")).unwrap(), b"published");
    assert_eq!(std::fs::read(volume).unwrap(), b"replacement");
}

#[test]
fn final_barrier_cannot_accept_replaced_root_or_volume_or_late_entry() {
    for mutation in ["root", "volume", "late"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("home");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("astrid.volume"), b"durable authority").unwrap();
        std::fs::write(root.join("packed"), b"published").unwrap();
        let result = retire_with_io_hooks(
            &root,
            || Ok(()),
            |_| Ok(()),
            |directory, _| {
                directory.sync_all()?;
                match mutation {
                    "root" => {
                        std::fs::rename(&root, temp.path().join("held-root"))?;
                        std::fs::create_dir(&root)?;
                        std::fs::write(root.join("precious"), b"replacement")
                    },
                    "volume" => {
                        std::fs::rename(
                            root.join("astrid.volume"),
                            temp.path().join("held.volume"),
                        )?;
                        std::fs::write(root.join("astrid.volume"), b"replacement")
                    },
                    _ => std::fs::write(root.join("late"), b"unreceipted"),
                }
            },
        );
        assert!(result.is_err(), "accepted final {mutation} mutation");
        let survivor = match mutation {
            "root" => root.join("precious"),
            "volume" => root.join("astrid.volume"),
            _ => root.join("late"),
        };
        assert!(survivor.exists());
    }
}
