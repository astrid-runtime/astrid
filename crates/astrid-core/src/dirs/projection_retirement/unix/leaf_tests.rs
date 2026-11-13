//! Count actual leaf observations and exercise replacement at the unlink fence.

use std::cell::RefCell;
use std::os::unix::fs::symlink;

use super::*;

thread_local! {
    static WATCH: RefCell<Option<(PathBuf, usize)>> = const { RefCell::new(None) };
}

pub(super) fn observe(path: &Path) {
    WATCH.with_borrow_mut(|watch| {
        if let Some((watched, count)) = watch
            && watched == path
        {
            *count = count.strict_add(1);
        }
    });
}

struct Watch;

impl Watch {
    fn new(path: &Path) -> Self {
        WATCH.with_borrow_mut(|watch| {
            assert!(watch.is_none());
            *watch = Some((path.to_owned(), 0));
        });
        Self
    }

    fn count() -> usize {
        WATCH.with_borrow(|watch| watch.as_ref().unwrap().1)
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        WATCH.with_borrow_mut(|watch| *watch = None);
    }
}

#[test]
fn regular_leaf_is_observed_once_after_the_unlink_hook() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let leaf = root.join("packed");
    std::fs::write(&leaf, b"packed").unwrap();
    std::fs::write(root.join(CANONICAL_VOLUME), b"authority").unwrap();
    let volume = File::open(root.join(CANONICAL_VOLUME)).unwrap();
    let expected = fstat(&volume).unwrap();
    let plan = PreparedProjectionRetirement::prepare(root).unwrap();
    let _watch = Watch::new(&leaf);
    let mut visited = false;
    plan.retire_with_hooks(
        Some(&expected),
        &mut RetirementHooks {
            before_unlink: |path: &Path| {
                if path == leaf {
                    assert_eq!(Watch::count(), 0, "no redundant pre-hook leaf stat");
                    visited = true;
                }
                Ok(())
            },
            sync_directory: |directory: &File, _: &Path| directory.sync_all(),
        },
    )
    .unwrap();
    assert!(visited);
    assert_eq!(Watch::count(), 1, "fresh no-follow stat before unlink");
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"authority"
    );
}

#[derive(Clone, Copy)]
enum Replacement {
    Missing,
    Directory,
    Symlink,
}

#[test]
fn deferred_leaf_check_rejects_replacement_or_absence_after_the_hook() {
    for replacement in [
        Replacement::Missing,
        Replacement::Directory,
        Replacement::Symlink,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("home");
        std::fs::create_dir(&root).unwrap();
        let leaf = root.join("packed");
        let saved = temp.path().join("saved");
        std::fs::write(&leaf, b"original").unwrap();
        std::fs::write(root.join(CANONICAL_VOLUME), b"authority").unwrap();
        let plan = PreparedProjectionRetirement::prepare(&root).unwrap();
        let _watch = Watch::new(&leaf);
        let error = plan
            .retire_with_hooks(
                None,
                &mut RetirementHooks {
                    before_unlink: |path: &Path| {
                        if path == leaf {
                            assert_eq!(Watch::count(), 0);
                            std::fs::rename(&leaf, &saved)?;
                            match replacement {
                                Replacement::Missing => {},
                                Replacement::Directory => std::fs::create_dir(&leaf)?,
                                Replacement::Symlink => symlink(&saved, &leaf)?,
                            }
                        }
                        Ok(())
                    },
                    sync_directory: |directory: &File, _: &Path| directory.sync_all(),
                },
            )
            .unwrap_err();
        assert_eq!(
            error.kind(),
            match replacement {
                Replacement::Missing => io::ErrorKind::NotFound,
                Replacement::Directory | Replacement::Symlink => io::ErrorKind::InvalidData,
            }
        );
        assert_eq!(Watch::count(), 1);
        assert_eq!(std::fs::read(&saved).unwrap(), b"original");
        assert_eq!(
            std::fs::symlink_metadata(&leaf).is_ok(),
            !matches!(replacement, Replacement::Missing)
        );
        assert_eq!(
            std::fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
            b"authority"
        );
    }
}
