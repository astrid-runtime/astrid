//! Exercise the common no-follow deletion path on actual scoped workers.

use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use super::*;

#[derive(Default)]
struct DispatchObservations {
    inventories: Vec<(PathBuf, usize)>,
    workers: Vec<(PathBuf, usize)>,
}

thread_local! {
    static DISPATCHES: RefCell<DispatchObservations> = RefCell::default();
}

pub(super) fn observe_dispatch(path: &Path, width: usize) {
    DISPATCHES.with_borrow_mut(|events| events.inventories.push((path.to_owned(), width)));
}

pub(super) fn observe_workers(path: &Path, count: usize) {
    DISPATCHES.with_borrow_mut(|events| events.workers.push((path.to_owned(), count)));
}

#[test]
fn singleton_spines_reach_the_real_wide_dispatch_without_nested_worker_pools() {
    for spine in ["log/principals", "etc/profiles"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        for child in ["a", "b"] {
            let directory = root.join(spine).join(child);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("leaf"), b"captured").unwrap();
        }
        std::fs::write(root.join(CANONICAL_VOLUME), b"authority").unwrap();
        let volume = File::open(root.join(CANONICAL_VOLUME)).unwrap();
        let plan = PreparedProjectionRetirement::prepare(root).unwrap();
        DISPATCHES.with_borrow_mut(|events| *events = DispatchObservations::default());
        plan.retire(&volume).unwrap();
        let events = DISPATCHES.with_borrow_mut(std::mem::take);
        let frontier = root.join(spine);
        let widths = events
            .inventories
            .iter()
            .filter_map(|(path, width)| (path == &frontier).then_some(*width))
            .collect::<Vec<_>>();
        assert_eq!(widths.len(), 1, "singleton descent must reach {spine}");
        assert_eq!(
            events.inventories.len(),
            2,
            "only the singleton and its wide frontier dispatch"
        );
        if widths[0] > 1 {
            assert_eq!(events.workers.len(), 1);
            assert_eq!(events.workers[0].0, frontier);
            assert!(
                events.workers[0].1 > 0,
                "derived capacity must start a scoped worker"
            );
        } else {
            assert!(
                events.workers.is_empty(),
                "resource-limited wide inventories stay serial"
            );
        }
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
            b"authority"
        );
    }
}

#[derive(Default)]
struct Rendezvous {
    started: Mutex<usize>,
    ready: Condvar,
}

impl Rendezvous {
    fn meet(&self) {
        let mut started = self.started.lock().unwrap();
        *started = started.strict_add(1);
        self.ready.notify_all();
        let (_started, timeout) = self
            .ready
            .wait_timeout_while(started, Duration::from_secs(5), |started| *started < 2)
            .unwrap();
        assert!(!timeout.timed_out(), "two real deletion jobs must overlap");
    }
}

fn two_leaves(root: &Path) -> PreparedProjectionRetirement {
    for name in ["a", "b"] {
        std::fs::write(root.join(name), b"captured").unwrap();
    }
    PreparedProjectionRetirement::prepare(root).unwrap()
}

#[test]
fn direct_children_overlap_and_each_captured_job_runs_once() {
    let temp = tempfile::tempdir().unwrap();
    let plan = two_leaves(temp.path());
    let rendezvous = Rendezvous::default();
    let calls = AtomicUsize::new(0);
    parallel::delete_with_width(
        &plan.directory,
        &plan.path,
        &plan.boundary,
        &plan.inventory,
        2,
        || {
            |_: &Path| {
                calls.fetch_add(1, Ordering::SeqCst);
                rendezvous.meet();
                Ok(())
            }
        },
    )
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn error_and_panic_join_every_started_child_before_returning() {
    for (panic, fail_on_caller) in [(false, false), (false, true), (true, false), (true, true)] {
        let caller = std::thread::current().id();
        let temp = tempfile::tempdir().unwrap();
        let plan = two_leaves(temp.path());
        let rendezvous = Rendezvous::default();
        let completed = AtomicUsize::new(0);
        let result = parallel::delete_with_width(
            &plan.directory,
            &plan.path,
            &plan.boundary,
            &plan.inventory,
            2,
            || {
                |_: &Path| {
                    rendezvous.meet();
                    if (std::thread::current().id() == caller) == fail_on_caller {
                        assert!(!panic, "injected deletion hook panic");
                        return Err(io::Error::other("injected deletion error"));
                    }
                    completed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        );
        assert!(result.is_err());
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        // A fresh plan may safely finish the partial retirement.
        super::retire(temp.path()).unwrap();
    }
}

#[test]
fn workers_reject_replacements_and_never_authorize_late_children() {
    for mutation in ["replacement", "late"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let plan = two_leaves(&root);
        let foreign = root.join("foreign");
        let saved = temp.path().join("saved");
        let result = parallel::delete_with_width(
            &plan.directory,
            &plan.path,
            &plan.boundary,
            &plan.inventory,
            2,
            || {
                |path: &Path| {
                    if path.file_name() == Some(OsStr::new("a")) {
                        if mutation == "replacement" {
                            std::fs::rename(path, &saved)?;
                            std::fs::write(path, b"foreign replacement")?;
                        } else {
                            std::fs::write(&foreign, b"unreceipted")?;
                        }
                    }
                    Ok(())
                }
            },
        );
        if mutation == "replacement" {
            assert!(result.is_err());
            assert_eq!(
                std::fs::read(root.join("a")).unwrap(),
                b"foreign replacement"
            );
            assert_eq!(std::fs::read(saved).unwrap(), b"captured");
        } else {
            result.unwrap();
            assert_eq!(std::fs::read(foreign).unwrap(), b"unreceipted");
            // The parent cannot retire with an unplanned surviving child.
            assert!(std::fs::remove_dir(&root).is_err());
        }
    }
}

#[test]
fn parallel_descendants_preserve_serial_root_barriers_and_canonical_volume() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    for name in ["a", "b"] {
        std::fs::create_dir(root.join(name)).unwrap();
        two_leaves(&root.join(name));
    }
    std::fs::write(root.join(CANONICAL_VOLUME), b"authority").unwrap();
    let volume = File::open(root.join(CANONICAL_VOLUME)).unwrap();
    let expected = fstat(&volume).unwrap();
    let plan = PreparedProjectionRetirement::prepare(root).unwrap();
    let mut removed = Vec::new();
    let mut barriers = 0;
    plan.retire_impl(
        Some(&expected),
        true,
        &mut RetirementHooks {
            before_unlink: |path: &Path| {
                assert_eq!(std::fs::read_dir(path)?.count(), 0);
                removed.push(path.file_name().unwrap().to_owned());
                Ok(())
            },
            sync_directory: |directory: &File, path: &Path| {
                assert_eq!(path, root);
                barriers += 1;
                if barriers <= 2 {
                    assert!(!root.join(if barriers == 1 { "a" } else { "b" }).exists());
                }
                directory.sync_all()
            },
        },
    )
    .unwrap();
    assert_eq!(removed, [OsString::from("a"), OsString::from("b")]);
    assert_eq!(barriers, 3);
    assert_eq!(
        std::fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"authority"
    );
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
}

#[test]
fn parallel_retirement_still_rejects_final_root_volume_and_namespace_changes() {
    for mutation in ["root", "volume", "late"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("log/principals")).unwrap();
        two_leaves(&root.join("log/principals"));
        std::fs::write(root.join(CANONICAL_VOLUME), b"authority").unwrap();
        let volume = File::open(root.join(CANONICAL_VOLUME)).unwrap();
        let expected = fstat(&volume).unwrap();
        let plan = PreparedProjectionRetirement::prepare(&root).unwrap();
        let mut barriers = 0;
        let result = plan.retire_impl(
            Some(&expected),
            true,
            &mut RetirementHooks {
                before_unlink: |_: &Path| Ok(()),
                sync_directory: |directory: &File, _: &Path| {
                    directory.sync_all()?;
                    barriers += 1;
                    if barriers != 2 {
                        return Ok(());
                    }
                    match mutation {
                        "root" => {
                            std::fs::rename(&root, temp.path().join("saved-root"))?;
                            std::fs::create_dir(&root)?;
                            std::fs::write(root.join("foreign"), b"foreign")
                        },
                        "volume" => {
                            std::fs::rename(
                                root.join(CANONICAL_VOLUME),
                                temp.path().join("saved-volume"),
                            )?;
                            std::fs::write(root.join(CANONICAL_VOLUME), b"foreign")
                        },
                        _ => std::fs::write(root.join("foreign"), b"foreign"),
                    }
                },
            },
        );
        assert!(result.is_err(), "accepted final {mutation} mutation");
        assert_eq!(barriers, 2);
        let foreign = root.join(if mutation == "volume" {
            CANONICAL_VOLUME
        } else {
            "foreign"
        });
        assert_eq!(std::fs::read(foreign).unwrap(), b"foreign");
    }
}
