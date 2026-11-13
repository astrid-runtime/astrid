//! Scoped concurrency at the first wide inventory below each top-level directory.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use nix::sys::resource::{Resource, getrlimit};

use super::{File, Path, PlannedEntry, RetirementHooks, RootBoundary, io};

pub(super) fn delete_children(
    directory: &File,
    path: &Path,
    root: &RootBoundary,
    inventory: &[PlannedEntry],
) -> io::Result<()> {
    let width = width(inventory);
    #[cfg(test)]
    super::parallel_tests::observe_dispatch(path, width);
    delete_with_width(
        directory,
        path,
        root,
        inventory,
        width,
        || |_: &Path| Ok(()),
    )
}

fn width(inventory: &[PlannedEntry]) -> usize {
    let Some(capacity) = descriptor_capacity(inventory) else {
        return 1;
    };
    thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(inventory.len())
        .min(capacity)
        .max(1)
}

fn descriptor_capacity(inventory: &[PlannedEntry]) -> Option<usize> {
    let (soft, _) = getrlimit(Resource::RLIMIT_NOFILE).ok()?;
    let soft = usize::try_from(soft).ok()?;
    // Count only numeric descriptor entries; /dev/fd itself remains open during
    // the census, so its slot is conservatively reserved after the meter closes.
    // If the host does not expose a trustworthy census, retain serial deletion.
    let mut occupied = 0usize;
    for entry in std::fs::read_dir("/dev/fd").ok()? {
        let entry = entry.ok()?;
        if entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            occupied = occupied.checked_add(1)?;
        }
    }
    let depth = inventory.iter().map(descriptor_depth).max().unwrap_or(0);
    // One retained descriptor per traversed directory, plus Linux's leaf and
    // mount-confirmation handles (also covers a fresh directory listing).
    soft.saturating_sub(occupied)
        .checked_div(depth.checked_add(2)?)
}

fn descriptor_depth(entry: &PlannedEntry) -> usize {
    entry
        .children
        .iter()
        .map(descriptor_depth)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

pub(super) fn delete_with_width<U: FnMut(&Path) -> io::Result<()>>(
    directory: &File,
    path: &Path,
    root: &RootBoundary,
    inventory: &[PlannedEntry],
    width: usize,
    hooks: impl Fn() -> U + Sync,
) -> io::Result<()> {
    super::require_inventory(directory, path, inventory)?;
    if width <= 1 {
        let mut hooks = RetirementHooks {
            before_unlink: hooks(),
            sync_directory: |_: &File, _: &Path| Ok(()),
        };
        // A singleton spine contains no sibling work to distribute. Preserve
        // eligibility until its first wide inventory; jobs at that frontier
        // disable eligibility, so workers never create nested pools. A wide
        // inventory limited to one worker by host resources stays serial.
        let parallel_children = inventory.len() == 1;
        for entry in inventory {
            super::delete_entry(
                directory,
                path,
                root,
                entry,
                false,
                parallel_children,
                &mut hooks,
            )?;
        }
        return Ok(());
    }
    let queue = AtomicUsize::new(0);
    let stopped = AtomicBool::new(false);
    let first_error = Mutex::new(None);
    let record_error = |error| {
        stopped.store(true, Ordering::Release);
        let mut first = first_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if first.is_none() {
            *first = Some(error);
        }
    };
    let work = || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut hooks = RetirementHooks {
                before_unlink: hooks(),
                sync_directory: |_: &File, _: &Path| Ok(()),
            };
            while !stopped.load(Ordering::Acquire) {
                let index = queue.fetch_add(1, Ordering::Relaxed);
                let Some(entry) = inventory.get(index) else {
                    break;
                };
                super::delete_entry(directory, path, root, entry, false, false, &mut hooks)?;
            }
            Ok(())
        }))
        .unwrap_or_else(|_| Err(io::Error::other("projection retirement worker panicked")));
        if let Err(error) = result {
            record_error(error);
        }
    };
    thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 1..width.min(inventory.len()) {
            match thread::Builder::new().spawn_scoped(scope, work) {
                Ok(worker) => workers.push(worker),
                // Resource pressure must not turn a serially viable retirement
                // into a hard failure. The caller drains the remaining queue.
                Err(_) => break,
            }
        }
        #[cfg(test)]
        super::parallel_tests::observe_workers(path, workers.len());
        work();
        for worker in workers {
            if worker.join().is_err() {
                record_error(io::Error::other("projection retirement worker panicked"));
            }
        }
    });
    match first_error
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
