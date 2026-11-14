//! Hooks observe real operation boundaries without replacing filesystem fences.

use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Event {
    BeforeBoundWriterClone,
    BeforeAppendReturn,
    FileSynced,
    BeforeRename,
    BeforeUnlink,
    BeforeTemporaryCleanup,
    TemporaryUnlinked,
    ParentSynced,
    RootSynced,
    RootRepairSynced,
}

type Hook = Box<dyn FnMut(Event) -> io::Result<()>>;
thread_local! {
    static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
}

pub(super) fn after(event: Event) -> io::Result<()> {
    HOOK.with_borrow_mut(|hook| match hook {
        Some(hook) => hook(event),
        None => Ok(()),
    })
}

pub(super) fn install(hook: impl FnMut(Event) -> io::Result<()> + 'static) -> Reset {
    HOOK.with_borrow_mut(|slot| *slot = Some(Box::new(hook)));
    Reset
}

pub(super) struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        HOOK.with_borrow_mut(|slot| *slot = None);
    }
}

thread_local! {
    static FILE_STAT_QUERIES: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn query_file_stat(file: &File) -> nix::Result<nix::sys::stat::FileStat> {
    FILE_STAT_QUERIES.with(|count| count.set(count.get().strict_add(1)));
    nix::sys::stat::fstat(file)
}

pub(super) fn take_file_stat_queries() -> usize {
    FILE_STAT_QUERIES.with(|count| count.replace(0))
}
