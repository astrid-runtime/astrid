//! Hooks run after actual fences, so tests cannot replace their execution.

use std::cell::RefCell;
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Event {
    FileSynced,
    BeforeRename,
    ParentSynced,
    RootSynced,
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
