//! Test seam for no-follow source retirement.

use std::path::Path;

#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

// The retirement boundary is intentionally no-follow and revalidates every
// leaf before unlinking it. Tests use this one-shot seam to model an
// same-UID operator replacement after validation but before the final
// unlink. It is compiled out of production builds.
#[cfg(test)]
type RetireLeafHook = Box<dyn FnOnce(&Path) + Send + 'static>;

#[cfg(test)]
static RETIRE_LEAF_HOOKS: OnceLock<Mutex<BTreeMap<PathBuf, RetireLeafHook>>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn set_test_retire_leaf_hook(path: PathBuf, hook: RetireLeafHook) {
    RETIRE_LEAF_HOOKS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .expect("retirement test hook lock")
        .insert(path, hook);
}

#[cfg(test)]
pub(super) fn run_test_retire_leaf_hook(path: &Path) {
    let mut hooks = RETIRE_LEAF_HOOKS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .expect("retirement test hook lock");
    if let Some(hook) = hooks.remove(path) {
        hook(path);
    }
}

#[cfg(not(test))]
#[inline]
pub(super) fn run_test_retire_leaf_hook(_path: &Path) {}
