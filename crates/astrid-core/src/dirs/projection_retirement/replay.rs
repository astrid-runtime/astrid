//! Root-qualified one-shot retirement interruption for integration tests.

use std::{
    collections::BTreeSet,
    io,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

static CUTS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

/// Fail the real retirement immediately before unlinking one captured entry.
///
/// Available only with `test-support`. The safe relative path is bound to the
/// explicit owned root; another root cannot consume this one-shot cut.
///
/// # Errors
/// Rejects absolute/empty/traversing paths and a poisoned test-hook registry.
pub fn interrupt_retirement_before_unlink_once(root: &Path, relative: &Path) -> io::Result<()> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "retirement cut must be relative",
        ));
    }
    CUTS.get_or_init(Mutex::default)
        .lock()
        .map_err(|_| io::Error::other("retirement cut registry poisoned"))?
        .insert(root.join(relative));
    Ok(())
}

pub(super) fn before_unlink(path: &Path) -> io::Result<()> {
    if let Some(cuts) = CUTS.get()
        && cuts
            .lock()
            .map_err(|_| io::Error::other("retirement cut registry poisoned"))?
            .remove(path)
    {
        return Err(io::Error::other(
            "injected projection retirement interruption",
        ));
    }
    Ok(())
}
