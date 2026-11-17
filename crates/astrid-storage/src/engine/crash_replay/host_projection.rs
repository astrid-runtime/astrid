//! One-shot interruption of actual host restoration after a committed write.

use std::{
    collections::BTreeSet,
    io,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use crate::content::ContentName;
use astrid_core::dirs::AstridHome;

static CUTS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

/// Interrupt restoration after this explicit home's named file is installed.
///
/// This panic models process interruption rather than a returned write error:
/// normal rollback does not run. Only `crash-replay` builds expose this hook.
///
/// # Errors
/// Rejects absolute/traversing names or a poisoned test-hook registry.
pub fn interrupt_restore_after_write_once(home: &AstridHome, name: &ContentName) -> io::Result<()> {
    let relative = Path::new(name.as_str());
    if relative
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "restore cut must be relative",
        ));
    }
    CUTS.get_or_init(Mutex::default)
        .lock()
        .map_err(|_| io::Error::other("restore cut registry poisoned"))?
        .insert(home.root().join(relative));
    Ok(())
}

pub(crate) fn after_write(root: &Path, relative: &str) {
    let interrupt = CUTS.get().is_some_and(|cuts| {
        cuts.lock()
            .expect("restore cut registry")
            .remove(&root.join(relative))
    });
    assert!(!interrupt, "injected projection restoration interruption");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_cut_rejects_names_that_escape_the_owned_root() {
        let directory = crate::test_directory::temporary().unwrap();
        let home = AstridHome::from_path(directory.path());
        for name in [
            "/outside/file",
            "../outside",
            "file/../../outside",
            "./file",
        ] {
            let error = interrupt_restore_after_write_once(&home, &ContentName::new(name).unwrap())
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn restore_cut_is_consumed_only_by_its_owned_root() {
        let first = crate::test_directory::temporary().unwrap();
        let second = crate::test_directory::temporary().unwrap();
        let name = ContentName::new("etc/layout-version").unwrap();
        interrupt_restore_after_write_once(&AstridHome::from_path(first.path()), &name).unwrap();
        after_write(second.path(), name.as_str());
        assert!(std::panic::catch_unwind(|| after_write(first.path(), name.as_str())).is_err());
        after_write(first.path(), name.as_str());
    }
}
