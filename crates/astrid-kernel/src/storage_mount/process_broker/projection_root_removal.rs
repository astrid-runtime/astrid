//! UUID-root removal with a deterministic test-only fault point.

#[cfg(all(test, any(unix, windows)))]
static ROOT_REMOVAL_FAULTS_FOR_TEST: std::sync::Mutex<
    std::collections::BTreeSet<std::path::PathBuf>,
> = std::sync::Mutex::new(std::collections::BTreeSet::new());

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn fail_next_root_removal_for_test(path: std::path::PathBuf) {
    ROOT_REMOVAL_FAULTS_FOR_TEST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(path);
}

pub(crate) fn remove_projection_root(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(all(test, any(unix, windows)))]
    {
        let fault = ROOT_REMOVAL_FAULTS_FOR_TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(path);
        if fault {
            return Err(std::io::Error::from_raw_os_error(5));
        }
    }
    std::fs::remove_dir_all(path)
}
