//! UUID-root removal with a deterministic test-only fault point.

#[cfg(all(test, any(unix, windows)))]
static ROOT_REMOVAL_FAULT_FOR_TEST: std::sync::Mutex<Option<std::path::PathBuf>> =
    std::sync::Mutex::new(None);

#[cfg(all(test, any(unix, windows)))]
pub(crate) fn fail_next_root_removal_for_test(path: std::path::PathBuf) {
    *ROOT_REMOVAL_FAULT_FOR_TEST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(path);
}

pub(crate) fn remove_projection_root(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(all(test, any(unix, windows)))]
    {
        let fault = ROOT_REMOVAL_FAULT_FOR_TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_deref()
            == Some(path);
        if fault {
            *ROOT_REMOVAL_FAULT_FOR_TEST
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            return Err(std::io::Error::from_raw_os_error(5));
        }
    }
    std::fs::remove_dir_all(path)
}
