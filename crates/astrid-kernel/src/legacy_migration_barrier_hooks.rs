//! Test-only interruption seam for migration crash-window coverage.

use std::io;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use astrid_core::dirs::AstridHome;

#[cfg(test)]
static INTERRUPT_AFTER_TMP_RETIREMENT: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn inject_tmp_retirement_interruption_once(home: &AstridHome) {
    *INTERRUPT_AFTER_TMP_RETIREMENT
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("tmp-retirement test hook lock") = Some(home.root().to_path_buf());
}

#[cfg_attr(not(test), allow(clippy::unnecessary_wraps))]
pub(crate) fn interrupt_after_tmp_retirement_if_requested(home: &AstridHome) -> io::Result<()> {
    #[cfg(test)]
    {
        let mut requested = INTERRUPT_AFTER_TMP_RETIREMENT
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("tmp-retirement test hook lock");
        if requested
            .as_ref()
            .is_some_and(|target| target == home.root())
        {
            requested.take();
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "injected crash after disposable tmp retirement",
            ));
        }
    }
    #[cfg(not(test))]
    let _ = home;
    Ok(())
}
