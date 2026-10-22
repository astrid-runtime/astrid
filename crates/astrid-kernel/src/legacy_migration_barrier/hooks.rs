//! Test-only interruption seam for migration crash-window coverage.

#[cfg(test)]
use std::collections::HashSet;
use std::io;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use astrid_core::dirs::AstridHome;

#[cfg(test)]
static INTERRUPT_AFTER_TMP_RETIREMENT: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn inject_tmp_retirement_interruption_once(home: &AstridHome) {
    INTERRUPT_AFTER_TMP_RETIREMENT
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .expect("tmp-retirement test hook lock")
        .insert(home.root().to_path_buf());
}

#[cfg_attr(not(test), allow(clippy::unnecessary_wraps))]
pub(crate) fn interrupt_after_tmp_retirement_if_requested(home: &AstridHome) -> io::Result<()> {
    #[cfg(test)]
    {
        let mut requested = INTERRUPT_AFTER_TMP_RETIREMENT
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .expect("tmp-retirement test hook lock");
        if requested.remove(home.root()) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_homes_keep_their_pending_interruptions() {
        let first_root = tempfile::tempdir().expect("first home");
        let second_root = tempfile::tempdir().expect("second home");
        let first = AstridHome::from_path(first_root.path());
        let second = AstridHome::from_path(second_root.path());

        inject_tmp_retirement_interruption_once(&first);
        inject_tmp_retirement_interruption_once(&second);
        assert_eq!(
            interrupt_after_tmp_retirement_if_requested(&first)
                .expect_err("first interruption")
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(
            interrupt_after_tmp_retirement_if_requested(&second)
                .expect_err("second interruption")
                .kind(),
            io::ErrorKind::Interrupted
        );
        interrupt_after_tmp_retirement_if_requested(&first).expect("first consumed once");
        interrupt_after_tmp_retirement_if_requested(&second).expect("second consumed once");
    }
}
