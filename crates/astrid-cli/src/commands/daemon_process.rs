//! Platform process-spawn policy for the daemon.
//!
//! Transport authentication and daemon ownership live elsewhere. This module
//! only controls the parent-side background spawn flags. On Windows,
//! `astrid start --foreground` and a directly invoked daemon remain attached.
//! On Unix the daemon binary preserves its historical `setsid` behavior unless
//! the CLI sets `ASTRID_DAEMON_FOREGROUND=1` for foreground mode.

use std::process::Command;

/// Configure a daemon spawned for background operation.
///
/// Unix performs its historical `setsid` inside the daemon binary. Windows has
/// no equivalent post-spawn call, so the parent must request a detached process
/// group when it creates the child.
pub(super) fn configure_background(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;

        command.creation_flags(background_creation_flags());
    }

    #[cfg(not(windows))]
    let _ = command;
}

#[cfg(windows)]
const fn background_creation_flags() -> u32 {
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};

    CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
}

#[cfg(all(test, windows))]
mod tests {
    use super::background_creation_flags;

    #[test]
    fn windows_background_daemon_is_detached_from_the_console() {
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};

        assert_eq!(
            background_creation_flags(),
            CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
        );
    }
}
