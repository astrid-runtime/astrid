//! Ordinary native unmount with bounded retries for transient kernel references.

use std::path::Path;
use std::time::Instant;

use anyhow::{Context as _, Result};
use nix::mount::MntFlags;

mod retry;

pub(crate) async fn unmount(mountpoint: &Path) -> Result<()> {
    let mountpoint = mountpoint.to_owned();
    let deadline = Instant::now() + crate::service::UNMOUNT_CONFIRM_TIMEOUT;
    tokio::task::spawn_blocking(move || {
        retry::unmount_with(
            || {
                // Never force an occupied mount. Typed errno avoids classifying
                // localized command output as a retryable condition.
                nix::mount::unmount(&mountpoint, MntFlags::empty())
                    .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
            },
            deadline,
            crate::service::UNMOUNT_CONFIRM_INTERVAL,
        )
        .with_context(|| format!("unmount native filesystem {}", mountpoint.display()))
    })
    .await
    .context("join native unmount operation")?
}
