//! Retry only a busy native mount; preserve all other errors and the deadline.

use std::io;
use std::time::{Duration, Instant};

pub(super) fn unmount_with(
    mut attempt: impl FnMut() -> io::Result<()>,
    deadline: Instant,
    interval: Duration,
) -> io::Result<()> {
    loop {
        match attempt() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::ResourceBusy => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(error);
                }
                std::thread::sleep(interval.min(remaining));
                if Instant::now() >= deadline {
                    return Err(error);
                }
            },
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
