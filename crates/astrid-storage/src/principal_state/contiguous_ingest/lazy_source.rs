//! Open each packed source only while its content worker consumes it.

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

pub(super) enum LazyHomeSource {
    Pending { path: PathBuf, logical_bytes: u64 },
    Reading(File),
    Complete,
}

impl LazyHomeSource {
    pub(super) fn new(path: PathBuf, logical_bytes: u64) -> Self {
        Self::Pending {
            path,
            logical_bytes,
        }
    }
}

impl Read for LazyHomeSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // An empty buffer does not establish EOF or justify opening a source.
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            match self {
                Self::Pending {
                    path,
                    logical_bytes,
                } => {
                    let source =
                        super::open_home_source(path, *logical_bytes).map_err(io::Error::other)?;
                    *self = Self::Reading(source);
                },
                Self::Reading(source) => {
                    let read = source.read(buffer)?;
                    if read == 0 {
                        // EOF releases the descriptor before the next source;
                        // later reads must not reopen a changed pathname.
                        *self = Self::Complete;
                    }
                    return Ok(read);
                },
                Self::Complete => return Ok(0),
            }
        }
    }
}

#[cfg(test)]
mod tests;
