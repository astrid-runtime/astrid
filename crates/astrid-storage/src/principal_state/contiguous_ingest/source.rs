//! Open packed inputs when consumed, so one atomic batch needs one source FD.
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::PathBuf;

use super::ContiguousFileIngest;

pub(super) struct HomeSource {
    path: PathBuf,
    expected_bytes: u64,
    source: Option<File>,
    exhausted: bool,
}

impl HomeSource {
    pub(super) fn new(file: &ContiguousFileIngest) -> Self {
        Self {
            path: file.path.clone(),
            expected_bytes: file.logical_bytes,
            source: None,
            exhausted: false,
        }
    }

    fn open(&self) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let source = options.open(&self.path)?;
        let metadata = source.metadata()?;
        if !metadata.is_file() || metadata.len() != self.expected_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "home source {} is not a regular file of expected length {} (found {})",
                    self.path.display(),
                    self.expected_bytes,
                    metadata.len()
                ),
            ));
        }
        Ok(source)
    }
}

impl Read for HomeSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.exhausted {
            return Ok(0);
        }
        if self.source.is_none() {
            self.source = Some(self.open().map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("open home source {}: {error}", self.path.display()),
                )
            })?);
        }
        let read = self
            .source
            .as_mut()
            .ok_or_else(|| io::Error::other("home source was not opened"))?
            .read(buffer)?;
        if read == 0 {
            self.source.take();
            self.exhausted = true;
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContentName;

    #[test]
    fn packed_sources_open_only_on_consumption_and_close_at_eof() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source");
        std::fs::write(&path, b"payload").unwrap();
        let file = ContiguousFileIngest::new(ContentName::new("test").unwrap(), path, 7);
        let mut readers = (0..2048)
            .map(|_| HomeSource::new(&file))
            .collect::<Vec<_>>();
        assert!(readers.iter().all(|reader| reader.source.is_none()));
        for reader in &mut readers {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"payload");
            assert!(reader.source.is_none());
            assert!(reader.exhausted);
        }
    }

    #[test]
    fn changed_source_fails_when_consumed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source");
        std::fs::write(&path, b"payload").unwrap();
        let file = ContiguousFileIngest::new(ContentName::new("test").unwrap(), &path, 7);
        let mut reader = HomeSource::new(&file);
        std::fs::write(&path, b"changed length").unwrap();
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        assert!(reader.source.is_none());
    }
}
