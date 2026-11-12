//! Inspect persisted fixture bytes through the owning locked handle.

use std::fs::File;
use std::io::{self, Seek, SeekFrom};

use super::HostedFileVolume;

impl HostedFileVolume {
    #[cfg(test)]
    pub(crate) fn copy_container_for_test(&self, path: &std::path::Path) {
        copy_container(self, path);
    }

    pub(crate) fn write_preclose_volume_image(
        &self,
        output: &mut dyn std::io::Write,
    ) -> io::Result<u64> {
        self.with_current_binding(&self.path, |file| write_locked_file(file, output))
    }
}

#[cfg(test)]
pub(super) fn read_container(volume: &HostedFileVolume) -> Vec<u8> {
    let mut state = volume.state.lock();
    read_locked_file(&mut state.file)
}

#[cfg(test)]
pub(super) fn read_locked_file(file: &mut File) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_locked_file(file, &mut bytes).unwrap();
    bytes
}

fn write_locked_file(mut file: &File, output: &mut dyn std::io::Write) -> io::Result<u64> {
    let position = file.stream_position()?;
    let result = (|| {
        file.seek(SeekFrom::Start(0))?;
        std::io::copy(&mut file, output)
    })();
    file.seek(SeekFrom::Start(position))?;
    result
}

#[cfg(test)]
pub(super) fn copy_container(volume: &HostedFileVolume, path: &std::path::Path) {
    // Reading the live path through a second handle violates Windows mandatory
    // byte-range locks. This captures bytes before Drop without another sync.
    std::fs::write(path, read_container(volume)).unwrap();
}
