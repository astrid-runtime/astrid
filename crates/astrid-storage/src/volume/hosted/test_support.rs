//! Inspect persisted fixture bytes through the owning locked handle.

use super::*;

impl HostedFileVolume {
    pub(crate) fn copy_container_for_test(&self, path: &std::path::Path) {
        copy_container(self, path);
    }
}

pub(super) fn read_container(volume: &HostedFileVolume) -> Vec<u8> {
    let mut state = volume.state.lock();
    read_locked_file(&mut state.file)
}

pub(super) fn read_locked_file(file: &mut File) -> Vec<u8> {
    let position = file.stream_position().unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    file.seek(SeekFrom::Start(position)).unwrap();
    bytes
}

pub(super) fn copy_container(volume: &HostedFileVolume, path: &std::path::Path) {
    // Reading the live path through a second handle violates Windows mandatory
    // byte-range locks. This captures bytes before Drop without another sync.
    std::fs::write(path, read_container(volume)).unwrap();
}
