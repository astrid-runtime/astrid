//! Inspect persisted fixture bytes through the owning locked handle.

use super::*;

pub(super) fn read_container(volume: &HostedFileVolume) -> Vec<u8> {
    let mut state = volume.state.lock();
    let position = state.file.stream_position().unwrap();
    state.file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    state.file.read_to_end(&mut bytes).unwrap();
    state.file.seek(SeekFrom::Start(position)).unwrap();
    bytes
}

pub(super) fn copy_container(volume: &HostedFileVolume, path: &std::path::Path) {
    // Reading the live path through a second handle violates Windows mandatory
    // byte-range locks. This captures bytes before Drop without another sync.
    std::fs::write(path, read_container(volume)).unwrap();
}
