use std::fs::File;

/// Snapshot through the volume's owned handle: a second open conflicts with
/// its intentional mandatory byte-range lock on Windows.
pub(super) fn container_bytes(file: &File) -> Vec<u8> {
    let length = usize::try_from(file.metadata().unwrap().len()).unwrap();
    let mut bytes = vec![0; length];
    super::super::recover::read_exact_at(file, 0, &mut bytes).unwrap();
    bytes
}
