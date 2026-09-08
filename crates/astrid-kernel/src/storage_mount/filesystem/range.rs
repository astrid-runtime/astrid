//! Stream replacement bytes without treating the RPC payload ceiling as a file limit.
use super::*;

pub(super) fn replace(
    filesystem: &impl CallbackFilesystem,
    path: &FilesystemPath,
    old_length: u64,
    new_length: u64,
    offset: u64,
    data: &[u8],
) -> Result<(), FilesystemError> {
    // Publication happens only after the reader finishes, so reads still see the
    // original file. The mount callback serializes its mutations.
    filesystem.write_streaming(
        path,
        Replacement {
            filesystem,
            path,
            old_length,
            new_length,
            offset,
            data,
            position: 0,
        },
    )
}

struct Replacement<'a, F> {
    filesystem: &'a F,
    path: &'a FilesystemPath,
    old_length: u64,
    new_length: u64,
    offset: u64,
    data: &'a [u8],
    position: u64,
}

impl<F: CallbackFilesystem> Read for Replacement<'_, F> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.new_length.saturating_sub(self.position);
        let count = usize::try_from(remaining.min(STORAGE_FILESYSTEM_MAX_IO_BYTES))
            .unwrap_or(usize::MAX)
            .min(output.len());
        if count == 0 {
            return Ok(0);
        }
        let patch_end = self.offset.strict_add(self.data.len() as u64);
        let count = if self.position >= self.offset && self.position < patch_end {
            let count = count
                .min(usize::try_from(patch_end.strict_sub(self.position)).unwrap_or(usize::MAX));
            let start = usize::try_from(self.position.strict_sub(self.offset))
                .map_err(|_| std::io::Error::other("patch offset exceeds address space"))?;
            output[..count].copy_from_slice(&self.data[start..start.strict_add(count)]);
            count
        } else {
            let boundary = if self.position < self.offset {
                self.offset
            } else {
                self.new_length
            };
            let count = count
                .min(usize::try_from(boundary.strict_sub(self.position)).unwrap_or(usize::MAX));
            if self.position < self.old_length {
                let count = count.min(
                    usize::try_from(self.old_length.strict_sub(self.position))
                        .unwrap_or(usize::MAX),
                );
                let bytes = self
                    .filesystem
                    .read(self.path, self.position, count as u64)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                if bytes.len() != count {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "mounted file changed during replacement",
                    ));
                }
                output[..count].copy_from_slice(&bytes);
                count
            } else {
                output[..count].fill(0);
                count
            }
        };
        self.position = self.position.strict_add(count as u64);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mounted_large_file_range_writes_resize_and_sync() {
        let temporary = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
        let kernel = crate::test_kernel_with_home(home).await;
        let store = kernel.principal_store.clone().unwrap();
        let fs = AstridFilesystem::new(
            store.content(),
            StateOwner::Principal(astrid_core::PrincipalUid::from_bytes([0xB8; 32])),
        );
        let path = FilesystemPath::new("large.bin").unwrap();
        fs.write(&path, b"seed").unwrap();
        let offset = STORAGE_FILESYSTEM_MAX_IO_BYTES + 1;
        execute_blocking(
            &fs,
            StorageFilesystemOperationV1::Write {
                path: path.as_str().into(),
                offset,
                data: b"tail".to_vec(),
            },
        )
        .unwrap();
        assert_eq!(fs.stat(&path).unwrap().logical_bytes(), offset + 4);
        assert_eq!(fs.read(&path, 0, 4).unwrap(), b"seed");
        assert_eq!(fs.read(&path, offset - 1, 5).unwrap(), b"\0tail");
        execute_blocking(
            &fs,
            StorageFilesystemOperationV1::Write {
                path: path.as_str().into(),
                offset: 1,
                data: b"XY".to_vec(),
            },
        )
        .unwrap();
        assert_eq!(fs.read(&path, 0, 4).unwrap(), b"sXYd");
        assert_eq!(fs.read(&path, offset, 4).unwrap(), b"tail");
        for length in [offset + 8, offset + 2, 0] {
            execute_blocking(
                &fs,
                StorageFilesystemOperationV1::SetLength {
                    path: path.as_str().into(),
                    length,
                },
            )
            .unwrap();
            assert_eq!(fs.stat(&path).unwrap().logical_bytes(), length);
            if length == offset + 8 {
                assert_eq!(fs.read(&path, offset, 8).unwrap(), b"tail\0\0\0\0");
            }
        }
        execute_blocking(&fs, StorageFilesystemOperationV1::Sync).unwrap();
    }
}
