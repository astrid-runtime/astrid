//! Frames whose integrity work is complete before the append critical section.

use std::io::{IoSlice, Write};

use super::{
    ArenaLocation, CHECKSUM_START, DurableError, DurableIo, FRAME_HEADER_LEN,
    FRAME_HEADER_LEN_USIZE, FRAME_VERSION, SeekFrom, frame_checksum, io, io_error,
};

// Deliberately below every supported platform's practical iovec ceiling. A
// bounded staging batch may contain hundreds of small frames; slicing it here
// avoids a platform-specific syscall limit without rebuilding one large copy.
const MAX_IO_SLICES: usize = 64;

/// One physical frame with its header and checksum prepared off-lock.
pub(in crate::engine::durable) struct PreparedFrame {
    header: [u8; FRAME_HEADER_LEN_USIZE],
    payload: Vec<u8>,
    payload_len: u64,
    checksum: [u8; 32],
}

impl PreparedFrame {
    pub(in crate::engine::durable) fn new(
        magic: [u8; 8],
        payload: Vec<u8>,
    ) -> Result<Self, DurableError> {
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let checksum = frame_checksum(magic, payload_len, &payload);
        let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
        header[..8].copy_from_slice(&magic);
        header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
        header[12..20].copy_from_slice(&payload_len.to_le_bytes());
        header[CHECKSUM_START..].copy_from_slice(&checksum);
        Ok(Self {
            header,
            payload,
            payload_len,
            checksum,
        })
    }

    pub(in crate::engine::durable) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(in crate::engine::durable) fn retained_bytes(&self) -> usize {
        self.header.len().saturating_add(self.payload.len())
    }

    fn encoded_len(&self) -> Result<u64, DurableError> {
        FRAME_HEADER_LEN
            .checked_add(self.payload_len)
            .ok_or(DurableError::EncodingOverflow)
    }
}

/// Append already-framed payloads without hashing or coalescing under lock.
pub(in crate::engine::durable) fn append_prepared_frames<F: DurableIo>(
    file: &mut F,
    frames: &[PreparedFrame],
) -> Result<Vec<ArenaLocation>, DurableError> {
    let base = file
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek prepared durable batch append", source))?;
    let mut offset = base;
    let mut locations = Vec::new();
    locations
        .try_reserve_exact(frames.len())
        .map_err(|_| DurableError::EncodingOverflow)?;
    for frame in frames {
        locations.push(ArenaLocation {
            offset,
            payload_len: frame.payload_len,
            checksum: frame.checksum,
        });
        offset = offset
            .checked_add(frame.encoded_len()?)
            .ok_or(DurableError::EncodingOverflow)?;
    }

    for batch in frames.chunks(MAX_IO_SLICES / 2) {
        let mut slices = Vec::new();
        slices
            .try_reserve_exact(batch.len().saturating_mul(2))
            .map_err(|_| DurableError::EncodingOverflow)?;
        for frame in batch {
            slices.push(IoSlice::new(&frame.header));
            slices.push(IoSlice::new(&frame.payload));
        }
        write_all_vectored(file, &mut slices)?;
    }
    Ok(locations)
}

fn write_all_vectored<W: Write + ?Sized>(
    writer: &mut W,
    slices: &mut [IoSlice<'_>],
) -> Result<(), DurableError> {
    let mut remaining = slices;
    while !remaining.is_empty() {
        let written = loop {
            match writer.write_vectored(remaining) {
                Ok(written) => break written,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => {},
                Err(source) => {
                    return Err(io_error("append prepared durable frame batch", source));
                },
            }
        };
        if written == 0 {
            return Err(io_error(
                "append prepared durable frame batch",
                io::Error::new(
                    io::ErrorKind::WriteZero,
                    "vectored frame append made no progress",
                ),
            ));
        }
        IoSlice::advance_slices(&mut remaining, written);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    use super::*;
    use crate::engine::durable::append_frames;

    #[test]
    fn prepared_append_preserves_the_frozen_frame_encoding() {
        let payloads = vec![b"first".to_vec(), vec![0x5a; 128], Vec::new()];
        let prepared = payloads
            .iter()
            .cloned()
            .map(|payload| {
                PreparedFrame::new(crate::engine::durable::ARENA_MAGIC, payload).unwrap()
            })
            .collect::<Vec<_>>();
        let mut expected = tempfile::tempfile().unwrap();
        let expected_locations = append_frames(
            &mut expected,
            crate::engine::durable::ARENA_MAGIC,
            &payloads,
        )
        .unwrap();
        let mut actual = tempfile::tempfile().unwrap();
        let actual_locations = append_prepared_frames(&mut actual, &prepared).unwrap();

        assert_eq!(actual_locations, expected_locations);
        assert_eq!(read_all(&mut actual), read_all(&mut expected));
    }

    #[test]
    fn vectored_append_retries_interrupted_and_short_writes() {
        let mut writer = InterruptedShortWriter::default();
        let first = b"prepared ";
        let second = b"frame";
        let mut slices = [IoSlice::new(first), IoSlice::new(second)];

        write_all_vectored(&mut writer, &mut slices).unwrap();

        assert!(writer.interrupted);
        assert!(writer.successful_writes > 1);
        assert_eq!(writer.bytes, [first.as_slice(), second.as_slice()].concat());
    }

    #[derive(Default)]
    struct InterruptedShortWriter {
        bytes: Vec<u8>,
        interrupted: bool,
        successful_writes: usize,
    }

    impl Write for InterruptedShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.write_vectored(&[IoSlice::new(bytes)])
        }

        fn write_vectored(&mut self, slices: &[IoSlice<'_>]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let mut remaining = 3_usize;
            let before = self.bytes.len();
            for slice in slices {
                let take = remaining.min(slice.len());
                self.bytes.extend_from_slice(&slice[..take]);
                remaining = remaining.checked_sub(take).unwrap();
                if remaining == 0 {
                    break;
                }
            }
            self.successful_writes = self.successful_writes.checked_add(1).unwrap();
            Ok(self.bytes.len().checked_sub(before).unwrap())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn read_all(file: &mut File) -> Vec<u8> {
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }
}
